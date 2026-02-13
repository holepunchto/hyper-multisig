/**
 * @typedef {import('corestore')} Corestore
 * @typedef {import('hypercore/lib/download')} Download
 * @typedef {{
 *   version: number
 *   hash: string
 *   quorum: number
 *   signers: Array<{
 *     signature: string
 *     publicKey: Buffer
 *     namespace: Buffer
 *   }>
 * }} Manifest
 * @typedef {{
 *   key: string
 *   length: number
 *   treeHash: string
 * }} CoreInfo
 */

const b4a = require('b4a')
const Hypercore = require('hypercore')
const { assemble, partialSignature } = require('hypercore/lib/multisig')
const crypto = require('hypercore-crypto')
const idEnc = require('hypercore-id-encoding')

const MultisigError = require('./error')

/**
 * @param {Hypercore} core
 * @param {Hypercore} batch
 * @param {Buffer[]} signatures
 * @param {{
 *   length?: number
 *   start?: number
 *   end?: number
 *   commit?: boolean
 * }} opts
 * @return {Promise<CoreInfo>}
 */
async function signCore(core, fromCore, signatures, { length, start, end, commit } = {}) {
  /** @type {Hypercore | null} */
  let batch = null
  try {
    batch = await createUpdateBatch(core, fromCore, { start, end })
    if (commit) {
      await commitUpdateBatch(core, batch, signatures, { length })
    }
    const batchInfo = await getCoreInfo(batch)
    return batchInfo
  } finally {
    if (batch) await batch.close()
  }
}

/**
 * @param {Hypercore} core
 * @param {Hypercore} fromCore
 * @param {Buffer[]} signatures
 * @param {Hypercore} blobsCore
 * @param {Hypercore} fromBlobsCore
 * @param {Buffer[]} blobsSignatures
 * @param {{
 *   start?: number
 *   end?: number
 *   length?: number
 *   blobsStart?: number
 *   blobsEnd?: number
 *   blobsLength?: number
 *   commit?: boolean
 * }} opts
 * @return {Promise<{ batch: CoreInfo, blobsBatch: CoreInfo }>}
 */
async function signDrive(
  core,
  fromCore,
  signatures,
  blobsCore,
  fromBlobsCore,
  blobsSignatures,
  { start, end, length, blobsStart, blobsEnd, blobsLength, commit } = {}
) {
  const blobsBatch = await signCore(blobsCore, fromBlobsCore, blobsSignatures, {
    start: blobsStart,
    end: blobsEnd,
    length: blobsLength,
    commit
  })
  const batch = await signCore(core, fromCore, signatures, {
    start,
    end,
    length,
    commit
  })
  return { batch, blobsBatch }
}

/**
 * @param {Hypercore} core
 * @param {Hypercore} fromCore
 * @param {{ start?: number, end?: number }} opts
 * @return {Promise<Hypercore>}
 */
async function createUpdateBatch(core, fromCore, { start, end } = {}) {
  start = start ?? core.length
  end = end ?? fromCore.length

  const download = fromCore.download({ start, end })
  await download.done()

  /** @type {Hypercore} */
  const batch = core.session({ name: 'batch', overwrite: true })
  for (let idx = start; idx < end; idx += 1) {
    await batch.append(await fromCore.get(idx))
  }
  return batch
}

/**
 * @param {Hypercore} core
 * @param {Hypercore} batch
 * @param {Buffer[]} signatures
 * @param {{ length?: number }} opts
 */
async function commitUpdateBatch(core, batch, signatures, { length } = {}) {
  length = length || batch.length

  const proofs = await Promise.all(
    signatures.map(async (sig, idx) => {
      if (!sig) return null
      const proof = await partialSignature(batch, idx, length, length, sig) // idx is important here, must match with the signers index
      return proof
    })
  )
  const validProofs = proofs.filter(Boolean)
  const multisig = assemble(validProofs)

  await core.commit(batch, { signature: multisig, length })
}

/**
 * @param {string[]} publicKeys
 * @param {string} namespace
 * @return {string}
 */
function getCoreKey(publicKeys, namespace) {
  const manifest = getManifest(publicKeys, namespace)
  return Hypercore.key(manifest)
}

/**
 * @param {string[]} publicKeys
 * @param {string} namespace
 * @return {Manifest}
 */
function getManifest(publicKeys, namespace, { quorum } = {}) {
  if (!quorum) quorum = Math.floor(publicKeys.length / 2) + 1

  return {
    version: 1,
    hash: 'blake2b',
    quorum,
    signers: publicKeys.map((publicKey) => ({
      signature: 'ed25519',
      publicKey: idEnc.decode(publicKey),
      namespace: idEnc.decode(getNamespace(namespace))
    }))
  }
}

/**
 * @param {string} namespace
 * @return {string}
 */
function getNamespace(namespace) {
  return idEnc.normalize(crypto.hash(Buffer.from(namespace)))
}

/**
 * @param {Manifest} manifest
 */
function normalizeManifest(manifest) {
  return {
    ...manifest,
    signers: manifest.signers.map((signer) => ({
      ...signer,
      publicKey: idEnc.normalize(signer.publicKey),
      namespace: idEnc.normalize(signer.namespace)
    }))
  }
}

/**
 * @param {Hypercore} core
 * @return {Promise<{ key: string, length: number, treeHash: string }>}
 */
async function getCoreInfo(core) {
  await core.ready()
  return {
    key: idEnc.normalize(core.key),
    length: core.length,
    treeHash: idEnc.normalize(await core.treeHash())
  }
}

async function verifyCoreRequestable(
  srcCore,
  length,
  { minPeers = 2, peerUpdateTimeout = 5000, coreId } = {}
) {
  await waitUntilCoreLength(srcCore, length, { timeout: peerUpdateTimeout })

  if (length > srcCore.length) {
    throw MultisigError.SOURCE_CORE_TOO_SMALL(length, { coreId })
  }

  await waitUntilSufficientPeers(srcCore, { minPeers, timeout: peerUpdateTimeout })

  const nrSrcPeers = srcCore.peers.length
  if (nrSrcPeers < minPeers) {
    throw MultisigError.SOURCE_CORE_INSUFFICIENT_PEERS(nrSrcPeers, minPeers)
  }

  await waitUntilFullySeeded(srcCore, { minPeers, timeout: peerUpdateTimeout })

  let srcFullCopies = 0
  for (const p of srcCore.peers) {
    if (p.remoteContiguousLength === srcCore.length) srcFullCopies++
  }
  if (srcFullCopies < minPeers) {
    throw MultisigError.SOURCE_CORE_NOT_FULLY_SEEDED(srcFullCopies, minPeers, { coreId })
  }
}

async function verifyCoreCommittable(
  srcCore,
  tgtCore,
  length,
  { minPeers = 2, skipTargetChecks = false, peerUpdateTimeout = 5000, coreId } = {}
) {
  await waitUntilCoreLength(srcCore, length, { timeout: peerUpdateTimeout })

  if (length > srcCore.length) {
    throw MultisigError.SOURCE_CORE_TOO_SMALL(length, { coreId })
  }

  // Either it corrupts the core, or it's a no-op (re-signing already signed data). There's no possible upside.
  if (tgtCore.length > srcCore.length) {
    throw MultisigError.TARGET_CORE_TOO_BIG()
  }

  await waitUntilSufficientPeers(srcCore, { minPeers, timeout: peerUpdateTimeout })

  const nrSrcPeers = srcCore.peers.length
  if (nrSrcPeers < minPeers) {
    throw MultisigError.SOURCE_CORE_INSUFFICIENT_PEERS(nrSrcPeers, minPeers)
  }

  await waitUntilFullySeeded(srcCore, { minPeers, timeout: peerUpdateTimeout })

  let srcFullCopies = 0
  for (const p of srcCore.peers) {
    if (p.remoteContiguousLength === srcCore.length) srcFullCopies++
  }
  if (srcFullCopies < minPeers) {
    throw MultisigError.SOURCE_CORE_NOT_FULLY_SEEDED(srcFullCopies, minPeers, { coreId })
  }

  if (skipTargetChecks) {
    // no checks on the target if it's the first commit
    if (tgtCore.length > 0) throw MultisigError.TARGET_NOT_EMPTY()
    return
  }

  const tgtPeers = tgtCore.peers.length
  if (tgtPeers < minPeers) {
    throw MultisigError.TARGET_CORE_INSUFFICIENT_PEERS(tgtPeers, minPeers, { coreId })
  }

  let tgtFullCopies = 0
  for (const p of tgtCore.peers) {
    if (p.remoteContiguousLength === tgtCore.length) tgtFullCopies++
  }
  if (tgtFullCopies < minPeers) {
    throw MultisigError.TARGET_CORE_NOT_FULLY_SEEDED(tgtFullCopies, minPeers, { coreId })
  }

  if (!b4a.equals(await tgtCore.treeHash(tgtCore.length), await srcCore.treeHash(tgtCore.length))) {
    throw MultisigError.INCOMPATIBLE_SOURCE_AND_TARGET({ coreId })
  }
}

async function waitUntilCoreLength(core, length, { timeout = 5000 } = {}) {
  return await waitUntil(() => core.length >= length, { timeout })
}

async function waitUntilSufficientPeers(core, { minPeers = 2, timeout = 5000 } = {}) {
  return await waitUntil(() => core.peers?.length >= minPeers, { timeout })
}

async function waitUntilFullySeeded(core, { minPeers = 2, timeout = 5000 } = {}) {
  return await waitUntil(
    () => core.peers?.filter((p) => p.remoteContiguousLength === core.length).length >= minPeers,
    { timeout }
  )
}

async function waitUntil(conditionFn, { timeout = 5000, interval = 100 } = {}) {
  if (await conditionFn()) return true
  if (timeout < 0) return false
  await new Promise((resolve) => setTimeout(resolve, interval))
  return waitUntil(conditionFn, { timeout: timeout - interval, interval })
}

module.exports = {
  signCore,
  signDrive,
  createUpdateBatch,
  commitUpdateBatch,
  getCoreKey,
  getManifest,
  getNamespace,
  normalizeManifest,
  getCoreInfo,
  verifyCoreRequestable,
  verifyCoreCommittable,
  waitUntilCoreLength,
  waitUntilSufficientPeers,
  waitUntilFullySeeded
}
