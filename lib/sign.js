/**
 * @typedef {import('hypercore')} Hypercore
 * @typedef {{
 *   key: string
 *   length: number
 *   treeHash: string
 * }} CoreInfo
 */

const z32 = require('z32')
const { assemble, partialSignature } = require('hypercore/lib/multisig')

const { getCoreInfo } = require('./core')

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

    // We always get an entry for every signer, but it's undefined if there's no signature
    const nrSigned = signatures.filter(Boolean).length
    let signature = null
    if (nrSigned >= core.manifest.quorum) {
      signature = await generateMultisigProof(batch, signatures, { length })
    }

    if (commit) {
      await core.commit(batch, { signature, length })
    }

    const batchInfo = await getCoreInfo(batch)
    batchInfo.signature = signature ? z32.encode(signature) : null

    return batchInfo
  } finally {
    if (batch) await batch.close()
  }
}

async function signTruncatedCore(core, signatures, length, { commit } = {}) {
  /** @type {Hypercore | null} */
  let batch = null
  try {
    batch = await createTruncateBatch(core, length)
    console.log('🚀 ~ signTruncatedCore ~ batch:', batch.fork, batch.length)

    // We always get an entry for every signer, but it's undefined if there's no signature
    const nrSigned = signatures.filter(Boolean).length
    let signature = null
    if (nrSigned >= core.manifest.quorum) {
      signature = await generateMultisigProof(batch, signatures)
    }

    if (commit) {
      await core.commit(batch, { signature, length })
      console.log('🚀 ~ signTruncatedCore ~ core:', core.fork, core.length)
    }

    const batchInfo = await getCoreInfo(batch)
    batchInfo.signature = signature ? z32.encode(signature) : null

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
 * @param {number} length
 * @return {Promise<Hypercore>}
 */
async function createTruncateBatch(core, length) {
  /** @type {Hypercore} */
  const batch = core.session({ name: 'batch', overwrite: true })
  await batch.truncate(length)
  return batch
}

/**
 * @param {Hypercore} core
 * @param {Hypercore} batch
 * @param {Buffer[]} signatures
 * @param {{ length?: number }} opts
 */
async function generateMultisigProof(batch, signatures, { length } = {}) {
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

  return multisig
}

module.exports = {
  signCore,
  signTruncatedCore,
  signDrive,
  createUpdateBatch,
  createTruncateBatch
}
