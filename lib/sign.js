/**
 * @typedef {import('hypercore')} Hypercore
 * @typedef {{
 *   key: string
 *   length: number
 *   treeHash: string
 * }} CoreInfo
 * @typedef {{
 *   start: number
 *   end: number
 *   idx: number
 * }} Progress
 */

const z32 = require('z32')
const { assemble, partialSignature } = require('hypercore/lib/multisig')

const { getCoreInfo } = require('./core')
const MultisigError = require('./error')

/**
 * @param {Hypercore} core
 * @param {Hypercore} batch
 * @param {Buffer[]} signatures
 * @param {{
 *   start?: number
 *   length?: number
 *   commit?: boolean
 *   onProgress?: (progress: Progress) => void
 * }} opts
 * @return {Promise<CoreInfo>}
 */
async function signCore(core, fromCore, signatures, { start, length, commit, onProgress } = {}) {
  /** @type {Hypercore | null} */
  let batch = null
  try {
    batch = await createUpdateBatch(core, fromCore, { start, length, onProgress })

    // We always get an entry for every signer, but it's undefined if there's no signature
    const nrSigned = signatures.filter(Boolean).length
    let signature = null
    if (nrSigned >= core.manifest.quorum) {
      signature = await generateMultisigProof(batch, signatures)
    }

    if (commit) {
      const result = await core.commit(batch, { signature })
      if (result === null) throw MultisigError.COMMIT_FAILED()
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
 *   length?: number
 *   blobsStart?: number
 *   blobsLength?: number
 *   commit?: boolean
 *   onProgress?: (progress: Progress) => void
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
  { start, length, blobsStart, blobsLength, commit, onProgress, onBlobsProgress } = {}
) {
  const blobsBatch = await signCore(blobsCore, fromBlobsCore, blobsSignatures, {
    start: blobsStart,
    length: blobsLength,
    commit,
    onProgress: onBlobsProgress
  })
  const batch = await signCore(core, fromCore, signatures, {
    start,
    length,
    commit,
    onProgress
  })
  return { batch, blobsBatch }
}

/**
 * @param {Hypercore} core
 * @param {Hypercore} fromCore
 * @param {{ start?: number, length?: number, onProgress?: (progress: Progress) => void }} opts
 * @return {Promise<Hypercore>}
 */
async function createUpdateBatch(core, fromCore, { start, length, onProgress } = {}) {
  start = start ?? core.contiguousLength
  const end = length || fromCore.length

  const download = fromCore.download({ start, end })
  await download.done()

  /** @type {Hypercore} */
  const batch = core.session({ name: 'batch', checkout: start, overwrite: true })
  for (let idx = start; idx < end; idx += 1) {
    await batch.append(await fromCore.get(idx))
    if (onProgress) onProgress({ start, end, idx })
  }
  return batch
}

/**
 * @param {Hypercore} batch
 * @param {Buffer[]} signatures
 */
async function generateMultisigProof(batch, signatures) {
  const length = batch.length

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
  signDrive,
  createUpdateBatch
}
