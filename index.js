/**
 * @typedef {import('corestore')} Corestore
 * @typedef {import('hypercore')} Hypercore
 * @typedef {import('hyperswarm')} Hyperswarm
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

const cenc = require('compact-encoding')
const CoreSign = require('hypercore-sign')
const SignRequest = require('hypercore-signing-request')
const Hyperdrive = require('hyperdrive')
const z32 = require('z32')

const MultisigUtil = require('./lib/util')

class HyperMultisig {
  constructor(store, swarm) {
    /** @type {Corestore} */
    this.store = store
    /** @type {Hyperswarm} */
    this.swarm = swarm
  }

  /**
   * @param {string[]} publicKeys
   * @param {string} namespace
   * @return {Promise<{ manifest: Manifest, key: Buffer, core: Hypercore }>}
   */
  async createCore(publicKeys, namespace, { quorum } = {}) {
    const manifest = MultisigUtil.getManifest(publicKeys, namespace, { quorum })
    const core = this.store.get({ manifest })
    await core.ready()
    return { manifest, key: core.key, core }
  }

  /**
   * @param {string[]} publicKeys
   * @param {string} namespace
   * @return {Promise<{
   *   manifest: Manifest, key: Buffer, core: Hypercore,
   *   blobsManifest: Manifest, blobsKey: Buffer, blobsCore: Hypercore
   * }>}
   */
  async createDrive(publicKeys, namespace, { quorum } = {}) {
    const { manifest, key, core } = await this.createCore(publicKeys, namespace, { quorum })

    const blobsManifest = Hyperdrive.getContentManifest(manifest, key)
    const blobsKey = Hyperdrive.getContentKey(manifest, key)
    const blobsCore = this.store.get({ manifest: blobsManifest })

    return { manifest, key, core, blobsManifest, blobsKey, blobsCore }
  }

  async requestCore(
    publicKeys,
    namespace,
    srcCore,
    length,
    { force = false, quorum, peerUpdateTimeout } = {}
  ) {
    await srcCore.ready()
    this.swarm.join(srcCore.discoveryKey, { client: true, server: false })
    await srcCore.download({ start: 0, end: length }).done()

    if (!force) await MultisigUtil.verifyCoreRequestable(srcCore, length, { peerUpdateTimeout })

    const manifest = MultisigUtil.getManifest(publicKeys, namespace, { quorum })
    const request = await SignRequest.generate(srcCore, { manifest, length })
    return { manifest, request }
  }

  async requestDrive(
    publicKeys,
    namespace,
    srcDrive,
    length,
    { force = false, quorum, peerUpdateTimeout } = {}
  ) {
    await srcDrive.ready()
    this.swarm.join(srcDrive.discoveryKey, { client: true, server: false })
    await srcDrive.getBlobs()
    length = length || srcDrive.core.length

    if (!force) {
      await MultisigUtil.verifyCoreRequestable(srcDrive.core, length, {
        peerUpdateTimeout,
        coreId: 'db'
      })
      const contentLength = await srcDrive.getBlobsLength(length)
      await MultisigUtil.verifyCoreRequestable(srcDrive.blobs.core, contentLength, {
        peerUpdateTimeout,
        coreId: 'blobs'
      })
    }

    const manifest = MultisigUtil.getManifest(publicKeys, namespace, { quorum })
    const request = await SignRequest.generateDrive(srcDrive, { manifest, length })
    return { manifest, request }
  }

  async commitCore(
    publicKeys,
    namespace,
    srcCore,
    request,
    responses,
    { force = false, dryRun, quorum, skipTargetChecks = false, peerUpdateTimeout } = {}
  ) {
    await srcCore.ready()
    this.swarm.join(srcCore.discoveryKey, { client: true, server: false })

    const { manifest, core } = await this.createCore(publicKeys, namespace, { quorum })
    this.swarm.join(core.discoveryKey)

    const { length } = SignRequest.decode(z32.decode(request))

    if (!force) {
      await MultisigUtil.verifyCoreCommittable(srcCore, core, length, {
        skipTargetChecks,
        peerUpdateTimeout
      })
    }

    const signResponses = []
    for (const response of responses) {
      const res = cenc.decode(CoreSign.messages.Response, z32.decode(response))
      await CoreSign.verify(response, request, z32.encode(res.publicKey))
      const publicKeyHex = res.publicKey.toString('hex')
      signResponses[publicKeyHex] = res
    }
    const obtainedQuorum = Object.keys(signResponses).length
    if (!dryRun && obtainedQuorum < manifest.quorum) {
      throw new Error(`Insufficient quorum: ${obtainedQuorum} / ${manifest.quorum}`)
    }

    // NOTE: the ordering is important here, must map to signers ordering
    const signatures = manifest.signers.map((signer) => {
      const publicKeyHex = signer.publicKey.toString('hex')
      return signResponses[publicKeyHex]?.signatures[0]
    })

    const batch = await MultisigUtil.signCore(core, srcCore, signatures, {
      end: length,
      commit: !dryRun
    })

    if (!force) {
      await MultisigUtil.verifyCoreCommitted(core)
    }

    const result = {
      destCore: await MultisigUtil.getCoreInfo(core),
      srcCore: await MultisigUtil.getCoreInfo(srcCore),
      batch
    }
    return { manifest, quorum: obtainedQuorum, result }
  }

  async commitDrive(
    publicKeys,
    namespace,
    srcDrive,
    request,
    responses,
    { dryRun, quorum, force = false, skipTargetChecks = false, peerUpdateTimeout } = {}
  ) {
    await srcDrive.ready()
    this.swarm.join(srcDrive.discoveryKey, { client: true, server: false })
    await srcDrive.getBlobs()

    const { manifest, core, blobsCore } = await this.createDrive(publicKeys, namespace, { quorum })
    this.swarm.join(core.discoveryKey)

    const { length, content } = SignRequest.decode(z32.decode(request))
    const blobsLength = content.length

    if (!force) {
      await MultisigUtil.verifyCoreCommittable(srcDrive.db.core, core, length, {
        skipTargetChecks,
        peerUpdateTimeout,
        coreId: 'db'
      })
      await MultisigUtil.verifyCoreCommittable(srcDrive.blobs.core, blobsCore, blobsLength, {
        skipTargetChecks,
        peerUpdateTimeout,
        coreId: 'blobs'
      })
    }

    const signResponses = []
    for (const response of responses) {
      const res = cenc.decode(CoreSign.messages.Response, z32.decode(response))
      await CoreSign.verify(response, request, z32.encode(res.publicKey))
      const publicKeyHex = res.publicKey.toString('hex')
      signResponses[publicKeyHex] = res
    }
    const obtainedQuorum = Object.keys(signResponses).length
    if (!dryRun && obtainedQuorum < manifest.quorum) {
      throw new Error(`Insufficient quorum: ${obtainedQuorum} / ${manifest.quorum}`)
    }

    const allSignatures = manifest.signers.map((signer) => {
      const publicKeyHex = signer.publicKey.toString('hex')
      return signResponses[publicKeyHex]?.signatures
    })
    // NOTE: the ordering is important here, must map to signers ordering
    const signatures = allSignatures.map((item) => item?.[0])
    const blobsSignatures = allSignatures.map((item) => item?.[1])

    const { batch, blobsBatch } = await MultisigUtil.signDrive(
      core,
      srcDrive.core,
      signatures,
      blobsCore,
      srcDrive.blobs.core,
      blobsSignatures,
      { end: length, blobsEnd: blobsLength, commit: !dryRun }
    )

    if (!force) {
      await MultisigUtil.verifyCoreCommitted(core)
      await MultisigUtil.verifyCoreCommitted(blobsCore)
    }

    const result = {
      db: {
        destCore: await MultisigUtil.getCoreInfo(core),
        srcCore: await MultisigUtil.getCoreInfo(srcDrive.core),
        batch
      },
      blobs: {
        destCore: await MultisigUtil.getCoreInfo(blobsCore),
        srcCore: await MultisigUtil.getCoreInfo(srcDrive.blobs.core),
        batch: blobsBatch
      }
    }
    return { manifest, quorum: obtainedQuorum, result }
  }
}

module.exports = HyperMultisig
