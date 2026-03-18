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

const { EventEmitter } = require('events')
const cenc = require('compact-encoding')
const CoreSign = require('hypercore-sign')
const SignRequest = require('hypercore-signing-request')
const Hyperdrive = require('hyperdrive')
const z32 = require('z32')

const { getCoreKey, getManifest, getCoreInfo } = require('./lib/core')
const { signCore, signDrive } = require('./lib/sign')
const {
  verifyCoreRequestable,
  verifyCoreCommittable,
  verifyCoreCommitted
} = require('./lib/verify')

class HyperMultisig {
  constructor(store, swarm) {
    /** @type {Corestore} */
    this.store = store
    /** @type {Hyperswarm} */
    this.swarm = swarm
  }

  static getCoreKey = getCoreKey

  /**
   * @param {string[]} publicKeys
   * @param {string} namespace
   * @return {Promise<{ manifest: Manifest, key: Buffer, core: Hypercore }>}
   */
  async createCore(publicKeys, namespace, { quorum } = {}) {
    const manifest = getManifest(publicKeys, namespace, { quorum })
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

  requestCore(
    publicKeys,
    namespace,
    srcCore,
    length,
    { force = false, quorum, peerUpdateTimeout } = {}
  ) {
    return new HyperMultisigRunner(async (runner) => {
      await srcCore.ready()
      this.swarm.join(srcCore.discoveryKey, { client: true, server: false })

      if (!force) await verifyCoreRequestable(srcCore, length, { peerUpdateTimeout })

      const manifest = getManifest(publicKeys, namespace, { quorum })
      const request = await SignRequest.generate(srcCore, { manifest, length })
      return { manifest, request }
    })
  }

  requestDrive(
    publicKeys,
    namespace,
    srcDrive,
    length,
    { force = false, quorum, peerUpdateTimeout } = {}
  ) {
    return new HyperMultisigRunner(async (runner) => {
      await srcDrive.ready()
      this.swarm.join(srcDrive.discoveryKey, { client: true, server: false })
      runner.emit('getting-src-blobs')
      await srcDrive.getBlobs()
      length = length || srcDrive.core.length

      if (!force) {
        runner.emit('verify-db-requestable-start')
        await verifyCoreRequestable(srcDrive.core, length, {
          peerUpdateTimeout,
          coreId: 'db'
        })

        runner.emit('getting-blobs-length')
        const contentLength = await srcDrive.getBlobsLength(length)

        runner.emit('verify-blobs-requestable-start')
        await verifyCoreRequestable(srcDrive.blobs.core, contentLength, {
          peerUpdateTimeout,
          coreId: 'blobs'
        })
      }

      runner.emit('creating-drive')
      const manifest = getManifest(publicKeys, namespace, { quorum })
      const request = await SignRequest.generateDrive(srcDrive, { manifest, length })
      return { manifest, request }
    })
  }

  commitCore(
    publicKeys,
    namespace,
    srcCore,
    request,
    responses,
    {
      quorum,
      dryRun,
      force = false,
      skipTargetChecks = false,
      peerUpdateTimeout,
      minFullCopies = 2
    } = {}
  ) {
    return new HyperMultisigRunner(async (runner) => {
      await srcCore.ready()
      this.swarm.join(srcCore.discoveryKey, { client: true, server: false })

      const { manifest, core } = await this.createCore(publicKeys, namespace, { quorum })
      this.swarm.join(core.discoveryKey)

      const { length } = SignRequest.decode(z32.decode(request))

      if (!force) {
        runner.emit('verify-committable-start', srcCore.key, core.key)
        await verifyCoreCommittable(srcCore, core, length, {
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

      runner.emit('commit-start')
      const batch = await signCore(core, srcCore, signatures, {
        end: length,
        commit: !dryRun
      })

      if (!force && !dryRun) {
        runner.emit('verify-committed-start', core.key)
        await verifyCoreCommitted(core, { minPeers: minFullCopies })
      }

      const result = {
        destCore: await getCoreInfo(core),
        srcCore: await getCoreInfo(srcCore),
        batch
      }

      return { manifest, core, quorum: obtainedQuorum, result }
    })
  }

  commitDrive(
    publicKeys,
    namespace,
    srcDrive,
    request,
    responses,
    { quorum, dryRun, force = false, skipTargetChecks = false, peerUpdateTimeout } = {}
  ) {
    return new HyperMultisigRunner(async (runner) => {
      await srcDrive.ready()
      this.swarm.join(srcDrive.discoveryKey, { client: true, server: false })
      await srcDrive.getBlobs()

      const { manifest, core, blobsCore } = await this.createDrive(publicKeys, namespace, {
        quorum
      })
      this.swarm.join(core.discoveryKey)

      const { length, content } = SignRequest.decode(z32.decode(request))
      const blobsLength = content.length

      if (!force) {
        runner.emit('verify-committable-start', srcDrive.db.core.key, core.key)
        await verifyCoreCommittable(srcDrive.db.core, core, length, {
          skipTargetChecks,
          peerUpdateTimeout,
          coreId: 'db'
        })
        await verifyCoreCommittable(srcDrive.blobs.core, blobsCore, blobsLength, {
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

      runner.emit('commit-start')
      const { batch, blobsBatch } = await signDrive(
        core,
        srcDrive.core,
        signatures,
        blobsCore,
        srcDrive.blobs.core,
        blobsSignatures,
        { end: length, blobsEnd: blobsLength, commit: !dryRun }
      )

      if (!force && !dryRun) {
        runner.emit('verify-committed-start', core.key)
        await verifyCoreCommitted(core)
        await verifyCoreCommitted(blobsCore)
      }

      const result = {
        db: {
          destCore: await getCoreInfo(core),
          srcCore: await getCoreInfo(srcDrive.core),
          batch
        },
        blobs: {
          destCore: await getCoreInfo(blobsCore),
          srcCore: await getCoreInfo(srcDrive.blobs.core),
          batch: blobsBatch
        }
      }
      return { manifest, core, blobsCore, quorum: obtainedQuorum, result }
    })
  }
}

class HyperMultisigRunner extends EventEmitter {
  constructor(handler) {
    super()
    this.handler = handler

    this._running = this._run()
    // This will always be awaited, but to avoid uncaughts in case it's not awaited in the same tick
    this._running.catch(() => {})
  }

  async _run() {
    // Tick so the user can register event listeners
    await new Promise((resolve) => queueMicrotask(resolve))
    return await this.handler(this)
  }

  async done() {
    return await this._running
  }
}

module.exports = HyperMultisig
