const b4a = require('b4a')
const test = require('brittle')
const cenc = require('compact-encoding')
const Corestore = require('corestore')
const Hypercore = require('hypercore')
const crypto = require('hypercore-crypto')
const idEnc = require('hypercore-id-encoding')
const SignMessages = require('hypercore-sign/lib/messages')
const SignSecure = require('hypercore-sign/lib/secure')
const SignRequest = require('hypercore-signing-request')
const createTestnet = require('hyperdht/testnet')
const Hyperdrive = require('hyperdrive')
const Hyperswarm = require('hyperswarm')
const sodium = require('sodium-native')
const z32 = require('z32')

const MultisigUtil = require('./lib/util')
const Multisig = require('.')

test('create core', async (t) => {
  t.timeout(120000)

  const { multisig, publicKeys, namespace } = await setupTest(t)
  const { manifest, key, core } = await multisig.createCore(publicKeys, namespace)

  t.alike(core.key, key, 'core key is correct')
  t.alike(core.key, Hypercore.key(manifest), 'core key is correct from manifest')
  t.is(core.writable, false, 'core is not writable')
})

test('create drive', async (t) => {
  t.timeout(120000)

  const { multisig, publicKeys, namespace } = await setupTest(t)
  const { manifest, key, core, blobsManifest, blobsKey, blobsCore } = await multisig.createDrive(
    publicKeys,
    namespace
  )

  t.alike(core.key, key, 'core key is correct')
  t.alike(core.key, Hypercore.key(manifest), 'core key is correct from manifest')
  t.is(core.writable, false, 'core is not writable')
  t.alike(blobsCore.key, blobsKey, 'blobs key is correct')
  t.alike(blobsCore.key, Hypercore.key(blobsManifest), 'blobs key is correct from manifest')
  t.is(blobsCore.writable, false, 'blobs is not writable')
})

test('sign core (dry-run)', async (t) => {
  t.timeout(120000)

  const { store, signers, multisig, publicKeys, namespace } = await setupTest(t)
  const { manifest, core } = await multisig.createCore(publicKeys, namespace)

  const beforeSigning = {
    length: core.length,
    treeHash: await core.treeHash()
  }

  const fromCore = store.get({ name: 'fromCore' })
  t.teardown(() => fromCore.close())
  await fromCore.append(b4a.from('0'))
  await fromCore.append(b4a.from('1'))
  await fromCore.append(b4a.from('2'))

  const { signatures } = await requestAndSign(signers, fromCore, manifest)

  const batch = await MultisigUtil.signCore(core, fromCore, signatures)

  t.is(batch.key, idEnc.normalize(core.key), 'batch key is correct')
  t.is(batch.length, fromCore.length, 'batch length is correct')
  t.is(batch.treeHash, idEnc.normalize(await fromCore.treeHash()), 'batch treeHash is correct')
  t.is(core.length, beforeSigning.length, 'core length is not changed')
  t.alike(await core.treeHash(), beforeSigning.treeHash, 'core treeHash is not changed')
})

test('sign core', async (t) => {
  t.timeout(120000)

  const { store, signers, multisig, publicKeys, namespace } = await setupTest(t)
  const { manifest, core } = await multisig.createCore(publicKeys, namespace)

  const fromCore = store.get({ name: 'fromCore' })
  t.teardown(() => fromCore.close())
  await fromCore.append(b4a.from('0'))
  await fromCore.append(b4a.from('1'))
  await fromCore.append(b4a.from('2'))

  const { signatures } = await requestAndSign(signers, fromCore, manifest)

  const batch = await MultisigUtil.signCore(core, fromCore, signatures, { commit: true })

  t.is(batch.key, idEnc.normalize(core.key), 'batch key is correct')
  t.is(batch.length, fromCore.length, 'batch length is correct')
  t.is(batch.treeHash, idEnc.normalize(await fromCore.treeHash()), 'batch treeHash is correct')
  t.is(core.length, fromCore.length, 'core length is updated')
  t.alike(await core.treeHash(), await fromCore.treeHash(), 'core treeHash is updated')
})

test('sign core multiple times (dry-run)', async (t) => {
  t.timeout(120000)

  const { store, signers, multisig, publicKeys, namespace } = await setupTest(t)
  const { manifest, core } = await multisig.createCore(publicKeys, namespace)

  const beforeSigning = {
    length: core.length,
    treeHash: await core.treeHash()
  }

  const fromCore = store.get({ name: 'fromCore' })
  t.teardown(() => fromCore.close())
  await fromCore.append(b4a.from('0'))
  await fromCore.append(b4a.from('1'))
  await fromCore.append(b4a.from('2'))

  const { signatures } = await requestAndSign(signers, fromCore, manifest)

  {
    const batch = await MultisigUtil.signCore(core, fromCore, signatures)
    t.is(batch.key, idEnc.normalize(core.key), 'batch key is correct [1]')
    t.is(batch.length, fromCore.length, 'batch length is correct [1]')
    t.is(
      batch.treeHash,
      idEnc.normalize(await fromCore.treeHash()),
      'batch treeHash is correct [1]'
    )
    t.is(core.length, beforeSigning.length, 'core length is not changed [1]')
    t.alike(await core.treeHash(), beforeSigning.treeHash, 'core treeHash is not changed [1]')
  }

  {
    const batch = await MultisigUtil.signCore(core, fromCore, signatures)
    t.is(batch.length, fromCore.length, 'batch length is correct [2]')
    t.is(
      batch.treeHash,
      idEnc.normalize(await fromCore.treeHash()),
      'batch treeHash is correct [2]'
    )
    t.is(core.length, beforeSigning.length, 'core length is not changed [2]')
    t.alike(await core.treeHash(), beforeSigning.treeHash, 'core treeHash is not changed [2]')
  }

  await fromCore.append(b4a.from('3'))
  await fromCore.append(b4a.from('4'))
  await fromCore.append(b4a.from('5'))

  {
    const batch = await MultisigUtil.signCore(core, fromCore, signatures)
    t.is(batch.length, fromCore.length, 'batch length is correct [3]')
    t.is(
      batch.treeHash,
      idEnc.normalize(await fromCore.treeHash()),
      'batch treeHash is correct [3]'
    )
    t.is(core.length, beforeSigning.length, 'core length is not changed [3]')
    t.alike(await core.treeHash(), beforeSigning.treeHash, 'core treeHash is not changed [3]')
  }
})

test('sign core multiple times', async (t) => {
  t.timeout(120000)

  const { store, signers, multisig, publicKeys, namespace } = await setupTest(t)
  const { manifest, core } = await multisig.createCore(publicKeys, namespace)

  const fromCore = store.get({ name: 'fromCore' })
  t.teardown(() => fromCore.close())
  await fromCore.append(b4a.from('0'))
  await fromCore.append(b4a.from('1'))
  await fromCore.append(b4a.from('2'))

  const { signatures } = await requestAndSign(signers, fromCore, manifest)

  {
    const batch = await MultisigUtil.signCore(core, fromCore, signatures, { commit: true })
    t.is(batch.key, idEnc.normalize(core.key), 'batch key is correct [1]')
    t.is(batch.length, fromCore.length, 'batch length is correct [1]')
    t.is(
      batch.treeHash,
      idEnc.normalize(await fromCore.treeHash()),
      'batch treeHash is correct [1]'
    )
    t.is(core.length, fromCore.length, 'core length is updated [1]')
    t.alike(await core.treeHash(), await fromCore.treeHash(), 'core treeHash is updated [1]')
  }

  const beforeSigning = {
    length: core.length,
    treeHash: await core.treeHash()
  }

  {
    const batch = await MultisigUtil.signCore(core, fromCore, signatures)
    t.is(batch.key, idEnc.normalize(core.key), 'batch key is correct [2]')
    t.is(batch.length, fromCore.length, 'batch length is correct [2]')
    t.is(
      batch.treeHash,
      idEnc.normalize(await fromCore.treeHash()),
      'batch treeHash is correct [2]'
    )
    t.is(core.length, beforeSigning.length, 'core length is not changed [2]')
    t.alike(await core.treeHash(), beforeSigning.treeHash, 'core treeHash is not changed [2]')
  }

  {
    const batch = await MultisigUtil.signCore(core, fromCore, signatures, { commit: true })
    t.is(batch.key, idEnc.normalize(core.key), 'batch key is correct [3]')
    t.is(batch.length, fromCore.length, 'batch length is correct [3]')
    t.is(
      batch.treeHash,
      idEnc.normalize(await fromCore.treeHash()),
      'batch treeHash is correct [3]'
    )
    t.is(core.length, beforeSigning.length, 'core length is not changed [3]')
    t.alike(await core.treeHash(), beforeSigning.treeHash, 'core treeHash is not changed [3]')
  }

  await fromCore.append(b4a.from('3'))
  await fromCore.append(b4a.from('4'))
  await fromCore.append(b4a.from('5'))

  const { signatures: signatures2 } = await requestAndSign(signers, fromCore, manifest)

  {
    const batch = await MultisigUtil.signCore(core, fromCore, signatures2)
    t.is(batch.key, idEnc.normalize(core.key), 'batch key is correct [4]')
    t.is(batch.length, fromCore.length, 'batch length is correct [4]')
    t.is(
      batch.treeHash,
      idEnc.normalize(await fromCore.treeHash()),
      'batch treeHash is correct [4]'
    )
    t.is(core.length, beforeSigning.length, 'core length is not changed [4]')
    t.alike(await core.treeHash(), beforeSigning.treeHash, 'core treeHash is not changed [4]')
  }

  {
    const batch = await MultisigUtil.signCore(core, fromCore, signatures2, { commit: true })
    t.is(batch.key, idEnc.normalize(core.key), 'batch key is correct [5]')
    t.is(batch.length, fromCore.length, 'batch length is correct [5]')
    t.is(
      batch.treeHash,
      idEnc.normalize(await fromCore.treeHash()),
      'batch treeHash is correct [5]'
    )
    t.is(core.length, fromCore.length, 'core length is updated [5]')
    t.alike(await core.treeHash(), await fromCore.treeHash(), 'core treeHash is updated [5]')
  }
})

test('sign core remotely', async (t) => {
  t.timeout(120000)
  const { store, swarm, store2, swarm2, multisig, multisig2, signers, publicKeys, namespace } =
    await setupTest(t, 2)

  const fromCore = store.get({ name: 'fromCore' })
  t.teardown(() => fromCore.close())
  await fromCore.ready()
  swarm.join(fromCore.discoveryKey)
  await fromCore.append(b4a.from('0'))
  await fromCore.append(b4a.from('1'))
  await fromCore.append(b4a.from('2'))

  {
    const { manifest, core } = await multisig.createCore(publicKeys, namespace)
    const { signatures } = await requestAndSign(signers, fromCore, manifest)
    const batch = await MultisigUtil.signCore(core, fromCore, signatures, { commit: true })

    t.is(batch.key, idEnc.normalize(core.key), 'batch key is correct')
    t.is(batch.length, fromCore.length, 'batch length is correct')
    t.is(batch.treeHash, idEnc.normalize(await fromCore.treeHash()), 'batch treeHash is correct')
    t.is(core.length, fromCore.length, 'core length is updated')
    t.alike(await core.treeHash(), await fromCore.treeHash(), 'core treeHash is updated')
  }

  const lastLength = fromCore.length

  const fromCore2 = store2.get({ key: fromCore.key })
  t.teardown(() => fromCore2.close())
  await fromCore2.ready()
  swarm2.join(fromCore2.discoveryKey)
  await fromCore2.download({ start: 0, end: fromCore.length }).done()
  t.is(fromCore2.length, fromCore.length, 'remote core length is correct')
  t.alike(await fromCore2.treeHash(), await fromCore.treeHash(), 'remote core treeHash is correct')

  await fromCore.append(b4a.from('3'))
  await fromCore.append(b4a.from('4'))
  await fromCore.append(b4a.from('5'))

  await fromCore2.download({ start: 0, end: fromCore.length }).done()
  t.is(fromCore2.length, fromCore.length, 'remote core length is correct [2]')
  t.alike(
    await fromCore2.treeHash(),
    await fromCore.treeHash(),
    'remote core treeHash is correct [2]'
  )

  {
    const { manifest, core } = await multisig2.createCore(publicKeys, namespace)
    await core.download({ start: 0, end: lastLength }).done()
    const { signatures } = await requestAndSign(signers, fromCore2, manifest, {
      length: fromCore.length
    })
    const batch = await MultisigUtil.signCore(core, fromCore2, signatures, { commit: true })

    t.is(batch.key, idEnc.normalize(core.key), 'batch key is correct [2]')
    t.is(batch.length, fromCore2.length, 'batch length is correct [2]')
    t.is(
      batch.treeHash,
      idEnc.normalize(await fromCore2.treeHash()),
      'batch treeHash is correct [2]'
    )
    t.is(core.length, fromCore2.length, 'core length is updated [2]')
    t.alike(await core.treeHash(), await fromCore2.treeHash(), 'core treeHash is updated [2]')
  }
})

test('sign drive', async (t) => {
  const { store, signers, multisig, publicKeys, namespace } = await setupTest(t)

  const { manifest, core, blobsCore } = await multisig.createDrive(publicKeys, namespace)

  const fromDrive = new Hyperdrive(store)
  t.teardown(() => fromDrive.close())
  await fromDrive.put('/file0', b4a.from('0'))
  await fromDrive.put('/file1', b4a.from('1'))
  await fromDrive.put('/file2', b4a.from('2'))

  const { signatures, blobsSignatures } = await requestAndSign(signers, fromDrive, manifest, {
    isDrive: true
  })

  const fromCore = fromDrive.core
  const fromBlobsCore = fromDrive.blobs.core
  const { batch, blobsBatch } = await MultisigUtil.signDrive(
    core,
    fromCore,
    signatures,
    blobsCore,
    fromBlobsCore,
    blobsSignatures,
    { commit: true }
  )

  t.is(batch.key, idEnc.normalize(core.key), 'batch key is correct')
  t.is(batch.length, fromCore.length, 'batch length is correct')
  t.is(batch.treeHash, idEnc.normalize(await fromCore.treeHash()), 'batch treeHash is correct')
  t.is(core.length, fromCore.length, 'core length is updated')
  t.alike(await core.treeHash(), await fromCore.treeHash(), 'core treeHash is updated')

  t.is(blobsBatch.key, idEnc.normalize(blobsCore.key), 'blobsBatch key is correct')
  t.is(blobsBatch.length, fromBlobsCore.length, 'blobsBatch length is correct')
  t.is(
    blobsBatch.treeHash,
    idEnc.normalize(await fromBlobsCore.treeHash()),
    'blobsBatch treeHash is correct'
  )
  t.is(blobsCore.length, fromBlobsCore.length, 'blobsCore length is updated')
  t.alike(
    await blobsCore.treeHash(),
    await fromBlobsCore.treeHash(),
    'blobsCore treeHash is updated'
  )
})

test('sign drive remotely', async (t) => {
  const { store, swarm, store2, swarm2, multisig, multisig2, signers, publicKeys, namespace } =
    await setupTest(t, 2)

  const fromDrive = new Hyperdrive(store)
  t.teardown(() => fromDrive.close())
  await fromDrive.ready()
  await swarm.join(fromDrive.discoveryKey)
  await fromDrive.put('/file0', b4a.from('0'))
  await fromDrive.put('/file1', b4a.from('1'))
  await fromDrive.put('/file2', b4a.from('2'))
  const fromCore = fromDrive.core
  const fromBlobsCore = fromDrive.blobs.core

  {
    const { manifest, core, blobsCore } = await multisig.createDrive(publicKeys, namespace)
    const { signatures, blobsSignatures } = await requestAndSign(signers, fromDrive, manifest, {
      isDrive: true
    })
    const { batch, blobsBatch } = await MultisigUtil.signDrive(
      core,
      fromCore,
      signatures,
      blobsCore,
      fromBlobsCore,
      blobsSignatures,
      { commit: true }
    )
    t.is(batch.key, idEnc.normalize(core.key), 'batch key is correct')
    t.is(batch.length, fromCore.length, 'batch length is correct')
    t.is(batch.treeHash, idEnc.normalize(await fromCore.treeHash()), 'batch treeHash is correct')
    t.is(core.length, fromCore.length, 'core length is updated')
    t.alike(await core.treeHash(), await fromCore.treeHash(), 'core treeHash is updated')

    t.is(blobsBatch.key, idEnc.normalize(blobsCore.key), 'blobsBatch key is correct')
    t.is(blobsBatch.length, fromBlobsCore.length, 'blobsBatch length is correct')
    t.is(
      blobsBatch.treeHash,
      idEnc.normalize(await fromBlobsCore.treeHash()),
      'blobsBatch treeHash is correct'
    )
    t.is(blobsCore.length, fromBlobsCore.length, 'blobsCore length is updated')
    t.alike(
      await blobsCore.treeHash(),
      await fromBlobsCore.treeHash(),
      'blobsCore treeHash is updated'
    )
  }

  const lastCoreLength = fromCore.length
  const lastBlobsCoreLength = fromBlobsCore.length

  const fromDrive2 = new Hyperdrive(store2, fromDrive.key)
  t.teardown(() => fromDrive2.close())
  await fromDrive2.ready()
  await swarm2.join(fromDrive2.discoveryKey)
  await fromDrive2.getBlobs()
  await fromDrive2.getBlobsLength(fromCore.length)
  const fromCore2 = fromDrive2.core
  const fromBlobsCore2 = fromDrive2.blobs.core
  t.is(fromCore2.length, fromCore.length, 'remote core length is correct')
  t.alike(await fromCore2.treeHash(), await fromCore.treeHash(), 'remote core treeHash is correct')
  t.is(fromBlobsCore2.length, fromBlobsCore.length, 'remote blobs core length is correct')
  t.alike(
    await fromBlobsCore2.treeHash(),
    await fromBlobsCore.treeHash(),
    'remote blobs core treeHash is correct'
  )

  await fromDrive.put('/file3', b4a.from('3'))
  await fromDrive.put('/file4', b4a.from('4'))
  await fromDrive.put('/file5', b4a.from('5'))

  await fromDrive2.getBlobs()
  await fromDrive2.getBlobsLength(fromCore.length)
  t.is(fromCore2.length, fromCore.length, 'remote core length is correct [2]')
  t.alike(
    await fromCore2.treeHash(),
    await fromCore.treeHash(),
    'remote core treeHash is correct [2]'
  )
  t.is(fromBlobsCore2.length, fromBlobsCore.length, 'remote blobs core length is correct [2]')
  t.alike(
    await fromBlobsCore2.treeHash(),
    await fromBlobsCore.treeHash(),
    'remote blobs core treeHash is correct [2]'
  )

  {
    const { manifest, core, blobsCore } = await multisig2.createDrive(publicKeys, namespace)
    await core.download({ start: 0, end: lastCoreLength }).done()
    await blobsCore.download({ start: 0, end: lastBlobsCoreLength }).done()
    const { signatures, blobsSignatures } = await requestAndSign(signers, fromDrive2, manifest, {
      length: fromCore.length,
      isDrive: true
    })
    const { batch, blobsBatch } = await MultisigUtil.signDrive(
      core,
      fromCore2,
      signatures,
      blobsCore,
      fromBlobsCore2,
      blobsSignatures,
      { commit: true }
    )
    t.is(batch.key, idEnc.normalize(core.key), 'batch key is correct [2]')
    t.is(batch.length, fromCore2.length, 'batch length is correct [2]')
    t.is(
      batch.treeHash,
      idEnc.normalize(await fromCore2.treeHash()),
      'batch treeHash is correct [2]'
    )
    t.is(core.length, fromCore2.length, 'core length is updated [2]')
    t.alike(await core.treeHash(), await fromCore2.treeHash(), 'core treeHash is updated [2]')

    t.is(blobsBatch.key, idEnc.normalize(blobsCore.key), 'blobsBatch key is correct [2]')
    t.is(blobsBatch.length, fromBlobsCore2.length, 'blobsBatch length is correct [2]')
    t.is(
      blobsBatch.treeHash,
      idEnc.normalize(await fromBlobsCore2.treeHash()),
      'blobsBatch treeHash is correct [2]'
    )
    t.is(blobsCore.length, fromBlobsCore2.length, 'blobsCore length is updated [2]')
    t.alike(
      await blobsCore.treeHash(),
      await fromBlobsCore2.treeHash(),
      'blobsCore treeHash is updated [2]'
    )
  }
})

test('request core', async (t) => {
  t.timeout(120000)

  const { store, multisig, publicKeys, namespace } = await setupTest(t)

  /** @type {import('hypercore')} */
  const srcCore = store.get({ name: 'srcCore' })
  t.teardown(() => srcCore.close())
  await srcCore.append(b4a.from('0'))
  await srcCore.append(b4a.from('1'))
  await srcCore.append(b4a.from('2'))

  const { manifest, request } = await multisig.requestCore(
    publicKeys,
    namespace,
    srcCore,
    srcCore.length,
    { force: true }
  )
  const req = SignRequest.decode(request)
  t.is(req.id, idEnc.normalize(Hypercore.key(manifest)), 'request key is correct')
  t.is(req.length, srcCore.length, 'request length is correct')
})

test('commit core', async (t) => {
  t.timeout(120000)

  const { store, multisig, publicKeys, namespace, signers } = await setupTest(t)

  /** @type {import('hypercore')} */
  const srcCore = store.get({ name: 'srcCore' })
  t.teardown(() => srcCore.close())
  await srcCore.append(b4a.from('0'))
  await srcCore.append(b4a.from('1'))
  await srcCore.append(b4a.from('2'))

  const { manifest, request } = await multisig.requestCore(
    publicKeys,
    namespace,
    srcCore,
    srcCore.length,
    { force: true }
  )
  const reqStr = z32.encode(request)

  const responses = signers.slice(0, manifest.quorum).map((signer) => signResponse(request, signer))
  const { result } = await multisig.commitCore(publicKeys, namespace, srcCore, reqStr, responses, {
    force: true
  })
  t.is(result.destCore.length, srcCore.length, 'core length is correct')
})

test('commit core multiple times', async (t) => {
  t.timeout(120000)

  const { store, multisig, publicKeys, namespace, signers } = await setupTest(t)

  /** @type {import('hypercore')} */
  const srcCore = store.get({ name: 'srcCore' })
  await srcCore.ready()
  await srcCore.append(b4a.from('0'))
  await srcCore.append(b4a.from('1'))
  await srcCore.append(b4a.from('2'))

  const { manifest, request } = await multisig.requestCore(
    publicKeys,
    namespace,
    srcCore,
    srcCore.length,
    { force: true }
  )
  const reqStr = z32.encode(request)

  const responses = signers.slice(0, manifest.quorum).map((signer) => signResponse(request, signer))
  const { result } = await multisig.commitCore(publicKeys, namespace, srcCore, reqStr, responses, {
    force: true
  })
  t.is(result.destCore.length, srcCore.length, 'core length is correct')

  const { result: result2 } = await multisig.commitCore(
    publicKeys,
    namespace,
    srcCore,
    reqStr,
    responses,
    { force: true }
  )
  t.is(result2.destCore.length, srcCore.length, 'core length is correct')
})

test('request core sanity checks throw correct errors', async (t) => {
  const { store, store2, store3, swarm, swarm2, swarm3, multisig, publicKeys, namespace } =
    await setupTest(t, 4, { numSigners: 1 })

  const srcCore = store.get({ name: 'srcCore' })
  await srcCore.append('block0')
  swarm.join(srcCore.discoveryKey)

  const copy2 = store2.get(srcCore.key)
  await copy2.ready()
  swarm2.join(copy2.discoveryKey)

  await t.exception(
    async () => {
      await multisig.requestCore(publicKeys, namespace, srcCore, srcCore.length)
    },
    /SOURCE_CORE_INSUFFICIENT_PEERS/,
    'source not well seeded error'
  )

  const copy3 = store3.get(srcCore.key)
  await copy3.ready()
  swarm3.join(copy3.discoveryKey)
  await MultisigUtil.waitUntilSufficientPeers(srcCore)

  await t.exception(
    async () => {
      await multisig.requestCore(publicKeys, namespace, srcCore, srcCore.length)
    },
    /SOURCE_CORE_NOT_FULLY_SEEDED/,
    'source not fully seeded error'
  )

  await copy2.get(0)
  await copy3.get(0)
  await MultisigUtil.waitUntilFullySeeded(srcCore)

  const { manifest, request } = await multisig.requestCore(
    publicKeys,
    namespace,
    srcCore,
    srcCore.length
  )
  const req = SignRequest.decode(request)
  t.is(req.id, idEnc.normalize(Hypercore.key(manifest)), 'request key is correct')
  t.is(req.length, srcCore.length, 'request length is correct')
})

test.solo('commit core sanity checks throw correct errors', async (t) => {
  t.timeout(60000)
  const {
    store2: srcStore1,
    store3: srcStore2,
    store4: srcStore3,
    store5: tgtStore1,
    store6: tgtStore2,
    store7: tgtStore3,
    swarm2: srcSwarm1,
    swarm3: srcSwarm2,
    swarm4: srcSwarm3,
    swarm5: tgtSwarm1,
    swarm6: tgtSwarm2,
    swarm7: tgtSwarm3,
    multisig,
    publicKeys,
    namespace,
    signers
  } = await setupTest(t, 7, { numSigners: 1 })

  const srcCore = srcStore1.get({ name: 'srcCore' })
  await srcCore.append('block0')
  srcSwarm1.join(srcCore.discoveryKey)

  const { request } = await multisig.requestCore(publicKeys, namespace, srcCore, srcCore.length, {
    force: true
  })
  const reqStr = z32.encode(request)
  const responses = [signResponse(request, signers[0])]
  
  await t.exception(
    async () => {
      await multisig.commitCore(publicKeys, namespace, srcCore, reqStr, responses)
    },
    /SOURCE_CORE_INSUFFICIENT_PEERS/,
    'source not well seeded error 1'
  )

  const srcCore2 = srcStore2.get(srcCore.key)
  await srcCore2.ready()
  srcSwarm2.join(srcCore2.discoveryKey)

  await t.exception(
    async () => {
      await multisig.commitCore(publicKeys, namespace, srcCore, reqStr, responses)
    },
    /SOURCE_CORE_INSUFFICIENT_PEERS/,
    'source not well seeded error 2'
  )

  const srcCore3 = srcStore3.get(srcCore.key)
  await srcCore3.ready()
  srcSwarm3.join(srcCore3.discoveryKey)

  await MultisigUtil.waitUntilSufficientPeers(srcCore)

  await t.exception(
    async () => {
      await multisig.commitCore(publicKeys, namespace, srcCore, reqStr, responses)
    },
    /SOURCE_CORE_NOT_FULLY_SEEDED/,
    'source not fully seeded error'
  )

  await srcCore2.get(0)
  await srcCore3.get(0)

  await MultisigUtil.waitUntilFullySeeded(srcCore)

  const commitPromise = multisig.commitCore(publicKeys, namespace, srcCore, reqStr, responses, {
    skipTargetChecks: true
  })

  const tgtCoreKey = MultisigUtil.getCoreKey(publicKeys, namespace)

  const tgtCopy1 = tgtStore1.get(tgtCoreKey)
  await tgtCopy1.ready()
  tgtSwarm1.join(tgtCopy1.discoveryKey)

  const tgtCopy2 = tgtStore2.get(tgtCoreKey)
  await tgtCopy2.ready()
  tgtSwarm2.join(tgtCopy2.discoveryKey)

  const tgtCopy3 = tgtStore3.get(tgtCoreKey)
  await tgtCopy3.ready()
  tgtSwarm3.join(tgtCopy3.discoveryKey)

  await tgtCopy1.get(0)
  await tgtCopy2.get(0)
  await tgtCopy3.get(0)

  const { result } = await commitPromise
  const tgtCore = result.destCore

  // A second commit
  await srcCore.append('block1')
  await srcCore2.get(1)
  await srcCore3.get(1)
  await MultisigUtil.waitUntilFullySeeded(srcCore)

  const { request: request2 } = await multisig.requestCore(
    publicKeys,
    namespace,
    srcCore,
    srcCore.length,
  )
  const reqStr2 = z32.encode(request2)
  const responses2 = [signResponse(request2, signers[0])]

  await t.exception(
    async () => {
      await multisig.commitCore(publicKeys, namespace, srcCore, reqStr2, responses2, {
        skipTargetChecks: true
      })
    },
    /TARGET_NOT_EMPTY/,
    'target core not empty error'
  )

  tgtSwarm1.suspend()
  tgtSwarm2.suspend()
  tgtSwarm3.suspend()

  await t.exception(
    async () => {
      await multisig.commitCore(publicKeys, namespace, srcCore, reqStr2, responses2)
    },
    /TARGET_CORE_INSUFFICIENT_PEERS/,
    'target core not well seeded error'
  )

  // tgtSwarm1.resume()
  // tgtSwarm2.resume()
  // tgtSwarm3.resume()

  // await MultisigUtil.waitUntilSufficientPeers(tgtCore)

  // await t.exception(
  //   async () => {
  //     await multisig.commitCore(publicKeys, namespace, srcCore, reqStr2, responses2)
  //   },
  //   /TARGET_CORE_NOT_FULLY_SEEDED/,
  //   'target core not fully downloaded by seeders error'
  // )

  // await multisig.commitCore(publicKeys, namespace, srcCore, reqStr2, responses2)

  // // Create a request that would break the multisig core due to incompatible history
  // {
  //   await tgtCopy2.get(1)
  //   await tgtCopy3.get(1)
  //   await tgtCopy4.get(1)

  //   const badSrcCore = store.get({ name: 'bad-core' })
  //   await badSrcCore.append('block0')
  //   await badSrcCore.append('different block1')
  //   await badSrcCore.append('block2')
  //   swarm.join(badSrcCore.discoveryKey)

  //   const badCopy2 = store2.get(badSrcCore.key)
  //   await badCopy2.ready()
  //   swarm2.join(badCopy2.discoveryKey)
  //   const badCopy3 = store3.get(badSrcCore.key)
  //   await badCopy3.ready()
  //   swarm3.join(badCopy3.discoveryKey)

  //   await Promise.all([
  //     badCopy2.get(0),
  //     badCopy2.get(1),
  //     badCopy2.get(2),
  //     badCopy3.get(0),
  //     badCopy3.get(1),
  //     badCopy3.get(2)
  //   ])
  //   await MultisigUtil.waitUntilFullySeeded(badSrcCore)

  //   const { request: request3 } = await multisig.requestCore(
  //     publicKeys,
  //     namespace,
  //     badSrcCore,
  //     badSrcCore.length,
  //     { force: true }
  //   )
  //   const reqStr3 = z32.encode(request3)
  //   const responses3 = [signResponse(request3, signers[0])]

  //   await t.exception(
  //     async () => {
  //       await multisig.commitCore(publicKeys, namespace, badSrcCore, reqStr3, responses3)
  //     },
  //     /INCOMPATIBLE_SOURCE_AND_TARGET/,
  //     'corruption error'
  //   )
  // }
})

test('request drive', async (t) => {
  t.timeout(60000)

  const { store, multisig, publicKeys, namespace } = await setupTest(t)

  const srcDrive = new Hyperdrive(store)
  t.teardown(() => srcDrive.close())
  await srcDrive.put('/file1', b4a.from('0'))
  await srcDrive.put('/file2', b4a.from('1'))
  await srcDrive.put('/file3', b4a.from('2'))

  const { manifest, request } = await multisig.requestDrive(
    publicKeys,
    namespace,
    srcDrive,
    srcDrive.version,
    { force: true }
  )
  const req = SignRequest.decode(request)
  t.is(req.id, idEnc.normalize(Hypercore.key(manifest)), 'request key is correct')
  t.is(req.length, srcDrive.core.length, 'request length is correct')
})

test('commit drive', async (t) => {
  t.timeout(60000)

  const { store, multisig, publicKeys, namespace, signers } = await setupTest(t)

  const srcDrive = new Hyperdrive(store)
  t.teardown(() => srcDrive.close())
  await srcDrive.put('/file1', b4a.from('0'))
  await srcDrive.put('/file2', b4a.from('1'))
  await srcDrive.put('/file3', b4a.from('2'))

  const { manifest, request } = await multisig.requestDrive(
    publicKeys,
    namespace,
    srcDrive,
    srcDrive.version,
    { force: true }
  )
  const reqStr = z32.encode(request)

  const responses = signers.slice(0, manifest.quorum).map((signer) => signResponse(request, signer))
  const { result } = await multisig.commitDrive(
    publicKeys,
    namespace,
    srcDrive,
    reqStr,
    responses,
    {
      force: true
    }
  )
  t.is(result.db.destCore.length, srcDrive.core.length, 'core length is correct')
})

test('commit drive multiple times', async (t) => {
  t.timeout(120000)

  const { store, multisig, publicKeys, namespace, signers } = await setupTest(t)

  const srcDrive = new Hyperdrive(store)
  t.teardown(() => srcDrive.close())
  await srcDrive.put('/file1', b4a.from('0'))
  await srcDrive.put('/file2', b4a.from('1'))
  await srcDrive.put('/file3', b4a.from('2'))

  const { manifest, request } = await multisig.requestDrive(
    publicKeys,
    namespace,
    srcDrive,
    srcDrive.version,
    { force: true }
  )
  const reqStr = z32.encode(request)

  const responses = signers.slice(0, manifest.quorum).map((signer) => signResponse(request, signer))
  const { result } = await multisig.commitDrive(
    publicKeys,
    namespace,
    srcDrive,
    reqStr,
    responses,
    {
      force: true
    }
  )
  t.is(result.db.destCore.length, srcDrive.core.length, 'core length is correct')

  const { result: result2 } = await multisig.commitDrive(
    publicKeys,
    namespace,
    srcDrive,
    reqStr,
    responses,
    { force: true }
  )
  t.is(result2.db.destCore.length, srcDrive.core.length, 'core length is correct')
})

test('request drive sanity checks throw correct errors', async (t) => {
  const { store, store2, store3, swarm, swarm2, swarm3, multisig, publicKeys, namespace } =
    await setupTest(t, 4, { numSigners: 1 })

  const srcDrive = new Hyperdrive(store)
  await srcDrive.put('/file', 'content')
  swarm.join(srcDrive.discoveryKey)

  const copy2 = new Hyperdrive(store2, srcDrive.key)
  await copy2.ready()
  swarm2.join(copy2.discoveryKey)

  await t.exception(
    async () => {
      await multisig.requestDrive(publicKeys, namespace, srcDrive, srcDrive.version)
    },
    /SOURCE_CORE_INSUFFICIENT_PEERS/,
    'source not well seeded error'
  )

  const copy3 = new Hyperdrive(store3, srcDrive.key)
  await copy3.ready()
  swarm3.join(copy3.discoveryKey)
  await MultisigUtil.waitUntilSufficientPeers(srcDrive.db.core)
  await MultisigUtil.waitUntilSufficientPeers(srcDrive.blobs.core)

  await t.exception(
    async () => {
      await multisig.requestDrive(publicKeys, namespace, srcDrive, srcDrive.version)
    },
    /SOURCE_CORE_NOT_FULLY_SEEDED: db/,
    'source not fully seeded error'
  )

  // We only get the db core, to verify it errors on incomplete blobs core
  for (let i = 0; i < srcDrive.db.core.length; i++) {
    await copy2.db.core.get(i)
    await copy3.db.core.get(i)
  }
  await MultisigUtil.waitUntilFullySeeded(srcDrive.db.core)

  await t.exception(
    async () => {
      await multisig.requestDrive(publicKeys, namespace, srcDrive, srcDrive.version)
    },
    /SOURCE_CORE_NOT_FULLY_SEEDED: blobs/,
    'blobs not fully seeded error'
  )

  await copy2.get('/file')
  await copy3.get('/file')
  await MultisigUtil.waitUntilFullySeeded(srcDrive.blobs.core)

  const { request, manifest } = await multisig.requestDrive(
    publicKeys,
    namespace,
    srcDrive,
    srcDrive.version
  )
  const req = SignRequest.decode(request)
  t.is(req.id, idEnc.normalize(Hypercore.key(manifest)), 'request key is correct')
  t.is(req.length, srcDrive.core.length, 'request length is correct')
})

test('commit drive sanity checks throw correct errors', async (t) => {
  t.timeout(60000)
  const {
    store,
    store2,
    store3,
    store4,
    swarm,
    swarm2,
    swarm3,
    swarm4,
    multisig,
    publicKeys,
    namespace,
    signers
  } = await setupTest(t, 4, { numSigners: 1 })

  const srcDrive = new Hyperdrive(store)
  await srcDrive.put('/file', 'content')
  swarm.join(srcDrive.discoveryKey)

  const copy2 = new Hyperdrive(store2, srcDrive.key)
  await copy2.ready()
  swarm2.join(copy2.discoveryKey)

  const { request } = await multisig.requestDrive(
    publicKeys,
    namespace,
    srcDrive,
    srcDrive.version,
    { force: true }
  )
  const reqStr = z32.encode(request)

  const responses = [signResponse(request, signers[0])]

  await t.exception(
    async () => {
      await multisig.commitDrive(publicKeys, namespace, srcDrive, reqStr, responses)
    },
    /SOURCE_CORE_INSUFFICIENT_PEERS/,
    'source not well seeded error'
  )

  const copy3 = new Hyperdrive(store3, srcDrive.key)
  await copy3.ready()
  swarm3.join(copy3.discoveryKey)
  await MultisigUtil.waitUntilSufficientPeers(srcDrive.db.core)
  await MultisigUtil.waitUntilSufficientPeers(srcDrive.blobs.core)

  await t.exception(
    async () => {
      await multisig.commitDrive(publicKeys, namespace, srcDrive, reqStr, responses)
    },
    /SOURCE_CORE_NOT_FULLY_SEEDED: db/,
    'source not fully seeded error'
  )

  // We only get the db core, to verify it errors on incomplete blobs core
  for (let i = 0; i < srcDrive.db.core.length; i++) {
    await copy2.db.core.get(i)
    await copy3.db.core.get(i)
  }
  await MultisigUtil.waitUntilFullySeeded(srcDrive.db.core)

  await t.exception(
    async () => {
      await multisig.commitDrive(publicKeys, namespace, srcDrive, reqStr, responses, {
        skipTargetChecks: true
      })
    },
    /SOURCE_CORE_NOT_FULLY_SEEDED: blobs/,
    'blobs not fully seeded error'
  )

  await copy2.get('/file')
  await copy3.get('/file')
  await MultisigUtil.waitUntilFullySeeded(srcDrive.blobs.core)

  const { result } = await multisig.commitDrive(
    publicKeys,
    namespace,
    srcDrive,
    reqStr,
    responses,
    {
      skipTargetChecks: true
    }
  )
  const tgtDbCore = result.db.destCore

  // A second commit
  await srcDrive.put('/file2', 'more')
  await copy2.checkout(srcDrive.version).get('/file2')
  await copy3.checkout(srcDrive.version).get('/file2')

  const { request: request2 } = await multisig.requestDrive(
    publicKeys,
    namespace,
    srcDrive,
    srcDrive.version,
    { force: true }
  )
  const reqStr2 = z32.encode(request2)
  const responses2 = [signResponse(request2, signers[0])]

  await t.exception(
    async () => {
      await multisig.commitDrive(publicKeys, namespace, srcDrive, reqStr2, responses2, {
        skipTargetChecks: true
      })
    },
    /TARGET_NOT_EMPTY/,
    'target core not empty error'
  )

  await t.exception(
    async () => {
      await multisig.commitDrive(publicKeys, namespace, srcDrive, reqStr2, responses2)
    },
    /TARGET_CORE_INSUFFICIENT_PEERS: db/,
    'target core not well seeded error'
  )

  const tgtDrive = new Hyperdrive(store, tgtDbCore.key)
  await tgtDrive.ready()

  const tgtCopy2 = new Hyperdrive(store2, tgtDbCore.key)
  await tgtCopy2.ready()
  swarm2.join(tgtCopy2.discoveryKey)

  const tgtCopy3 = new Hyperdrive(store3, tgtDbCore.key)
  await tgtCopy3.ready()
  swarm3.join(tgtCopy3.discoveryKey)

  const tgtCopy4 = new Hyperdrive(store4, tgtDbCore.key)
  await tgtCopy4.ready()
  swarm4.join(tgtCopy4.discoveryKey)

  await MultisigUtil.waitUntilSufficientPeers(tgtDrive.db.core)
  await MultisigUtil.waitUntilSufficientPeers(tgtDrive.blobs.core)

  await t.exception(
    async () => {
      await multisig.commitDrive(publicKeys, namespace, srcDrive, reqStr2, responses2)
    },
    /TARGET_CORE_NOT_FULLY_SEEDED/,
    'target core not fully downloaded by seeders error'
  )

  // We only get the db core, to verify it errors on incomplete blobs core
  for (let i = 0; i < tgtDrive.db.core.length; i++) {
    await tgtCopy2.db.core.get(i)
    await tgtCopy3.db.core.get(i)
    await tgtCopy4.db.core.get(i)
  }
  await MultisigUtil.waitUntilFullySeeded(tgtDrive.db.core)

  await t.exception(
    async () => {
      await multisig.commitDrive(publicKeys, namespace, srcDrive, reqStr, responses)
    },
    /TARGET_CORE_NOT_FULLY_SEEDED: blobs/,
    'blobs not fully seeded error'
  )

  await tgtCopy2.get('/file')
  await tgtCopy3.get('/file')
  await tgtCopy4.get('/file')
  await MultisigUtil.waitUntilFullySeeded(tgtDrive.blobs.core)

  const promise = Promise.all([
    tgtCopy2.db.core.get(tgtDrive.db.core.length),
    tgtCopy3.db.core.get(tgtDrive.db.core.length),
    tgtCopy4.db.core.get(tgtDrive.db.core.length),
    tgtCopy2.blobs.core.get(tgtDrive.blobs.core.length),
    tgtCopy3.blobs.core.get(tgtDrive.blobs.core.length),
    tgtCopy4.blobs.core.get(tgtDrive.blobs.core.length)
  ])

  await multisig.commitDrive(publicKeys, namespace, srcDrive, reqStr2, responses2)

  // Create a request that would break the multisig due to incompatible history
  {
    await promise

    const badSrcDrive = new Hyperdrive(store.namespace('other'))
    await badSrcDrive.put('/file', 'bad')
    await badSrcDrive.put('/file2', 'worse')
    await badSrcDrive.put('/file3', 'owow')
    swarm.join(badSrcDrive.discoveryKey)

    const badCopy2 = new Hyperdrive(store2, badSrcDrive.key)
    await badCopy2.ready()
    swarm2.join(badCopy2.discoveryKey)
    const badCopy3 = new Hyperdrive(store3, badSrcDrive.key)
    await badCopy3.ready()
    swarm3.join(badCopy3.discoveryKey)

    await Promise.all([
      badCopy2.get('/file'),
      badCopy2.get('/file2'),
      badCopy2.get('/file3'),
      badCopy3.get('/file'),
      badCopy3.get('/file2'),
      badCopy3.get('/file3')
    ])
    await badCopy2.getBlobs()
    await badCopy2.getBlobsLength(badSrcDrive.version)
    await badCopy3.getBlobs()
    await badCopy3.getBlobsLength(badSrcDrive.version)
    await MultisigUtil.waitUntilFullySeeded(badSrcDrive.db.core)

    const { request: request3 } = await multisig.requestDrive(
      publicKeys,
      namespace,
      badSrcDrive,
      badSrcDrive.version,
      { force: true }
    )
    const reqStr3 = z32.encode(request3)
    const responses3 = [signResponse(request3, signers[0])]
    await t.exception(
      async () => {
        await multisig.commitDrive(publicKeys, namespace, badSrcDrive, reqStr3, responses3)
      },
      /INCOMPATIBLE_SOURCE_AND_TARGET/,
      'corruption error'
    )
  }
})

/** @type {function(): Promise<{ signatures: Buffer[], blobsSignatures: Buffer[] }>} */
async function requestAndSign(signers, fromCore, manifest, { length, isDrive } = {}) {
  const request = isDrive
    ? await SignRequest.generateDrive(fromCore, { manifest, length })
    : await SignRequest.generate(fromCore, { manifest, length })

  const allSignatures = signers
    .slice(0, manifest.quorum)
    .map((signer) => sign(request, signer).signatures)
  const signatures = allSignatures.map((item) => item[0])
  const blobsSignatures = allSignatures.map((item) => item[1])
  return { signatures, blobsSignatures }
}

function sign(request, signer) {
  // clone to avoid mutation
  const clonedSigner = Object.keys(signer).reduce((acc, key) => {
    acc[key] = b4a.from(signer[key])
    return acc
  }, {})

  const decodedReq = SignRequest.decode(request)
  const signables = SignRequest.signable(clonedSigner.publicKey, decodedReq)

  const password = sodium.sodium_malloc(8)
  sodium.randombytes_buf_deterministic(password, clonedSigner.seed)

  const signatures = SignSecure.sign(signables, clonedSigner.secretKey, password)
  return { clonedSigner, decodedReq, signatures }
}

function signResponse(request, signer) {
  const { clonedSigner, decodedReq, signatures } = sign(request, signer)
  const res = cenc.encode(SignMessages.Response, {
    version: decodedReq.version,
    requestHash: crypto.hash(request),
    publicKey: clonedSigner.publicKey,
    signatures
  })
  return z32.encode(res)
}

/**
 * @type {function(): Promise<{
 *   store: import('corestore'),
 *   swarm: import('hyperswarm'),
 *   store2?: import('corestore'),
 *   swarm2?: import('hyperswarm'),
 *   multisig: Multisig,
 *   multisig2?: Multisig,
 *   namespace: string,
 *   signers: { id: Buffer, publicKey: Buffer, secretKey: Buffer, seed: Buffer }[],
 *   publicKeys: string[]
 * }>}
 */
async function setupTest(t, n, { numSigners } = {}) {
  const res = await setup(t, n)

  res.multisig = new Multisig(res.store, res.swarm)
  if (res.store2) res.multisig2 = new Multisig(res.store2, res.swarm2)

  return { ...res, ...setupMultisig(undefined, numSigners) }
}

function setupMultisig(namespace = 'holepunchto/my-test', numSigners = 3) {
  const signers = []
  for (let i = 0; i < numSigners; i++) {
    const seed = sodium.sodium_malloc(sodium.randombytes_SEEDBYTES)
    sodium.randombytes_buf(seed)
    const password = sodium.sodium_malloc(8)
    sodium.randombytes_buf_deterministic(password, seed)

    const keys = SignSecure.generateKeys(password)
    signers.push({ ...keys, seed })
  }
  const publicKeys = signers.map((signer) => idEnc.normalize(signer.publicKey))
  return { namespace, signers, publicKeys }
}

async function setup(t, n = 1, network) {
  const res = network ?? (await setupTestnet(t))
  const { bootstrap } = res

  for (let step = 1; step <= n; step++) {
    const storage = await t.tmp()
    const store = new Corestore(storage)
    t.teardown(() => store.close(), { order: 4000 })
    const swarm = new Hyperswarm({ bootstrap })
    t.teardown(() => swarm.destroy(), { order: 3000 })

    swarm.on('connection', (conn) => store.replicate(conn))

    const nstring = step > 1 ? step : ''
    res[`storage${nstring}`] = storage
    res[`store${nstring}`] = store
    res[`swarm${nstring}`] = swarm
  }

  return res
}

async function setupTestnet(t) {
  const testnet = await createTestnet()
  t.teardown(() => testnet.destroy(), { order: 5000 })
  const bootstrap = testnet.bootstrap
  return { testnet, bootstrap }
}
