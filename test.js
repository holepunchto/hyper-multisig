const b4a = require('b4a')
const test = require('brittle')
const Corestore = require('corestore')
const Hypercore = require('hypercore')
const crypto = require('hypercore-crypto')
const idEnc = require('hypercore-id-encoding')
const CoreSign = require('hypercore-sign-lib')
const SignRequest = require('hypercore-signing-request')
const createTestnet = require('hyperdht/testnet')
const Hyperdrive = require('hyperdrive')
const Hyperswarm = require('hyperswarm')
const sodium = require('sodium-native')
const z32 = require('z32')
const { once } = require('events')

const { getCoreKey } = require('./lib/core')
const { signCore, signDrive, createUpdateBatch } = require('./lib/sign')
const { waitUntilSufficientPeers, waitUntilFullySeeded } = require('./lib/verify')
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

  const batch = await signCore(core, fromCore, signatures)
  const dryRunSignature = batch.signature

  t.is(batch.key, idEnc.normalize(core.key), 'batch key is correct')
  t.is(batch.length, fromCore.length, 'batch length is correct')
  t.is(batch.treeHash, idEnc.normalize(await fromCore.treeHash()), 'batch treeHash is correct')
  t.is(core.length, beforeSigning.length, 'core length is not changed')
  t.alike(await core.treeHash(), beforeSigning.treeHash, 'core treeHash is not changed')
  t.is(dryRunSignature !== null, true, 'dryrun includes signature if quorum met')
  t.is(core.length, 0, 'did not commit')

  const commitBatch = await signCore(core, fromCore, signatures, { commit: true })
  t.is(core.length, 3, 'did commit')
  t.is(commitBatch.signature, dryRunSignature, 'sanity check: same signature with commit')
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

  const batch = await signCore(core, fromCore, signatures, { commit: true })

  t.is(batch.key, idEnc.normalize(core.key), 'batch key is correct')
  t.is(batch.length, fromCore.length, 'batch length is correct')
  t.is(batch.treeHash, idEnc.normalize(await fromCore.treeHash()), 'batch treeHash is correct')
  t.is(core.length, fromCore.length, 'core length is updated')
  t.alike(await core.treeHash(), await fromCore.treeHash(), 'core treeHash is updated')
})

test('sign core with request length less than source length', async (t) => {
  t.timeout(120000)

  const { store, signers, multisig, publicKeys, namespace } = await setupTest(t)
  const { manifest, core } = await multisig.createCore(publicKeys, namespace)

  const fromCore = store.get({ name: 'fromCore' })
  t.teardown(() => fromCore.close())
  await fromCore.append(b4a.from('0'))
  await fromCore.append(b4a.from('1'))
  await fromCore.append(b4a.from('2'))
  await fromCore.append(b4a.from('3'))
  await fromCore.append(b4a.from('4'))
  await fromCore.append(b4a.from('5'))

  const requestLength = 4
  const { signatures } = await requestAndSign(signers, fromCore, manifest, {
    length: requestLength
  })
  await fromCore.append(b4a.from('6'))
  await fromCore.append(b4a.from('7'))

  const batch = await signCore(core, fromCore, signatures, {
    length: requestLength,
    commit: true
  })
  await fromCore.append(b4a.from('8'))
  await fromCore.append(b4a.from('9'))

  t.is(requestLength, 4, 'request length is less than source length')
  t.is(batch.key, idEnc.normalize(core.key), 'batch key is correct')
  t.is(batch.length, requestLength, 'batch length is correct')
  t.is(
    batch.treeHash,
    idEnc.normalize(await fromCore.treeHash(requestLength)),
    'batch treeHash is correct'
  )
  t.is(core.length, requestLength, 'core length is updated')
  t.alike(await core.treeHash(), await fromCore.treeHash(requestLength), 'core treeHash is updated')
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
    const batch = await signCore(core, fromCore, signatures)
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
    const batch = await signCore(core, fromCore, signatures)
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
    const batch = await signCore(core, fromCore, signatures)
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
    const batch = await signCore(core, fromCore, signatures, { commit: true })
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
    const batch = await signCore(core, fromCore, signatures)
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
    const batch = await signCore(core, fromCore, signatures, { commit: true })
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
    const batch = await signCore(core, fromCore, signatures2)
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
    const batch = await signCore(core, fromCore, signatures2, { commit: true })
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

test('sign core multiple times w/ partial replication from previous sign', async (t) => {
  t.timeout(120000)

  const { store, signers, multisig, publicKeys, namespace } = await setupTest(t)
  const { manifest, core } = await multisig.createCore(publicKeys, namespace)

  const fromCore = store.get({ name: 'fromCore' })
  t.teardown(() => fromCore.close())
  await fromCore.append(b4a.from('0'))
  await fromCore.append(b4a.from('1'))
  await fromCore.append(b4a.from('2'))
  await fromCore.append(b4a.from('3'))
  await fromCore.append(b4a.from('4'))
  await fromCore.append(b4a.from('5'))

  const { signatures } = await requestAndSign(signers, fromCore, manifest)

  {
    const batch = await signCore(core, fromCore, signatures, { commit: true })
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

  {
    // Create new storage to simulate separate peer
    const store2 = new Corestore(await t.tmp())
    t.teardown(() => store2.close(), { order: 4000 })

    t.comment('second sign')
    const localCore = store2.get({ manifest })
    t.teardown(() => localCore.close())
    t.is(localCore.length, 0, '2nd signer core is new')

    t.comment('replicate state of sign core')
    const s1 = store.replicate(true)
    const s2 = store2.replicate(false)
    s1.pipe(s2).pipe(s1)

    await once(localCore, 'append')

    // Sparsely populate localCore with blocks: 0, 1, 4
    await localCore.get(0)
    await localCore.get(1)

    await localCore.get(4)

    t.is(localCore.length, core.length, 'same lengths')
    t.alike(localCore.key, core.key, 'same key')
    t.absent(await localCore.has(0, core.length), '2nd signer core is missing blocks')

    const batch = await signCore(localCore, fromCore, signatures, { commit: true })
    t.is(batch.key, idEnc.normalize(core.key), 'batch key is correct [2]')
    t.is(batch.length, fromCore.length, 'batch length is correct [2]')
    t.is(
      batch.treeHash,
      idEnc.normalize(await fromCore.treeHash()),
      'batch treeHash is correct [2]'
    )

    t.ok(await localCore.has(0, core.length), '2nd signer core has all blocks')
  }
})

test('sign core rejects different batch recommit w/ partial replication from previous sign', async (t) => {
  t.timeout(120000)

  const { store, signers, multisig, publicKeys, namespace } = await setupTest(t)
  const { manifest, core } = await multisig.createCore(publicKeys, namespace)

  const fromCore = store.get({ name: 'fromCore' })
  t.teardown(() => fromCore.close())
  await fromCore.append(b4a.from('0'))
  await fromCore.append(b4a.from('1'))
  await fromCore.append(b4a.from('2'))
  await fromCore.append(b4a.from('3'))
  await fromCore.append(b4a.from('4'))
  await fromCore.append(b4a.from('5'))

  const { signatures } = await requestAndSign(signers, fromCore, manifest)

  await signCore(core, fromCore, signatures, { commit: true })

  // Create new storage to simulate separate peer
  const store2 = new Corestore(await t.tmp())
  t.teardown(() => store2.close(), { order: 4000 })

  const localCore = store2.get({ manifest })
  t.teardown(() => localCore.close())
  t.is(localCore.length, 0, '2nd signer core is new')

  const s1 = store.replicate(true)
  const s2 = store2.replicate(false)
  t.teardown(() => {
    s1.destroy()
    s2.destroy()
  })
  s1.pipe(s2).pipe(s1)

  await once(localCore, 'append')

  // Sparsely populate localCore with blocks: 0, 1, 4
  await localCore.get(0)
  await localCore.get(1)
  await localCore.get(4)

  t.is(localCore.length, core.length, 'same lengths')
  t.alike(localCore.key, core.key, 'same key')

  // Stop replication
  s1.destroy()
  s2.destroy()

  t.alike(await Hypercore.treeHashFromStorage(localCore), await core.treeHash(), 'same treeHash')
  t.absent(await localCore.has(0, core.length), '2nd signer core is missing blocks')

  const differentFromCore = store.get({ name: 'differentFromCore' })
  t.teardown(() => differentFromCore.close())
  await differentFromCore.append(b4a.from('0'))
  await differentFromCore.append(b4a.from('1'))
  await differentFromCore.append(b4a.from('2'))
  await differentFromCore.append(b4a.from('different-3'))
  await differentFromCore.append(b4a.from('4'))
  await differentFromCore.append(b4a.from('different-5'))

  t.is(differentFromCore.length, fromCore.length, 'different batch length matches')
  t.unlike(await differentFromCore.treeHash(), await fromCore.treeHash(), 'second batch differs')

  await t.exception(
    () => signCore(localCore, differentFromCore, signatures, { commit: true }),
    /COMMIT_FAILED/,
    'invalid commit throws commit failed'
  )

  t.is(localCore.length, core.length, 'length not updated after invalid commit')
  t.alike(localCore.key, core.key, 'same key after invalid commit')
  t.alike(
    await Hypercore.treeHashFromStorage(localCore),
    await core.treeHash(),
    '2nd signer core treeHash is not updated after invalid commit'
  )
  t.absent(
    await localCore.has(0, core.length),
    '2nd signer core is still missing blocks after invalid commit'
  )

  const batch = await signCore(localCore, fromCore, signatures, { commit: true })
  t.is(batch.key, idEnc.normalize(core.key), 'batch key is correct')
  t.is(batch.length, fromCore.length, 'batch length is correct')
  t.is(batch.treeHash, idEnc.normalize(await fromCore.treeHash()), 'batch treeHash is correct')
  t.ok(await localCore.has(0, fromCore.length), '2nd signer core has all blocks')
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
    const batch = await signCore(core, fromCore, signatures, { commit: true })

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
    const batch = await signCore(core, fromCore2, signatures, { commit: true })

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

test('createUpdateBatch with start', async (t) => {
  const {
    store,
    swarm,
    swarm2,
    swarm3,
    multisig,
    multisig2,
    multisig3,
    signers,
    publicKeys,
    namespace
  } = await setupTest(t, 3)

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
    await signCore(core, fromCore, signatures, { commit: true })
    t.is(core.length, fromCore.length, 'core length is updated')
    swarm.join(core.discoveryKey)
  }

  await fromCore.append(b4a.from('3'))
  await fromCore.append(b4a.from('4'))
  await fromCore.append(b4a.from('5'))

  {
    const { core } = await multisig2.createCore(publicKeys, namespace)
    swarm2.join(core.discoveryKey)
    await once(core, 'peer-add')
    await core.update({ wait: true })
    t.is(core.length, 3, 'core length is correct')
    t.is(core.contiguousLength, 0, 'core contiguous length is 0')

    const batch = await createUpdateBatch(core, fromCore)
    t.ok(await batch.has(0, 6), 'batch has all blocks')
  }

  {
    const { core } = await multisig3.createCore(publicKeys, namespace)
    swarm3.join(core.discoveryKey)
    await once(core, 'peer-add')
    await core.update({ wait: true })
    t.is(core.length, 3, 'core length is correct')
    t.is(core.contiguousLength, 0, 'core contiguous length is 0')

    const batch = await createUpdateBatch(core, fromCore, { start: 3 })
    t.absent(await batch.has(0), 'batch does not have block 0')
    t.absent(await batch.has(1), 'batch does not have block 1')
    t.absent(await batch.has(2), 'batch does not have block 2')
    t.ok(await batch.has(3, 6), 'batch has block 3, 4, 5')
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

  let dryrunDbSignature = null
  let dryrunBlobsSignature = null
  {
    const { batch, blobsBatch } = await signDrive(
      core,
      fromCore,
      signatures,
      blobsCore,
      fromBlobsCore,
      blobsSignatures,
      { commit: false }
    )

    dryrunDbSignature = batch.signature
    dryrunBlobsSignature = blobsBatch.signature
    t.ok(
      dryrunDbSignature !== null && dryrunDbSignature !== undefined,
      'db signature set when quorum met'
    )
    t.ok(
      dryrunBlobsSignature !== null && dryrunBlobsSignature !== undefined,
      'blobs signature set when quorum met'
    )
  }

  const { batch, blobsBatch } = await signDrive(
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
  t.is(batch.signature, dryrunDbSignature, 'db signature matches dryrun')
  t.is(blobsBatch.signature, dryrunBlobsSignature, 'blobs signature matches dryrun')
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
    const { batch, blobsBatch } = await signDrive(
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
    const { batch, blobsBatch } = await signDrive(
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

  const { manifest, request } = await multisig
    .requestCore(publicKeys, namespace, srcCore, srcCore.length, { force: true })
    .done()
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

  const { manifest, request } = await multisig
    .requestCore(publicKeys, namespace, srcCore, srcCore.length, { force: true })
    .done()
  const reqStr = z32.encode(request)

  const responses = await Promise.all(
    signers.slice(0, manifest.quorum).map((signer) => signResponse(request, signer))
  )
  const commitCore = multisig.commitCore(publicKeys, namespace, srcCore, reqStr, responses, {
    force: true
  })

  const { core, result } = await commitCore.done()

  t.is(idEnc.normalize(core.key), result.destCore.key)
  t.is(core.key.toString('hex'), result.destCore.keyHex)
  t.is(result.destCore.length, srcCore.length, 'core length is correct')
})

test('commit core with swarmAsServer false', async (t) => {
  t.timeout(120000)

  const { store, swarm, store2, swarm2, store3, swarm3, multisig, publicKeys, namespace, signers } =
    await setupTest(t, 3)

  const srcCore = store.get({ name: 'srcCore' })
  t.teardown(() => srcCore.close())
  await srcCore.append(b4a.from('0'))
  await srcCore.append(b4a.from('1'))
  await srcCore.append(b4a.from('2'))

  const { manifest, request } = await multisig
    .requestCore(publicKeys, namespace, srcCore, srcCore.length, { force: true })
    .done()
  const reqStr = z32.encode(request)

  const responses = await Promise.all(
    signers.slice(0, manifest.quorum).map((signer) => signResponse(request, signer))
  )

  const targetCore2 = store2.get({ manifest })
  const targetCore3 = store3.get({ manifest })
  t.teardown(() => targetCore2.close())
  t.teardown(() => targetCore3.close())
  await Promise.all([targetCore2.ready(), targetCore3.ready()])

  const { core, result } = await multisig
    .commitCore(publicKeys, namespace, srcCore, reqStr, responses, {
      force: true,
      swarmAsServer: false
    })
    .done()
  t.is(idEnc.normalize(core.key), result.destCore.key)
  t.is(result.destCore.length, srcCore.length, 'core length is correct')

  const peer2Session = swarm2.join(targetCore2.discoveryKey, { client: true, server: false })
  const peer2Download = targetCore2.download({ start: 0, end: srcCore.length }).done()
  await Promise.all([swarm.flush(), swarm2.flush()])

  const peer2DownloadedFromMain = await Promise.race([
    peer2Download.then(() => true),
    new Promise((resolve) => setTimeout(() => resolve(false), 1000))
  ])
  t.absent(peer2DownloadedFromMain, 'peer 2 cannot download from client-only main')
  t.absent(await targetCore2.has(0, srcCore.length), 'peer 2 has no blocks from main')

  swarm3.join(targetCore3.discoveryKey, { client: true, server: true })
  await swarm3.flush()

  await Promise.all([swarm.status(core.discoveryKey).refresh(), peer2Session.refresh()])
  await Promise.all([swarm.flush(), swarm2.flush(), swarm3.flush()])
  await targetCore3.download({ start: 0, end: srcCore.length }).done()
  t.alike(await targetCore3.treeHash(), await srcCore.treeHash(), 'peer 3 received committed core')

  await peer2Download
  t.alike(await targetCore2.treeHash(), await srcCore.treeHash(), 'peer 2 received committed core')
  t.ok(await targetCore2.has(0, srcCore.length), 'peer 2 downloaded blocks from peer 3')
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

  const { manifest, request } = await multisig
    .requestCore(publicKeys, namespace, srcCore, srcCore.length, { force: true })
    .done()
  const reqStr = z32.encode(request)

  const responses = await Promise.all(
    signers.slice(0, manifest.quorum).map((signer) => signResponse(request, signer))
  )
  const { result } = await multisig
    .commitCore(publicKeys, namespace, srcCore, reqStr, responses, {
      force: true
    })
    .done()
  t.is(result.destCore.length, srcCore.length, 'core length is correct')

  const { result: result2 } = await multisig
    .commitCore(publicKeys, namespace, srcCore, reqStr, responses, { force: true })
    .done()
  t.is(result2.destCore.length, srcCore.length, 'core length is correct')
})

test('commit core dry-run with start', async (t) => {
  t.timeout(120000)

  const {
    store,
    store2,
    store3,
    swarm,
    swarm2,
    swarm3,
    multisig,
    multisig2,
    multisig3,
    signers,
    publicKeys,
    namespace
  } = await setupTest(t, 3)

  const srcCore = store.get({ name: 'srcCore' })
  t.teardown(() => srcCore.close())
  await srcCore.ready()
  swarm.join(srcCore.discoveryKey)
  await srcCore.append(b4a.from('0'))
  await srcCore.append(b4a.from('1'))
  await srcCore.append(b4a.from('2'))

  {
    const { manifest, request } = await multisig
      .requestCore(publicKeys, namespace, srcCore, srcCore.length, { force: true })
      .done()
    const reqStr = z32.encode(request)
    const responses = await Promise.all(
      signers.slice(0, manifest.quorum).map((signer) => signResponse(request, signer))
    )
    const { core, result } = await multisig
      .commitCore(publicKeys, namespace, srcCore, reqStr, responses, { force: true })
      .done()
    t.is(result.destCore.length, srcCore.length, 'core length is correct')
    t.is(core.length, srcCore.length, 'core length is updated')
  }

  await srcCore.append(b4a.from('3'))
  await srcCore.append(b4a.from('4'))
  await srcCore.append(b4a.from('5'))

  {
    const srcCore2 = store2.get({ key: srcCore.key })
    t.teardown(() => srcCore2.close())

    await srcCore2.ready()
    swarm2.join(srcCore2.discoveryKey)
    await once(srcCore2, 'peer-add')
    await srcCore2.update({ wait: true })
    t.is(srcCore2.length, 6, 'srcCore2 length is correct')
    t.is(srcCore2.contiguousLength, 0, 'srcCore2 contiguous length is 0')

    const { request } = await multisig2
      .requestCore(publicKeys, namespace, srcCore2, srcCore2.length, { force: true })
      .done()
    const reqStr = z32.encode(request)
    await multisig2
      .commitCore(publicKeys, namespace, srcCore2, reqStr, [], {
        force: true,
        dryRun: true
      })
      .done()
    t.ok(await srcCore2.has(0, 6), 'srcCore2 has all blocks')
  }

  {
    const srcCore3 = store3.get({ key: srcCore.key })
    t.teardown(() => srcCore3.close())

    await srcCore3.ready()
    swarm3.join(srcCore3.discoveryKey)
    await once(srcCore3, 'peer-add')
    await srcCore3.update({ wait: true })
    t.is(srcCore3.length, 6, 'srcCore3 length is correct')
    t.is(srcCore3.contiguousLength, 0, 'srcCore3 contiguous length is 0')

    const { request } = await multisig3
      .requestCore(publicKeys, namespace, srcCore3, srcCore3.length, { force: true })
      .done()
    const reqStr = z32.encode(request)
    await multisig3
      .commitCore(publicKeys, namespace, srcCore3, reqStr, [], {
        force: true,
        dryRun: true,
        start: 3
      })
      .done()
    t.absent(await srcCore3.has(0), 'srcCore3 does not have block 0')
    t.absent(await srcCore3.has(1), 'srcCore3 does not have block 1')
    t.absent(await srcCore3.has(2), 'srcCore3 does not have block 2')
    t.ok(await srcCore3.has(3, 6), 'srcCore3 has blocks 3, 4, 5')
  }
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
      await multisig.requestCore(publicKeys, namespace, srcCore, srcCore.length).done()
    },
    /SOURCE_CORE_INSUFFICIENT_PEERS/,
    'source not well seeded error'
  )

  const copy3 = store3.get(srcCore.key)
  await copy3.ready()
  swarm3.join(copy3.discoveryKey)
  await waitUntilSufficientPeers(srcCore)

  await t.exception(
    async () => {
      await multisig.requestCore(publicKeys, namespace, srcCore, srcCore.length).done()
    },
    /SOURCE_CORE_NOT_FULLY_SEEDED/,
    'source not fully seeded error'
  )

  await copy2.get(0)
  await copy3.get(0)
  await waitUntilFullySeeded(srcCore)

  const { manifest, request } = await multisig
    .requestCore(publicKeys, namespace, srcCore, srcCore.length)
    .done()
  const req = SignRequest.decode(request)
  t.is(req.id, idEnc.normalize(Hypercore.key(manifest)), 'request key is correct')
  t.is(req.length, srcCore.length, 'request length is correct')
})

test('commit core sanity checks throw correct errors', async (t) => {
  t.timeout(60000)
  const {
    store2: srcStore1,
    store3: srcStore2,
    store4: srcStore3,
    store5: tgtStore1,
    store6: tgtStore2,
    store7: tgtStore3,
    store8: tgtStore4,
    store9: tgtStore5,
    store10: tgtStore6,
    swarm2: srcSwarm1,
    swarm3: srcSwarm2,
    swarm4: srcSwarm3,
    swarm5: tgtSwarm1,
    swarm6: tgtSwarm2,
    swarm7: tgtSwarm3,
    swarm8: tgtSwarm4,
    swarm9: tgtSwarm5,
    swarm10: tgtSwarm6,
    multisig,
    publicKeys,
    namespace,
    signers
  } = await setupTest(t, 10, { numSigners: 1 })

  const srcCore = srcStore1.get({ name: 'srcCore' })
  await srcCore.append('block0')
  srcSwarm1.join(srcCore.discoveryKey)

  const { request } = await multisig
    .requestCore(publicKeys, namespace, srcCore, srcCore.length, {
      force: true
    })
    .done()
  const reqStr = z32.encode(request)
  const responses = [await signResponse(request, signers[0])]

  await t.exception(
    () => multisig.commitCore(publicKeys, namespace, srcCore, reqStr, responses).done(),
    /SOURCE_CORE_INSUFFICIENT_PEERS/,
    'source not well seeded error 1'
  )

  const srcCore2 = srcStore2.get(srcCore.key)
  await srcCore2.ready()
  srcSwarm2.join(srcCore2.discoveryKey)

  await t.exception(
    () => multisig.commitCore(publicKeys, namespace, srcCore, reqStr, responses).done(),
    /SOURCE_CORE_INSUFFICIENT_PEERS/,
    'source not well seeded error 2'
  )

  const srcCore3 = srcStore3.get(srcCore.key)
  await srcCore3.ready()
  srcSwarm3.join(srcCore3.discoveryKey)

  await waitUntilSufficientPeers(srcCore)

  await t.exception(
    () => multisig.commitCore(publicKeys, namespace, srcCore, reqStr, responses).done(),
    /SOURCE_CORE_NOT_FULLY_SEEDED/,
    'source not fully seeded error'
  )

  await srcCore2.get(0)
  await srcCore3.get(0)

  await waitUntilFullySeeded(srcCore)

  const commitCore = multisig.commitCore(publicKeys, namespace, srcCore, reqStr, responses, {
    skipTargetChecks: true
  })

  let verifyCommittableStart = 0
  let commitStart = 0
  let verifyCommittedStart = 0
  commitCore.on('verify-committable-start', () => verifyCommittableStart++)
  commitCore.on('commit-start', () => commitStart++)
  commitCore.on('verify-committed-start', () => verifyCommittedStart++)

  const commitPromise = commitCore.done()

  const tgtCoreKey = getCoreKey(publicKeys, namespace)

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

  const { core: tgtCore } = await commitPromise

  t.is(verifyCommittableStart, 1, 'verify-committable-start event')
  t.is(commitStart, 1, 'commit-start event')
  t.is(verifyCommittedStart, 1, 'verify-committed-start event')

  await tgtSwarm1.destroy()
  await tgtSwarm2.destroy()
  await tgtSwarm3.destroy()

  // A second commit
  await srcCore.append('block1')
  await srcCore2.get(1)
  await srcCore3.get(1)
  await waitUntilFullySeeded(srcCore)

  const { request: request2 } = await multisig
    .requestCore(publicKeys, namespace, srcCore, srcCore.length, { force: true })
    .done()
  const reqStr2 = z32.encode(request2)
  const responses2 = [await signResponse(request2, signers[0])]

  await t.exception(
    () =>
      multisig
        .commitCore(publicKeys, namespace, srcCore, reqStr2, responses2, {
          skipTargetChecks: true
        })
        .done(),
    /TARGET_NOT_EMPTY/,
    'target not empty error'
  )

  await t.exception(
    () => multisig.commitCore(publicKeys, namespace, srcCore, reqStr2, responses2).done(),
    /TARGET_CORE_INSUFFICIENT_PEERS/,
    'target not well seeded error'
  )

  const tgtCopy4 = tgtStore4.get(tgtCoreKey)
  await tgtCopy4.ready()
  tgtSwarm4.join(tgtCopy4.discoveryKey)

  const tgtCopy5 = tgtStore5.get(tgtCoreKey)
  await tgtCopy5.ready()
  tgtSwarm5.join(tgtCopy5.discoveryKey)

  const tgtCopy6 = tgtStore6.get(tgtCoreKey)
  await tgtCopy6.ready()
  tgtSwarm6.join(tgtCopy6.discoveryKey)

  await waitUntilSufficientPeers(tgtCore)

  await t.exception(
    () => multisig.commitCore(publicKeys, namespace, srcCore, reqStr2, responses2).done(),
    /TARGET_CORE_NOT_FULLY_SEEDED/,
    'target not fully seeded error'
  )

  await tgtCopy4.get(0)
  await tgtCopy5.get(0)
  await tgtCopy6.get(0)

  await waitUntilFullySeeded(tgtCore)

  const commitPromise2 = multisig
    .commitCore(publicKeys, namespace, srcCore, reqStr2, responses2)
    .done()

  await tgtCopy4.get(1)
  await tgtCopy5.get(1)
  await tgtCopy6.get(1)

  await commitPromise2

  // Create a request that would break the multisig core due to incompatible history
  {
    await srcCore.append('block2')

    const badSrcCore = srcStore1.get({ name: 'bad-core' })
    await badSrcCore.append('block0')
    await badSrcCore.append('different block1')
    await badSrcCore.append('block2')
    srcSwarm1.join(badSrcCore.discoveryKey)

    const badCopy2 = srcStore2.get(badSrcCore.key)
    await badCopy2.ready()
    srcSwarm2.join(badCopy2.discoveryKey)
    const badCopy3 = srcStore3.get(badSrcCore.key)
    await badCopy3.ready()
    srcSwarm3.join(badCopy3.discoveryKey)

    await Promise.all([
      badCopy2.get(0),
      badCopy2.get(1),
      badCopy2.get(2),
      badCopy3.get(0),
      badCopy3.get(1),
      badCopy3.get(2)
    ])
    await waitUntilFullySeeded(badSrcCore)

    const { request: request3 } = await multisig
      .requestCore(publicKeys, namespace, badSrcCore, badSrcCore.length, { force: true })
      .done()
    const reqStr3 = z32.encode(request3)
    const responses3 = [await signResponse(request3, signers[0])]

    await t.exception(
      () => multisig.commitCore(publicKeys, namespace, srcCore, reqStr3, responses3).done(),
      /SRC_KEY_MISMATCH/,
      'source key mismatch error'
    )

    await t.exception(
      () => multisig.commitCore(publicKeys, namespace, badSrcCore, reqStr3, responses3).done(),
      /INCOMPATIBLE_SOURCE_AND_TARGET/,
      'corruption error'
    )
  }

  await srcCore2.get(2)
  await srcCore3.get(2)
  await waitUntilFullySeeded(srcCore)

  const { request: request4 } = await multisig
    .requestCore(publicKeys, namespace, srcCore, srcCore.length, { force: true })
    .done()
  const reqStr4 = z32.encode(request4)
  const responses4 = [await signResponse(request4, signers[0])]

  const { result: result4 } = await multisig
    .commitCore(publicKeys, namespace, srcCore, reqStr4, responses4, { minFullCopies: 0 })
    .done()
  t.is(result4.destCore.length, 3, 'target core length is correct after request4 commit')

  const { request: request5 } = await multisig
    .requestCore(publicKeys, namespace, srcCore, srcCore.length, { force: true })
    .done()
  const reqStr5 = z32.encode(request5)
  const responses5 = [await signResponse(request5, signers[0])]

  await waitUntilSufficientPeers(tgtCore)
  const tgtFullCopies = tgtCore.peers.filter(
    (peer) => peer.remoteContiguousLength === tgtCore.length
  ).length
  t.ok(tgtFullCopies < 2, 'target core is not fully seeded after request4 commit')

  await t.exception(
    async () => {
      await multisig
        .commitCore(publicKeys, namespace, srcCore, reqStr5, responses5, {
          minFullCopies: 0,
          peerUpdateTimeout: -1
        })
        .done()
    },
    /TARGET_CORE_NOT_FULLY_SEEDED/,
    'request5 fails when target is not fully seeded'
  )

  const { result: result5 } = await multisig
    .commitCore(publicKeys, namespace, srcCore, reqStr5, responses5, {
      skipTargetWellSeeded: true,
      minFullCopies: 0,
      peerUpdateTimeout: -1
    })
    .done()
  t.is(result5.destCore.length, 3, 'request5 commits with skipTargetWellSeeded')
})

test('request drive', async (t) => {
  t.timeout(60000)

  const { store, multisig, publicKeys, namespace } = await setupTest(t)

  const srcDrive = new Hyperdrive(store)
  t.teardown(() => srcDrive.close())
  await srcDrive.put('/file1', b4a.from('0'))
  await srcDrive.put('/file2', b4a.from('1'))
  await srcDrive.put('/file3', b4a.from('2'))

  const { manifest, request } = await multisig
    .requestDrive(publicKeys, namespace, srcDrive, srcDrive.version, { force: true })
    .done()
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

  const { manifest, request } = await multisig
    .requestDrive(publicKeys, namespace, srcDrive, srcDrive.version, { force: true })
    .done()
  const reqStr = z32.encode(request)

  const responses = await Promise.all(
    signers.slice(0, manifest.quorum).map((signer) => signResponse(request, signer))
  )
  const { result } = await multisig
    .commitDrive(publicKeys, namespace, srcDrive, reqStr, responses, {
      force: true
    })
    .done()
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

  const { manifest, request } = await multisig
    .requestDrive(publicKeys, namespace, srcDrive, srcDrive.version, { force: true })
    .done()
  const reqStr = z32.encode(request)

  const responses = await Promise.all(
    signers.slice(0, manifest.quorum).map((signer) => signResponse(request, signer))
  )
  const { result } = await multisig
    .commitDrive(publicKeys, namespace, srcDrive, reqStr, responses, {
      force: true
    })
    .done()
  t.is(result.db.destCore.length, srcDrive.core.length, 'core length is correct')

  const { result: result2 } = await multisig
    .commitDrive(publicKeys, namespace, srcDrive, reqStr, responses, { force: true })
    .done()
  t.is(result2.db.destCore.length, srcDrive.core.length, 'core length is correct')
})

test('commit drive dry-run with start', async (t) => {
  t.timeout(120000)

  const {
    store,
    store2,
    store3,
    swarm,
    swarm2,
    swarm3,
    multisig,
    multisig2,
    multisig3,
    signers,
    publicKeys,
    namespace
  } = await setupTest(t, 3)

  const srcDrive = new Hyperdrive(store)
  t.teardown(() => srcDrive.close())
  await srcDrive.ready()
  swarm.join(srcDrive.discoveryKey)
  await srcDrive.put('/file0', b4a.alloc(65536 * 4))
  await srcDrive.put('/file1', b4a.alloc(65536 * 8))
  await srcDrive.put('/file2', b4a.alloc(65536 * 12))

  {
    const { manifest, request } = await multisig
      .requestDrive(publicKeys, namespace, srcDrive, srcDrive.version, { force: true })
      .done()
    const reqStr = z32.encode(request)
    const responses = await Promise.all(
      signers.slice(0, manifest.quorum).map((signer) => signResponse(request, signer))
    )
    const { core, blobsCore, result } = await multisig
      .commitDrive(publicKeys, namespace, srcDrive, reqStr, responses, { force: true })
      .done()
    t.is(result.db.destCore.length, srcDrive.core.length, 'core length is correct')
    t.is(core.length, srcDrive.core.length, 'core length is updated')
    t.is(blobsCore.length, srcDrive.blobs.core.length, 'blobsCore length is updated')
  }

  await srcDrive.put('/file3', b4a.alloc(65536 * 12))
  await srcDrive.put('/file4', b4a.alloc(65536 * 16))
  await srcDrive.put('/file5', b4a.alloc(65536 * 20))

  {
    const srcDrive2 = new Hyperdrive(store2, srcDrive.key)
    t.teardown(() => srcDrive2.close())
    await srcDrive2.ready()
    swarm2.join(srcDrive2.discoveryKey)

    await srcDrive2.getBlobs()
    await srcDrive2.blobs.core.update({ wait: true })
    t.is(srcDrive2.blobs.core.length, 72, 'srcDrive2.blobs.core length is correct')
    t.is(srcDrive2.blobs.core.contiguousLength, 0, 'srcDrive2.blobs.core contiguous length is 0')

    await srcDrive2.core.update({ wait: true })
    t.is(srcDrive2.core.length, 7, 'srcDrive2.core length is correct')
    t.is(srcDrive2.core.contiguousLength, 1, 'srcDrive2.core contiguous length is 0')

    const { request } = await multisig2
      .requestDrive(publicKeys, namespace, srcDrive, srcDrive.version, { force: true })
      .done()
    const reqStr = z32.encode(request)
    await multisig2
      .commitDrive(publicKeys, namespace, srcDrive2, reqStr, [], {
        force: true,
        dryRun: true
      })
      .done()
    t.ok(await srcDrive2.core.has(0, 7), 'srcDrive2 has all blocks')
  }

  {
    const srcDrive3 = new Hyperdrive(store3, srcDrive.key)
    t.teardown(() => srcDrive3.close())
    await srcDrive3.ready()
    swarm3.join(srcDrive3.discoveryKey)

    await srcDrive3.getBlobs()
    await srcDrive3.blobs.core.update({ wait: true })
    t.is(srcDrive3.blobs.core.length, 72, 'srcDrive3.blobs.core length is correct')
    t.is(srcDrive3.blobs.core.contiguousLength, 0, 'srcDrive3.blobs.core contiguous length is 0')

    await srcDrive3.core.update({ wait: true })
    t.is(srcDrive3.core.length, 7, 'srcDrive3.core length is correct')
    t.is(srcDrive3.core.contiguousLength, 1, 'srcDrive3.core contiguous length is 0')

    const { manifest, request } = await multisig3
      .requestDrive(publicKeys, namespace, srcDrive, srcDrive.version, { force: true })
      .done()
    const reqStr = z32.encode(request)
    await multisig3
      .commitDrive(publicKeys, namespace, srcDrive3, reqStr, [], {
        force: true,
        dryRun: true,
        start: 4,
        blobsStart: 24
      })
      .done()
    t.ok(await srcDrive3.core.has(0), 'srcDrive3 has block 0')
    t.absent(await srcDrive3.core.has(1), 'srcDrive3 does not have block 1')
    t.absent(await srcDrive3.core.has(2), 'srcDrive3 does not have block 2')
    t.absent(await srcDrive3.core.has(3), 'srcDrive3 does not have block 3')
    t.ok(await srcDrive3.core.has(4, 7), 'srcDrive3 has blocks 4, 5, 6')
  }
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
      await multisig.requestDrive(publicKeys, namespace, srcDrive, srcDrive.version).done()
    },
    /SOURCE_CORE_INSUFFICIENT_PEERS/,
    'source not well seeded error'
  )

  const copy3 = new Hyperdrive(store3, srcDrive.key)
  await copy3.ready()
  swarm3.join(copy3.discoveryKey)
  await waitUntilSufficientPeers(srcDrive.db.core)
  await waitUntilSufficientPeers(srcDrive.blobs.core)

  await t.exception(
    async () => {
      await multisig.requestDrive(publicKeys, namespace, srcDrive, srcDrive.version).done()
    },
    /SOURCE_CORE_NOT_FULLY_SEEDED: db/,
    'source not fully seeded error'
  )

  // We only get the db core, to verify it errors on incomplete blobs core
  for (let i = 0; i < srcDrive.db.core.length; i++) {
    await copy2.db.core.get(i)
    await copy3.db.core.get(i)
  }
  await waitUntilFullySeeded(srcDrive.db.core)

  await t.exception(
    async () => {
      await multisig.requestDrive(publicKeys, namespace, srcDrive, srcDrive.version).done()
    },
    /SOURCE_CORE_NOT_FULLY_SEEDED: blobs/,
    'blobs not fully seeded error'
  )

  await copy2.get('/file')
  await copy3.get('/file')
  await waitUntilFullySeeded(srcDrive.blobs.core)

  const { request, manifest } = await multisig
    .requestDrive(publicKeys, namespace, srcDrive, srcDrive.version)
    .done()
  const req = SignRequest.decode(request)
  t.is(req.id, idEnc.normalize(Hypercore.key(manifest)), 'request key is correct')
  t.is(req.length, srcDrive.core.length, 'request length is correct')
})

test('commit drive sanity checks throw correct errors', async (t) => {
  t.timeout(60000)
  const {
    store2: srcStore1,
    store3: srcStore2,
    store4: srcStore3,
    store5: tgtStore1,
    store6: tgtStore2,
    store7: tgtStore3,
    store8: tgtStore4,
    store9: tgtStore5,
    store10: tgtStore6,
    swarm2: srcSwarm1,
    swarm3: srcSwarm2,
    swarm4: srcSwarm3,
    swarm5: tgtSwarm1,
    swarm6: tgtSwarm2,
    swarm7: tgtSwarm3,
    swarm8: tgtSwarm4,
    swarm9: tgtSwarm5,
    swarm10: tgtSwarm6,
    multisig,
    publicKeys,
    namespace,
    signers
  } = await setupTest(t, 10, { numSigners: 1 })

  const srcDrive = new Hyperdrive(srcStore1)
  await srcDrive.put('/file', 'content')
  srcSwarm1.join(srcDrive.discoveryKey)

  const { request } = await multisig
    .requestDrive(publicKeys, namespace, srcDrive, srcDrive.version, { force: true })
    .done()
  const reqStr = z32.encode(request)
  const responses = [await signResponse(request, signers[0])]

  await t.exception(
    () => multisig.commitDrive(publicKeys, namespace, srcDrive, reqStr, responses).done(),
    /SOURCE_CORE_INSUFFICIENT_PEERS/,
    'source not well seeded error 1'
  )

  const srcCore2 = new Hyperdrive(srcStore2, srcDrive.key)
  await srcCore2.ready()
  srcSwarm2.join(srcCore2.discoveryKey)

  await t.exception(
    () => multisig.commitDrive(publicKeys, namespace, srcDrive, reqStr, responses).done(),
    /SOURCE_CORE_INSUFFICIENT_PEERS/,
    'source not well seeded error 2'
  )

  const srcCore3 = new Hyperdrive(srcStore3, srcDrive.key)
  await srcCore3.ready()
  srcSwarm3.join(srcCore3.discoveryKey)

  await waitUntilSufficientPeers(srcDrive.db.core)
  await waitUntilSufficientPeers(srcDrive.blobs.core)

  await t.exception(
    () => multisig.commitDrive(publicKeys, namespace, srcDrive, reqStr, responses).done(),
    /SOURCE_CORE_NOT_FULLY_SEEDED: db/,
    'source not fully seeded error'
  )

  // We only get the db core, to verify it errors on incomplete blobs core
  for (let i = 0; i < srcDrive.db.core.length; i++) {
    await srcCore2.db.core.get(i)
    await srcCore3.db.core.get(i)
  }

  await waitUntilFullySeeded(srcDrive.db.core)

  await t.exception(
    () =>
      multisig
        .commitDrive(publicKeys, namespace, srcDrive, reqStr, responses, {
          skipTargetChecks: true
        })
        .done(),
    /SOURCE_CORE_NOT_FULLY_SEEDED: blobs/,
    'source blobs not fully seeded error'
  )

  await srcCore2.get('/file')
  await srcCore3.get('/file')

  await waitUntilFullySeeded(srcDrive.blobs.core)

  let verifyCommittableStart = 0
  let commitStart = 0
  let verifyCommittedStart = 0

  const commitDrive = multisig.commitDrive(publicKeys, namespace, srcDrive, reqStr, responses, {
    skipTargetChecks: true
  })

  commitDrive.on('verify-committable-start', () => verifyCommittableStart++)
  commitDrive.on('commit-start', () => commitStart++)
  commitDrive.on('verify-committed-start', () => verifyCommittedStart++)

  const commitPromise = commitDrive.done()

  const tgtCoreKey = getCoreKey(publicKeys, namespace)

  const tgtCopy1 = new Hyperdrive(tgtStore1, tgtCoreKey)
  await tgtCopy1.ready()
  tgtSwarm1.join(tgtCopy1.discoveryKey)

  const tgtCopy2 = new Hyperdrive(tgtStore2, tgtCoreKey)
  await tgtCopy2.ready()
  tgtSwarm2.join(tgtCopy2.discoveryKey)

  const tgtCopy3 = new Hyperdrive(tgtStore3, tgtCoreKey)
  await tgtCopy3.ready()
  tgtSwarm3.join(tgtCopy3.discoveryKey)

  for (let i = 0; i < srcDrive.db.core.length; i++) {
    await tgtCopy1.db.core.get(i)
    await tgtCopy2.db.core.get(i)
    await tgtCopy3.db.core.get(i)
  }
  for (let i = 0; i < srcDrive.blobs.core.length; i++) {
    await tgtCopy1.blobs.core.get(i)
    await tgtCopy2.blobs.core.get(i)
    await tgtCopy3.blobs.core.get(i)
  }

  const { core: tgtCore, blobsCore: tgtBlobsCore } = await commitPromise

  t.is(verifyCommittableStart, 1, 'verify-committable-start event')
  t.is(commitStart, 1, 'commit-start event')
  t.is(verifyCommittedStart, 1, 'verify-committed-start event')

  await tgtSwarm1.destroy()
  await tgtSwarm2.destroy()
  await tgtSwarm3.destroy()

  // A second commit
  await srcDrive.put('/file2', 'more')
  await srcCore2.checkout(srcDrive.version).get('/file2')
  await srcCore3.checkout(srcDrive.version).get('/file2')

  const { request: request2 } = await multisig
    .requestDrive(publicKeys, namespace, srcDrive, srcDrive.version, { force: true })
    .done()
  const reqStr2 = z32.encode(request2)
  const responses2 = [await signResponse(request2, signers[0])]

  await t.exception(
    () =>
      multisig
        .commitDrive(publicKeys, namespace, srcDrive, reqStr2, responses2, {
          skipTargetChecks: true
        })
        .done(),
    /TARGET_NOT_EMPTY/,
    'target not empty error'
  )

  await t.exception(
    () => multisig.commitDrive(publicKeys, namespace, srcDrive, reqStr2, responses2).done(),
    /TARGET_CORE_INSUFFICIENT_PEERS: db/,
    'target not well seeded error'
  )

  const tgtCopy4 = new Hyperdrive(tgtStore4, tgtCoreKey)
  await tgtCopy4.ready()
  tgtSwarm4.join(tgtCopy4.discoveryKey)

  const tgtCopy5 = new Hyperdrive(tgtStore5, tgtCoreKey)
  await tgtCopy5.ready()
  tgtSwarm5.join(tgtCopy5.discoveryKey)

  const tgtCopy6 = new Hyperdrive(tgtStore6, tgtCoreKey)
  await tgtCopy6.ready()
  tgtSwarm6.join(tgtCopy6.discoveryKey)

  await waitUntilSufficientPeers(tgtCore)
  await waitUntilSufficientPeers(tgtBlobsCore)

  await t.exception(
    () => multisig.commitDrive(publicKeys, namespace, srcDrive, reqStr2, responses2).done(),
    /TARGET_CORE_NOT_FULLY_SEEDED/,
    'target not fully seeded error'
  )

  // We only get the db core, to verify it errors on incomplete blobs core
  for (let i = 0; i < tgtCore.length; i++) {
    await tgtCopy4.db.core.get(i)
    await tgtCopy5.db.core.get(i)
    await tgtCopy6.db.core.get(i)
  }

  await waitUntilFullySeeded(tgtCore)

  await t.exception(
    () => multisig.commitDrive(publicKeys, namespace, srcDrive, reqStr2, responses2).done(),
    /TARGET_CORE_NOT_FULLY_SEEDED: blobs/,
    'target blobs not fully seeded error'
  )

  for (let i = 0; i < tgtBlobsCore.length; i++) {
    await tgtCopy4.blobs.core.get(i)
    await tgtCopy5.blobs.core.get(i)
    await tgtCopy6.blobs.core.get(i)
  }

  await waitUntilFullySeeded(tgtBlobsCore)

  const commitPromise2 = multisig
    .commitDrive(publicKeys, namespace, srcDrive, reqStr2, responses2)
    .done()

  for (let i = 0; i < srcDrive.db.core.length; i++) {
    await tgtCopy4.db.core.get(i)
    await tgtCopy5.db.core.get(i)
    await tgtCopy6.db.core.get(i)
  }
  for (let i = 0; i < srcDrive.blobs.core.length; i++) {
    await tgtCopy4.blobs.core.get(i)
    await tgtCopy5.blobs.core.get(i)
    await tgtCopy6.blobs.core.get(i)
  }

  await commitPromise2

  // Create a request that would break the multisig due to incompatible history
  {
    await srcDrive.put('/file3', 'even more')

    const badSrcDrive = new Hyperdrive(srcStore1.namespace('other'))
    await badSrcDrive.put('/file', 'bad')
    await badSrcDrive.put('/file2', 'worse')
    await badSrcDrive.put('/file3', 'owow')
    srcSwarm1.join(badSrcDrive.discoveryKey)

    const badCopy2 = new Hyperdrive(srcStore2, badSrcDrive.key)
    await badCopy2.ready()
    srcSwarm2.join(badCopy2.discoveryKey)
    const badCopy3 = new Hyperdrive(srcStore3, badSrcDrive.key)
    await badCopy3.ready()
    srcSwarm3.join(badCopy3.discoveryKey)

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
    await waitUntilFullySeeded(badSrcDrive.db.core)

    const { request: request3 } = await multisig
      .requestDrive(publicKeys, namespace, badSrcDrive, badSrcDrive.version, { force: true })
      .done()
    const reqStr3 = z32.encode(request3)
    const responses3 = [await signResponse(request3, signers[0])]

    await t.exception(
      async () => {
        await multisig.commitDrive(publicKeys, namespace, srcDrive, reqStr3, responses3).done()
      },
      /SRC_KEY_MISMATCH/,
      'source key mismatch error'
    )

    await t.exception(
      async () => {
        await multisig.commitDrive(publicKeys, namespace, badSrcDrive, reqStr3, responses3).done()
      },
      /INCOMPATIBLE_SOURCE_AND_TARGET/,
      'corruption error'
    )
  }

  await srcCore2.checkout(srcDrive.version).get('/file3')
  await srcCore3.checkout(srcDrive.version).get('/file3')
  await waitUntilFullySeeded(srcDrive.db.core)
  await waitUntilFullySeeded(srcDrive.blobs.core)

  const { request: request4 } = await multisig
    .requestDrive(publicKeys, namespace, srcDrive, srcDrive.version, { force: true })
    .done()
  const reqStr4 = z32.encode(request4)
  const responses4 = [await signResponse(request4, signers[0])]

  const { result: result4 } = await multisig
    .commitDrive(publicKeys, namespace, srcDrive, reqStr4, responses4, { minFullCopies: 0 })
    .done()
  t.is(
    result4.db.destCore.length,
    srcDrive.db.core.length,
    'target db length is correct after request4 commit'
  )
  t.is(
    result4.blobs.destCore.length,
    srcDrive.blobs.core.length,
    'target blobs length is correct after request4 commit'
  )

  const { request: request5 } = await multisig
    .requestDrive(publicKeys, namespace, srcDrive, srcDrive.version, { force: true })
    .done()
  const reqStr5 = z32.encode(request5)
  const responses5 = [await signResponse(request5, signers[0])]

  await waitUntilSufficientPeers(tgtCore)
  await waitUntilSufficientPeers(tgtBlobsCore)

  const tgtFullCopies = tgtCore.peers.filter(
    (peer) => peer.remoteContiguousLength === tgtCore.length
  ).length
  const tgtBlobsFullCopies = tgtBlobsCore.peers.filter(
    (peer) => peer.remoteContiguousLength === tgtBlobsCore.length
  ).length

  t.ok(tgtFullCopies < 2, 'target db core is not fully seeded after request4 commit')
  t.ok(tgtBlobsFullCopies < 2, 'target blobs core is not fully seeded after request4 commit')

  await t.exception(
    async () => {
      await multisig
        .commitDrive(publicKeys, namespace, srcDrive, reqStr5, responses5, {
          minFullCopies: 0,
          peerUpdateTimeout: -1
        })
        .done()
    },
    /TARGET_CORE_NOT_FULLY_SEEDED: db/,
    'request5 fails when target is not fully seeded'
  )

  const { result: result5 } = await multisig
    .commitDrive(publicKeys, namespace, srcDrive, reqStr5, responses5, {
      skipTargetWellSeeded: true,
      minFullCopies: 0,
      peerUpdateTimeout: -1
    })
    .done()
  t.is(
    result5.db.destCore.length,
    srcDrive.db.core.length,
    'request5 commits with skipTargetWellSeeded'
  )
  t.is(
    result5.blobs.destCore.length,
    srcDrive.blobs.core.length,
    'request5 blobs commit with skipTargetWellSeeded'
  )
})

test('verify core remotely (can get tree hash)', async (t) => {
  t.timeout(120000)
  const { store, swarm, multisig, multisig2, publicKeys, namespace, signers, store2, swarm2 } =
    await setupTest(t, 2)

  const srcCore = store.get({ name: 'srcCore' })
  t.teardown(() => srcCore.close())
  await srcCore.append(b4a.from('0'))
  await srcCore.append(b4a.from('1'))
  await srcCore.append(b4a.from('2'))
  swarm.join(srcCore.discoveryKey)

  const { manifest, request } = await multisig
    .requestCore(publicKeys, namespace, srcCore, srcCore.length, { force: true })
    .done()
  const reqStr = z32.encode(request)

  const responses = await Promise.all(
    signers.slice(0, manifest.quorum).map((signer) => signResponse(request, signer))
  )
  const commitCore = multisig.commitCore(publicKeys, namespace, srcCore, reqStr, responses, {
    force: true
  })

  const { core: multisigCore } = await commitCore.done()
  swarm.join(multisigCore.discoveryKey)
  await new Promise((resolve) => setTimeout(resolve, 200)) // flush swarm
  await srcCore.append(b4a.from('3'))
  await srcCore.append(b4a.from('4'))
  await srcCore.append(b4a.from('5'))
  await srcCore.append(b4a.from('6'))

  const { request: request2 } = await multisig
    .requestCore(publicKeys, namespace, srcCore, srcCore.length, { force: true })
    .done()
  const reqStr2 = z32.encode(request2)

  const readonlyFromCore = store2.get(srcCore.key)
  swarm2.join(readonlyFromCore.discoveryKey)
  await once(readonlyFromCore, 'append') // get length but no other info

  const { result } = await multisig2
    .commitCore(publicKeys, namespace, readonlyFromCore, reqStr2, [], { dryRun: true, minPeers: 1 })
    .done()

  t.pass('Could verify request (did not crash due to not being able to get the treeHash)')
  t.is(result.srcCore.length, 7, 'sanity check')
})

/** @type {function(): Promise<{ signatures: Buffer[], blobsSignatures: Buffer[] }>} */
async function requestAndSign(signers, fromCore, manifest, { length, isDrive } = {}) {
  const request = isDrive
    ? await SignRequest.generateDrive(fromCore, { manifest, length })
    : await SignRequest.generate(fromCore, { manifest, length })

  const allSignatures = await Promise.all(
    signers.slice(0, manifest.quorum).map((signer) => sign(request, signer))
  )
  const signatures = allSignatures.map((item) => item.signatures[0])
  const blobsSignatures = allSignatures.map((item) => item.signatures[1])
  return { signatures, blobsSignatures }
}

async function sign(request, signer) {
  // clone to avoid mutation
  const clonedSigner = Object.keys(signer).reduce((acc, key) => {
    acc[key] = b4a.from(signer[key])
    return acc
  }, {})

  const decodedReq = SignRequest.decode(request)

  const password = sodium.sodium_malloc(8)
  sodium.randombytes_buf_deterministic(password, clonedSigner.seed)

  const response = await CoreSign.sign(request, clonedSigner.secretKey, password)
  const { signatures } = SignRequest.decodeResponse(response)
  return { clonedSigner, decodedReq, signatures }
}

async function signResponse(request, signer) {
  const { clonedSigner, decodedReq, signatures } = await sign(request, signer)
  const res = SignRequest.encodeResponse({
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
 *   multisig3?: Multisig,
 *   namespace: string,
 *   signers: { id: Buffer, publicKey: Buffer, secretKey: Buffer, seed: Buffer }[],
 *   publicKeys: string[]
 * }>}
 */
async function setupTest(t, n, { numSigners } = {}) {
  const res = await setup(t, n)

  res.multisig = new Multisig(res.store, res.swarm)
  if (res.store2) res.multisig2 = new Multisig(res.store2, res.swarm2)
  if (res.store3) res.multisig3 = new Multisig(res.store3, res.swarm3)

  return { ...res, ...(await setupMultisig(undefined, numSigners)) }
}

async function setupMultisig(namespace = 'holepunchto/my-test', numSigners = 3) {
  const signers = []
  for (let i = 0; i < numSigners; i++) {
    const seed = sodium.sodium_malloc(sodium.randombytes_SEEDBYTES)
    sodium.randombytes_buf(seed)
    const password = sodium.sodium_malloc(8)
    sodium.randombytes_buf_deterministic(password, seed)

    const keys = await CoreSign.generateKeys(password)
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
