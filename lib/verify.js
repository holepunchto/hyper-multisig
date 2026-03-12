const b4a = require('b4a')

const MultisigError = require('./error')

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

  await waitUntilSufficientPeers(tgtCore, { minPeers, timeout: peerUpdateTimeout })

  const tgtPeers = tgtCore.peers.length
  if (tgtPeers < minPeers) {
    throw MultisigError.TARGET_CORE_INSUFFICIENT_PEERS(tgtPeers, minPeers, { coreId })
  }

  await waitUntilFullySeeded(tgtCore, { minPeers, timeout: peerUpdateTimeout })

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

async function verifyCoreCommitted(tgtCore, { minPeers = 2 } = {}) {
  let tgtFullCopies = 0
  for (const p of tgtCore.peers) {
    if (p.remoteContiguousLength === tgtCore.length) tgtFullCopies++
  }
  if (tgtFullCopies < minPeers) {
    await new Promise((resolve) => setTimeout(resolve, 100))
    await verifyCoreCommitted(tgtCore, { minPeers })
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
  verifyCoreRequestable,
  verifyCoreCommittable,
  verifyCoreCommitted,
  waitUntilCoreLength,
  waitUntilSufficientPeers,
  waitUntilFullySeeded
}
