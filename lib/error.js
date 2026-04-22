class MultisigError extends Error {
  constructor(msg, code, fn = MultisigError) {
    super(`${code}: ${msg}`)
    this.code = code

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, fn)
    }
  }

  get name() {
    return 'MultisigError'
  }

  static SOURCE_CORE_TOO_SMALL(length, { coreId = '' } = {}) {
    return new MultisigError(
      `${coreId} Source core is smaller than the requested length of ${length}`,
      'SOURCE_CORE_TOO_SMALL',
      MultisigError.SOURCE_CORE_TOO_SMALL
    )
  }

  static SRC_KEY_MISMATCH({ coreId = '' } = {}) {
    return new MultisigError(
      `${coreId} Mismatch between request srcKey and config srcKey`,
      'SRC_KEY_MISMATCH',
      MultisigError.SRC_KEY_MISMATCH
    )
  }

  static TARGET_CORE_TOO_BIG() {
    return new MultisigError(
      'The target core already has higher length than the source core. Committing this signing request will most likely corrupt your core',
      'TARGET_CORE_TOO_BIG',
      MultisigError.TARGET_CORE_TOO_BIG
    )
  }

  static SOURCE_CORE_INSUFFICIENT_PEERS(nrPeers, minPeers) {
    return new MultisigError(
      `Source core is not well seeded (${nrPeers}/${minPeers} peers)`,
      'SOURCE_CORE_INSUFFICIENT_PEERS',
      MultisigError.SOURCE_CORE_INSUFFICIENT_PEERS
    )
  }

  static SOURCE_CORE_NOT_FULLY_SEEDED(fullCopies, minPeers, { coreId = '' } = {}) {
    return new MultisigError(
      `${coreId} Source core is not yet fully downloaded by sufficient seeders (${fullCopies}/${minPeers})`,
      'SOURCE_CORE_NOT_FULLY_SEEDED',
      MultisigError.SOURCE_CORE_NOT_FULLY_SEEDED
    )
  }

  static TARGET_NOT_EMPTY() {
    return new MultisigError(
      'Target core is not empty, so you should not skip those checks',
      'TARGET_NOT_EMPTY',
      MultisigError.TARGET_NOT_EMPTY
    )
  }

  static TARGET_CORE_INSUFFICIENT_PEERS(nrPeers, minPeers, { coreId = '' } = {}) {
    return new MultisigError(
      `${coreId} Target core is not well seeded (${nrPeers}/${minPeers} peers)`,
      'TARGET_CORE_INSUFFICIENT_PEERS',
      MultisigError.TARGET_CORE_INSUFFICIENT_PEERS
    )
  }

  static TARGET_CORE_NOT_FULLY_SEEDED(fullCopies, minPeers, { coreId = '' } = {}) {
    return new MultisigError(
      `${coreId} Target core is not yet fully downloaded by sufficient seeders (${fullCopies}/${minPeers})`,
      'TARGET_CORE_NOT_FULLY_SEEDED',
      MultisigError.TARGET_CORE_NOT_FULLY_SEEDED
    )
  }

  static INCOMPATIBLE_SOURCE_AND_TARGET({ coreId = '' } = {}) {
    return new MultisigError(
      `${coreId} Target core contains different data from the source core. Committing this signing request will corrupt your core.`,
      'INCOMPATIBLE_SOURCE_AND_TARGET',
      MultisigError.INCOMPATIBLE_SOURCE_AND_TARGET
    )
  }
}

module.exports = MultisigError
