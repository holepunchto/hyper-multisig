/**
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

const Hypercore = require('hypercore')
const crypto = require('hypercore-crypto')
const idEnc = require('hypercore-id-encoding')

/**
 * @param {string[]} publicKeys
 * @param {string} namespace
 * @param {{ quorum?: number }} [opts]
 * @return {string}
 */
function getCoreKey(publicKeys, namespace, { quorum } = {}) {
  const manifest = getManifest(publicKeys, namespace, { quorum })
  return Hypercore.key(manifest)
}

/**
 * @param {string[]} publicKeys
 * @param {string} namespace
 * @param {{ quorum?: number }} [opts]
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
 * @return {Promise<{ key: string, length: number, fork: number, treeHash: string }>}
 */
async function getCoreInfo(core) {
  await core.ready()
  return {
    key: idEnc.normalize(core.key),
    length: core.length,
    fork: core.fork,
    treeHash: idEnc.normalize(await core.treeHash())
  }
}

module.exports = {
  getCoreKey,
  getManifest,
  getNamespace,
  normalizeManifest,
  getCoreInfo
}
