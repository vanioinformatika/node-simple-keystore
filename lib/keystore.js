/* eslint-disable padded-blocks */
const Promise = require('bluebird')

const { PrivateKeyNotFoundError, CertificateNotFoundError } = require('./errors')

/**
 * Holds a cached private key and certificate data
 * @typedef KeyAndCert
 * @type {object}
 * @property {number} timestamp Timestamp of loading
 * @property {string} privKey Private key data in PEM format
 * @property {string} cert Certificate data in PEM format
 * @property {string} keyAlg JWT key algorithm (RS256, ES256, etc.)
 * @property {string} privKeyPassphrase Passphrase for the private key (if any)
 */

 /**
  * Holds a private key and the corresponding passphrase
  * @typedef PrivateKeyAndPassphrase
  * @type {object}
  * @property {string} key Private key data in PEM format
  * @property {string} passphrase Passphrase for the private key (if any)
  */

/**
 * Synchronous or asnyhronous callback for loading private keys and certificates
 * @callback KeystoreService~keystoreReaderCallback
 * @return {Map.<KeyAndCert>} The loaded key and certificate data
 */

/**
 * Creates a new keystore service
 * @param {string} debugNamePrefix Name prefix used for the debug module
 * @param {Object} signingKeyPassphrases Stores passphrases for each signing keys. Key: key id, value: passphrase
 * @param {KeystoreService~keystoreReaderCallback} keystoreReader Keystore reader callback (sync or async)
 * @param {integer} refreshInterval Interval of the keystore refresh [millisec]
 */
module.exports = (debugNamePrefix, signingKeyPassphrases, keystoreReader, refreshInterval) => {

  const debug = require('debug')(debugNamePrefix + ':keystore')

  /** The current signing key ID */
  let currentSigningKeyId

  /** Cache for the private key and certificate data */
  let keys = new Map()

  // Reading keystore asynchronously
  const keystoreReaderAsync = Promise.method(keystoreReader)
  const keystoreReaderTask = () => {
    keystoreReaderAsync(keys)
      .then(newKeys => {
        debug('Keystore reloaded, keys: ', newKeys.keys())
        keys = newKeys
        currentSigningKeyId = selectCurrentSigningKeyId(keys)
        debug('Current signing key id: ' + currentSigningKeyId)
      })
      .catch(err => {
        debug('Reading keystore failed', err) // FIXME: should signal this error somehow. an EventEmitter maybe?
      })
  }
  keystoreReaderTask() // first call before starting timer
  setInterval(keystoreReaderTask, refreshInterval)

  /**
   * Selects the current signing key id
   *
   * @param {Array} currentKeys The current keys
   * @return {string} The selected key id
   */
  function selectCurrentSigningKeyId (currentKeys) {
    /* eslint-disable no-useless-return */
    if (currentKeys.size === 0) {
      return
    } else if (currentKeys.size === 1) {
      return currentKeys.keys().next().value
    } else {
      const now = Math.floor(Date.now() / 1000)
      const maxTimestamp = now - (20 * 60) // the youngest key to use
      const allKeys = Array.from(currentKeys)
      let allowedKeys = allKeys.filter(keyEntry => keyEntry[1].timestamp < maxTimestamp)
      debug('allowedKeys: ', allowedKeys)
      if (allowedKeys.length === 0) {
        allowedKeys = allKeys
      }
      allowedKeys = allowedKeys.sort((a, b) => a[0] > b[0] ? 1 : a[0] < b[0] ? -1 : 0)
      const entryToUse = allowedKeys[allowedKeys.length - 1]
      return entryToUse[0]
    }
  }

  /**
  * Returns the ID of the signing key that has to be used for signing
  * @return {string} The ID of the key that has to be used for signing
  */
  function getCurrentSigningKeyId () {
    return currentSigningKeyId
  }

  /**
  * PRIVATE function! Returns the passphrase for the given private key
  * @param  {string} id The id of the private key
  * @return {string} The passphrase for the private key
  */
  function getPrivateKeyPassphrase (id) {
    return signingKeyPassphrases[id]
  }

  /**
  * Returns the private key with the given id
  * Throws PrivateKeyNotFoundError if the certificate is not found in the store
  *
  * @param  {string} id The private key id
  * @return {Promise.<PrivateKeyAndPassphrase, PrivateKeyNotFoundError>} Promise to the private key {key(PEM), passphrase}
  */
  function getPrivateKey (id) {
    if (keys.has(id)) {
      const key = keys.get(id)
      return Promise.resolve({
        alg: key.keyAlg,
        key: key.privKey,
        passphrase: getPrivateKeyPassphrase(id)
      })
    } else {
      return Promise.reject(new PrivateKeyNotFoundError(`Loading private key ${id} failed`))
    }
  }

  /**
  * Returns the certificate with the given id
  * Throws CertificateNotFoundError if the certificate is not found in the store
  *
  * @param  {string} id The certificate id
  * @return {Promise.<string, CertificateNotFoundError>} Promise to the certificate (PEM)
  */
  function getCertificate (id) {
    if (keys.has(id)) {
      const key = keys.get(id)
      return Promise.resolve({
        alg: key.keyAlg,
        cert: key.cert
      })
    } else {
      return Promise.reject(new CertificateNotFoundError(`Loading certificate ${id} failed`))
    }
  }

  /**
   * Represents a public key with a certificate chain attached
   * @typedef JWK
   * @type {object}
   * @property {string} kid Key id
   * @property {string} x5c X.509 certificate chain
   */

  /**
   * Returns all certificates in JWKS format
   *
   * @return {Array.JWK} An array of JWK objects
   */
  function getAllCertificatesAsJWKS () {
    const keySet = []
    keys.forEach((key) => {
      keySet.push(key.pubkeyJwk)
    })
    return keySet
  }

  return {
    getCurrentSigningKeyId,
    getPrivateKey,
    getCertificate,
    getAllCertificatesAsJWKS,
    getPrivateKeyPassphrase,
    selectCurrentSigningKeyId
  }
}
