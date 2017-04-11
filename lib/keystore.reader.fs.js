/**
 * Filesystem keystore reader module
 * @module keystore/keystore.reader.fs
 */
const Promise = require('bluebird')
const fs = require('fs')
const path = require('path')
const pem = require('pem')
const r = require('jsrsasign')

const readFileAsync = Promise.promisify(fs.readFile)
const readdirAsync = Promise.promisify(fs.readdir)
const verifySigningChainAsync = Promise.promisify(pem.verifySigningChain)

/**
 * Creates a keystore reader function
 * @alias keystoreReaderFactory
 * @param {string} baseDir The keystore base directory
 * @return {keystoreReaderFactory~readKeys} A function to (re)load private keys and certificates
 */
module.exports = function (debugName, baseDir) {
  //
  const debug = require('debug')(`${debugName}:reader.fs`)
  //
  const rootCACert = fs.readFileSync(path.join(baseDir, `rootCA.cert.pem`))
  debug('Root CA cert loaded: ' + rootCACert)
  const caCert = rootCACert.toString()
  debug('CA store created')

  const algMap = {
    'SHA256withECDSA': 'ES256',
    'SHA256withRSA': 'RS256'
  }

  /**
   * Handles the specified key id, i.e. returns a promise that loads the appropriate
   * private key and certificate from files
   *
   * @param {Map.<KeyAndCert>} newKeys A Map of key and cert data objects
   * @param {string} keyId Key ID
   * @return {Promise} A Promise that is resolved when the private and key a certificate for
   *                   the given keyId is loaded into the newKeys Object
   */
  function handleKeyId (newKeys, keyId) {
    debug(`keyId: ${keyId}`)
    if (!newKeys.has(keyId)) {
      debug(`${keyId} not found in cache`)
      return readKeyAndCert(newKeys, keyId)
    } else {
      debug(`${keyId} already cached`)
    }
  }

  /**
   * Creates s combined set of promises that are used for verifying and reading certs and private keys
   *
   * @param  {type} newKeys {Map.<KeyAndCert>} newKeys A Map of key and cert data objects
   * @param  {type} keyId Key ID
   * @return {Promise} A promise which is resolved when both the certificate and the
   *                   private key is loaded for the given key id
   */
  function readKeyAndCert (newKeys, keyId) {
    return Promise.all([
      readFileAsync(path.join(baseDir, `${keyId}.privkey.pem`)),
      readFileAsync(path.join(baseDir, `${keyId}.cert.pem`))
    ])
    .spread((privKeyPem, certPem) => {
      debug(`Key id ${keyId}, privkey and cert read`)
      const cert = new r.X509()
      cert.readCertPEM(certPem.toString())
      return verifyCertAsync(keyId, certPem, cert)
            .then(verifiedCert => {
              const certStr = verifiedCert.toString()
              const publicKey = r.KEYUTIL.getKey(certStr)
              const pubkeyJwk = r.KEYUTIL.getJWKFromKey(publicKey)
              pubkeyJwk.kid = keyId
              pubkeyJwk.alg = algMap[cert.getSignatureAlgorithmField()]
              pubkeyJwk.use = 'sig'
              pubkeyJwk.x5c = [r.X509.pemToBase64(certStr)]
              debug(`Key id ${keyId}, key alg: ${cert.getSignatureAlgorithmField()}`)
              newKeys.set(keyId, {
                timestamp: Math.floor(Date.now() / 1000), // unix time
                cert: certStr,
                keyAlg: algMap[cert.getSignatureAlgorithmField()],
                privKey: privKeyPem.toString(),
                pubkeyJwk
              })
            })
    })
  }

  /**
   * Verifies the given certificate if it is certified with the KKSZB CA
   *
   * @param {string} keyId Key id
   * @param {string} certPem The certificate in PEM format
   * @return {Promise} A promise which is resolved if the given certificate is trusted
   */
  function verifyCertAsync (keyId, certPem) {
    return verifySigningChainAsync(certPem, caCert)
           .then(() => {
             debug(`Key id ${keyId}, signing certificate verified`)
             return Promise.resolve(certPem)
           })
  }

  /**
   * Reads all keys and certs from the keystore base directory
   *
   * @param {Object} keys A map containing the currently loaded keys
   * @return {Promise.<Map.<KeyAndCert>, Error>} Promise to an object containing the already existing and loaded keys
   */
  function readKeys (keys) {
    const newKeys = new Map(keys)
    return readdirAsync(baseDir)
    .then(files => {
      const promises = []
      files.forEach(file => {
        const match = file.match(/([0-9]+)\.privkey.pem/)
        if (match) {
          const keyId = match[1]
          const keyIdHandler = handleKeyId(newKeys, keyId)
          if (keyIdHandler) promises.push(keyIdHandler)
        }
      })
      return Promise.all(promises).then(() => {
        debug('All keys loaded')
        return Promise.resolve(newKeys)
      })
    })
  }
  return readKeys
}
