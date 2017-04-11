const { KeystoreError, PrivateKeyNotFoundError, CertificateNotFoundError } = require('./errors')

module.exports = (debugName, baseDir, signingKeyPassphrases) => {
  const keystoreReaderFs = require('./keystore.reader.fs')(baseDir)
  const keystore = require('./keystore')(
    debugName, signingKeyPassphrases, keystoreReaderFs, 5 * 60 * 1000
  )
  return {
    getCurrentSigningKeyId: keystore.getCurrentSigningKeyId,
    getPrivateKey: keystore.getPrivateKey,
    getCertificate: keystore.getCertificate,
    getAllCertificatesAsJWK: keystore.getAllCertificatesAsJWK,
    KeystoreError,
    PrivateKeyNotFoundError,
    CertificateNotFoundError
  }
}
