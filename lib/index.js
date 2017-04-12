const { KeystoreError, PrivateKeyNotFoundError, CertificateNotFoundError } = require('./errors')

module.exports = (debugNamePrefix, baseDir, refreshIntervalMillis, signingKeyPassphrases) => {
  const keystoreReader = require('./keystore.reader.fs')(baseDir)
  const keystore = require('./keystore')(
    debugNamePrefix, signingKeyPassphrases, keystoreReader, refreshIntervalMillis
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
