const { KeystoreError, PrivateKeyNotFoundError, CertificateNotFoundError } = require('./errors')

module.exports = (debugNamePrefix, baseDir, refreshIntervalMillis, signingKeyPassphrases) => {
  const keystoreReader = require('./keystore.reader.fs')(debugNamePrefix, baseDir)
  const keystore = require('./keystore')(
    debugNamePrefix, signingKeyPassphrases, keystoreReader, refreshIntervalMillis
  )
  return {
    getCurrentSigningKeyId: keystore.getCurrentSigningKeyId,
    getPrivateKey: keystore.getPrivateKey,
    getCertificate: keystore.getCertificate,
    getAllCertificatesAsJWKS: keystore.getAllCertificatesAsJWKS,
    KeystoreError,
    PrivateKeyNotFoundError,
    CertificateNotFoundError
  }
}
