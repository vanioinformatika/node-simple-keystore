/** Error subclass for signaling keystore errors */
class KeystoreError extends Error {
  constructor (message) {
    super(message)
    this.name = this.constructor.name
    this.message = message
    Error.captureStackTrace(this, this.constructor)
  }
}

/** Error subclass for signaling keystore error when a given private key is not found */
class PrivateKeyNotFoundError extends KeystoreError {
  constructor (keyId) {
    super(`private key not found, key id: ${keyId}`)
    this.keyId = keyId
  }
}

/** Error subclass for signaling keystore error when a given public key is not found */
class CertificateNotFoundError extends KeystoreError {
  constructor (keyId) {
    super(`certificate not found, key id: ${keyId}`)
    this.keyId = keyId
  }
}

module.exports = {
  KeystoreError, PrivateKeyNotFoundError, CertificateNotFoundError
}
