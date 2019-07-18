/**
 *  Error subclass for signaling keystore errors
 */
export class KeystoreError extends Error {
    constructor(message: string) {
        super(message)
        this.name = this.constructor.name
        Error.captureStackTrace(this, this.constructor)
        Object.setPrototypeOf(this, KeystoreError.prototype)
    }
}

/**
 *  Error subclass for signaling keystore error when a given private key is not found
 */
export class PrivateKeyNotFoundError extends KeystoreError {
    public keyId: string

    constructor(keyId: string) {
        super(`private key not found, key id: ${keyId}`)
        this.keyId = keyId
        Object.setPrototypeOf(this, PrivateKeyNotFoundError.prototype)
    }
}

/**
 *  Error subclass for signaling keystore error when a given public key is not found
 */
export class CertificateNotFoundError extends KeystoreError {
    public keyId: string

    constructor(keyId: string) {
        super(`certificate not found, key id: ${keyId}`)
        this.keyId = keyId
        Object.setPrototypeOf(this, CertificateNotFoundError.prototype)
    }
}

