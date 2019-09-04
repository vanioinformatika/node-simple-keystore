import {KeystoreError} from './KeystoreError'

/**
 *  Error subclass for signaling keystore error when a given public key is not found
 */
export class CertificateNotFoundError extends KeystoreError {
    public keyId: string

    constructor(keyId: string) {
        super(`certificate not found, key id: ${keyId}`)
        this.keyId = keyId
        Object.setPrototypeOf(this, CertificateNotFoundError.prototype)
        Error.captureStackTrace(this, this.constructor)
        this.name = this.constructor.name
    }
}

