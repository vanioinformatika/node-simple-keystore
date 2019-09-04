import {KeystoreError} from './KeystoreError'

/**
 *  Error subclass for signaling keystore error when a given private key is not found
 */
export class PrivateKeyNotFoundError extends KeystoreError {
    public keyId: string

    constructor(keyId: string) {
        super(`private key not found, key id: ${keyId}`)
        this.keyId = keyId
        Object.setPrototypeOf(this, PrivateKeyNotFoundError.prototype)
        Error.captureStackTrace(this, this.constructor)
        this.name = this.constructor.name
    }
}
