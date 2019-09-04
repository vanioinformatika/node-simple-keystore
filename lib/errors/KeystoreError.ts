/**
 *  Error subclass for signaling keystore errors
 */
export class KeystoreError extends Error {
    constructor(message: string) {
        super(message)
        Object.setPrototypeOf(this, KeystoreError.prototype)
        Error.captureStackTrace(this, this.constructor)
        this.name = this.constructor.name
    }
}
