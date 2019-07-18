import {KeystoreReaderFs} from './keystore.reader.fs'
import {Keystore} from './keystore'

export {CertificateNotFoundError, PrivateKeyNotFoundError, KeystoreError} from './errors'
export {KeystoreReaderFs} from './keystore.reader.fs'
export {KeyAndCert, JWK, Keystore, PrivateKey, Certificate} from './keystore'

export default (debugNamePrefix: string,
    baseDir: string,
    refreshIntervalMillis: number,
    signingKeyPassphrases: { [key: string]: string },
): Keystore => {
    const keystoreReader = new KeystoreReaderFs(debugNamePrefix, baseDir).readKeys
    return new Keystore(debugNamePrefix, signingKeyPassphrases, keystoreReader, refreshIntervalMillis)
}
