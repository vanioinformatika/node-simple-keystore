import Debug, {IDebugger} from 'debug'
import {CertificateNotFoundError, PrivateKeyNotFoundError, PrivateKeyPassphraseNotFoundError} from './errors'
import {Certificate, JWK, KeyAndCert, KeystoreReader, PrivateKey} from './contracts'

export class Keystore {
    protected debug: IDebugger

    protected signingKeyPassphrases: { [key: string]: string }

    protected keystoreReader: KeystoreReader

    /** The current signing key ID */
    protected currentSigningKeyId: string | null = null

    /** Cache for the private key and certificate data */
    protected keys: Map<string, KeyAndCert> = new Map()

    protected interval?: NodeJS.Timeout

    /**
     * Creates a new keystore service
     *
     * @param debugNamePrefix Name prefix used for the debug module
     * @param signingKeyPassphrases Stores passphrases for each signing keys. Key: key id, value: passphrase
     * @param keystoreReader Keystore reader callback (sync or async)
     */
    public constructor(
        signingKeyPassphrases: { [key: string]: string },
        keystoreReader: KeystoreReader,
        debugNamePrefix?: string,
    ) {
        this.debug = Debug(`${debugNamePrefix ? debugNamePrefix + ':' : ''}keystore`)
        this.signingKeyPassphrases = signingKeyPassphrases
        this.keystoreReader = keystoreReader
    }

    /**
     * Start reader task
     *
     * @param refreshInterval Interval of the keystore refresh [millisec]
     */
    public async start(refreshInterval: number): Promise<void> {
        // first call before starting timer
        await this.keystoreReaderTask()
        this.interval = setInterval(this.keystoreReaderTask.bind(this), refreshInterval)
    }

    /**
     * Stop reader task
     */
    public stop(): void {
        if (this.interval) {
            clearInterval(this.interval)
        }
    }

    /**
     * Selects the current signing key id
     *
     * @param currentKeys The current keys
     *
     * @return The selected key id
     */
    public selectCurrentSigningKeyId(currentKeys: Map<string, KeyAndCert>): string | null {
        if (currentKeys.size === 0) {
            return null
        }
        if (currentKeys.size === 1) {
            return currentKeys.keys().next().value
        }
        const now = Math.floor(Date.now() / 1000)
        const maxTimestamp = now - (20 * 60) // the youngest key to use
        const allKeys = Array.from(currentKeys)
        let allowedKeys = allKeys.filter(keyEntry => keyEntry[1].timestamp < maxTimestamp)
        this.debug('allowedKeys: ', allowedKeys.map(keyEntry => keyEntry[0]))
        if (allowedKeys.length === 0) {
            allowedKeys = allKeys
        }
        allowedKeys = allowedKeys.sort((a, b) => a[0] > b[0] ? 1 : a[0] < b[0] ? -1 : 0)
        const entryToUse = allowedKeys[allowedKeys.length - 1]
        return entryToUse[0]
    }

    /**
     * Returns the ID of the signing key that has to be used for signing
     *
     * @return The ID of the key that has to be used for signing
     */
    public getCurrentSigningKeyId(): string | null {
        return this.currentSigningKeyId
    }

    /**
     * Returns the passphrase for the given private key
     *
     * @param id The id of the private key
     *
     * @return The passphrase for the private key
     */
    public getPrivateKeyPassphrase(id: string): string {
        if (this.signingKeyPassphrases.hasOwnProperty(id)) {
            return this.signingKeyPassphrases[id]
        }

        throw new PrivateKeyPassphraseNotFoundError(id)
    }

    /**
     * Returns the private key with the given id
     * Throws PrivateKeyNotFoundError if the certificate is not found in the store
     *
     * @param id The private key id
     *
     * @return Promise to the private key {key(PEM), passphrase}
     */
    public async getPrivateKey(id: string): Promise<PrivateKey> {
        const key = this.keys.get(id)
        if (!key) {
            throw new PrivateKeyNotFoundError(`Loading private key ${id} failed`)
        }
        return {
            alg: key.keyAlg,
            key: key.privKey,
            passphrase: this.getPrivateKeyPassphrase(id),
        }
    }

    /**
     * Returns the certificate with the given id
     * Throws CertificateNotFoundError if the certificate is not found in the store
     *
     * @param id The certificate id
     *
     * @return Promise to the certificate (PEM)
     */
    public async getCertificate(id: string): Promise<Certificate> {
        const key = this.keys.get(id)
        if (!key) {
            throw new CertificateNotFoundError(`Loading certificate ${id} failed`)
        }
        return {
            alg: key.keyAlg,
            cert: key.cert,
        }
    }

    /**
     * Returns all certificates in JWKS format
     *
     * @return An array of JWK objects
     */
    public getAllCertificatesAsJWKS(): JWK[] {
        const keySet: JWK[] = []
        this.keys.forEach((key) => {
            keySet.push(key.pubkeyJwk)
        })
        return keySet
    }

    protected async keystoreReaderTask(): Promise<void> {
        try {
            const newKeys = await this.keystoreReader.readKeys(this.keys)
            this.debug('Keystore reloaded, keys: ', newKeys.keys())
            this.keys = newKeys
            this.currentSigningKeyId = this.selectCurrentSigningKeyId(this.keys)
            this.debug('Current signing key id: ' + this.currentSigningKeyId)
        } catch (err) {
            // FIXME: should signal this error somehow. an EventEmitter maybe?
            this.debug('Reading keystore failed', err)
        }
    }
}
