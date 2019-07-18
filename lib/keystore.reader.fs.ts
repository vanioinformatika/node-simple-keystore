import Debug, {IDebugger} from 'debug'
import {KeyAndCert} from './keystore'
import * as fs from 'fs'
import * as path from 'path'
import * as pem from 'pem'
import {hextob64, KEYUTIL, pemtohex, X509} from 'jsrsasign'

export class KeystoreReaderFs {
    protected debug: IDebugger

    protected baseDir: string

    protected caCert: string

    protected algMap: { [key: string]: string }

    /**
     * Creates a keystore reader function
     *
     * @param {string} debugNamePrefix Name prefix used for the debug module
     * @param {string} baseDir The keystore base directory
     */
    public constructor(debugNamePrefix: string, baseDir: string) {
        this.debug = Debug(debugNamePrefix + ':keystore.reader')
        this.baseDir = baseDir

        const rootCACert = fs.readFileSync(path.join(baseDir, `rootCA.cert.pem`))
        this.debug('Root CA cert loaded: ' + rootCACert)
        this.caCert = rootCACert.toString()
        this.debug('CA store created')

        this.algMap = {
            'SHA256withECDSA': 'ES256',
            'SHA256withRSA': 'RS256',
        }
    }

    /**
     * Handles the specified key id, i.e. returns a promise that loads the appropriate
     * private key and certificate from files
     *
     * @param {Map.<KeyAndCert>} newKeys A Map of key and cert data objects
     * @param {string} keyId Key ID
     * @return {Promise} A Promise that is resolved when the private and key a certificate for
     *                   the given keyId is loaded into the newKeys Object
     */
    protected async handleKeyId(newKeys: Map<string, KeyAndCert>, keyId: string): Promise<void> {
        this.debug(`keyId: ${keyId}`)
        if (!newKeys.has(keyId)) {
            this.debug(`${keyId} not found in cache`)
            await this.readKeyAndCert(newKeys, keyId)
        } else {
            this.debug(`${keyId} already cached`)
        }
    }

    /**
     * Creates s combined set of promises that are used for verifying and reading certs and private keys
     *
     * @param  {type} newKeys {Map.<KeyAndCert>} newKeys A Map of key and cert data objects
     * @param  {type} keyId Key ID
     * @return {Promise} A promise which is resolved when both the certificate and the
     *                   private key is loaded for the given key id
     */
    public async readKeyAndCert(newKeys: Map<string, KeyAndCert>, keyId: string) {
        const privKeyPem = fs.readFileSync(path.join(this.baseDir, `${keyId}.privkey.pem`))
        const certPem = fs.readFileSync(path.join(this.baseDir, `${keyId}.cert.pem`))

        this.debug(`Key id ${keyId}, privkey and cert read`)
        const cert = new X509()
        cert.readCertPEM(certPem.toString())
        const verifiedCert = this.verifyCertAsync(keyId, certPem.toString())
        const certStr = verifiedCert.toString()
        const publicKey = KEYUTIL.getKey(certStr)
        const pubkeyJwk = KEYUTIL.getJWKFromKey(publicKey)
        pubkeyJwk.kid = keyId
        pubkeyJwk.alg = this.algMap[cert.getSignatureAlgorithmField()]
        pubkeyJwk.use = 'sig'
        const x5c = hextob64(pemtohex(certStr))
        pubkeyJwk.x5c = [x5c]
        this.debug(`Key id ${keyId}, key alg: ${cert.getSignatureAlgorithmField()}`)
        newKeys.set(keyId, {
            timestamp: Math.floor(Date.now() / 1000), // unix time
            cert: certStr,
            keyAlg: this.algMap[cert.getSignatureAlgorithmField()],
            privKey: privKeyPem.toString(),
            pubkeyJwk,
        })
    }

    /**
     * Verifies the given certificate if it is certified with the KKSZB CA
     *
     * @param {string} keyId Key id
     * @param {string} certPem The certificate in PEM format
     * @return {Promise} A promise which is resolved if the given certificate is trusted
     */
    public async verifyCertAsync(keyId: string, certPem: string): Promise<string> {
        await new Promise<boolean>(
            (resolve, reject) => pem.verifySigningChain(
                certPem,
                [this.caCert],
                (error, result) => error ? reject(error) : resolve(result),
            ),
        )

        this.debug(`Key id ${keyId}, signing certificate verified`)
        return certPem
    }

    /**
     * Reads all keys and certs from the keystore base directory
     *
     * @param {Object} keys A map containing the currently loaded keys
     * @return {Promise.<Map.<KeyAndCert>, Error>} Promise to an object containing the already existing and loaded keys
     */
    public async readKeys(keys: Map<string, KeyAndCert>) {
        const newKeys = new Map(keys)
        const files = fs.readdirSync(this.baseDir)
        await Promise.all(files.map(async (file) => {
            const match = file.match(/([0-9]+)\.privkey.pem/)
            if (match) {
                await this.handleKeyId(newKeys, match[1])
            }
        }))
        this.debug('All keys loaded')
        return newKeys
    }
}
