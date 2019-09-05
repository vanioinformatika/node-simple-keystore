import * as chai from 'chai'
import {expect} from 'chai'
import {Keystore} from './keystore'
import {CertificateNotFoundError, PrivateKeyNotFoundError} from './errors'
import {KeyAndCert, KeystoreReader} from './contracts'
import chaiAsPromised = require('chai-as-promised')
import dirtyChai = require('dirty-chai')

chai.use(chaiAsPromised)
chai.use(dirtyChai)

describe('keystore', () => {
    //
    const signingKeyPassphrases: { [key: string]: string } = {
        signingKeyId: 'test',
    }

    const signingKeyId = '2'

    let newKeys: Map<string, KeyAndCert>
    const keystoreReader: KeystoreReader = {
        readKeys: (keys: Map<string, KeyAndCert>) => {
            newKeys = new Map(keys)
            newKeys.set('1', {
                timestamp: Math.floor(Date.now() / 1000) - 10000,
                privKey: 'privkey1',
                cert: 'cert1',
                keyAlg: 'RS256',
                pubkeyJwk: {kid: '1', x5c: ''} as any,
            })
            newKeys.set('2', {
                timestamp: Math.floor(Date.now() / 1000) - 20000,
                privKey: 'privkey2',
                cert: 'cert2',
                keyAlg: 'RS256',
                pubkeyJwk: {kid: '2', x5c: ''} as any,
            })
            return newKeys
        },
    }

    let keystore: Keystore

    //
    before(async function () {
        this.timeout(3000)
        keystore = new Keystore('keystore', signingKeyPassphrases, keystoreReader, 1000)
        await keystore.start()
    })

    after(function () {
        keystore.stop()
    })

    describe('getCurrentSigningKeyId', () => {
        it('should return the current keyid for signing', () => {
            expect(keystore.getCurrentSigningKeyId()).to.be.equal(signingKeyId)
        })
    })

    describe('getPrivateKey', () => {
        it('should return the private key if a valid private key ID is passed', async () => {
            await keystore.getPrivateKey(signingKeyId)
        })
        it('should return the private key if a valid private key ID is passed and it has been already cached',
            async () => {
                await keystore.getPrivateKey(signingKeyId)
            })
        it('should be rejected with PrivateKeyNotFoundError if a nonexistent private key ID is passed', async () => {
            await expect(keystore.getPrivateKey('fake_privkey_id')).be.rejectedWith(PrivateKeyNotFoundError)
        })
    })

    describe('getCertificate', () => {
        it('should return the certificate if a valid certificate ID is passed', async () => {
            await keystore.getCertificate(signingKeyId)
        })
        it('should return the certificate if a valid certificate ID is passed and it has been already cached',
            async () => {
                await keystore.getCertificate(signingKeyId)
            })
        it('should be rejected with CertificateNotFoundError if a nonexistent certificate ID is passed', async () => {
            expect(keystore.getCertificate('fake_privkey_id')).be.rejectedWith(CertificateNotFoundError)
        })
    })

    describe('getAllCertificatesAsJWKS', () => {
        it('should return all certificates is JWK set format', () => {
            const certList = keystore.getAllCertificatesAsJWKS()
            expect(certList).to.exist()
            expect(certList.length).to.equal(2)
            const key1 = newKeys.get('1')
            expect(certList[0]).to.equal(key1 && key1.pubkeyJwk)
            const key2 = newKeys.get('2')
            expect(certList[1]).to.equal(key2 && key2.pubkeyJwk)
        })
    })

    describe('getPrivateKeyPassphrase', () => {
        it('should return the appropriate private key passphrase if a valid private key ID is passed', () => {
            expect(keystore.getPrivateKeyPassphrase(signingKeyId)).be.equal(signingKeyPassphrases[signingKeyId])
        })
        it('should be rejected with CertificateNotFoundError if a nonexistent certificate ID is passed', () => {
            expect(keystore.getPrivateKeyPassphrase('fake_privkey_id')).be.undefined()
        })
    })

    describe('selectCurrentSigningKeyId', () => {
        const now = Math.floor(Date.now() / 1000)
        const maxTimestamp = now - (20 * 60) // the youngest key to use
        it('should return the only key if there is only one key', () => {
            const keys = new Map()
            keys.set('1', {timestamp: 1000, dummy: 1})
            expect(keystore.selectCurrentSigningKeyId(keys)).be.equal('1')
        })
        it('should return last key id if all keys are too young', () => {
            const keys = new Map()
            keys.set('3', {timestamp: maxTimestamp + 30, dummy: 3})
            keys.set('1', {timestamp: maxTimestamp + 10, dummy: 1})
            keys.set('4', {timestamp: maxTimestamp + 40, dummy: 4})
            keys.set('2', {timestamp: maxTimestamp + 20, dummy: 2})
            expect(keystore.selectCurrentSigningKeyId(keys)).be.equal('4')
        })
        it('should return the one allowed key id there is only one key that is appropriate', () => {
            const keys = new Map()
            keys.set('3', {timestamp: maxTimestamp + 30, dummy: 3})
            keys.set('1', {timestamp: maxTimestamp + 10, dummy: 1})
            keys.set('4', {timestamp: maxTimestamp + 40, dummy: 4})
            keys.set('5', {timestamp: maxTimestamp - 10, dummy: 4})
            keys.set('2', {timestamp: maxTimestamp + 20, dummy: 2})
            expect(keystore.selectCurrentSigningKeyId(keys)).be.equal('5')
        })
        it('should return the youngest allowed key id there are more keys that are appropriate', () => {
            const keys = new Map()
            keys.set('3', {timestamp: maxTimestamp + 30, dummy: 3})
            keys.set('1', {timestamp: maxTimestamp + 10, dummy: 1})
            keys.set('6', {timestamp: maxTimestamp - 5, dummy: 6})
            keys.set('4', {timestamp: maxTimestamp + 40, dummy: 4})
            keys.set('5', {timestamp: maxTimestamp - 40, dummy: 5})
            keys.set('2', {timestamp: maxTimestamp + 20, dummy: 2})
            expect(keystore.selectCurrentSigningKeyId(keys)).be.equal('6')
        })
        it('should return the youngest allowed key id there are more keys that are appropriate', () => {
            const keys = new Map()
            keys.set('3', {timestamp: maxTimestamp + 30, dummy: 3})
            keys.set('1', {timestamp: maxTimestamp + 10, dummy: 1})
            keys.set('6', {timestamp: maxTimestamp - 5, dummy: 6})
            keys.set('4', {timestamp: maxTimestamp - 5, dummy: 4})
            keys.set('5', {timestamp: maxTimestamp - 5, dummy: 5})
            keys.set('2', {timestamp: maxTimestamp + 20, dummy: 2})
            expect(keystore.selectCurrentSigningKeyId(keys)).be.equal('6')
        })
        it('should return the largest key id if there are multiple keys but none of them are appropriate', () => {
            const keys = new Map()
            keys.set('3', {timestamp: maxTimestamp + 30, dummy: 3})
            keys.set('1', {timestamp: maxTimestamp + 30, dummy: 1})
            keys.set('6', {timestamp: maxTimestamp + 30, dummy: 6})
            keys.set('4', {timestamp: maxTimestamp + 30, dummy: 4})
            keys.set('5', {timestamp: maxTimestamp + 30, dummy: 5})
            expect(keystore.selectCurrentSigningKeyId(keys)).be.equal('6')
        })
        it('should return undefined key id there no keys', () => {
            const keys = new Map()
            expect(keystore.selectCurrentSigningKeyId(keys)).to.not.exist()
        })
    })
})
