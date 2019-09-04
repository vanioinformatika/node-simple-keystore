import * as chai from 'chai'
import {expect} from 'chai'
import * as path from 'path'
import {KeystoreReaderFs} from './reader'
import chaiAsPromised = require('chai-as-promised')
import dirtyChai = require('dirty-chai')

chai.use(chaiAsPromised)
chai.use(dirtyChai)

const debugName = 'keystore'

describe('keystoreReaderFs', () => {
    const keys = new Map()
    it('Should read all RSA keys in a directory', async () => {
        const baseDir = path.join(__dirname, '/../test/keys_ca/rsa')
        const keystoreReaderFs = new KeystoreReaderFs(debugName, baseDir)

        const newKeys = await keystoreReaderFs.readKeys(keys)
        newKeys.forEach(key => {
            expect(key).has.property('timestamp')
            expect(key).has.property('cert')
            expect(key).has.property('privKey')
            expect(key).has.property('pubkeyJwk')
            expect(key.pubkeyJwk).has.property('kid')
            expect(key.pubkeyJwk.kty).to.equal('RSA')
            expect(key.pubkeyJwk).has.property('n')
            expect(key.pubkeyJwk).has.property('e')
            expect(key.pubkeyJwk.alg).to.equal('RS256')
            expect(key.pubkeyJwk.use).to.equal('sig')
            expect(key.pubkeyJwk).has.property('x5c')
        })
        expect(newKeys.has('1')).to.be.true()
        expect(newKeys.has('2')).to.be.true()
        expect(newKeys.has('3')).to.be.true()
        expect(newKeys.size).to.equal(3)
    })
    it('Should read all ECDSA keys in a directory', async () => {
        const baseDir = path.join(__dirname, '/../test/keys_ca/ecdsa')
        const keystoreReaderFs = new KeystoreReaderFs(debugName, baseDir)
        const newKeys = await keystoreReaderFs.readKeys(keys)
        newKeys.forEach(key => {
            expect(key).has.property('timestamp')
            expect(key).has.property('cert')
            expect(key).has.property('privKey')
            expect(key).has.property('pubkeyJwk')
            expect(key.pubkeyJwk).has.property('kid')
            expect(key.pubkeyJwk.kty).to.equal('EC')
            expect(key.pubkeyJwk.crv).to.equal('P-256')
            expect(key.pubkeyJwk).has.property('x')
            expect(key.pubkeyJwk).has.property('y')
            expect(key.pubkeyJwk.alg).to.equal('ES256')
            expect(key.pubkeyJwk.use).to.equal('sig')
            expect(key.pubkeyJwk).has.property('x5c')
        })
        expect(newKeys.has('1')).to.be.true()
        expect(newKeys.has('2')).to.be.true()
        expect(newKeys.has('3')).to.be.true()
        expect(newKeys.size).to.equal(3)
    })
    it('Should fail if a wrong directory is passed', function () {
        const fakeBaseDir = path.join(__dirname, '/../test/keys_ca/_fake_')
        expect(() => new KeystoreReaderFs('keystore', fakeBaseDir)).to.throw(Error, /ENOENT/)
    })
})
