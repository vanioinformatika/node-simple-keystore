const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
const dirtyChai = require('dirty-chai')
chai.use(dirtyChai)
const expect = chai.expect

const { PrivateKeyNotFoundError, CertificateNotFoundError } = require('./errors')

describe('keystore', function () {
  //
  const signingKeyPassphrases = {
    signingKeyId: 'test'
  }

  const signingKeyId = '2'

  let newKeys
  const keystoreReader = (keys) => {
    newKeys = new Map(keys)
    newKeys.set('1', {
      timestamp: Math.floor(Date.now() / 1000) - 10000,
      privKey: 'privkey1',
      cert: 'cert1',
      jwkPubkey: {kid: '1', alg: 'RS256'}
    })
    newKeys.set('2', {
      timestamp: Math.floor(Date.now() / 1000) - 20000,
      privKey: 'privkey2',
      cert: 'cert2',
      jwkPubkey: {kid: '2', alg: 'RS256'}
    })
    return newKeys
  }

  let keystore

  //
  before(function (done) {
    this.timeout(3000)
    keystore = require('./keystore')(
      'keystore', signingKeyPassphrases, keystoreReader, 1000
    )
    setTimeout(done, 1100)
  })

  describe('getCurrentSigningKeyId', function () {
    it('should return the current keyid for signing', function () {
      expect(keystore.getCurrentSigningKeyId()).to.be.equal(signingKeyId)
    })
  })

  describe('getPrivateKey', function () {
    it('should return the private key if a valid private key ID is passed', function (done) {
      expect(keystore.getPrivateKey(signingKeyId)).be.eventually.fulfilled.notify(done)
    })
    it('should return the private key if a valid private key ID is passed and it has been already cached', function (done) {
      expect(keystore.getPrivateKey(signingKeyId)).be.eventually.fulfilled.notify(done)
    })
    it('should be rejected with PrivateKeyNotFoundError if a nonexistent private key ID is passed', function (done) {
      expect(keystore.getPrivateKey('fake_privkey_id')).be.rejectedWith(PrivateKeyNotFoundError).notify(done)
    })
  })

  describe('getCertificate', function () {
    it('should return the certificate if a valid certificate ID is passed', function (done) {
      expect(keystore.getCertificate(signingKeyId)).be.eventually.fulfilled.notify(done)
    })
    it('should return the certificate if a valid certificate ID is passed and it has been already cached', function (done) {
      expect(keystore.getCertificate(signingKeyId)).be.eventually.fulfilled.notify(done)
    })
    it('should be rejected with CertificateNotFoundError if a nonexistent certificate ID is passed', function (done) {
      expect(keystore.getCertificate('fake_privkey_id')).be.rejectedWith(CertificateNotFoundError).notify(done)
    })
  })

  describe('getAllCertificatesAsJWKS', function () {
    it('should return all certificates is JWK set format', function () {
      const certList = keystore.getAllCertificatesAsJWKS()
      expect(certList).to.exist()
      expect(certList.length).to.equal(2)
      expect(certList[0]).to.equal(newKeys.get('1').jwk)
      expect(certList[1]).to.equal(newKeys.get('2').jwk)
    })
  })

  describe('getPrivateKeyPassphrase', function () {
    it('should return the appropriate private key passphrase if a valid private key ID is passed', function () {
      expect(keystore.getPrivateKeyPassphrase(signingKeyId)).be.equal(signingKeyPassphrases[signingKeyId])
    })
    it('should be rejected with CertificateNotFoundError if a nonexistent certificate ID is passed', function () {
      expect(keystore.getPrivateKeyPassphrase('fake_privkey_id')).be.undefined()
    })
  })

  describe('selectCurrentSigningKeyId', function () {
    const now = Math.floor(Date.now() / 1000)
    const maxTimestamp = now - (20 * 60) // the youngest key to use
    it('should return the only key if there is only one key', function () {
      const keys = new Map()
      keys.set('1', {timestamp: 1000, dummy: 1})
      expect(keystore.selectCurrentSigningKeyId(keys)).be.equal('1')
    })
    it('should return last key id if all keys are too young', function () {
      const keys = new Map()
      keys.set('3', {timestamp: maxTimestamp + 30, dummy: 3})
      keys.set('1', {timestamp: maxTimestamp + 10, dummy: 1})
      keys.set('4', {timestamp: maxTimestamp + 40, dummy: 4})
      keys.set('2', {timestamp: maxTimestamp + 20, dummy: 2})
      expect(keystore.selectCurrentSigningKeyId(keys)).be.equal('4')
    })
    it('should return the one allowed key id there is only one key that is appropriate', function () {
      const keys = new Map()
      keys.set('3', {timestamp: maxTimestamp + 30, dummy: 3})
      keys.set('1', {timestamp: maxTimestamp + 10, dummy: 1})
      keys.set('4', {timestamp: maxTimestamp + 40, dummy: 4})
      keys.set('5', {timestamp: maxTimestamp - 10, dummy: 4})
      keys.set('2', {timestamp: maxTimestamp + 20, dummy: 2})
      expect(keystore.selectCurrentSigningKeyId(keys)).be.equal('5')
    })
    it('should return the youngest allowed key id there are more keys that are appropriate', function () {
      const keys = new Map()
      keys.set('3', {timestamp: maxTimestamp + 30, dummy: 3})
      keys.set('1', {timestamp: maxTimestamp + 10, dummy: 1})
      keys.set('6', {timestamp: maxTimestamp - 5, dummy: 6})
      keys.set('4', {timestamp: maxTimestamp + 40, dummy: 4})
      keys.set('5', {timestamp: maxTimestamp - 40, dummy: 5})
      keys.set('2', {timestamp: maxTimestamp + 20, dummy: 2})
      expect(keystore.selectCurrentSigningKeyId(keys)).be.equal('6')
    })
    it('should return the youngest allowed key id there are more keys that are appropriate', function () {
      const keys = new Map()
      keys.set('3', {timestamp: maxTimestamp + 30, dummy: 3})
      keys.set('1', {timestamp: maxTimestamp + 10, dummy: 1})
      keys.set('6', {timestamp: maxTimestamp - 5, dummy: 6})
      keys.set('4', {timestamp: maxTimestamp - 5, dummy: 4})
      keys.set('5', {timestamp: maxTimestamp - 5, dummy: 5})
      keys.set('2', {timestamp: maxTimestamp + 20, dummy: 2})
      expect(keystore.selectCurrentSigningKeyId(keys)).be.equal('6')
    })
    it('should return the largest key id if there are multiple keys but none of them are appropriate', function () {
      const keys = new Map()
      keys.set('3', {timestamp: maxTimestamp + 30, dummy: 3})
      keys.set('1', {timestamp: maxTimestamp + 30, dummy: 1})
      keys.set('6', {timestamp: maxTimestamp + 30, dummy: 6})
      keys.set('4', {timestamp: maxTimestamp + 30, dummy: 4})
      keys.set('5', {timestamp: maxTimestamp + 30, dummy: 5})
      expect(keystore.selectCurrentSigningKeyId(keys)).be.equal('6')
    })
    it('should return undefined key id there no keys', function () {
      const keys = new Map()
      expect(keystore.selectCurrentSigningKeyId(keys)).to.not.exist()
    })
  })
})
