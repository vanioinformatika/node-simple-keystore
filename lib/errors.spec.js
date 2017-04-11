const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
const dirtyChai = require('dirty-chai')
chai.use(dirtyChai)
const expect = chai.expect
const { KeystoreError, PrivateKeyNotFoundError, CertificateNotFoundError } = require('./errors')

const message = 'Sample message'
const keyId = 'keyid_1'

function throwKeystoreError () {
  throw new KeystoreError(message)
}

function throwPrivateKeyNotFoundError () {
  throw new PrivateKeyNotFoundError(keyId)
}

function throwCertificateNotFoundError () {
  throw new CertificateNotFoundError(keyId)
}

describe('errors', function () {
  describe('KeystoreError', function () {
    it('a new instance should have the appropriate properties', function () {
      try {
        throwKeystoreError()
      } catch (err) {
        expect(err.name).to.equal('KeystoreError')
        expect(err instanceof KeystoreError).to.be.true()
        expect(err instanceof Error).to.be.true()
        expect(require('util').isError(err)).to.be.true()
        expect(err.stack).to.exist()
        expect(err.toString()).to.equal(`KeystoreError: ${message}`)
        expect(err.stack.split('\n')[0]).to.equal(`KeystoreError: ${message}`)
        expect(err.stack.split('\n')[1].indexOf('throwKeystoreError')).to.equal(7)
      }
    })
  })

  describe('PrivateKeyNotFoundError', function () {
    it('a new instance should have the appropriate properties', function () {
      try {
        throwPrivateKeyNotFoundError()
      } catch (err) {
        expect(err.name).to.equal('PrivateKeyNotFoundError')
        expect(err instanceof PrivateKeyNotFoundError).to.be.true()
        expect(err instanceof KeystoreError).to.be.true()
        expect(err instanceof Error).to.be.true()
        expect(require('util').isError(err)).to.be.true()
        expect(err.stack).to.exist()
        expect(err.toString()).to.equal(`PrivateKeyNotFoundError: private key not found, key id: ${keyId}`)
        expect(err.keyId).to.equal(keyId)
        expect(err.message).to.equal(`private key not found, key id: ${keyId}`)
        expect(err.stack.split('\n')[0]).to.equal(`PrivateKeyNotFoundError: private key not found, key id: ${keyId}`)
        expect(err.stack.split('\n')[1].indexOf('throwPrivateKeyNotFoundError')).to.equal(7)
      }
    })
  })

  describe('CertificateNotFoundError', function () {
    it('a new instance should have the appropriate properties', function () {
      try {
        throwCertificateNotFoundError()
      } catch (err) {
        expect(err.name).to.equal('CertificateNotFoundError')
        expect(err instanceof CertificateNotFoundError).to.be.true()
        expect(err instanceof KeystoreError).to.be.true()
        expect(err instanceof Error).to.be.true()
        expect(require('util').isError(err)).to.be.true()
        expect(err.stack).to.exist()
        expect(err.toString()).to.equal(`CertificateNotFoundError: certificate not found, key id: ${keyId}`)
        expect(err.keyId).to.equal(keyId)
        expect(err.message).to.equal(`certificate not found, key id: ${keyId}`)
        expect(err.stack.split('\n')[0]).to.equal(`CertificateNotFoundError: certificate not found, key id: ${keyId}`)
        expect(err.stack.split('\n')[1].indexOf('throwCertificateNotFoundError')).to.equal(7)
      }
    })
  })
})
