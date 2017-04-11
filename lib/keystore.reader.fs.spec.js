const path = require('path')

const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
const expect = chai.expect

const debugName = 'keystore'

describe('keystoreReaderFs', function () {
  const keys = new Map()
  it('Should read all RSA keys in a directory', function (done) {
    const baseDir = path.join(__dirname, '/../test/keys_ca/rsa')
    const keystoreReaderFs = require('./keystore.reader.fs')(debugName, baseDir)
    expect(
      keystoreReaderFs(keys).then(newKeys => {
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
    ).to.be.fulfilled.notify(done)
  })
  it('Should read all ECDSA keys in a directory', function (done) {
    const baseDir = path.join(__dirname, '/../test/keys_ca/ecdsa')
    const keystoreReaderFs = require('./keystore.reader.fs')(debugName, baseDir)
    expect(
      keystoreReaderFs(keys).then(newKeys => {
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
    ).to.be.fulfilled.notify(done)
  })
  it('Should fail if a wrong directory is passed', function () {
    const fakeBaseDir = path.join(__dirname, '/../test/keys_ca/_fake_')
    expect(() => require('./keystore.reader.fs')('keystore', fakeBaseDir)).to.throw(Error, /ENOENT/)
  })
})
