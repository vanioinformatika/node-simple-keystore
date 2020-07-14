[![Build Status](https://travis-ci.org/vanioinformatika/node-simple-keystore.svg?branch=master)](https://travis-ci.org/vanioinformatika/node-simple-keystore)

# Simple filesystem based keystore for Node.js

Simple filesystem keystore implementation

# Usage

```javascript
const {Keystore, KeystoreReaderFs} = require('@vanioinformatika/simple-keystore')

// initializing keystore
const baseDir = '<directory containing key files>'
const refreshIntervalMillis = 30 * 1000 // 30 secs
const signingKeyPassphrases = { // an object containing passphrases for private keys
  'key_id_1': 'passphrase1',
  'key_id_2': 'passphrase2'
}
const keystoreReader = new KeystoreReaderFs(baseDir)
const keystore = new Keystore(signingKeyPassphrases, keystoreReader)

// start reading keystore periodically 
keystore.start(refreshIntervalMillis)

...

// publishing public keys with express.js
router.route('/certs').get((req, res) => {
  const certificateList = keystore.fny.getAllCertificatesAsJWKS()
  res.status(HttpStatus.OK).json({keys: certificateList})
})
```

The keys directory has to contain the following files:
```
rootCA.cert.pem
{keyId}.privkey.pem
{keyId}.cert.pem
```
The `rootCA.cert.pem` contains the certificate of the CA that issued the certificates.
All other files that end with `.privkey.pem` and `.cert.pem` are the private keys and certificates for a given key id.

