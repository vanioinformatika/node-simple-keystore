# Simple filesystem based keystore for Node.js

Simple filesystem keystore implementation

# Usage

```js
// initializing keystore
const debugNamePrefix = 'myproject' // name prefix used for the debug module
const baseDir = <directory containing key files>
const refreshIntervalMillis = 30 * 1000 // 30 secs
const signingKeyPassphrases = { // an object containing passphrases for private keys
  'key_id_1': 'passphrase1',
  'key_id_2': 'passphrase2'
}
const keystore = require('@vanioinformatika/simple-keystore') (
  debugNamePrefix, baseDir, refreshIntervalMillis, signingKeyPassphrases
)

...

// publishing public keys with express.js
router.route('/certs').get((req, res) => {
  const certificateList = keystore.fny.getAllCertificatesAsJWKS()
  res.status(HttpStatus.OK).json({keys: certificateList})
})
```
