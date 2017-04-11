openssl ecparam -out rootCA.privkey.pem -name prime256v1 -genkey
openssl req -x509 -new -nodes -key rootCA.privkey.pem -sha256 -days 1024 -out rootCA.cert.pem -subj "/C=HU/ST=Budapest/L=/O=TESTORG/OU=/CN=Root CA"

openssl ecparam -out 1.privkey.pem -name prime256v1 -genkey
openssl req -new -key 1.privkey.pem -out 1.csr -subj "/C=HU/ST=Budapest/L=/O=TESTORG/OU=ORGUNIT/CN=Token signer"
openssl x509 -req -in 1.csr -extfile v3.ext -CA rootCA.cert.pem -CAkey rootCA.privkey.pem -CAcreateserial -out 1.cert.pem -days 5000 -sha256

openssl ecparam -out 2.privkey.pem -name prime256v1 -genkey
openssl req -new -key 2.privkey.pem -out 2.csr -subj "/C=HU/ST=Budapest/L=/O=TESTORG/OU=ORGUNIT/CN=Token signer"
openssl x509 -req -in 2.csr -extfile v3.ext -CA rootCA.cert.pem -CAkey rootCA.privkey.pem -CAcreateserial -out 2.cert.pem -days 5000 -sha256

openssl ecparam -out 3.privkey.pem -name prime256v1 -genkey
openssl req -new -key 3.privkey.pem -out 3.csr -subj "/C=HU/ST=Budapest/L=/O=TESTORG/OU=ORGUNIT/CN=Token signer"
openssl x509 -req -in 3.csr -extfile v3.ext -CA rootCA.cert.pem -CAkey rootCA.privkey.pem -CAcreateserial -out 3.cert.pem -days 5000 -sha256

