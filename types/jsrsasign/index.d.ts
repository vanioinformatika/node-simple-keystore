declare module 'jsrsasign' {
    class KEYUTIL {
        static getKey(param: string, passcode?: string, hextype?: string): any

        static getJWKFromKey(keyObj: any): any
    }

    class X509 {
        /**
         * Get format version (X.509v1 or v3 certificate).
         *
         * @return 1 for X509v1, 3 for X509v3, otherwise 0
         */
        getVersion(): string

        /**
         * Get hexadecimal string of serialNumber field of certificate.
         *
         * @return hexadecimal string of certificate serial number
         */
        getSerialNumberHex(): string

        /**
         * Get signature algorithm name in basic field
         *
         * @return signature algorithm name (ex. SHA1withRSA, SHA256withECDSA)
         */
        getSignatureAlgorithmField(): string

        /**
         * Get hexadecimal string of issuer field TLV of certificate.
         *
         * @return hexadecial string of issuer DN ASN.1
         */
        getIssuerHex(): string

        /**
         * Get string of issuer field of certificate.
         *
         * @return issuer DN string
         */
        getIssuerString(): string

        /**
         * Get hexadecimal string of subject field of certificate.
         *
         * @return hexadecial string of subject DN ASN.1
         */
        getSubjectHex(): string

        /**
         * Get string of subject field of certificate.
         *
         * @return subject DN string
         */
        getSubjectString(): string

        /**
         * Get notBefore field string of certificate.
         *
         * @return not before time value (ex. "151231235959Z")
         */
        getNotBefore(): string

        /**
         * Get notAfter field string of certificate.
         *
         * @return not after time value (ex. "151231235959Z")
         */
        getNotAfter(): string

        /**
         * Get a hexadecimal string of subjectPublicKeyInfo field.
         *
         * @return ASN.1 SEQUENCE hexadecimal string of subjectPublicKeyInfo field
         */
        getPublicKeyHex(): string

        /**
         * Get a string index of subjectPublicKeyInfo field for hexadecimal string certificate.
         *
         * @return string index of subjectPublicKeyInfo field for hexadecimal string certificate.
         */
        getPublicKeyIdx(): number

        /**
         * Get a string index of contents of subjectPublicKeyInfo BITSTRING value from hexadecimal certificate.
         *
         * @return string index of key contents
         */
        getPublicKeyContentIdx(): number

        // /**
        //  * Get a RSAKey/ECDSA/DSA public key object of subjectPublicKeyInfo field.
        //  *
        //  * @return RSAKey/ECDSA/DSA public key object of subjectPublicKeyInfo field
        //  */
        // getPublicKey()

        /**
         * Get signature algorithm name from hexadecimal certificate data.
         *
         * @return signature algorithm name (ex. SHA1withRSA, SHA256withECDSA)
         */
        getSignatureAlgorithmName(): string

        /**
         * Get signature value in hexadecimal string.
         *
         * @return signature value hexadecimal string without BitString unused bits
         */
        getSignatureValueHex(): string

        // /**
        //  * Verifies signature value by public key.
        //  *
        //  * @param pubKey public key object
        //  *
        //  * @return true if signature value is valid otherwise false
        //  */
        // verifySignature(pubKey): boolean

        /**
         * Set array of X.509v3 extesion information such as extension OID, criticality and value index.
         */
        parseExt(): void

        /**
         * @param oidOrName X.509 extension oid or name (ex. keyUsage or 2.5.29.19)
         *
         * @return X.509 extension information such as extension OID or value index
         */
        getExtInfo(oidOrName: string): { oid: string, critical: boolean, vidx: number }

        /**
         * Get BasicConstraints extension value as object in the certificate.
         *
         * @return associative array which may have "cA" and "pathLen" parameters
         */
        getExtBasicConstraints(): { cA: boolean, pathLen: number }

        /**
         * Get KeyUsage extension value as binary string in the certificate.
         *
         * @return binary string of key usage bits (ex. '101')
         */
        getExtKeyUsageBin(): string

        /**
         * Get KeyUsage extension value as names in the certificate.
         *
         * @return comma separated string of key usage
         */
        getExtKeyUsageString(): string

        /**
         * Get subjectKeyIdentifier value as hexadecimal string in the certificate.
         *
         * @return hexadecimal string of subject key identifier or null
         */
        getExtSubjectKeyIdentifier(): string | null

        /**
         * Get authorityKeyIdentifier value as JSON object in the certificate.
         *
         * @return JSON object of authority key identifier or null
         */
        getExtAuthorityKeyIdentifier(): { kid: string } | null

        /**
         * Get extKeyUsage value as array of name string in the certificate.
         *
         * @return array of extended key usage ID name or oid
         */
        getExtExtKeyUsageName(): string[]

        /**
         * Get subjectAltName value as array of string in the certificate.
         *
         * @deprecated
         *
         * @return array of alt names
         */
        getExtSubjectAltName(): string[]

        /**
         * Get subjectAltName value as array of string in the certificate.
         *
         * @return array of alt name array
         */
        getExtSubjectAltName2(): Array<[string, string]>

        /**
         * Get array of string for fullName URIs in cRLDistributionPoints(CDP) in the certificate.
         *
         * @return array of fullName URIs of CDP of the certificate
         */
        getExtCRLDistributionPointsURI(): string[]

        /**
         * Get AuthorityInfoAccess extension value in the certificate as associative array.
         *
         * @return associative array of AIA extension properties
         */
        getExtAIAInfo(): { ocsp: string[], caissuer: string[] }

        /**
         * Get CertificatePolicies extension value in the certificate as array.
         *
         * @return array of PolicyInformation JSON object
         */
        getExtCertificatePolicies(): Array<{ id: number, cps: string, unotice: string }>

        /**
         * Read PEM formatted X.509 certificate from string.
         *
         * @param sCertPEM string for PEM formatted X.509 certificate
         */
        readCertPEM(sCertPEM: string): void

        /**
         * Read a hexadecimal string of X.509 certificate
         *
         * @param sCertHex hexadecimal string of X.509 certificate
         */
        readCertHex(sCertHex: string): void

        /**
         * Get certificate information as string.
         *
         * @return certificate information string
         */
        getInfo(): string

        /**
         * Get distinguished name string in OpenSSL online format from hexadecimal string of ASN.1 DER X.500 name.
         *
         * @param hex hexadecimal string of ASN.1 DER distinguished name
         * @param idx index of hexadecimal string (DEFAULT=0)
         *
         * @return OpenSSL online format distinguished name.
         */
        static hex2dn(hex: string, idx?: number): string[]

        /**
         * Get relative distinguished name string in OpenSSL online format from hexadecimal string of ASN.1 DER RDN.
         *
         * @param hex hexadecimal string of ASN.1 DER concludes relative distinguished name
         * @param idx index of hexadecimal string (DEFAULT=0)
         *
         * @return OpenSSL online format relative distinguished name
         */
        static hex2rdn(hex: string, idx?: number): string

        /**
         * Get string from hexadecimal string of ASN.1 DER AttributeTypeAndValue
         *
         * @param hex hexadecimal string of ASN.1 DER concludes AttributeTypeAndValue
         * @param idx  index of hexadecimal string (DEFAULT=0)
         *
         * @return string representation of AttributeTypeAndValue (ex. C=US)
         */
        static hex2attrTypeValue(hex: string, idx?: number): string

        /**
         * Get RSA/DSA/ECDSA public key object from X.509 certificate hexadecimal string.
         *
         * @param h hexadecimal string of X.509 certificate for RSA/ECDSA/DSA public key
         *
         * @return returns RSAKey/KJUR.crypto.{ECDSA,DSA} object of public key
         */
        static getPublicKeyFromCertHex(h: string): any

        /**
         * Get RSA/DSA/ECDSA public key object from PEM certificate string.
         *
         * @param sCertPEM PEM formatted RSA/ECDSA/DSA X.509 certificate
         *
         * @return returns RSAKey/KJUR.crypto.{ECDSA,DSA} object of public key
         */
        static getPublicKeyFromCertPEM(sCertPEM: string): any

        /**
         * Get public key information from PEM certificate.
         *
         * @param sCertPEM string of PEM formatted certificate
         *
         * @return hash of information for public key
         */
        static getPublicKeyInfoPropOfCertPEM(sCertPEM: string): any
    }

    function hextob64(s: string): string

    function pemtohex(s: string, sHead?: string): string
}
