declare namespace SimpleKeystore {
    class KeystoreError extends Error {
        constructor(message: string);
    }

    class PrivateKeyNotFoundError extends KeystoreError {
        constructor(keyId: string);
    }

    class CertificateNotFoundError extends KeystoreError {
        constructor(keyId: string);
    }

    interface PrivateKey {
        alg: string;
        key: string;
        passphrase: string;
    }

    interface Certificate {
        alg: string;
        cert: string;
    }

    interface JWK {
        // Key id
        kid: string;

        // X.509 certificate chain
        x5c: string;
    }

    interface Keystore {
        KeystoreError: new (message: string) => KeystoreError;

        PrivateKeyNotFoundError: new (keyId: string) => PrivateKeyNotFoundError;

        CertificateNotFoundError: new (keyId: string) => CertificateNotFoundError;

        getCurrentSigningKeyId(): void;

        getPrivateKey(id: string): Promise<PrivateKey>;

        getCertificate(id: string): Promise<Certificate>;

        getAllCertificatesAsJWKS(): JWK[]
    }

    type KeyPassphrasse = string

    type KeyPassphrasseCollection = {
        [key: string]: KeyPassphrasse
    }
}

declare function SimpleKeystore(debugNamePrefix: string, baseDir: string, refreshIntervalMillis: number, signingKeyPassphrases: SimpleKeystore.KeyPassphrasseCollection): SimpleKeystore.Keystore;

export = SimpleKeystore;
