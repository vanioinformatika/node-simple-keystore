export interface PrivateKey {
    /**
     * JWT key algorithm (RS256, ES256, etc.)
     */
    alg: string
    /**
     * Certificate data in PEM format
     */
    key: string
    /**
     * Passphrase for the private key (if any)
     */
    passphrase?: string
}
