export interface JWK {
    /**
     * Key id
     */
    kid: string

    /**
     * X.509 certificate chain
     */
    x5c: string

    kty: string

    n: string

    e: string

    alg: string

    use: string

    crv: string
}
