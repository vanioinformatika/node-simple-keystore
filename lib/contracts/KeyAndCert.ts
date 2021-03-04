/**
 * Holds a cached private key and certificate data
 */
import {JWK} from "./JWK"

export interface KeyAndCert {
    /**
     * Timestamp of loading
     */
    timestamp: number
    /**
     * Private key data in PEM format
     */
    privKey: string
    /**
     * Certificate data in PEM format
     */
    cert: string
    /**
     * JWT key algorithm (RS256, ES256, etc.)
     */
    keyAlg: string
    pubkeyJwk: JWK
}
