import {KeyAndCert} from './KeyAndCert'

export interface KeystoreReader {
    readKeys(keys: Map<string, KeyAndCert>): Map<string, KeyAndCert> | Promise<Map<string, KeyAndCert>>
}
