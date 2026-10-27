/*
 * algorithms.cj — JOSE algorithm identifiers.
 * Mirrors JOSESwift Algorithms.swift (subset: only the algs used by EUDI/openid4vp).
 * KeyManagementAlgorithm: ECDH_ES only.
 * ContentEncryptionAlgorithm: A256GCM only.
 * SignatureAlgorithm: ES256 only.
 */
package ohos_app_cangjie_eudi_cjjose.jose

/* RFC 7518 §4 key-management algorithm identifiers. */
public enum KeyManagementAlgorithm {
    /* ECDH-ES: Ephemeral Static ECDH + Concat KDF, direct CEK (no wrap). */
    | EcdhEs

    public func rawValue(): String {
        match (this) {
            case EcdhEs => "ECDH-ES"
        }
    }

    /* Key bit size of the derived CEK for the given content-encryption algorithm. */
    public func cekBitSize(enc: ContentEncryptionAlgorithm): Int64 {
        match (this) {
            case EcdhEs => enc.keyBitSize()
        }
    }
}

/* RFC 7518 §5 content-encryption algorithm identifiers. */
public enum ContentEncryptionAlgorithm {
    /* AES-GCM with 256-bit key. */
    | A256Gcm

    public func rawValue(): String {
        match (this) {
            case A256Gcm => "A256GCM"
        }
    }

    /* Key bit size (for Concat KDF derivation). */
    public func keyBitSize(): Int64 {
        match (this) {
            case A256Gcm => 256
        }
    }

    /* Key byte size (for AesGcm). */
    public func keyByteSize(): Int64 {
        match (this) {
            case A256Gcm => 32
        }
    }
}

/* RFC 7518 §3 digital-signature algorithm identifiers (subset). */
public enum SignatureAlgorithm {
    /* ECDSA P-256 with SHA-256. */
    | Es256

    public func rawValue(): String {
        match (this) {
            case Es256 => "ES256"
        }
    }
}
