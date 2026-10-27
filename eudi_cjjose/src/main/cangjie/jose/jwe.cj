/*
 * jwe.cj — RFC 7516 JWE compact serialization (5-segment).
 * Mirrors JOSESwift JWE.swift: holds header / encryptedKey / iv / ciphertext / authTag,
 * serializes to compact string, parses from compact string.
 *
 * Compact form: BASE64URL(header) "." BASE64URL(encKey) "." BASE64URL(iv) "."
 *               BASE64URL(ciphertext) "." BASE64URL(tag)
 *
 * For ECDH-ES: encryptedKey is always empty (direct CEK agreement, no key wrap).
 */
package ohos_app_cangjie_eudi_cjjose.jose

import eudi_lib_core_crypto.Base64Url

public class Jwe {
    public let header: JweHeader
    public let encryptedKey: Array<UInt8>
    public let initializationVector: Array<UInt8>
    public let ciphertext: Array<UInt8>
    public let authenticationTag: Array<UInt8>

    public init(
        header: JweHeader,
        encryptedKey: Array<UInt8>,
        initializationVector: Array<UInt8>,
        ciphertext: Array<UInt8>,
        authenticationTag: Array<UInt8>
    ) {
        this.header = header
        this.encryptedKey = encryptedKey
        this.initializationVector = initializationVector
        this.ciphertext = ciphertext
        this.authenticationTag = authenticationTag
    }

    /*
     * Serialize to compact JWE string.
     * Mirrors JOSESwift compactSerializedString.
     */
    public func compactSerialized(): String {
        let h = Base64Url.encode(this.header.toJsonBytes())
        let ek = Base64Url.encode(this.encryptedKey)
        let iv = Base64Url.encode(this.initializationVector)
        let ct = Base64Url.encode(this.ciphertext)
        let tag = Base64Url.encode(this.authenticationTag)
        return h + "." + ek + "." + iv + "." + ct + "." + tag
    }

    /*
     * Parse a compact-serialized JWE string into a Jwe object.
     * Throws JoseException if not exactly 5 segments or base64url decoding fails.
     */
    public static func fromCompact(compact: String): Jwe {
        let bytes = compact.toArray()
        // First pass: count ALL dots to detect wrong segment count (including >5 segments).
        var totalDots: Int64 = 0
        for (b in bytes) {
            if (b == b'.') { totalDots += 1 }
        }
        if (totalDots != 4) {
            throw JoseException("JWE.fromCompact: expected 5 segments, found ${totalDots + 1}")
        }
        // Second pass: record the positions of the 4 dots.
        let dots = Array<Int64>(4, repeat: -1)
        var dotCount: Int64 = 0
        var i: Int64 = 0
        while (i < bytes.size) {
            if (bytes[i] == b'.') {
                dots[dotCount] = i
                dotCount += 1
            }
            i += 1
        }
        let seg0 = sliceString(bytes, 0, dots[0])
        let seg1 = sliceString(bytes, dots[0] + 1, dots[1])
        let seg2 = sliceString(bytes, dots[1] + 1, dots[2])
        let seg3 = sliceString(bytes, dots[2] + 1, dots[3])
        let seg4 = sliceString(bytes, dots[3] + 1, bytes.size)

        let headerBytes = Base64Url.decode(seg0)
        let encKey = if (seg1.isEmpty()) {
            Array<UInt8>()
        } else {
            Base64Url.decode(seg1)
        }
        let iv = Base64Url.decode(seg2)
        let ct = Base64Url.decode(seg3)
        let tag = Base64Url.decode(seg4)
        let header = JweHeader.fromJsonBytes(headerBytes)
        return Jwe(header, encKey, iv, ct, tag)
    }

    private static func sliceString(src: Array<UInt8>, from: Int64, to: Int64): String {
        if (from >= to) {
            return ""
        }
        let slice = Array<UInt8>(to - from, repeat: 0)
        for (k in 0..(to - from)) {
            slice[k] = src[from + k]
        }
        return String.fromUtf8(slice)
    }
}
