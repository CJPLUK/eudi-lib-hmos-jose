/*
 * jwk.cj — RFC 7517/7518 EC JWK representation.
 * Mirrors JOSESwift ECKeys.swift (ECPublicKey / ECPrivateKey structs).
 * Stores coordinates as base64url strings (no padding), serializes to/from
 * a minimal JSON object used in JWE header "epk" and for ECDH-ES key exchange.
 *
 * HUKS key material conversion:
 *   HUKS exportPublicKey returns 65 bytes: 0x04 || X(32) || Y(32)  (uncompressed P-256).
 *   fromHuksUncompressed() extracts X/Y and base64url-encodes them.
 *   toHuksUncompressed() reconstructs 65-byte uncompressed point from X/Y.
 */
package ohos_app_cangjie_eudi_cjjose.jose

import eudi_lib_core_crypto.Base64Url
import eudi_lib_core_crypto.Digest
import std.math.numeric.BigInt

// X.509 SubjectPublicKeyInfo DER prefix for a P-256 uncompressed EC point
// (SEQUENCE / AlgorithmIdentifier id-ecPublicKey + prime256v1 / BIT STRING).
let p256SpkiPrefix: Array<UInt8> = [
    0x30u8, 0x59u8, 0x30u8, 0x13u8, 0x06u8, 0x07u8, 0x2Au8, 0x86u8,
    0x48u8, 0xCEu8, 0x3Du8, 0x02u8, 0x01u8, 0x06u8, 0x08u8, 0x2Au8,
    0x86u8, 0x48u8, 0xCEu8, 0x3Du8, 0x03u8, 0x01u8, 0x07u8, 0x03u8,
    0x42u8, 0x00u8
]


/*
 * P-256 (secp256r1 / prime256v1) domain parameters, NIST FIPS 186-4.
 * Curve equation: y^2 = x^3 + a*x + b (mod p), with a = p - 3.
 * Used to reject attacker-supplied points that are not on the curve
 * (invalid-curve attack defense before an EC point is handed to ECDH).
 */
class P256Params {
    // p = 2^256 - 2^224 + 2^192 + 2^96 - 1
    static let P: BigInt = BigInt.parse("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", radix: 16)
    // a = p - 3
    static let A: BigInt = BigInt.parse("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", radix: 16)
    static let B: BigInt = BigInt.parse("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", radix: 16)

    /*
     * Returns true iff (x, y) is a valid affine point on the P-256 curve:
     *   - 0 <= x < p and 0 <= y < p
     *   - (x, y) != (0, 0)  (point at infinity / identity is not a valid public key)
     *   - y^2 ≡ x^3 + a*x + b (mod p)
     * x and y are big-endian non-negative 32-byte coordinates.
     */
    static func isOnCurve(xBytes: Array<UInt8>, yBytes: Array<UInt8>): Bool {
        // true => non-negative magnitude (coordinates are unsigned big-endian).
        let x = BigInt(true, xBytes)
        let y = BigInt(true, yBytes)
        let zero = BigInt(0)
        if (x < zero || x >= P256Params.P) {
            return false
        }
        if (y < zero || y >= P256Params.P) {
            return false
        }
        if (x == zero && y == zero) {
            return false
        }
        let p = P256Params.P
        let lhs = nonNegMod(y * y, p)
        let rhs = nonNegMod(x * x * x + P256Params.A * x + P256Params.B, p)
        return lhs == rhs
    }

    // Modular reduction that always returns a value in [0, m).
    static func nonNegMod(v: BigInt, m: BigInt): BigInt {
        let r = v % m
        if (r < BigInt(0)) {
            return r + m
        }
        return r
    }
}

public enum EcCurve {
    | P256

    public func rawValue(): String {
        match (this) {
            case P256 => "P-256"
        }
    }

    public static func fromString(s: String): Option<EcCurve> {
        if (s == "P-256") {
            return Option<EcCurve>.Some(EcCurve.P256)
        }
        return Option<EcCurve>.None
    }
}

public class EcPublicKey {
    public let crv: EcCurve
    public let x: String
    public let y: String

    public init(crv: EcCurve, x: String, y: String) {
        this.crv = crv
        this.x = x
        this.y = y
    }

    /*
     * Build from HUKS uncompressed point: 0x04 || X(32) || Y(32) = 65 bytes.
     * Throws JoseException if length is wrong.
     */
    public static func fromHuksUncompressed(bytes: Array<UInt8>): EcPublicKey {
        // HUKS exportKeyItem returns an X.509 SubjectPublicKeyInfo DER (91 bytes
        // for P-256): strip the fixed 26-byte SPKI prefix down to 0x04||X||Y.
        var point = bytes
        if (bytes.size == 65 + p256SpkiPrefix.size) {
            var prefixOk = true
            for (i in 0..p256SpkiPrefix.size) {
                if (bytes[i] != p256SpkiPrefix[i]) { prefixOk = false; break }
            }
            if (prefixOk) {
                let stripped = Array<UInt8>(65, repeat: 0)
                for (i in 0..65) { stripped[i] = bytes[p256SpkiPrefix.size + i] }
                point = stripped
            }
        }
        if (point.size != 65 || point[0] != 0x04u8) {
            throw JoseException("EcPublicKey: expected 65-byte uncompressed point (0x04||X||Y), got ${point.size} bytes")
        }
        let xBytes = Array<UInt8>(32, repeat: 0)
        let yBytes = Array<UInt8>(32, repeat: 0)
        for (i in 0..32) {
            xBytes[i] = point[1 + i]
            yBytes[i] = point[33 + i]
        }
        if (!P256Params.isOnCurve(xBytes, yBytes)) {
            throw JoseException("EcPublicKey: point (x,y) is not on the P-256 curve (invalid-curve attack defense)")
        }
        return EcPublicKey(EcCurve.P256, Base64Url.encode(xBytes), Base64Url.encode(yBytes))
    }

    /*
     * Reconstruct HUKS 65-byte uncompressed point from base64url x/y.
     * Throws JoseException on decode failure.
     */
    public func toHuksUncompressed(): Array<UInt8> {
        let xBytes = Base64Url.decode(this.x)
        let yBytes = Base64Url.decode(this.y)
        if (xBytes.size != 32 || yBytes.size != 32) {
            throw JoseException("EcPublicKey: x/y components must be 32 bytes each")
        }
        // Reject points not on P-256 before they reach ECDH key agreement.
        // The epk in a JWE header is attacker-controlled on the decrypt side;
        // importing an off-curve / small-subgroup point enables invalid-curve
        // attacks that can leak the recipient's static private key.
        if (!P256Params.isOnCurve(xBytes, yBytes)) {
            throw JoseException("EcPublicKey: point (x,y) is not on the P-256 curve (invalid-curve attack defense)")
        }
        let out = Array<UInt8>(65, repeat: 0)
        out[0] = 0x04u8
        for (i in 0..32) {
            out[1 + i] = xBytes[i]
            out[33 + i] = yBytes[i]
        }
        return out
    }

    /*
     * X.509 SubjectPublicKeyInfo DER for this P-256 key — the format HUKS
     * exportKeyItem produces and the ECDH agree updateSession expects as the
     * peer key inData (a bare 65-byte point is rejected with
     * "Invalid parameters.").
     */
    public func toHuksSpki(): Array<UInt8> {
        let point = toHuksUncompressed()
        let out = Array<UInt8>(p256SpkiPrefix.size + point.size, repeat: 0)
        for (i in 0..p256SpkiPrefix.size) { out[i] = p256SpkiPrefix[i] }
        for (i in 0..point.size) { out[p256SpkiPrefix.size + i] = point[i] }
        return out
    }

    /*
     * Serialize to JSON object string for embedding in JWE header "epk".
     * Format: {"crv":"P-256","kty":"EC","x":"...","y":"..."}
     */
    public func toJson(): String {
        return "{\"crv\":\"" + this.crv.rawValue() + "\",\"kty\":\"EC\",\"x\":\"" + this.x + "\",\"y\":\"" + this.y + "\"}"
    }

    /*
     * RFC 7638 JWK Thumbprint for this EC public key.
     * Canonical JSON member order: crv, kty, x, y (lexicographic).
     * Returns the unpadded base64url-encoded SHA-256 digest.
     * Mirrors JOSESwift ECPublicKey thumbprint().
     */
    public func thumbprint(): String {
        let canonical = "{\"crv\":\"" + this.crv.rawValue() + "\",\"kty\":\"EC\",\"x\":\"" + this.x + "\",\"y\":\"" + this.y + "\"}"
        let hash = Digest.sha256(canonical.toArray())
        return Base64Url.encode(hash)
    }

    /*
     * Parse an EC public key from a minimal JSON object.
     * Throws JoseException on parse failure.
     */
    public static func fromJson(json: String): EcPublicKey {
        let crv = extractJsonString(json, "crv")
        let x = extractJsonString(json, "x")
        let y = extractJsonString(json, "y")
        match (crv) {
            case Some(crvStr) =>
                match (EcCurve.fromString(crvStr)) {
                    case Some(curve) =>
                        match (x) {
                            case Some(xStr) =>
                                match (y) {
                                    case Some(yStr) => return EcPublicKey(curve, xStr, yStr)
                                    case None => throw JoseException("EcPublicKey.fromJson: missing 'y' field")
                                }
                            case None => throw JoseException("EcPublicKey.fromJson: missing 'x' field")
                        }
                    case None => throw JoseException("EcPublicKey.fromJson: unsupported curve '${crvStr}'")
                }
            case None => throw JoseException("EcPublicKey.fromJson: missing 'crv' field")
        }
    }
}

public class EcPrivateKey {
    public let crv: EcCurve
    public let x: String
    public let y: String
    public let d: String

    public init(crv: EcCurve, x: String, y: String, d: String) {
        this.crv = crv
        this.x = x
        this.y = y
        this.d = d
    }

    public func publicKey(): EcPublicKey {
        return EcPublicKey(this.crv, this.x, this.y)
    }
}

/*
 * Minimal JSON string value extractor.
 * Finds "key":"value" and returns value as Option<String>.
 */
func extractJsonString(json: String, key: String): Option<String> {
    let needle = "\"" + key + "\":"
    let jsonBytes = json.toArray()
    let needleBytes = needle.toArray()
    var i: Int64 = 0
    while (i + needleBytes.size <= jsonBytes.size) {
        var match_ = true
        var j: Int64 = 0
        while (j < needleBytes.size) {
            if (jsonBytes[i + j] != needleBytes[j]) {
                match_ = false
                break
            }
            j += 1
        }
        if (match_) {
            var pos = i + needleBytes.size
            while (pos < jsonBytes.size && jsonBytes[pos] == b' ') {
                pos += 1
            }
            if (pos >= jsonBytes.size || jsonBytes[pos] != b'"') {
                return Option<String>.None
            }
            pos += 1
            var end = pos
            while (end < jsonBytes.size && jsonBytes[end] != b'"') {
                end += 1
            }
            if (end >= jsonBytes.size) {
                return Option<String>.None
            }
            let valueBytes = Array<UInt8>(end - pos, repeat: 0)
            for (k in 0..(end - pos)) {
                valueBytes[k] = jsonBytes[pos + k]
            }
            return Option<String>.Some(String.fromUtf8(valueBytes))
        }
        i += 1
    }
    return Option<String>.None
}

