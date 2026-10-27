package ohos_app_cangjie_entry

import std.unittest.*
import std.unittest.testmacro.*

import ohos_app_cangjie_eudi_cjjose.jose.*

// arraysEqual is defined in concat_kdf_test.cj in the same package

// ---------------------------------------------------------------------------
// Test 5: EcPublicKeyUT
// ---------------------------------------------------------------------------

@Test
class EcPublicKeyUT {

    // A real on-curve P-256 point (the curve generator G). fromHuksUncompressed
    // now enforces the curve equation, so test points must actually be on P-256.
    // The xBase/yBase arguments are retained for call-site compatibility but the
    // returned point is always a valid curve point.
    private func makeTestPoint(xBase: Int64, yBase: Int64): Array<UInt8> {
        let _ = xBase
        let _ = yBase
        return hexToBytes(
            "046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296" +
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
        )
    }

    private func hexToBytes(hex: String): Array<UInt8> {
        let chars = hex.toArray()
        let out = Array<UInt8>(chars.size / 2, repeat: 0)
        for (i in 0..out.size) {
            out[i] = UInt8(hexVal(chars[2 * i]) * 16 + hexVal(chars[2 * i + 1]))
        }
        return out
    }

    private func hexVal(c: UInt8): Int64 {
        if (c >= b'0' && c <= b'9') {
            return Int64(c - b'0')
        }
        if (c >= b'A' && c <= b'F') {
            return Int64(c - b'A') + 10
        }
        if (c >= b'a' && c <= b'f') {
            return Int64(c - b'a') + 10
        }
        return 0
    }

    // Local base64url (no padding) encoder so the test does not need a direct
    // dependency on eudi_lib_core_crypto (entry only depends on eudi_cjjose).
    private func b64u(data: Array<UInt8>): String {
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".toArray()
        let out = StringBuilder()
        var i: Int64 = 0
        while (i + 3 <= data.size) {
            let n = (Int64(data[i]) << 16) | (Int64(data[i + 1]) << 8) | Int64(data[i + 2])
            out.append(Rune(UInt32(alphabet[(n >> 18) & 0x3F])))
            out.append(Rune(UInt32(alphabet[(n >> 12) & 0x3F])))
            out.append(Rune(UInt32(alphabet[(n >> 6) & 0x3F])))
            out.append(Rune(UInt32(alphabet[n & 0x3F])))
            i += 3
        }
        let rem = data.size - i
        if (rem == 1) {
            let n = Int64(data[i]) << 16
            out.append(Rune(UInt32(alphabet[(n >> 18) & 0x3F])))
            out.append(Rune(UInt32(alphabet[(n >> 12) & 0x3F])))
        } else if (rem == 2) {
            let n = (Int64(data[i]) << 16) | (Int64(data[i + 1]) << 8)
            out.append(Rune(UInt32(alphabet[(n >> 18) & 0x3F])))
            out.append(Rune(UInt32(alphabet[(n >> 12) & 0x3F])))
            out.append(Rune(UInt32(alphabet[(n >> 6) & 0x3F])))
        }
        return out.toString()
    }

    @TestCase
    func testToHuksUncompressed_size65_firstByte04(): Unit {
        let point = makeTestPoint(1, 100)
        let key = EcPublicKey.fromHuksUncompressed(point)
        let reconstructed = key.toHuksUncompressed()
        @Expect(reconstructed.size, 65)
        @Expect(reconstructed[0], 0x04u8)
    }

    @TestCase
    func testToHuksUncompressed_exactRoundTrip(): Unit {
        let point = makeTestPoint(7, 200)
        let key = EcPublicKey.fromHuksUncompressed(point)
        let reconstructed = key.toHuksUncompressed()
        @Expect(arraysEqual(reconstructed, point), true)
    }

    @TestCase
    func testFromHuksUncompressed_wrongSize_throws(): Unit {
        var threw = false
        try {
            let _ = EcPublicKey.fromHuksUncompressed(Array<UInt8>(64, repeat: 0))
        } catch (e: JoseException) {
            threw = true
        }
        @Expect(threw, true)
    }

    @TestCase
    func testFromHuksUncompressed_wrongPrefix_throws(): Unit {
        let bad = Array<UInt8>(65, repeat: 0)
        bad[0] = 0x02u8
        var threw = false
        try {
            let _ = EcPublicKey.fromHuksUncompressed(bad)
        } catch (e: JoseException) {
            threw = true
        }
        @Expect(threw, true)
    }

    @TestCase
    func testToJson_containsKtyEcCrvXY(): Unit {
        let point = makeTestPoint(50, 150)
        let key = EcPublicKey.fromHuksUncompressed(point)
        let json = key.toJson()
        @Expect(json.contains("\"kty\":\"EC\""))
        @Expect(json.contains("\"crv\":\"P-256\""))
        @Expect(json.contains("\"x\":"))
        @Expect(json.contains("\"y\":"))
        @Expect(!json.contains("\"d\":"))
    }

    @TestCase
    func testFromJson_roundTrip_crvXY(): Unit {
        let point = makeTestPoint(20, 120)
        let key1 = EcPublicKey.fromHuksUncompressed(point)
        let json = key1.toJson()
        let key2 = EcPublicKey.fromJson(json)
        @Expect(key2.crv.rawValue(), "P-256")
        @Expect(key2.x, key1.x)
        @Expect(key2.y, key1.y)
    }

    @TestCase
    func testFromJson_toHuksUncompressed_preservesBytes(): Unit {
        let point = makeTestPoint(99, 199)
        let key1 = EcPublicKey.fromHuksUncompressed(point)
        let json = key1.toJson()
        let key2 = EcPublicKey.fromJson(json)
        let reconstructed = key2.toHuksUncompressed()
        @Expect(arraysEqual(reconstructed, point), true)
    }

    @TestCase
    func testFromJson_missingCrv_throws(): Unit {
        var threw = false
        try {
            let _ = EcPublicKey.fromJson("{\"kty\":\"EC\",\"x\":\"abc\",\"y\":\"def\"}")
        } catch (e: JoseException) {
            threw = true
        }
        @Expect(threw, true)
    }

    @TestCase
    func testFromJson_unknownCurve_throws(): Unit {
        var threw = false
        try {
            let _ = EcPublicKey.fromJson("{\"crv\":\"P-521\",\"kty\":\"EC\",\"x\":\"abc\",\"y\":\"def\"}")
        } catch (e: JoseException) {
            threw = true
        }
        @Expect(threw, true)
    }

    @TestCase
    func testRawValue_xAndY_nonEmpty(): Unit {
        let point = makeTestPoint(3, 177)
        let key = EcPublicKey.fromHuksUncompressed(point)
        @Expect(!key.x.isEmpty())
        @Expect(!key.y.isEmpty())
    }

    // ---- Audit fix #2: invalid-curve attack defense -----------------------

    // A 0x04-prefixed, 65-byte, correct-length point whose (x,y) is NOT on the
    // P-256 curve must be rejected by fromHuksUncompressed (was previously
    // accepted: only size==65 && first byte 0x04 were checked).
    @TestCase
    func testFromHuksUncompressed_offCurvePoint_throws(): Unit {
        // Take the real generator point and flip the last byte of Y so that
        // y^2 != x^3 + a*x + b (mod p): still 65 bytes, still 0x04 prefix.
        let bad = makeTestPoint(0, 0)
        bad[64] = bad[64] ^ 0x01u8
        var threw = false
        try {
            let _ = EcPublicKey.fromHuksUncompressed(bad)
        } catch (e: JoseException) {
            threw = true
        }
        @Expect(threw, true)
    }

    // The same off-curve point reaching ECDH via base64url x/y -> toHuksUncompressed
    // must also be rejected (this is the actual attacker-controlled epk path).
    @TestCase
    func testToHuksUncompressed_offCurvePoint_throws(): Unit {
        let valid = makeTestPoint(0, 0)
        let xBytes = Array<UInt8>(32, repeat: 0)
        let yBytes = Array<UInt8>(32, repeat: 0)
        for (i in 0..32) {
            xBytes[i] = valid[1 + i]
            yBytes[i] = valid[33 + i]
        }
        yBytes[31] = yBytes[31] ^ 0x01u8
        // Build an EcPublicKey directly from off-curve base64url coords (bypasses
        // fromHuksUncompressed) and confirm toHuksUncompressed rejects it.
        let key = EcPublicKey(EcCurve.P256, b64u(xBytes), b64u(yBytes))
        var threw = false
        try {
            let _ = key.toHuksUncompressed()
        } catch (e: JoseException) {
            threw = true
        }
        @Expect(threw, true)
    }

    // The on-curve generator point round-trips through toHuksUncompressed cleanly.
    @TestCase
    func testToHuksUncompressed_onCurvePoint_ok(): Unit {
        let point = makeTestPoint(0, 0)
        let key = EcPublicKey.fromHuksUncompressed(point)
        let reconstructed = key.toHuksUncompressed()
        @Expect(arraysEqual(reconstructed, point), true)
    }
}

// ---------------------------------------------------------------------------
// Test 6: EcPrivateKeyUT
// ---------------------------------------------------------------------------

@Test
class EcPrivateKeyUT {

    private func makeFakePrivKey(): EcPrivateKey {
        return EcPrivateKey(
            EcCurve.P256,
            "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
        )
    }

    @TestCase
    func testCrv_rawValue(): Unit {
        let priv = makeFakePrivKey()
        @Expect(priv.crv.rawValue(), "P-256")
    }

    @TestCase
    func testPublicKey_preservesCrvXY(): Unit {
        let priv = makeFakePrivKey()
        let pub = priv.publicKey()
        @Expect(pub.crv.rawValue(), "P-256")
        @Expect(pub.x, priv.x)
        @Expect(pub.y, priv.y)
    }

    @TestCase
    func testPublicKey_doesNotHaveD(): Unit {
        let priv = makeFakePrivKey()
        let pub = priv.publicKey()
        let pubJson = pub.toJson()
        @Expect(!pubJson.contains("\"d\":"))
    }

    @TestCase
    func testXYD_nonEmpty(): Unit {
        let priv = makeFakePrivKey()
        @Expect(!priv.x.isEmpty())
        @Expect(!priv.y.isEmpty())
        @Expect(!priv.d.isEmpty())
    }
}

// ---------------------------------------------------------------------------
// Test 12: EcPublicKeyThumbprintUT
//
// RFC 7638 JWK Thumbprint for EC P-256 key.
// Canonical JSON: {"crv":"P-256","kty":"EC","x":"...","y":"..."} (dict order).
// SHA-256 hashed and base64url-encoded.
//
// Known-vector test (computed independently via Python hashlib.sha256):
//   Input key: x = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
//              y = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
//   Canonical: {"crv":"P-256","kty":"EC","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}
//   SHA-256 → base64url (no padding): oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U
//   Verified by: hashlib.sha256(canonical.encode()) → base64.urlsafe_b64encode(...).rstrip("=")
// ---------------------------------------------------------------------------

@Test
class EcPublicKeyThumbprintUT {

    private static let TEST_X: String = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
    private static let TEST_Y: String = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
    private static let EXPECTED_THUMBPRINT: String = "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U"

    @TestCase
    func testThumbprint_knownVector(): Unit {
        let key = EcPublicKey(EcCurve.P256, EcPublicKeyThumbprintUT.TEST_X, EcPublicKeyThumbprintUT.TEST_Y)
        let thumb = key.thumbprint()
        @Expect(thumb, EcPublicKeyThumbprintUT.EXPECTED_THUMBPRINT)
    }

    @TestCase
    func testThumbprint_deterministic(): Unit {
        let key = EcPublicKey(EcCurve.P256, EcPublicKeyThumbprintUT.TEST_X, EcPublicKeyThumbprintUT.TEST_Y)
        let t1 = key.thumbprint()
        let t2 = key.thumbprint()
        @Expect(t1, t2)
    }

    @TestCase
    func testThumbprint_differentKeys_differentOutput(): Unit {
        let key1 = EcPublicKey(EcCurve.P256, EcPublicKeyThumbprintUT.TEST_X, EcPublicKeyThumbprintUT.TEST_Y)
        let key2 = EcPublicKey(EcCurve.P256, "g83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", EcPublicKeyThumbprintUT.TEST_Y)
        let t1 = key1.thumbprint()
        let t2 = key2.thumbprint()
        @Expect(t1 != t2, true)
    }

    @TestCase
    func testThumbprint_length_43(): Unit {
        let key = EcPublicKey(EcCurve.P256, EcPublicKeyThumbprintUT.TEST_X, EcPublicKeyThumbprintUT.TEST_Y)
        let thumb = key.thumbprint()
        @Expect(thumb.size, 43)
    }

    @TestCase
    func testThumbprint_noBase64Padding(): Unit {
        let key = EcPublicKey(EcCurve.P256, EcPublicKeyThumbprintUT.TEST_X, EcPublicKeyThumbprintUT.TEST_Y)
        let thumb = key.thumbprint()
        @Expect(!thumb.contains("="))
    }
}

// ---------------------------------------------------------------------------
// Test 13: EcdhEsKidUT
// ---------------------------------------------------------------------------

@Test
class EcdhEsKidUT {

    @TestCase
    func testHeader_kidSetAndRoundTrips(): Unit {
        let h = JweHeader(KeyManagementAlgorithm.EcdhEs, ContentEncryptionAlgorithm.A256Gcm)
        h.kid = Option<String>.Some("key-42")
        let bytes = h.toJsonBytes()
        let h2 = JweHeader.fromJsonBytes(bytes)
        match (h2.kid) {
            case Some(k) => @Expect(k, "key-42")
            case None => @Expect(false, true)
        }
    }

    @TestCase
    func testHeader_kidDefaultIsNone(): Unit {
        let h = JweHeader(KeyManagementAlgorithm.EcdhEs, ContentEncryptionAlgorithm.A256Gcm)
        let bytes = h.toJsonBytes()
        let h2 = JweHeader.fromJsonBytes(bytes)
        match (h2.kid) {
            case None => @Expect(true, true)
            case Some(_) => @Expect(false, true)
        }
    }

    @TestCase
    func testCompact_kidPreservedInHeaderSegment(): Unit {
        let h = JweHeader(KeyManagementAlgorithm.EcdhEs, ContentEncryptionAlgorithm.A256Gcm)
        h.kid = Option<String>.Some("my-key-id")
        let jwe = Jwe(h, Array<UInt8>(), Array<UInt8>(12, repeat: 0),
            Array<UInt8>(4, repeat: 0), Array<UInt8>(16, repeat: 0))
        let compact = jwe.compactSerialized()
        let jwe2 = Jwe.fromCompact(compact)
        match (jwe2.header.kid) {
            case Some(k) => @Expect(k, "my-key-id")
            case None => @Expect(false, true)
        }
    }

    @TestCase
    func testHeader_kidInJsonBytes(): Unit {
        let h = JweHeader(KeyManagementAlgorithm.EcdhEs, ContentEncryptionAlgorithm.A256Gcm)
        h.kid = Option<String>.Some("test-key")
        let jsonStr = String.fromUtf8(h.toJsonBytes())
        @Expect(jsonStr.contains("\"kid\":\"test-key\""))
        let h2 = JweHeader(KeyManagementAlgorithm.EcdhEs, ContentEncryptionAlgorithm.A256Gcm)
        let jsonStr2 = String.fromUtf8(h2.toJsonBytes())
        @Expect(!jsonStr2.contains("\"kid\":"))
    }
}

public func registerJwkTests(): Unit {
    reg({ => EcPublicKeyUT() })
    reg({ => EcPrivateKeyUT() })
    reg({ => EcPublicKeyThumbprintUT() })
    reg({ => EcdhEsKidUT() })
}
