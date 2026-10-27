package ohos_app_cangjie_entry

import std.unittest.*
import std.unittest.testmacro.*

import ohos_app_cangjie_eudi_cjjose.runJoseDemo
import ohos_app_cangjie_eudi_cjjose.jose.*

// ---------------------------------------------------------------------------
// Test 7: JweHeaderUT
// ---------------------------------------------------------------------------

@Test
class JweHeaderUT {

    @TestCase
    func testBasicHeader_algEnc_roundTrip(): Unit {
        let h = JweHeader(KeyManagementAlgorithm.EcdhEs, ContentEncryptionAlgorithm.A256Gcm)
        let bytes = h.toJsonBytes()
        let h2 = JweHeader.fromJsonBytes(bytes)
        @Expect(h2.alg.rawValue(), "ECDH-ES")
        @Expect(h2.enc.rawValue(), "A256GCM")
    }

    @TestCase
    func testHeaderWithEpk_roundTrip(): Unit {
        // Use a real on-curve P-256 public key (the curve generator G); epk
        // construction now enforces the curve equation, so arbitrary bytes
        // would (correctly) be rejected.
        let point = Array<UInt8>(65, repeat: 0)
        point[0] = 0x04u8
        let gx: Array<UInt8> = [
            0x6Bu8, 0x17u8, 0xD1u8, 0xF2u8, 0xE1u8, 0x2Cu8, 0x42u8, 0x47u8,
            0xF8u8, 0xBCu8, 0xE6u8, 0xE5u8, 0x63u8, 0xA4u8, 0x40u8, 0xF2u8,
            0x77u8, 0x03u8, 0x7Du8, 0x81u8, 0x2Du8, 0xEBu8, 0x33u8, 0xA0u8,
            0xF4u8, 0xA1u8, 0x39u8, 0x45u8, 0xD8u8, 0x98u8, 0xC2u8, 0x96u8
        ]
        let gy: Array<UInt8> = [
            0x4Fu8, 0xE3u8, 0x42u8, 0xE2u8, 0xFEu8, 0x1Au8, 0x7Fu8, 0x9Bu8,
            0x8Eu8, 0xE7u8, 0xEBu8, 0x4Au8, 0x7Cu8, 0x0Fu8, 0x9Eu8, 0x16u8,
            0x2Bu8, 0xCEu8, 0x33u8, 0x57u8, 0x6Bu8, 0x31u8, 0x5Eu8, 0xCEu8,
            0xCBu8, 0xB6u8, 0x40u8, 0x68u8, 0x37u8, 0xBFu8, 0x51u8, 0xF5u8
        ]
        for (i in 0..32) {
            point[1 + i] = gx[i]
            point[33 + i] = gy[i]
        }
        let epk = EcPublicKey.fromHuksUncompressed(point)
        let h = JweHeader(KeyManagementAlgorithm.EcdhEs, ContentEncryptionAlgorithm.A256Gcm)
        h.epk = Option<EcPublicKey>.Some(epk)
        let bytes = h.toJsonBytes()
        let json = String.fromUtf8(bytes)
        @Expect(json.contains("\"epk\""))
        @Expect(json.contains("P-256"))
        let h2 = JweHeader.fromJsonBytes(bytes)
        match (h2.epk) {
            case Some(epk2) =>
                @Expect(epk2.crv.rawValue(), "P-256")
                @Expect(epk2.x, epk.x)
                @Expect(epk2.y, epk.y)
            case None =>
                @Expect(false, true)
        }
    }

    @TestCase
    func testHeaderWithApuApv_roundTrip(): Unit {
        let h = JweHeader(KeyManagementAlgorithm.EcdhEs, ContentEncryptionAlgorithm.A256Gcm)
        h.apu = Option<String>.Some("alice-apu")
        h.apv = Option<String>.Some("bob-apv")
        let bytes = h.toJsonBytes()
        let h2 = JweHeader.fromJsonBytes(bytes)
        match (h2.apu) {
            case Some(v) => @Expect(v, "alice-apu")
            case None => @Expect(false, true)
        }
        match (h2.apv) {
            case Some(v) => @Expect(v, "bob-apv")
            case None => @Expect(false, true)
        }
    }

    @TestCase
    func testHeaderWithKidTyp_roundTrip(): Unit {
        let h = JweHeader(KeyManagementAlgorithm.EcdhEs, ContentEncryptionAlgorithm.A256Gcm)
        h.kid = Option<String>.Some("key-1")
        h.typ = Option<String>.Some("JWT")
        let bytes = h.toJsonBytes()
        let h2 = JweHeader.fromJsonBytes(bytes)
        match (h2.kid) {
            case Some(v) => @Expect(v, "key-1")
            case None => @Expect(false, true)
        }
        match (h2.typ) {
            case Some(v) => @Expect(v, "JWT")
            case None => @Expect(false, true)
        }
    }

    @TestCase
    func testOptionalFields_absent_areNone(): Unit {
        let h = JweHeader(KeyManagementAlgorithm.EcdhEs, ContentEncryptionAlgorithm.A256Gcm)
        let bytes = h.toJsonBytes()
        let h2 = JweHeader.fromJsonBytes(bytes)
        match (h2.epk) {
            case None => @Expect(true, true)
            case Some(_) => @Expect(false, true)
        }
        match (h2.apu) {
            case None => @Expect(true, true)
            case Some(_) => @Expect(false, true)
        }
        match (h2.apv) {
            case None => @Expect(true, true)
            case Some(_) => @Expect(false, true)
        }
        match (h2.kid) {
            case None => @Expect(true, true)
            case Some(_) => @Expect(false, true)
        }
        match (h2.typ) {
            case None => @Expect(true, true)
            case Some(_) => @Expect(false, true)
        }
    }

    @TestCase
    func testFromJsonBytes_badAlg_throws(): Unit {
        let badJson = "{\"alg\":\"RSA-OAEP\",\"enc\":\"A256GCM\"}"
        var threw = false
        try {
            let _ = JweHeader.fromJsonBytes(badJson.toArray())
        } catch (e: JoseException) {
            threw = true
        }
        @Expect(threw, true)
    }

    @TestCase
    func testFromJsonBytes_missingAlg_throws(): Unit {
        let badJson = "{\"enc\":\"A256GCM\"}"
        var threw = false
        try {
            let _ = JweHeader.fromJsonBytes(badJson.toArray())
        } catch (e: JoseException) {
            threw = true
        }
        @Expect(threw, true)
    }

    @TestCase
    func testFromBase64Url_roundTrip(): Unit {
        let h = JweHeader(KeyManagementAlgorithm.EcdhEs, ContentEncryptionAlgorithm.A256Gcm)
        let jwe = Jwe(h, Array<UInt8>(), Array<UInt8>(12, repeat: 0),
            Array<UInt8>(4, repeat: 0), Array<UInt8>(16, repeat: 0))
        let compact = jwe.compactSerialized()
        let segs = compact.toArray()
        var dotPos: Int64 = -1
        for (i in 0..segs.size) {
            if (segs[i] == b'.') { dotPos = i; break }
        }
        let encodedBytes = Array<UInt8>(dotPos, repeat: 0)
        for (i in 0..dotPos) { encodedBytes[i] = segs[i] }
        let encoded = String.fromUtf8(encodedBytes)
        let h2 = JweHeader.fromBase64Url(encoded)
        @Expect(h2.alg.rawValue(), "ECDH-ES")
        @Expect(h2.enc.rawValue(), "A256GCM")
    }
}

// ---------------------------------------------------------------------------
// Test 8: JweCompactUT
// ---------------------------------------------------------------------------

@Test
class JweCompactUT {

    private func makeHeader(): JweHeader {
        return JweHeader(KeyManagementAlgorithm.EcdhEs, ContentEncryptionAlgorithm.A256Gcm)
    }

    @TestCase
    func testCompactSerialized_hasFiveSegments(): Unit {
        let jwe = Jwe(
            makeHeader(),
            Array<UInt8>(),
            Array<UInt8>(12, repeat: 0xAAu8),
            Array<UInt8>(16, repeat: 0xBBu8),
            Array<UInt8>(16, repeat: 0xCCu8)
        )
        let compact = jwe.compactSerialized()
        var dots: Int64 = 0
        for (b in compact.toArray()) {
            if (b == b'.') { dots += 1 }
        }
        @Expect(dots, 4)
    }

    @TestCase
    func testFromCompact_ivCtTagSize_preserved(): Unit {
        let iv = Array<UInt8>(12, repeat: 0x11u8)
        let ct = Array<UInt8>(20, repeat: 0x22u8)
        let tag = Array<UInt8>(16, repeat: 0x33u8)
        let jwe = Jwe(makeHeader(), Array<UInt8>(), iv, ct, tag)
        let compact = jwe.compactSerialized()
        let jwe2 = Jwe.fromCompact(compact)
        @Expect(jwe2.initializationVector.size, 12)
        @Expect(jwe2.ciphertext.size, 20)
        @Expect(jwe2.authenticationTag.size, 16)
    }

    @TestCase
    func testFromCompact_ivBytes_exactMatch(): Unit {
        let iv = Array<UInt8>(12, repeat: 0)
        for (i in 0..12) { iv[i] = UInt8(i + 1) }
        let jwe = Jwe(makeHeader(), Array<UInt8>(), iv, Array<UInt8>(4, repeat: 0), Array<UInt8>(16, repeat: 0))
        let jwe2 = Jwe.fromCompact(jwe.compactSerialized())
        @Expect(arraysEqual(jwe2.initializationVector, iv), true)
    }

    @TestCase
    func testFromCompact_tagBytes_exactMatch(): Unit {
        let tag = Array<UInt8>(16, repeat: 0)
        for (i in 0..16) { tag[i] = UInt8(i + 50) }
        let jwe = Jwe(makeHeader(), Array<UInt8>(), Array<UInt8>(12, repeat: 0), Array<UInt8>(4, repeat: 0), tag)
        let jwe2 = Jwe.fromCompact(jwe.compactSerialized())
        @Expect(arraysEqual(jwe2.authenticationTag, tag), true)
    }

    @TestCase
    func testFromCompact_headerFields_preserved(): Unit {
        let jwe = Jwe(makeHeader(), Array<UInt8>(), Array<UInt8>(12, repeat: 0),
            Array<UInt8>(8, repeat: 0), Array<UInt8>(16, repeat: 0))
        let jwe2 = Jwe.fromCompact(jwe.compactSerialized())
        @Expect(jwe2.header.alg.rawValue(), "ECDH-ES")
        @Expect(jwe2.header.enc.rawValue(), "A256GCM")
    }

    @TestCase
    func testFromCompact_tooFewSegments_throws(): Unit {
        var threw = false
        try {
            let _ = Jwe.fromCompact("aaa.bbb.ccc")
        } catch (e: JoseException) {
            threw = true
        }
        @Expect(threw, true)
    }

    @TestCase
    func testFromCompact_tooManySegments_throws(): Unit {
        var threw = false
        try {
            let _ = Jwe.fromCompact("a.b.c.d.e.f")
        } catch (e: JoseException) {
            threw = true
        }
        @Expect(threw, true)
    }
}

// ---------------------------------------------------------------------------
// Test 10: EcdhEsRoundTripUT
//
// True ECDH-ES encrypt → decrypt round-trip on a real device (HUKS).
// Non-HUKS: missing epk throws JoseException (no HUKS needed).
// ---------------------------------------------------------------------------

@Test
class EcdhEsRoundTripUT {

    private static let TEST_X: String = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
    private static let TEST_Y: String = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
    private static let TEST_D: String = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"

    private func makeRecipientPriv(): EcPrivateKey {
        return EcPrivateKey(EcCurve.P256, EcdhEsRoundTripUT.TEST_X,
            EcdhEsRoundTripUT.TEST_Y, EcdhEsRoundTripUT.TEST_D)
    }

    // A valid on-curve P-256 public key (the recipient's own public key serves
    // as a well-formed epk for structural tests).
    private func makeValidEpk(): EcPublicKey {
        return EcPublicKey(EcCurve.P256, EcdhEsRoundTripUT.TEST_X, EcdhEsRoundTripUT.TEST_Y)
    }

    private func makeJweWithEpk(epk: EcPublicKey, ct: Array<UInt8>, tag: Array<UInt8>): String {
        let header = JweHeader(KeyManagementAlgorithm.EcdhEs, ContentEncryptionAlgorithm.A256Gcm)
        header.epk = Option<EcPublicKey>.Some(epk)
        let jwe = Jwe(header, Array<UInt8>(), Array<UInt8>(12, repeat: 0x07u8), ct, tag)
        return jwe.compactSerialized()
    }

    @TestCase
    func testDecrypt_missingEpk_throws(): Unit {
        let priv = makeRecipientPriv()
        let header = JweHeader(KeyManagementAlgorithm.EcdhEs, ContentEncryptionAlgorithm.A256Gcm)
        let jwe = Jwe(header, Array<UInt8>(), Array<UInt8>(12, repeat: 0),
            Array<UInt8>(4, repeat: 0), Array<UInt8>(16, repeat: 0))
        let compact = jwe.compactSerialized()
        var threw = false
        try {
            let _ = EcdhEsDecrypter.decrypt(compact, priv)
        } catch (e: JoseException) {
            threw = true
        }
        @Expect(threw, true)
    }

    // ---- Audit fix #2 at the decrypt path (non-HUKS) ----------------------
    // An attacker-controlled epk that is NOT on the P-256 curve must be rejected
    // before any ECDH agreement happens. The point is built from off-curve
    // coordinates so toHuksUncompressed (called inside decrypt) throws. This runs
    // without HUKS because rejection happens during epk reconstruction.
    @TestCase
    func testDecrypt_offCurveEpk_rejected(): Unit {
        // y from a valid key but x = all zeros => (0, y) is not on the curve.
        // base64url of 32 zero bytes is 43 'A' characters.
        let zeroX = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        let offCurveEpk = EcPublicKey(EcCurve.P256, zeroX, EcdhEsRoundTripUT.TEST_Y)
        let compact = makeJweWithEpk(offCurveEpk, Array<UInt8>(8, repeat: 0x55u8),
            Array<UInt8>(16, repeat: 0x66u8))
        let priv = makeRecipientPriv()
        var threw = false
        try {
            let _ = EcdhEsDecrypter.decrypt(compact, priv)
        } catch (e: JoseException) {
            threw = true
        }
        @Expect(threw, true)
    }

    // ---- Audit fix #1: constant-semantic-failure CEK fallback (HUKS) ------
    // With a well-formed, on-curve epk but a ciphertext/tag that cannot
    // authenticate under the derived CEK, decrypt must converge on the SAME
    // uniform AES-GCM authentication failure (a JoseException whose message
    // names the tag verification failure) — never a distinguishable derivation
    // or key-agreement error. Requires HUKS (real ECDH), so runs on device.
    @TestCase
    func testDecrypt_tamperedCiphertext_uniformAuthFailure(): Unit {
        let epk = makeValidEpk()
        let compact = makeJweWithEpk(epk, Array<UInt8>(16, repeat: 0xAAu8),
            Array<UInt8>(16, repeat: 0xBBu8))
        let priv = makeRecipientPriv()
        var caught = ""
        var threw = false
        try {
            let _ = EcdhEsDecrypter.decrypt(compact, priv)
        } catch (e: JoseException) {
            threw = true
            caught = e.message
        }
        @Expect(threw, true)
        // The error must be the uniform authentication failure, regardless of
        // whether key agreement itself succeeded or fell back to a random CEK.
        @Expect(caught.contains("authentication tag verification failed"), true)
    }
}

// ---------------------------------------------------------------------------
// Test 11: JoseDemoUT — smoke test (retained)
// ---------------------------------------------------------------------------

@Test
class JoseDemoUT {

    @TestCase
    func testRunJoseDemo_containsOkLines(): Unit {
        let result = runJoseDemo()
        @Expect(result.contains("ConcatKDF") || result.contains("JOSE"))
        @Expect(result.contains("OK"))
    }

    @TestCase
    func testRunJoseDemo_noFailLines(): Unit {
        let result = runJoseDemo()
        @Expect(!result.contains("FAIL"))
    }
}

public func registerJweTests(): Unit {
    reg({ => JweHeaderUT() })
    reg({ => JweCompactUT() })
    reg({ => EcdhEsRoundTripUT() })
    reg({ => JoseDemoUT() })
}
