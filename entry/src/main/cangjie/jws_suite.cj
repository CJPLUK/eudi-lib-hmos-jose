package ohos_app_cangjie_entry

import std.unittest.*
import std.unittest.testmacro.*

import ohos_app_cangjie_eudi_cjjose.jose.*
import stdx.crypto.keys.*

// ---------------------------------------------------------------------------
// Test 9: JoseJwsUT
//
// Uses ECDSAPrivateKey(Curve.P256) from stdx.crypto.keys to obtain real
// key pair instances, then exercises JoseJws.signEs256 / verifyEs256.
//
// Tests:
//   - sign + verify → true  (empty, short, multi-byte UTF-8 payloads)
//   - tampered payload → false
//   - tampered signature (flip one byte) → false
//   - wrong public key → false
// ---------------------------------------------------------------------------

@Test
class JoseJwsUT {

    private static let headerJson: String = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}"

    @TestCase
    func testSignVerify_shortPayload_returnsTrue(): Unit {
        let priv = ECDSAPrivateKey(Curve.P256)
        let pub = ECDSAPublicKey(priv)
        let payload = "hello world".toArray()
        let compact = JoseJws.signEs256(JoseJwsUT.headerJson, payload, priv)
        @Expect(JoseJws.verifyEs256(compact, pub), true)
    }

    @TestCase
    func testSignVerify_emptyPayload_returnsTrue(): Unit {
        let priv = ECDSAPrivateKey(Curve.P256)
        let pub = ECDSAPublicKey(priv)
        let payload = Array<UInt8>()
        let compact = JoseJws.signEs256(JoseJwsUT.headerJson, payload, priv)
        @Expect(JoseJws.verifyEs256(compact, pub), true)
    }

    @TestCase
    func testSignVerify_multibyteUtf8Payload_returnsTrue(): Unit {
        let priv = ECDSAPrivateKey(Curve.P256)
        let pub = ECDSAPublicKey(priv)
        // UTF-8: "EUDI Wallet €" (includes 3-byte € = 0xE2 0x82 0xAC)
        let payload: Array<UInt8> = [
            0x45u8, 0x55u8, 0x44u8, 0x49u8, 0x20u8, 0x57u8, 0x61u8, 0x6Cu8,
            0x6Cu8, 0x65u8, 0x74u8, 0x20u8, 0xE2u8, 0x82u8, 0xACu8
        ]
        let compact = JoseJws.signEs256(JoseJwsUT.headerJson, payload, priv)
        @Expect(JoseJws.verifyEs256(compact, pub), true)
    }

    @TestCase
    func testVerify_tamperedPayload_returnsFalse(): Unit {
        let priv = ECDSAPrivateKey(Curve.P256)
        let pub = ECDSAPublicKey(priv)
        let payload = "sensitive data 42".toArray()
        let compact = JoseJws.signEs256(JoseJwsUT.headerJson, payload, priv)

        let segments = compact.toArray()
        var firstDot: Int64 = -1
        var secondDot: Int64 = -1
        for (i in 0..segments.size) {
            if (segments[i] == b'.') {
                if (firstDot < 0) { firstDot = i }
                else if (secondDot < 0) { secondDot = i }
            }
        }
        let mid = (firstDot + secondDot) / 2
        segments[mid] = if (segments[mid] == b'A') { b'B' } else { b'A' }
        let tampered = String.fromUtf8(segments)

        @Expect(JoseJws.verifyEs256(tampered, pub), false)
    }

    @TestCase
    func testVerify_tamperedSignature_returnsFalse(): Unit {
        let priv = ECDSAPrivateKey(Curve.P256)
        let pub = ECDSAPublicKey(priv)
        let payload = "data to protect".toArray()
        let compact = JoseJws.signEs256(JoseJwsUT.headerJson, payload, priv)

        let segments = compact.toArray()
        var secondDot: Int64 = -1
        var dotCount: Int64 = 0
        for (i in 0..segments.size) {
            if (segments[i] == b'.') {
                dotCount += 1
                if (dotCount == 2) { secondDot = i }
            }
        }
        if (secondDot >= 0 && secondDot + 1 < segments.size) {
            let pos = secondDot + 1
            segments[pos] = if (segments[pos] == b'A') { b'B' } else { b'A' }
        }
        let tampered = String.fromUtf8(segments)

        @Expect(JoseJws.verifyEs256(tampered, pub), false)
    }

    @TestCase
    func testVerify_wrongPublicKey_returnsFalse(): Unit {
        let priv1 = ECDSAPrivateKey(Curve.P256)
        let priv2 = ECDSAPrivateKey(Curve.P256)
        let pub2 = ECDSAPublicKey(priv2)
        let payload = "cross-key test".toArray()
        let compact = JoseJws.signEs256(JoseJwsUT.headerJson, payload, priv1)
        @Expect(JoseJws.verifyEs256(compact, pub2), false)
    }

    @TestCase
    func testVerify_malformedCompact_returnsFalse(): Unit {
        let pub = ECDSAPublicKey(ECDSAPrivateKey(Curve.P256))
        @Expect(JoseJws.verifyEs256("aaa.bbb", pub), false)
    }
}

public func registerJwsTests(): Unit {
    reg({ => JoseJwsUT() })
}
