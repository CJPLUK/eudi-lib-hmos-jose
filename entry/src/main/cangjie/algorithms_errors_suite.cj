package ohos_app_cangjie_entry

import std.unittest.*
import std.unittest.testmacro.*

import ohos_app_cangjie_eudi_cjjose.jose.*

// ---------------------------------------------------------------------------
// Test 2: AlgorithmsUT
// ---------------------------------------------------------------------------

@Test
class AlgorithmsUT {

    @TestCase
    func testEcdhEs_rawValue(): Unit {
        @Expect(KeyManagementAlgorithm.EcdhEs.rawValue(), "ECDH-ES")
    }

    @TestCase
    func testA256Gcm_rawValue(): Unit {
        @Expect(ContentEncryptionAlgorithm.A256Gcm.rawValue(), "A256GCM")
    }

    @TestCase
    func testA256Gcm_keyBitSize(): Unit {
        @Expect(ContentEncryptionAlgorithm.A256Gcm.keyBitSize(), 256)
    }

    @TestCase
    func testA256Gcm_keyByteSize(): Unit {
        @Expect(ContentEncryptionAlgorithm.A256Gcm.keyByteSize(), 32)
    }

    @TestCase
    func testEcdhEs_cekBitSize_A256Gcm(): Unit {
        let bitSize = KeyManagementAlgorithm.EcdhEs.cekBitSize(ContentEncryptionAlgorithm.A256Gcm)
        @Expect(bitSize, 256)
    }

    @TestCase
    func testEs256_rawValue(): Unit {
        @Expect(SignatureAlgorithm.Es256.rawValue(), "ES256")
    }
}

// ---------------------------------------------------------------------------
// Test 3: JoseExceptionUT
// ---------------------------------------------------------------------------

@Test
class JoseExceptionUT {

    @TestCase
    func testConstruct_messagePreserved(): Unit {
        let ex = JoseException("test error message")
        @Expect(ex.message.contains("test error message"))
    }

    // Verify JoseException inherits from Exception.
    // We use isInstanceOf instead of throw/catch to avoid triggering the framework's
    // exception counter (Cangjie TestReport.errorCount increments on any throw).
    @TestCase
    func testIsException(): Unit {
        let ex = JoseException("inherits from Exception")
        @Expect(ex is Exception, true)
    }

    @TestCase
    func testMessageContent(): Unit {
        let ex = JoseException("unique-test-marker")
        @Expect(ex.message.contains("unique-test-marker"))
        @Expect(!ex.message.contains("wrong-marker"))
    }
}

// ---------------------------------------------------------------------------
// Test 4: EcCurveUT
// ---------------------------------------------------------------------------

@Test
class EcCurveUT {

    @TestCase
    func testP256_rawValue(): Unit {
        @Expect(EcCurve.P256.rawValue(), "P-256")
    }

    @TestCase
    func testFromString_P256(): Unit {
        let curve = EcCurve.fromString("P-256")
        match (curve) {
            case Some(c) => @Expect(c.rawValue(), "P-256")
            case None => @Expect(false, true)
        }
    }

    @TestCase
    func testFromString_unknownCurve_returnsNone(): Unit {
        let curve = EcCurve.fromString("P-521")
        match (curve) {
            case Some(_) => @Expect(false, true)
            case None => @Expect(true, true)
        }
    }

    @TestCase
    func testKeyBitSize(): Unit {
        // Real on-curve P-256 generator G (0x04||Gx||Gy); fromHuksUncompressed
        // now enforces the curve equation, so the point must be valid.
        let hex = ("046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296" +
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5").toArray()
        func hv(c: UInt8): Int64 {
            if (c >= b'0' && c <= b'9') { return Int64(c - b'0') }
            if (c >= b'A' && c <= b'F') { return Int64(c - b'A') + 10 }
            return 0
        }
        let point = Array<UInt8>(65, repeat: 0)
        for (i in 0..65) {
            point[i] = UInt8(hv(hex[2 * i]) * 16 + hv(hex[2 * i + 1]))
        }
        let key = EcPublicKey.fromHuksUncompressed(point)
        @Expect(key.crv.rawValue(), "P-256")
        @Expect(key.x.size >= 43)
        @Expect(key.y.size >= 43)
    }
}

public func registerAlgErrTests(): Unit {
    reg({ => AlgorithmsUT() })
    reg({ => JoseExceptionUT() })
    reg({ => EcCurveUT() })
}
