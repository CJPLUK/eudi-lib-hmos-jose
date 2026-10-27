/*
 * index.cj — public surface of ohos_app_cangjie_eudi_cjjose.
 * Re-exports all jose sub-package symbols so external consumers can
 * import ohos_app_cangjie_eudi_cjjose.* and access all JOSE types.
 *
 * Provides runJoseDemo() smoke-test consumed by the entry module.
 */
package ohos_app_cangjie_eudi_cjjose

import ohos_app_cangjie_eudi_cjjose.jose.*

// Decode a hex string to bytes (demo-local helper).
func joseDemoHex(hex: String): Array<UInt8> {
    let cs = hex.toArray()
    func v(c: UInt8): Int64 {
        if (c >= b'0' && c <= b'9') { return Int64(c - b'0') }
        if (c >= b'A' && c <= b'F') { return Int64(c - b'A') + 10 }
        if (c >= b'a' && c <= b'f') { return Int64(c - b'a') + 10 }
        return 0
    }
    let out = Array<UInt8>(cs.size / 2, repeat: 0)
    for (i in 0..out.size) {
        out[i] = UInt8(v(cs[2 * i]) * 16 + v(cs[2 * i + 1]))
    }
    return out
}

/*
 * Smoke-test: exercises Concat KDF and JWE compact serialization / parsing
 * without actual HUKS calls (which require device runtime).
 * Verifies:
 *   - ConcatKdf.derive produces 32 bytes for A256GCM keydataLen=256.
 *   - JweHeader serialization round-trip (toJsonBytes → fromJsonBytes).
 *   - JWE compact serialization produces 5 segments.
 *   - EcPublicKey HUKS uncompressed round-trip.
 */
public func runJoseDemo(): String {
    var result = "JOSE demo:\n"

    // 1. Concat KDF: derive 32 bytes from a 32-byte zero secret
    let z = Array<UInt8>(32, repeat: 0)
    let algId = "A256GCM".toArray()
    let cek = ConcatKdf.derive(z, algId, Array<UInt8>(), Array<UInt8>(), 256)
    if (cek.size == 32) {
        result = result + "ConcatKDF(32-byte zero) -> 32-byte CEK: OK\n"
    } else {
        result = result + "ConcatKDF FAIL: got ${cek.size} bytes\n"
    }

    // 2. JweHeader round-trip
    let header = JweHeader(KeyManagementAlgorithm.EcdhEs, ContentEncryptionAlgorithm.A256Gcm)
    let headerBytes = header.toJsonBytes()
    let header2 = JweHeader.fromJsonBytes(headerBytes)
    let algOk = header2.alg.rawValue() == "ECDH-ES"
    let encOk = header2.enc.rawValue() == "A256GCM"
    if (algOk && encOk) {
        result = result + "JweHeader round-trip: OK\n"
    } else {
        result = result + "JweHeader round-trip FAIL\n"
    }

    // 3. JWE compact 5-segment check
    // Real on-curve P-256 generator point G (0x04 || Gx || Gy). EcPublicKey now
    // enforces the curve equation, so a valid on-curve point is required.
    let fakePoint = joseDemoHex(
        "046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296" +
        "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5")
    let ephJwk = EcPublicKey.fromHuksUncompressed(fakePoint)
    let jweHeader = JweHeader(KeyManagementAlgorithm.EcdhEs, ContentEncryptionAlgorithm.A256Gcm)
    jweHeader.epk = Option<EcPublicKey>.Some(ephJwk)
    let jwe = Jwe(
        jweHeader,
        Array<UInt8>(),
        Array<UInt8>(12, repeat: 0),
        Array<UInt8>(16, repeat: 0xABu8),
        Array<UInt8>(16, repeat: 0xCDu8)
    )
    let compact = jwe.compactSerialized()
    var dots: Int64 = 0
    for (b in compact.toArray()) {
        if (b == b'.') { dots += 1 }
    }
    if (dots == 4) {
        result = result + "JWE compact 5-segment: OK\n"
    } else {
        result = result + "JWE compact FAIL: ${dots + 1} segments\n"
    }

    // 4. EcPublicKey HUKS uncompressed round-trip
    let roundTrip = EcPublicKey.fromHuksUncompressed(fakePoint).toHuksUncompressed()
    let rtOk = roundTrip.size == 65 && roundTrip[0] == 0x04u8
    if (rtOk) {
        result = result + "EcPublicKey HUKS uncompressed round-trip: OK\n"
    } else {
        result = result + "EcPublicKey HUKS round-trip FAIL\n"
    }

    return result
}
