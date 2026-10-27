/*
 * concat_kdf.cj — NIST SP800-56A Concat KDF (single-step KDF with SHA-256).
 * Mirrors JOSESwift ECDHKeyAgreement.swift: concatKDF() / keyAgreementCompute().
 * Used by ECDH-ES to derive the CEK from the ECDH shared secret Z.
 *
 * RFC 7518 §4.6.2 specifies the otherInfo structure:
 *   AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo
 * Each field is length-prefixed with a 4-byte big-endian uint32.
 */
package ohos_app_cangjie_eudi_cjjose.jose

import eudi_lib_core_crypto.Digest

public class ConcatKdf {
    /*
     * Derive `keydataLenBits` bits from shared secret z using SHA-256 Concat KDF.
     *
     * Parameters follow RFC 7518 §4.6.2 / JOSESwift keyAgreementCompute():
     *   z              — ECDH shared secret bytes
     *   algId          — UTF-8 bytes of the algorithm identifier (enc rawValue for ECDH-ES)
     *   apu            — base64url-decoded PartyUInfo (may be empty)
     *   apv            — base64url-decoded PartyVInfo (may be empty)
     *   keydataLenBits — desired output key length in bits (256 for A256GCM)
     *
     * Returns the first keydataLenBits/8 bytes of the derived keying material.
     */
    public static func derive(
        z: Array<UInt8>,
        algId: Array<UInt8>,
        apu: Array<UInt8>,
        apv: Array<UInt8>,
        keydataLenBits: Int64
    ): Array<UInt8> {
        if (keydataLenBits <= 0) {
            return Array<UInt8>()
        }
        let keydataLenBytes = keydataLenBits / 8

        let algIdPrefixed = prefixLen32(algId)
        let apuPrefixed = prefixLen32(apu)
        let apvPrefixed = prefixLen32(apv)
        let suppPubInfo = uint32BigEndian(UInt32(keydataLenBits))

        let otherInfoLen = algIdPrefixed.size + apuPrefixed.size + apvPrefixed.size + suppPubInfo.size
        let otherInfo = Array<UInt8>(otherInfoLen, repeat: 0)
        var pos: Int64 = 0
        pos = copyInto(algIdPrefixed, otherInfo, pos)
        pos = copyInto(apuPrefixed, otherInfo, pos)
        pos = copyInto(apvPrefixed, otherInfo, pos)
        pos = copyInto(suppPubInfo, otherInfo, pos)

        let hashBitLen: Int64 = 256
        let hashByteLen: Int64 = 32
        let reps: Int64 = (keydataLenBits + hashBitLen - 1) / hashBitLen

        let allBytes = Array<UInt8>(reps * hashByteLen, repeat: 0)
        var outPos: Int64 = 0
        var round: Int64 = 1
        while (round <= reps) {
            let counter = uint32BigEndian(UInt32(round))
            let inputLen = counter.size + z.size + otherInfo.size
            let hashInput = Array<UInt8>(inputLen, repeat: 0)
            var hp: Int64 = 0
            hp = copyInto(counter, hashInput, hp)
            hp = copyInto(z, hashInput, hp)
            hp = copyInto(otherInfo, hashInput, hp)
            let digest = Digest.sha256(hashInput)
            for (i in 0..digest.size) {
                allBytes[outPos + i] = digest[i]
            }
            outPos += hashByteLen
            round += 1
        }

        if (keydataLenBytes >= allBytes.size) {
            return allBytes
        }
        let out = Array<UInt8>(keydataLenBytes, repeat: 0)
        for (i in 0..keydataLenBytes) {
            out[i] = allBytes[i]
        }
        return out
    }

    private static func prefixLen32(data: Array<UInt8>): Array<UInt8> {
        let prefix = uint32BigEndian(UInt32(data.size))
        let out = Array<UInt8>(prefix.size + data.size, repeat: 0)
        var pos: Int64 = 0
        pos = copyInto(prefix, out, pos)
        pos = copyInto(data, out, pos)
        return out
    }

    private static func uint32BigEndian(value: UInt32): Array<UInt8> {
        let out = Array<UInt8>(4, repeat: 0)
        out[0] = UInt8((value >> 24) & 0xFFu32)
        out[1] = UInt8((value >> 16) & 0xFFu32)
        out[2] = UInt8((value >> 8) & 0xFFu32)
        out[3] = UInt8(value & 0xFFu32)
        return out
    }

    private static func copyInto(src: Array<UInt8>, dst: Array<UInt8>, dstOffset: Int64): Int64 {
        for (i in 0..src.size) {
            dst[dstOffset + i] = src[i]
        }
        return dstOffset + src.size
    }
}
