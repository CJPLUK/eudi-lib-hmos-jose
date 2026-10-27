/*
 * decrypter.cj — ECDH-ES + A256GCM JWE decryption.
 * Mirrors JOSESwift Decrypter.swift + ECKeyEncryption.DecryptionMode.
 *
 * Protocol:
 *   1. Parse JWE compact string → header / iv / ct / tag.
 *   2. Read epk from header (the sender's ephemeral public key).
 *   3. Import recipient private key into HUKS (temp alias).
 *   4. ECDH agree(recipientPrivAlias, epkBytes) → shared secret Z.
 *   5. Delete recipient's temp key from HUKS.
 *   6. Concat KDF(Z, "A256GCM", apu, apv, 256) → CEK (32 bytes).
 *   7. AAD = base64url(header segment from compact string).
 *   8. AesGcm.open(CEK, iv, AAD, ct||tag) → Option<plaintext>.
 *   9. Return plaintext or throw JoseException on tag mismatch.
 *
 * HUKS import format for P-256 private key for ECDH agreement:
 *   0x04 || X(32) || Y(32) || D(32) = 97 bytes.
 */
package ohos_app_cangjie_eudi_cjjose.jose

import eudi_lib_core_crypto.EcdhP256
import eudi_lib_core_crypto.AesGcm
import eudi_lib_core_crypto.Base64Url
import eudi_lib_core_crypto.Rng
import kit.UniversalKeystoreKit.*

public class EcdhEsDecrypter {
    private static let aliasPrefix: String = "jose_recv_"

    /*
     * Decrypt a compact JWE string using the recipient's EC private key (JWK form).
     *
     * compact       — JWE compact serialization (5 segments).
     * recipientPriv — recipient's EC private key (JWK with crv/x/y/d as base64url).
     *
     * Returns the plaintext bytes.
     * Throws JoseException on any structural or cryptographic failure.
     */
    public static func decrypt(compact: String, recipientPriv: EcPrivateKey): Array<UInt8> {
        let jwe = Jwe.fromCompact(compact)

        let epkPubBytes = match (jwe.header.epk) {
            case Some(epk) => epk.toHuksSpki()
            case None => throw JoseException("EcdhEsDecrypter: JWE header missing 'epk' field")
        }

        let apu = match (jwe.header.apu) {
            case Some(v) => Base64Url.decode(v)
            case None => Array<UInt8>()
        }
        let apv = match (jwe.header.apv) {
            case Some(v) => Base64Url.decode(v)
            case None => Array<UInt8>()
        }

        // Constant-semantic-failure CEK derivation, mirroring JOSESwift
        // ECKeyEncryption.DecryptionMode.determineContentEncryptionKey
        // (ECKeyEncryption.swift:104-117): pre-generate a random 32-byte CEK,
        // attempt the real ECDH-ES + Concat KDF derivation, and fall back to the
        // random CEK if anything fails or the derived key is not 32 bytes.
        // Every derivation failure then converges on the SAME AES-GCM tag
        // verification failure, so the caller cannot distinguish a key-agreement
        // error from a tampered ciphertext (MMA / padding-oracle resistance).
        let randomCek = Rng.bytes(32)
        var cek = randomCek
        try {
            let recvAlias = aliasPrefix + Base64Url.encode(Rng.bytes(8))
            importRecipientKey(recvAlias, recipientPriv)
            var sharedZ = Array<UInt8>()
            try {
                sharedZ = EcdhP256.agree(recvAlias, epkPubBytes)
            } finally {
                if (EcdhP256.hasKey(recvAlias)) {
                    EcdhP256.deleteKey(recvAlias)
                }
            }
            let algIdBytes = ContentEncryptionAlgorithm.A256Gcm.rawValue().toArray()
            let derived = ConcatKdf.derive(sharedZ, algIdBytes, apu, apv, 256)
            if (derived.size == 32) {
                cek = derived
            } else {
                // Wrong-length derivation => keep the random CEK (iOS line 114).
                cek = randomCek
            }
        } catch (e: Exception) {
            // Any derivation/agreement failure => keep the random CEK so the
            // failure surfaces only as an AES-GCM authentication failure below.
            cek = randomCek
        }

        let headerSeg = extractFirstSegment(compact)
        let aadBytes = headerSeg.toArray()

        let tagLen: Int64 = 16
        let ctAndTag = Array<UInt8>(jwe.ciphertext.size + tagLen, repeat: 0)
        for (i in 0..jwe.ciphertext.size) {
            ctAndTag[i] = jwe.ciphertext[i]
        }
        for (i in 0..tagLen) {
            ctAndTag[jwe.ciphertext.size + i] = jwe.authenticationTag[i]
        }

        let plaintext = AesGcm.open(cek, jwe.initializationVector, aadBytes, ctAndTag)
        match (plaintext) {
            case Some(p) => return p
            case None => throw JoseException("EcdhEsDecrypter: AES-GCM authentication tag verification failed")
        }
    }

    /*
     * Import recipient private key into HUKS for ECDH agreement.
     * Format: 0x04 || X(32) || Y(32) || D(32) = 97 bytes.
     */
    private static func importRecipientKey(alias: String, priv: EcPrivateKey): Unit {
        let xBytes = Base64Url.decode(priv.x)
        let yBytes = Base64Url.decode(priv.y)
        let dBytes = Base64Url.decode(priv.d)
        if (xBytes.size != 32 || yBytes.size != 32 || dBytes.size != 32) {
            throw JoseException("EcdhEsDecrypter: EC private key components must be 32 bytes each")
        }
        let keyMaterial = Array<UInt8>(97, repeat: 0)
        keyMaterial[0] = 0x04u8
        for (i in 0..32) {
            keyMaterial[1 + i] = xBytes[i]
            keyMaterial[33 + i] = yBytes[i]
            keyMaterial[65 + i] = dBytes[i]
        }
        let properties: Array<HuksParam> = [
            HuksParam(
                HuksTag.HUKS_TAG_ALGORITHM,
                HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_ECC)
            ),
            HuksParam(
                HuksTag.HUKS_TAG_KEY_SIZE,
                HuksParamValue.Uint32Value(HuksKeySize.HUKS_ECC_KEY_SIZE_256)
            ),
            HuksParam(
                HuksTag.HUKS_TAG_PURPOSE,
                HuksParamValue.Uint32Value(HuksKeyPurpose.HUKS_KEY_PURPOSE_AGREE)
            ),
            HuksParam(
                HuksTag.HUKS_TAG_DIGEST,
                HuksParamValue.Uint32Value(HuksKeyDigest.HUKS_DIGEST_NONE)
            ),
            HuksParam(
                HuksTag.HUKS_TAG_IMPORT_KEY_TYPE,
                HuksParamValue.Uint32Value(HuksImportKeyType.HUKS_KEY_TYPE_KEY_PAIR)
            )
        ]
        importKeyItem(alias, HuksOptions(properties: properties, inData: keyMaterial))
    }

    private static func extractFirstSegment(compact: String): String {
        let bytes = compact.toArray()
        var dotPos: Int64 = -1
        var i: Int64 = 0
        while (i < bytes.size) {
            if (bytes[i] == b'.') {
                dotPos = i
                break
            }
            i += 1
        }
        if (dotPos <= 0) {
            throw JoseException("JWE.extractFirstSegment: malformed compact serialization")
        }
        let seg = Array<UInt8>(dotPos, repeat: 0)
        for (k in 0..dotPos) {
            seg[k] = bytes[k]
        }
        return String.fromUtf8(seg)
    }
}
