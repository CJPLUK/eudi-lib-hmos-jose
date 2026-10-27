/*
 * encrypter.cj — ECDH-ES + A256GCM JWE encryption.
 * Mirrors JOSESwift Encrypter.swift + ECKeyEncryption.EncryptionMode +
 * ECDHKeyAgreement.swift (keyAgreementCompute / concatKDF).
 *
 * Protocol:
 *   1. Generate ephemeral P-256 key pair inside HUKS (temp alias).
 *   2. Export ephemeral public key (65-byte uncompressed).
 *   3. ECDH agree(ephAlias, recipientPubBytes) → shared secret Z.
 *   4. Delete ephemeral key from HUKS.
 *   5. Concat KDF(Z, "A256GCM", apu, apv, 256) → CEK (32 bytes).
 *   6. Build JWE header with epk = ephemeral public key JWK.
 *   7. AAD = base64url(headerJsonBytes).
 *   8. Generate 12-byte random nonce.
 *   9. AesGcm.seal(CEK, nonce, AAD, plaintext) → ct||tag.
 *  10. Split ct and tag; assemble Jwe and return compact string.
 */
package ohos_app_cangjie_eudi_cjjose.jose

import eudi_lib_core_crypto.EcdhP256
import eudi_lib_core_crypto.AesGcm
import eudi_lib_core_crypto.Base64Url
import eudi_lib_core_crypto.Rng

public class EcdhEsEncrypter {
    private static let aliasPrefix: String = "jose_eph_"

    /*
     * Encrypt plaintext for the given recipient EC public key.
     *
     * recipientPub — recipient's EC public key (JWK form).
     * plaintext    — plaintext bytes to encrypt.
     * apu          — PartyUInfo raw bytes (may be empty).
     * apv          — PartyVInfo raw bytes (may be empty).
     * kid          — optional key identifier set in the JWE protected header.
     *                When Some(s), sets header.kid = s. Default is None.
     *                Existing callers without this argument are unaffected.
     *
     * Returns the compact-serialized JWE string.
     */
    public static func encrypt(
        recipientPub: EcPublicKey,
        plaintext: Array<UInt8>,
        apu: Array<UInt8>,
        apv: Array<UInt8>,
        kid!: Option<String> = Option<String>.None
    ): String {
        let ephAlias = aliasPrefix + Base64Url.encode(Rng.bytes(8))
        try {
            EcdhP256.generateKey(ephAlias)
        } catch (e: Exception) {
            throw JoseException("EcdhEsEncrypter.generateKey: " + e.message)
        }
        var ephPubBytes = Array<UInt8>()
        var sharedZ = Array<UInt8>()
        try {
            try {
                ephPubBytes = EcdhP256.exportPublicKey(ephAlias)
            } catch (e: Exception) {
                throw JoseException("EcdhEsEncrypter.exportPublicKey: " + e.message)
            }
            let recipientPubBytes = recipientPub.toHuksSpki()
            try {
                sharedZ = EcdhP256.agree(ephAlias, recipientPubBytes)
            } catch (e: Exception) {
                throw JoseException("EcdhEsEncrypter.agree(recipientLen=" + recipientPubBytes.size.toString() + "): " + e.message)
            }
        } finally {
            if (EcdhP256.hasKey(ephAlias)) {
                EcdhP256.deleteKey(ephAlias)
            }
        }
        let ephPubJwk = EcPublicKey.fromHuksUncompressed(ephPubBytes)

        let algIdBytes = ContentEncryptionAlgorithm.A256Gcm.rawValue().toArray()
        let cek = ConcatKdf.derive(sharedZ, algIdBytes, apu, apv, 256)

        let header = JweHeader(KeyManagementAlgorithm.EcdhEs, ContentEncryptionAlgorithm.A256Gcm)
        header.epk = Option<EcPublicKey>.Some(ephPubJwk)
        if (apu.size > 0) {
            header.apu = Option<String>.Some(Base64Url.encode(apu))
        }
        if (apv.size > 0) {
            header.apv = Option<String>.Some(Base64Url.encode(apv))
        }
        match (kid) {
            case Some(k) => header.kid = Option<String>.Some(k)
            case None => ()
        }

        let headerJsonBytes = header.toJsonBytes()
        let aadString = Base64Url.encode(headerJsonBytes)
        let aadBytes = aadString.toArray()

        let nonce = Rng.bytes(12)

        let ctAndTag = AesGcm.seal(cek, nonce, aadBytes, plaintext)

        let tagLen: Int64 = 16
        let ctLen = ctAndTag.size - tagLen
        if (ctLen < 0) {
            throw JoseException("EcdhEsEncrypter: AesGcm output too short (${ctAndTag.size} bytes)")
        }
        let ct = Array<UInt8>(ctLen, repeat: 0)
        let tag = Array<UInt8>(tagLen, repeat: 0)
        for (i in 0..ctLen) {
            ct[i] = ctAndTag[i]
        }
        for (i in 0..tagLen) {
            tag[i] = ctAndTag[ctLen + i]
        }

        let jwe = Jwe(header, Array<UInt8>(), nonce, ct, tag)
        return jwe.compactSerialized()
    }
}
