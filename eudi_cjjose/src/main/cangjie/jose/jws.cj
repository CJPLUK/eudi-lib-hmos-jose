/*
 * jws.cj — RFC 7515 JWS ES256 thin wrapper.
 * Delegates directly to core-crypto Jws.signEs256 / Jws.verifyEs256.
 * Mirrors JOSESwift JWS usage: provides a stable JOSE-layer API surface
 * so openid4vp callers import eudi_cjjose rather than eudi_lib_core_crypto directly.
 *
 * JWS compact form: BASE64URL(headerJson) "." BASE64URL(payload) "." BASE64URL(sig)
 */
package ohos_app_cangjie_eudi_cjjose.jose

import eudi_lib_core_crypto.Jws
import stdx.crypto.keys.ECDSAPrivateKey
import stdx.crypto.keys.ECDSAPublicKey

public class JoseJws {
    /*
     * Sign payload bytes with ES256. headerJson must declare "alg":"ES256".
     * Returns the compact JWS string.
     */
    public static func signEs256(headerJson: String, payload: Array<UInt8>, priv: ECDSAPrivateKey): String {
        return Jws.signEs256(headerJson, payload, priv)
    }

    /*
     * Verify a compact ES256 JWS. Returns true on valid signature, false on any failure.
     */
    public static func verifyEs256(compact: String, pub: ECDSAPublicKey): Bool {
        return Jws.verifyEs256(compact, pub)
    }
}
