/*
 * errors.cj — typed exception for eudi_cjjose.
 * Mirrors JOSESwiftError: thrown on structural / crypto failures that callers
 * must handle.  AES-GCM tag mismatch uses Option<>.None (never throws).
 */
package ohos_app_cangjie_eudi_cjjose.jose

public class JoseException <: Exception {
    public init(message: String) {
        super(message)
    }
}
