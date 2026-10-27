/*
 * jwe_header.cj — RFC 7516 JWE Protected Header.
 * Mirrors JOSESwift JWEHeader.swift: stores alg/enc/epk/apu/apv/kid/typ.
 * Serializes to/from JSON bytes (the first base64url segment of a JWE compact form).
 */
package ohos_app_cangjie_eudi_cjjose.jose

import eudi_lib_core_crypto.Base64Url

public class JweHeader {
    public let alg: KeyManagementAlgorithm
    public let enc: ContentEncryptionAlgorithm
    public var epk: Option<EcPublicKey>
    public var apu: Option<String>
    public var apv: Option<String>
    public var kid: Option<String>
    public var typ: Option<String>

    public init(alg: KeyManagementAlgorithm, enc: ContentEncryptionAlgorithm) {
        this.alg = alg
        this.enc = enc
        this.epk = Option<EcPublicKey>.None
        this.apu = Option<String>.None
        this.apv = Option<String>.None
        this.kid = Option<String>.None
        this.typ = Option<String>.None
    }

    /*
     * Serialize to canonical JSON bytes.
     * Field order: alg, enc, epk (if set), apu (if set), apv (if set), kid (if set), typ (if set).
     * Result is used as the JWE header segment and as AAD for content encryption.
     */
    public func toJsonBytes(): Array<UInt8> {
        var json = "{\"alg\":\"" + this.alg.rawValue() + "\",\"enc\":\"" + this.enc.rawValue() + "\""
        match (this.epk) {
            case Some(key) =>
                json = json + ",\"epk\":" + key.toJson()
            case None => ()
        }
        match (this.apu) {
            case Some(v) =>
                json = json + ",\"apu\":\"" + v + "\""
            case None => ()
        }
        match (this.apv) {
            case Some(v) =>
                json = json + ",\"apv\":\"" + v + "\""
            case None => ()
        }
        match (this.kid) {
            case Some(v) =>
                json = json + ",\"kid\":\"" + v + "\""
            case None => ()
        }
        match (this.typ) {
            case Some(v) =>
                json = json + ",\"typ\":\"" + v + "\""
            case None => ()
        }
        json = json + "}"
        return json.toArray()
    }

    /*
     * Parse a JWE header from its JSON byte representation.
     * Requires "alg" and "enc"; other fields are optional.
     * Throws JoseException on missing required fields or unknown algorithm values.
     */
    public static func fromJsonBytes(bytes: Array<UInt8>): JweHeader {
        let json = String.fromUtf8(bytes)
        let algStr = extractJsonString(json, "alg")
        let encStr = extractJsonString(json, "enc")
        let alg = match (algStr) {
            case Some(s) => parseKeyManagementAlgorithm(s)
            case None => throw JoseException("JweHeader: missing 'alg' field")
        }
        let enc = match (encStr) {
            case Some(s) => parseContentEncryptionAlgorithm(s)
            case None => throw JoseException("JweHeader: missing 'enc' field")
        }
        let header = JweHeader(alg, enc)
        let epkJson = extractJsonObject(json, "epk")
        match (epkJson) {
            case Some(epkStr) =>
                header.epk = Option<EcPublicKey>.Some(EcPublicKey.fromJson(epkStr))
            case None => ()
        }
        header.apu = extractJsonString(json, "apu")
        header.apv = extractJsonString(json, "apv")
        header.kid = extractJsonString(json, "kid")
        header.typ = extractJsonString(json, "typ")
        return header
    }

    public static func fromBase64Url(encoded: String): JweHeader {
        let bytes = Base64Url.decode(encoded)
        return fromJsonBytes(bytes)
    }
}

func parseKeyManagementAlgorithm(s: String): KeyManagementAlgorithm {
    if (s == "ECDH-ES") {
        return KeyManagementAlgorithm.EcdhEs
    }
    throw JoseException("JweHeader: unsupported key-management algorithm '${s}'")
}

func parseContentEncryptionAlgorithm(s: String): ContentEncryptionAlgorithm {
    if (s == "A256GCM") {
        return ContentEncryptionAlgorithm.A256Gcm
    }
    throw JoseException("JweHeader: unsupported content-encryption algorithm '${s}'")
}

func extractJsonObject(json: String, key: String): Option<String> {
    let needle = "\"" + key + "\":"
    let jsonBytes = json.toArray()
    let needleBytes = needle.toArray()
    var i: Int64 = 0
    while (i + needleBytes.size <= jsonBytes.size) {
        var matchFound = true
        var j: Int64 = 0
        while (j < needleBytes.size) {
            if (jsonBytes[i + j] != needleBytes[j]) {
                matchFound = false
                break
            }
            j += 1
        }
        if (matchFound) {
            var pos = i + needleBytes.size
            while (pos < jsonBytes.size && jsonBytes[pos] == b' ') {
                pos += 1
            }
            if (pos >= jsonBytes.size || jsonBytes[pos] != b'{') {
                return Option<String>.None
            }
            let start = pos
            var depth: Int64 = 0
            var end = pos
            while (end < jsonBytes.size) {
                if (jsonBytes[end] == b'{') {
                    depth += 1
                } else if (jsonBytes[end] == b'}') {
                    depth -= 1
                    if (depth == 0) {
                        end += 1
                        break
                    }
                }
                end += 1
            }
            if (depth != 0) {
                return Option<String>.None
            }
            let objBytes = Array<UInt8>(end - start, repeat: 0)
            for (k in 0..(end - start)) {
                objBytes[k] = jsonBytes[start + k]
            }
            return Option<String>.Some(String.fromUtf8(objBytes))
        }
        i += 1
    }
    return Option<String>.None
}
