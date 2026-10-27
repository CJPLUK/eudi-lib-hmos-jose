# eudi_lib_jose

Cangjie (HarmonyOS) port of the JOSE primitives the EUDI Wallet needs, modelled on
[JOSESwift](https://github.com/airsidemobile/JOSESwift). Scoped to what the wallet / openid4vp use:
**JWE (ECDH-ES + A256GCM)** for VP-response encryption and **JWS (ES256)**.

Cangjie 包名: `ohos_app_cangjie_eudi_cjjose`(模块目录 `eudi_cjjose`)。

## 能力
- **JWE**:`EcdhEsEncrypter.encrypt` / `EcdhEsDecrypter.decrypt`(ECDH-ES 密钥协商 + A256GCM 内容加密 + compact 5 段序列化)
- **ConcatKDF**(NIST SP800-56A,ECDH-ES 派生 CEK,基于 SHA-256)
- **JWS**:`JoseJws.signEs256` / `verifyEs256`
- **JWK**:`EcPublicKey` / `EcPrivateKey`(crv/x/y/d ↔ HUKS 65B 未压缩点)
- 算法枚举:`KeyManagementAlgorithm` / `ContentEncryptionAlgorithm` / `SignatureAlgorithm`

## 复用(非自造密码学,仅补 Concat KDF)
全部密码学原语复用 `eudi_lib_core_crypto`:
- A256GCM → `AesGcm.seal/open`
- ECDH-ES 协商 → `EcdhP256.agree`(HUKS,临时密钥 generate→agree→delete)
- JWS ES256 → `Jws.signEs256/verifyEs256`
- Base64Url / SHA-256(Concat KDF)/ Rng → core-crypto
唯一新增:`ConcatKdf`(core-crypto 无对应)。

## 依赖消费(external_repo_module)
clone 本仓到 `third_party/eudi_lib_jose`,`eudi_lib_core_crypto` 置于同级 `third_party/`(见 project_blueprint `integration_modes.external_repo_module`);消费方
`cjpm.toml [dependencies]` 加 `ohos_app_cangjie_eudi_cjjose = { path = "../third_party/eudi_lib_jose/eudi_cjjose" }`。

## 测试
entry 内含 11 个 `@Test` 类(OpenHarmonyTestRunner),覆盖全部公开接口,含**真 HUKS JWE 加解密往返**、ConcatKdf 确定性、JWS 真签验+篡改检测;模拟器 `aa test` 全过(ResultCode 0)。

> 逐函数对照 JOSESwift(范围内)迁移;被 openid4vp-vci 消费。
