# 小米 Passkey 创建与认证全流程

> 2026-11-16 于 HyperOS 实测逆向（com.miui.passwords 1.1.26 / com.fido.asm v220260331 /
> TEE AAGUID `XMCTAP-000000002`）。所有报文均来自真实抓包（Telegram / X / PasskeyDemo 三端）。

## 1. 总览

小米 HyperOS 的 passkey（通行密钥）走 **CredentialManager → 密码管理 → MiFido(ASM) → TEE** 四层：

```
App（Telegram / X / 任意）
  │ ① CredentialManager.createCredential(options)          [androidx.credentials]
  ▼
系统凭据框架 com.android.credentialmanager
  │ ② 查询全部 provider 的 begin 能力
  │    ├ GMS  PasswordAndPasskeyService（Google）
  │    └ 小米  XiaomiCredentialProviderService @ com.miui.passwords
  │ ③ 弹出选择器（MiuiCredentialManager，type=PASSKEY）
  ▼ 用户选「密码管理」
FidoCredentialCreateActivity @ com.miui.passwords
  │ ④ action=com.xiaomi.credential.provider.FIDO_CREDENTIAL_CREATE
  │    AIDL(org.fidoalliance.aidl.activity.CREDENTIAL_PROVIDER_OPERATION)
  ▼ binder
com.fido.asm（MiFido，内含 Nok Nok UAF 框架）
  │ ⑤ App 身份校验 ─── ★关卡一：服务端 RP 白名单
  │ ⑥ ClientDataProcessor 组 clientDataJSON → SHA-256 → clientDataHash
  ▼
TEE FIDO TA（AAGUID: XMCTAP-000000002）
  │ ⑦ makeCredential → packed attestation（小米 CA 证书链）
  │    MiCloudKeyBoxService(passkeeper) 记录元数据——本地 TA，无服务端门槛
  ▼
com.fido.asm
  │ ⑧ attestation 降级 fmt:"none"，组 registrationResponseJson
  ▼ setResult 回传 → 框架 → App → RP 服务端
  │ ⑨ RP 校验 challenge/type/rpIdHash/origin/userHandle ─── ★关卡二：origin 白名单
  │    （登录断言另有 ★关卡三：userHandle 被 setUserSelected 自抹，见 §6.1）
```

## 2. 关卡一：App 身份校验（RP 白名单）

`i5.b`（AppAuthenticationManager）→ 先查内存缓存（TTL 180s）→ 未命中则请求小米服务端：

```
POST https://api.account.xiaomi.com/pass/verify/assetlink
form: rp=telegram.org
      assetlinkUrlList=["https://telegram.org/.well-known/assetlinks.json", ...]
      namespace=android_app | web
      fingerprints=<调用方签名证书 SHA-256 冒号格式>
      packageName=<调用方包名>
      serialNo=<随机 UUID>

→ {"code":0, ...}                                通过
→ {"code":210003, "desc":"asset_not_support",    未注册（服务端 (rp, packageName) 库）
   "msg":"cannot be fount packagename:<pkg>"}
```

实测该库仅收录小米自家（`account.xiaomi.com + com.xiaomi.account`——返回
`fingerprints not match` 即代表已注册、仅指纹不符）；Telegram、微信、X 等均不在库。

失败时 `p2.e`（VendorValidator）抛出 `vendor validate failed : message=asset_not_support。serialNo=…`，
`p2.c`（FacetIDsValidator）终结流程。**FuckMiuiPasswords 的 NetForge 伪造 + SHORT-CIRCUIT 正是切在这两层**，
且伪造前先过 AssetlinkGate 本地闸门——每次抓 RP 的 assetlinks.json 按 DAL 语义实时核验
（get_login_creds + android_app + 包名 + 指纹，无静态白名单，换签名/更新声明自动跟上），
只放行声明里的调用方，拒绝时伪造忠实失败体。

## 3. clientDataJSON 与 origin

`o2.b`（ClientDataProcessor）以 POJO `c3/k`{androidPackageName, challenge, origin, type} 序列化
（字段名即 JSON 键），随后 `o2.b.c()` 算 `clientDataHash = SHA-256(clientDataJSON)` 送入 TEE。

真实样本（X 创建）：

```json
{
  "androidPackageName": "com.twitter.android",
  "challenge": "G177NFi-LgXeULORKF5DD4TcJ-BMzg207-nWehB5PXw",
  "origin": "android:apk-key-hash:D9mgz7B7ZZUJl7Tq69xTkxOSORqkBlOKOwQHO8LOL+k",
  "type": "webauthn.create"
}
```

| 调用方 | origin 形态 | 编码 |
|---|---|---|
| Android App | `android:apk-key-hash:<签名证书 SHA-256>` | **标准 Base64**（含 `+/`，非规范 base64url）|
| 浏览器 | `https://` + rpId | 框架自带 link 格式（`o2.b.d()`）|

**各 RP 的 origin 策略**（2026-11-24 复测修正）：X、Telegram 的创建与登录**均接受
原生 `android:apk-key-hash` 源**（base64url 归一后），不需要 web 源改写。早期
（11-15）「Telegram 只认 web 源、报 `PASSKEY_ORIGIN_MISMATCH`」的结论已被推翻
——当时另一变量（userHandle 缺失，见 §6.1）未被识别。按 RP 分组改写机制保留
（`WEB_RPS`/`WEB_ORIGIN_PACKAGES`），当前名单空置，供未来确有 web-only 要求的 RP 使用。

## 4. TEE 交互（CTAP 风格 APDU，经 MiFido_TeeConnector）

```
0F 04                                → getInfo：FIDO_2_0，扩展 credProtect/credBlob/devicePubKey…
0F 01 A6 {                           → makeCredential
    1: <clientDataHash 32B>,
    2: {id:"telegram.org", name:"Telegram Messenger"},
    3: {id:"<userHandle>", name:"+86…", displayName:"…"},
    4: [{alg:-7 (ES256)}, {alg:-257 (RS256)}],
    6: {sysTime, sysAccountId},
    7: {rk:true, up:true}
}  → 返回 packed attestation：authData + {alg:-7, sig, x5c:[XMCTAP-000000002 小米 CA 证书链]}
0F 51                                → pksInfo：passkey 元数据记录（含签名）
```

密钥对在 TEE 内生成，私钥不出 TA。密钥库走 `MiCloudKeyBoxService`（passkeeper）：
`miuikeybox.key.hardstore` 硬件主密钥 + `MiKeyBoxTAService` 本地 TA 调用（返回 success/200 TLV），
云同步为 E2EE——**无服务端准入校验**，因此 FuckMiuiPasswords 无需 hook `com.miui.cloudservice`。

## 5. 响应组装（含隐私降级）

TEE 给出带小米 CA 证书链的 packed attestation，ASM 输出前**降级**为 `fmt:"none"`
（隐私保护标准做法，且恰好免去 RP 信任小米 CA 的问题）：

```
attestationObject = {"fmt":"none", "attStmt":{}, "authData":<…>}

registrationResponseJson = {
  "id", "rawId", "type":"public-key", "authenticatorAttachment":"platform",
  "response": {
    "clientDataJSON", "attestationObject", "authenticatorData",
    "publicKey": "<SPKI base64>", "publicKeyAlgorithm": -7,
    "transports": ["hybrid","internal"]
  },
  "clientExtensionResults": {}
}
```

authData 字节布局：

```
rpIdHash(32) | flags(1) | signCount(4) |
[aaguid(16)="XMCTAP-000000002" | credIdLen(2) | credId | COSE key]
flags：创建 0x45 = UP|UV|AT；认证 0x05 = UP|UV
```

## 6. 认证（登录）流程

与创建同路径，差异点：

- `o2.b.a()` 组 `type:"webauthn.get"` 的 clientData；TEE 侧走 getAssertion
- 响应 = `{clientDataJSON, authenticatorData, signature, userHandle}`
- **`signature = ES256(authData ‖ SHA-256(clientDataJSON))`** ——因此 origin 改写必须发生在
  **进 TEE 之前**（FuckMiuiPasswords 的 ClientDataFixHook 即为此设计：签名/响应/服务端校验三者一致）
- `userHandle` = 注册时的 user.id（Telegram 借此编 `datacenterId:userId` 做跨 DC 登录路由；
  X 等 RP 登录校验同样要求它）
- 服务端校验：challenge 匹配、type=webauthn.get、rpIdHash、UP/UV、**ES256 验签**、signCount 递增

### 6.1 userHandle 陷阱（★关卡三：MiFido 自抹）

TEE 的 getAssertion 响应**本来就带 user**（CBOR key 4 = `{id, displayName, name}`），
但 `b2/j.N`（PasskeyAuthenticator.setUserSelected，日志锚
`setUserSelected isDiscoverCredential:`）在**非 discoverable（allowList）断言**里执行
`d0.d = null` 后把响应重新序列化——严格照 CTAP2「allowList 断言不带 user」语义。
随后 `o2/j.d` 重解析的就是这份被抹过的字节，`c3/a.c()` 组 JSON 时 userHandle 整个缺席。

- 创建响应本就没有 userHandle 字段 → **创建能过**
- 登录断言缺 userHandle → **RP 服务端直接拒**（2026-11-24 X 实测：指纹验证后报错）
- discoverable 流程（无 allowList，如 PasskeyDemo）不抹——所以早期样本带 userHandle
- userHandle **不在 TEE 签名覆盖内**（签名只盖 authData‖clientDataHash），补回安全

FuckMiuiPasswords 的 `UserHandleFixHook` 把 `isDiscoverCredential` 翻成 true，
走「保留 user + userSelected=true」分支（userSelected 全下游无人消费，零副作用）。
修复后 X 登录实测通过（2026-11-24）。

真实认证样本（PasskeyDemo 实测，服务端五项校验全绿）：

```json
{
  "id": "…", "type": "public-key", "authenticatorAttachment": "platform",
  "response": {
    "clientDataJSON": "<base64url: type=webauthn.get, origin=android:apk-key-hash:…>",
    "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA",
    "signature": "MEQCICWhZ7UxztT6UtdUM-OI5NcMg2yAFBLV4M5OCTy1IjWGAiBLvYzBLCvKGriqDSlyOAt9aUPFx9oyqnJK_3l4p2nuEA",
    "userHandle": "ZGVtbw"
  }
}
```

## 7. 进程地图

| 进程 | 角色 | FuckMiuiPasswords hook 价值 |
|---|---|---|
| `com.fido.asm` | 身份校验 + clientData + TEE + 响应组装 | **全部功能**（伪造/短路/源级 origin 改写）|
| `com.miui.passwords` | Provider 入口 + FidoCredentialActivity + setResult 回传 | 仅排障 dump（三轮实测零功能贡献）|
| `com.miui.cloudservice` | passkeeper/keybox（本地 TA + E2EE 云同步）| 无（无服务端门槛）|

## 8. 三道关卡速查

| 关卡 | 表现 | 根因 | FuckMiuiPasswords 对策 |
|---|---|---|---|
| ★一 | `asset not support` | 小米服务端 (rp, packageName) 白名单未收录（另比对签名指纹） | AssetlinkGate 本地闸门（assetlinks.json DAL 每次现查）+ NetForge 伪造响应 + SHORT-CIRCUIT |
| ★二 | `PASSKEY_ORIGIN_MISMATCH`（历史） | 各 RP 的 origin 策略不同 | 按 RP 分组改写 origin（源级，TEE 前）——2026-11-24 实测 X/TG 均收 app 源，名单已空置 |
| ★三 | 创建成功、登录报错（响应无 userHandle） | MiFido setUserSelected 在非 discoverable 断言自抹 user | UserHandleFixHook（isDiscoverCredential 翻 true 保住 user，§6.1）|
