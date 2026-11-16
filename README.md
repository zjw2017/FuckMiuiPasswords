# FuckMiuiPasswords —— HyperOS 小米密码管理 passkey 绕过 LSPosed 模块

**状态：v2.0 实测通过 —— Telegram（web 源组）✅、X/com.twitter.android（apk-key-hash 组）✅**

基于 libxposed 新 API + [HookTool](https://github.com/HChenX/HookTool)（HChenX，LGPL-2.1）架构。

## 背景：两道服务端/格式关卡

1. **`asset not support`**：小米 `api.account.xiaomi.com/pass/verify/assetlink`
   服务端维护 (rp, packageName) 注册库，只收录了小米自家（account.xiaomi.com），
   其余一律 `{"code":210003,"desc":"asset_not_support"}` → **伪造校验响应**绕过。
2. **`PASSKEY_ORIGIN_MISMATCH`**：MiFido 产出的 `clientDataJSON.origin` 是
   `android:apk-key-hash:<指纹>`（且用标准 Base64）。是否接受由各 RP 服务端自定：
   - Telegram 只认 web 源（官方 GPM 流程同样会挂）→ 改写为 `https://telegram.org`
   - X 等规范 RP 接受 apk-key-hash → 保留形式，仅把编码修成规范 base64url

⚠️ **登录 passkey 时模块必须保持启用**（断言签名覆盖 clientDataJSON，改写在 TEE 签名前，
create/get 同一改写点，签名/响应/服务端校验三者一致）。

## 小米 Passkey 创建与认证全流程（逆向实录）

> 以下为 2026-11-16 于 HyperOS（com.miui.passwords 1.1.26 / com.fido.asm v220260331）
> 实测逆向所得，含 APDU 级细节与真实报文样本。

### 创建（注册）时序

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
  │ ④ 以 action=com.xiaomi.credential.provider.FIDO_CREDENTIAL_CREATE 启动，
  │    经 AIDL(org.fidoalliance.aidl.activity.CREDENTIAL_PROVIDER_OPERATION)
  ▼ binder
com.fido.asm（MiFido，包内含 Nok Nok UAF 框架）
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
  │ ⑨ RP 校验 challenge/type/rpIdHash/origin ─── ★关卡二：origin 白名单
```

### ⑤ App 身份校验（★关卡一）

`i5.b`（AppAuthenticationManager）→ 先查内存缓存（TTL 180s）→ 未命中则：

```
POST https://api.account.xiaomi.com/pass/verify/assetlink
form: rp=telegram.org
      assetlinkUrlList=["https://telegram.org/.well-known/assetlinks.json", ...]
      namespace=android_app | web
      fingerprints=<调用方签名证书 SHA-256 冒号格式>
      packageName=<调用方包名>
      serialNo=<随机 UUID>
→ {"code":0, ...}                            ← 通过
→ {"code":210003, "desc":"asset_not_support",
   "msg":"cannot be fount packagename:<pkg>"} ← 未注册（服务端 (rp, packageName) 库）
```

实测该库仅收录小米自家（account.xiaomi.com + com.xiaomi.account，报 `fingerprints not match`
即代表已注册）；失败时 `p2.e`（VendorValidator）抛 `vendor validate failed : message=...`，
`p2.c`（FacetIDsValidator）终结流程——本模块的 NetForge 伪造 + SHORT-CIRCUIT 就在这两层。

### ⑥ clientDataJSON 与 origin

`o2.b`（ClientDataProcessor）以 POJO `c3/k`{androidPackageName, challenge, origin, type} 序列化：

```json
{"androidPackageName":"com.twitter.android",
 "challenge":"<base64url>",
 "origin":"android:apk-key-hash:D9mgz7B7…LOL+k",   ← App 端：签名证书 SHA-256
 "type":"webauthn.create"}                          ← 或 "webauthn.get"
```

| 调用方 | origin 形态 | 备注 |
|---|---|---|
| Android App | `android:apk-key-hash:<指纹>` | 用**标准 Base64** 编码（非规范 base64url）|
| 浏览器 | `https://` + rpId | 框架自带 link 格式（`o2.b.d()`）|

随后 `o2.b.c()` 算 `clientDataHash = SHA-256(clientDataJSON)`，与请求一起进 TEE。

### ⑦ TEE 交互（CTAP 风格 APDU，经 MiFido_TeeConnector）

```
0F 04                              → getInfo：FIDO_2_0 + credProtect/credBlob 等扩展
0F 01 A6 {1:clientDataHash,        → makeCredential
          2:{id:"telegram.org", name:"…"},
          3:{id:"<userHandle>", name, displayName},
          4:[{alg:-7(ES256)}, {alg:-257(RS256)}],
          6:{sysTime, sysAccountId},
          7:{rk:true, up:true}}
        → 返回 packed attestation：authData + {alg:-7, sig, x5c:[XMCTAP-000000002 证书链]}
0F 51                              → pksInfo：passkey 元数据记录（签名）
```

密钥对在 TEE 内生成；私钥不出 TA。密钥库走 `MiCloudKeyBoxService`
（`miuikeybox.key.hardstore` 硬件主密钥 + MiKeyBoxTAService 本地 TA，云同步 E2EE，
**无服务端准入校验**——因此本模块无需 hook com.miui.cloudservice）。

### ⑧ 响应组装（含隐私降级）

TEE 给的是带小米 CA 证书链的 packed attestation，ASM 输出前**降级**为 `fmt:"none"`：

```
attestationObject = {"fmt":"none", "attStmt":{}, "authData":<…>}
registrationResponseJson = {
  "id","rawId","type":"public-key","authenticatorAttachment":"platform",
  "response":{"clientDataJSON","attestationObject","authenticatorData",
              "publicKey"(SPKI), "publicKeyAlgorithm":-7,
              "transports":["hybrid","internal"]},
  "clientExtensionResults":{}}
```

authData 布局：`rpIdHash(32) | flags(1) | signCount(4) | [aaguid(16) | credIdLen(2) | credId | COSE key]`
（flags 创建时 0x45=UP|UV|AT，认证时 0x05=UP|UV）。

### 认证（登录）时序

与创建同路径，差异仅在：
- `o2.b.a()` 组 `type:"webauthn.get"` 的 clientData；TeeConnector 发 `getAssertion`
- 响应 = `{clientDataJSON, authenticatorData, signature, userHandle}`
- **signature = ES256(authData ‖ SHA-256(clientDataJSON))**——所以 origin 必须在
  **进 TEE 之前**改写，否则服务端验签必挂（本模块的 ClientDataFixHook 即为此设计）
- `userHandle` = 注册时的 user.id（Telegram 用它编 `datacenterId:userId` 做跨 DC 登录路由）
- 服务端校验：challenge 匹配、type=webauthn.get、rpIdHash、UP/UV、**ES256 验签**、signCount 递增

### 进程地图

| 进程 | 角色 | 本模块 hook 价值 |
|---|---|---|
| `com.fido.asm` | 校验 + clientData + TEE + 响应组装 | **全部功能**（短路/伪造/源级 origin 改写）|
| `com.miui.passwords` | Provider 入口 + FidoCredentialActivity + setResult 回传 | 仅排障 dump（三轮实测零功能贡献）|
| `com.miui.cloudservice` | passkeeper/keybox（本地 TA + E2EE 云同步）| 无需（无服务端门槛）|

## origin 策略（按调用方包名分组，`config/Config.java`）

| 组 | 包名 | 处理 |
|---|---|---|
| web 源组 `WEB_ORIGIN_PACKAGES` | 官方 Telegram 三包（可继续加客户端） | origin → `https://telegram.org` |
| 其它 App `OTHER_APPS_MODE` | 全部 | 保留 `android:apk-key-hash:`，编码修 base64url |

## 架构（v2.0，HookTool 范式）

```
FidoEntrance (ModuleEntrance)          生命周期分发
├── hook/FidoAsmHook (AbsModule)       com.fido.asm：核心
│   ├── net/NetForge                   URL.openConnection 动态挂连接类：伪造 assetlink + 探测日志
│   ├── hook/VendorValidateHook        DexStringLocator 定位 p2.e，before→setResult 短路
│   └── hook/ClientDataFixHook         源级改写 origin + 同步重算 SHA-256（carrier/hash-input 双钩）
└── hook/PasswordsHook (AbsModule)     com.miui.passwords：排障
    └── hook/ResultDumpHook            setResult 响应 dump + 事后兜底改写（幂等）
util/OriginFix、util/DexStringLocator  origin 改写 / 常量串反查类（抗混淆）
```

四层全部抗混淆：常量串定位（`vendor validate failed`、`webauthn.`）+ 方法形态匹配，
不写死目标类名，APK 升级自动重定位。

## 构建

**方式 A（已用）：手工流水线，不依赖 Gradle。**

```bash
bash manual-build/fetch-libs.sh   # 首次：拉依赖到 manual-build/libs/（jitpack/maven）
bash manual-build/build.sh        # javac → d8 → aapt2 → zipalign → apksigner
```

产物 `FuckMiuiPasswords.apk`。工具链在 `toolchain/sdk`（platforms;android-34 + build-tools;36.0.0，
HookTool 是 Java 21 字节码，34 的 d8 不认）。libxposed api 仅编译不打包（运行时由框架提供）。

**方式 B：Android Studio。** `Open` 选本目录 → Gradle sync → `Build > Build APK(s)`。

## 安装与激活

1. `adb install -r FuckMiuiPasswords.apk`
2. **LSPosed 管理器 → 模块 → 启用 FuckMiuiPasswords**，作用域勾选：
   - `com.fido.asm`（**唯一必需**，全部功能 hook 都在这）
   - `com.miui.passwords`（**不需要**——三轮实测证明功能贡献为零；
     仅想观察响应原文时临时勾选看 ResultDump 日志）
3. **重启手机**（模块为 libxposed 现代声明：`META-INF/xposed/*`，无经典 xposed meta-data）

## 实测结论（2026-11-16，三轮对照）

| 轮次 | passwords 是否在作用域 | 结果 |
|---|---|---|
| PasskeyDemo 第一轮 | 否 | 创建全绿 |
| PasskeyDemo 第二轮 | 是 | 创建+认证（ES256 验签）全绿；其 hook 仅产出 RESULT dump |
| X 真实应用（创建+登录）| 是 | 全部成功；功能事件全部在 com.fido.asm，passwords 侧 ORIGIN FIX/FORGE 触发数 = **0** |

X 案例同时验证了"其它 App"分支：指纹含 `+`（`…LOL+k`）被修成 base64url（`…LOL-k`），
且断言（登录）走同一源级改写点——签名覆盖改写后的 clientDataJSON，X 服务端验签通过。

**判定：作用域收窄至 `com.fido.asm` 即可**（scope.list 已默认如此）。

## 验证

```bash
adb logcat -s FuckMiuiPasswords
```

预期（X 的实测样本）：

```
FuckMiuiPasswords: package ready: com.fido.asm
FuckMiuiPasswords: SHORT-CIRCUIT vendor validate
FuckMiuiPasswords: ORIGIN FIX(src)[com.twitter.android]: android:apk-key-hash:...+k
                                                -> android:apk-key-hash:...-k
```

## 如果还是失败

1. **过了 vendor validate 又冒出新错误**：把 `NET <= ...` 日志里的接口 URL 加进
   `Config.forgeBodyFor()`（注释里有示例格式）。
2. **SHORT-CIRCUIT / clientData: no method matched**：目标 APK 升级改了结构，
   发 FuckMiuiPasswords 日志重新定位。
3. **完全无日志**：LSPosed 里确认模块已启用 + 作用域已勾 + 已重启。

## 已知边界

- 生成的 passkey 仍绑定 rpId、仍要求锁屏/指纹，私钥在 TEE；被跳过的只是
  小米服务端 RP 白名单与 origin 格式校验。
- 混淆名只影响"形状匹配"层，当前对照：FidoAuthen2 v220260331、密码管理 1.1.26。
- Telegram 服务端 origin 白名单纯服务端硬编码（客户端是哑管道，源码已验证），
  官方 GPM 流程同样过不了第 2 关。
