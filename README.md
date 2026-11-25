# FuckMiuiPasswords —— HyperOS 小米密码管理 passkey 绕过 LSPosed 模块

**状态：实测通过 —— Telegram、X 创建+登录四链路全通（2026-11-24/25，apk-key-hash 源）**

基于 libxposed 新 API + [HookTool](https://github.com/HChenX/HookTool)（HChenX，LGPL-2.1）架构。

## 背景：三道关卡

1. **`asset not support`**：小米 `api.account.xiaomi.com/pass/verify/assetlink`
   服务端维护 (rp, packageName) 注册库，只收录了小米自家（account.xiaomi.com），
   其余一律 `{"code":210003,"desc":"asset_not_support"}`；已注册但签名指纹不符
   则报 `fingerprints not match`。→ **本地闸门复刻后伪造校验响应**绕过
   （见下「关卡一闸门」）。
2. **origin 格式**：MiFido 产出的 `clientDataJSON.origin` 是
   `android:apk-key-hash:<指纹>`（标准 Base64）。2026-11-24 实测 **X、Telegram
   创建+登录均接受**（修成规范 base64url 后）——早期「Telegram 只认 web 源」
   结论已证伪（真凶是第 3 关）。按 RP 的 web 改写机制保留、名单空置。
3. **userHandle 自抹（登录专属，真凶）**：MiFido `setUserSelected` 在非
   discoverable（allowList）断言里把 user 抹掉再序列化，WebAuthn 响应缺
   `userHandle` → RP 登录拒绝。创建响应本无此字段，所以症状是
   「创建成功、登录报错」。→ `UserHandleFixHook` 修复（见下「架构」）。

⚠️ **登录 passkey 时模块必须保持启用**——每次登录断言都要靠
`UserHandleFixHook` 保住 userHandle（签名只盖 authData‖clientDataHash，
userHandle 补回安全；create/get 同一源级改写点，签名/响应/服务端校验三者一致）。

## 小米 Passkey 创建与认证全流程

完整逆向实录见 **[docs/xiaomi-passkey-flow.md](docs/xiaomi-passkey-flow.md)**：
创建/认证时序图、`pass/verify/assetlink` API 报文、clientDataJSON/authData 布局、
TEE CTAP 级 APDU（getInfo/makeCredential/pksInfo）、packed→fmt:none 隐私降级、
断言签名机制（origin 改写须在进 TEE 前的原理）、三进程地图、两道关卡速查。

一句话版：App → 凭据框架/选择器 → 密码管理 → **MiFido(com.fido.asm)**
（①服务端 RP 白名单校验 → ②组 clientDataJSON → ③TEE 生成密钥/attestation）
→ 降级 fmt:none 回传 → RP 校验（challenge/rpIdHash/origin/验签）。

## TOTP 云同步（动态令牌）

完整逆向实录见 **[docs/xiaomi-totp-sync-flow.md](docs/xiaomi-totp-sync-flow.md)**：
同步协议（Mi Cloud PDC）字段清单、syncExtensionStr 通道被服务器丢弃的探针实录、
E2EE blob 钥匙栈（record key→AppKey→keybag/TA）、独立信封方案（blob.t）与 hook 定位表、
清空语义与存量回灌、双机闭环实测记录。

一句话版：密码管理同步默认**静默丢弃 TOTP 四列**（totpSecret/Algorithm/Issuer/Digits）；
TotpSyncHook 把 TOTP 封成**独立的第二个 E2EE 信封**挂在 blob 的 `"t"` 键（复用官方
j()/g() 封装机器，与密码同层同钥匙栈、模块零密钥）——服务器只见密文；**无模块/旧版
客户端天然安全，密码明文全程纯净**；编辑/删除/新增双向同步，两端装模块即闭环。

## origin 策略（`config/Config.java`）

| 组 | 范围 | 处理 |
|---|---|---|
| web 源组 `WEB_RPS` | 空（2026-11-24 实测 X/TG 均收 app 源） | 机制保留，供未来 web-only RP（rpId → `https://<rpId>`，无硬编码） |
| 其它 App `OTHER_APPS_MODE` | 全部 | 保留 `android:apk-key-hash:`，编码修 base64url |

## 关卡一闸门（伪造 code:0 之前的 identity 校验，`net/AssetlinkGate.java`）

无条件放行等于拆门——任何 App 都能借道模块对任意 rpId 创建/断言 passkey。
闸门把服务端的核验搬到本地，伪造的 `code:0` 只发给过闸的调用方：

**每次抓 RP 的 assetlinks.json 按标准 DAL 语义比对**（get_login_creds +
android_app + 包名 + 指纹），无静态白名单——调用方换签名、RP 更新声明自动
跟上，零配置维护。声明 URL 只采信 rp 域名内（含子域），防调用方塞私有 URL
伪造声明；浏览器流（web namespace）比对声明里的 **web 条目**（site=`https://<rpId>`
\+ get_login_creds，网站认自己的源，x.com 有、telegram.org 无）。

拒绝时伪造忠实失败体（asset_not_support / fingerprints not match），上游抛原生
`vendor validate failed : message=…serialNo=…`，与真机拒批行为一致。
`ASSETLINK_GATE_MODE`：**建议先 `log`**（只记日志放行）跑几天看 GATE 行，
确认各调用方都能过 DAL 后改 `enforce`；`off` = 旧行为无条件放行。

## 架构（HookTool 范式）

```
FidoEntrance (ModuleEntrance)          生命周期分发
├── hook/FidoAsmHook (AbsModule)       com.fido.asm：核心
│   ├── net/NetForge                   URL.openConnection 动态挂连接类：伪造 assetlink + 探测日志
│   ├── net/AssetlinkGate              关卡一闸门：assetlinks.json DAL 每次现查，两层钩子共用
│   ├── hook/VendorValidateHook        DexStringLocator 定位 p2.e，过闸后 setResult 短路
│   ├── hook/ClientDataFixHook         源级 origin 归一/改写 + 同步重算 SHA-256（carrier/hash-input 双钩）
│   └── hook/UserHandleFixHook         关卡三：setUserSelected 翻 isDiscoverCredential 保住 userHandle
└── hook/PasswordsHook (AbsModule)     com.miui.passwords
    ├── hook/TotpSyncHook              TOTP 云同步桥：动态令牌独立 E2EE 信封（blob.t）随密码同步
    └── hook/ResultDumpHook            setResult 响应 dump + 事后兜底改写（幂等）
util/OriginFix、util/DexStringLocator  origin 改写 / 常量串反查类（抗混淆）
```

全部抗混淆：常量串定位（`vendor validate failed`、`webauthn.`、
`setUserSelected isDiscoverCredential:`）+ 方法形态匹配，
不写死目标类名，APK 升级自动重定位。

## 构建

**方式 A（已用）：手工流水线，不依赖 Gradle。**

```bash
bash manual-build/fetch-libs.sh   # 首次：拉依赖到 manual-build/libs/（jitpack/maven）
bash manual-build/build.sh        # javac → d8 → aapt2 → zipalign → apksigner
```

产物 `FuckMiuiPasswords.apk`。工具链在 `toolchain/sdk`（platforms/android-37.0 + build-tools/36.0.0）。
libxposed api 仅编译不打包（运行时由框架提供）。

**方式 B：Android Studio。** `Open` 选本目录 → Gradle sync → `Build > Build APK(s)`。

## 安装与激活

1. `adb install -r FuckMiuiPasswords.apk`
2. **LSPosed 管理器 → 模块 → 启用 FuckMiuiPasswords**，作用域勾选：
   - `com.fido.asm`（passkey 绕过的全部 hook 都在这）
   - `com.miui.passwords`（**TOTP 云同步所需**）
3. **重启手机**（模块为 libxposed 现代声明：`META-INF/xposed/*`）

## 实测结论（2026-11-16，三轮对照）

| 轮次 | passwords 是否在作用域 | 结果 |
|---|---|---|
| PasskeyDemo 第一轮 | 否 | 创建全绿 |
| PasskeyDemo 第二轮 | 是 | 创建+认证（ES256 验签）全绿；其 hook 仅产出 RESULT dump |
| X 真实应用（创建+登录）| 是 | 全部成功；功能事件全部在 com.fido.asm，passwords 侧 ORIGIN FIX/FORGE 触发数 = **0** |

X 案例同时验证了"其它 App"分支：指纹含 `+`（`…LOL+k`）被修成 base64url（`…LOL-k`），
且断言（登录）走同一源级改写点——签名覆盖改写后的 clientDataJSON，X 服务端验签通过。

**判定：passkey 功能收窄至 `com.fido.asm` 即可**。

### TOTP 云同步（2026-11-19，双机闭环）

| 项目 | 结果 |
|---|---|
| 上传：源机 6 行 TOTP 标脏重传（含无 issuer 测试条目） | ✅ 6/6 注入 blob.t 信封，随 record key 加密上云 |
| 下载：接收机（密码管理 1.1.25） | ✅ 6/6 解出回填（密钥/issuer/位数一一对应） |
| UI 动态令牌出码 | ✅ 人工验证通过 |
| 编辑 / 删除 / 新增语义 | ✅ 双向同步、删除对端清空、新增自动携带（复合明文轮次实测，信封同链路） |
| syncExtensionStr 候选通道 | ❌ 探针实证被 PDC 服务器丢弃（详见文档第 2 节） |

> 载体两代演进：复合明文（能同步，但无模块裸恢复会把 json 前缀污染进密码）
> → **独立信封 blob.t（现行）**：TOTP 自成一个与密码同规格的 E2EE 信封挂在
> blob 附加键上，无模块/旧版客户端原生忽略、密码全程纯净。信封版双机闭环
> 复测通过（6/6）。⚠️ 早期信封构建的合成 Cursor 未定位（j() 直接读当前行抛
> CursorIndexOutOfBounds），信封注入静默失败——已修复，旧构建传过裸 blob 的
> 设备需按"如果还是失败"第 4 条重传一轮。

**判定：TOTP 同步需 `com.miui.passwords` 在作用域、且两端装模块**（scope.list 已含两者）。

### passkey 三关补完（2026-11-24/25）

| 项目 | 结果 |
|---|---|
| userHandle 自抹根因定位（setUserSelected；TeeConnector 明文 APDU 逐层对账） | ✅ UserHandleFixHook 修复，X 登录实测通过 |
| origin 证伪：X、Telegram 创建+登录均收 apk-key-hash 源 | ✅ web 改写名单清空（机制保留） |
| AssetlinkGate 收敛为 DAL-only（每次现查 assetlinks.json，声明 URL 限 rp 域名） | ✅ X 创建/登录两链路 GATE PASS |
| X、Telegram 创建+登录四链路 | ✅ 全通（签名绑定逐条对账） |

## 验证

```bash
adb logcat -s FuckMiuiPasswords
```

预期（X 的实测样本）：

```
FuckMiuiPasswords: package ready: com.fido.asm
FuckMiuiPasswords: NET <= GET https://x.com/.well-known/assetlinks.json body(5788B)=[...
FuckMiuiPasswords: GATE PASS rp=x.com pkg=com.twitter.android
FuckMiuiPasswords: SHORT-CIRCUIT vendor validate [gate PASS] rp=x.com pkg=com.twitter.android
FuckMiuiPasswords: ORIGIN FIX(src)[com.twitter.android]: android:apk-key-hash:...+k
                                                -> android:apk-key-hash:...-k
FuckMiuiPasswords: userHandle fix: isDiscoverCredential false->true（保住 user/userHandle）
```

闸门裁决（log/enforce 模式）每个调用方一行（每次现查 assetlinks.json）。

## 如果还是失败

1. **过了 vendor validate 又冒出新错误**：把 `NET <= ...` 日志里的接口 URL 加进
   `Config.forgeBodyFor()`（注释里有示例格式）。
2. **SHORT-CIRCUIT / clientData: no method matched**：目标 APK 升级改了结构，
   发 FuckMiuiPasswords 日志重新定位。
3. **完全无日志**：LSPosed 里确认模块已启用 + 作用域已勾 + 已重启。
4. **TOTP 没同步**：抓 `totp-sync` 日志定环节——缺 `upload 注入 blob.t 信封`
   是上传侧、缺 `download 解出 TOTP` 是下载侧；装过早期信封构建（修复前）的
   设备传过裸 blob 且行已同步（localStatus=-1）不会再传，把 TOTP 条目编辑一遍
   触发重传，或删 `shared_prefs/fuckmiuipasswords_totp.xml` 后重启密码管理强制回灌。

## 已知边界

- 生成的 passkey 仍绑定 rpId、仍要求锁屏/指纹，私钥在 TEE；被跳过的只是
  小米服务端的准入校验——语义已由本地闸门（AssetlinkGate，DAL 核验）接管，
  enforce 模式下不在 RP 声明里的调用方会被拒批。
- 混淆名只影响"形状匹配"层，当前对照：FidoAuthen2 v220260331、密码管理 1.1.26。
- 早期「Telegram 只认 web 源」结论已证伪（2026-11-24 实测创建+登录均收
  apk-key-hash 源）——当时未识别的真凶是 userHandle 自抹。
