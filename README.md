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

产物 `FuckMiuiPasswords.apk`。工具链在 `toolchain/sdk`（platforms;android-37.0 + build-tools;36.0.0，
HookTool 是 Java 21 字节码，34 的 d8 不认）。libxposed api 仅编译不打包（运行时由框架提供）。
SDK 级别：minSdk 36 / targetSdk 37 / compileSdk 37。

**方式 B：Android Studio。** `Open` 选本目录 → Gradle sync → `Build > Build APK(s)`。

## 安装与激活

1. `adb install -r FuckMiuiPasswords.apk`
2. **LSPosed 管理器 → 模块 → 启用 FuckMiuiPasswords**，作用域勾选：
   - `com.fido.asm`（**唯一必需**）
   - `com.miui.passwords`（可选，响应 dump + 兜底）
3. **重启手机**（模块为 libxposed 现代声明：`META-INF/xposed/*`，无经典 xposed meta-data）

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
