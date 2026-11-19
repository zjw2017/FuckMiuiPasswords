# 小米密码管理 TOTP 云同步全流程

> 2026-11-19 于 HyperOS 双机实测逆向（源机 com.miui.passwords 1.1.26 / 接收机 1.1.25，
> Mi Cloud PDC 同步报文 + content provider 实测）。结论：动态令牌四列默认静默丢失，
> 可借道 E2EE 明文与密码同层同步——FuckMiuiPasswords 的 TotpSyncHook 已实现并双机闭环。

## 1. 总览

密码管理云同步走 **PasswordSyncService → Mi Cloud PDC**，按水位 token 增量收发：

```
本地 password_record（含 totpSecret/totpAlgorithm/totpIssuer/totpDigits）
  │ 上传：收集脏行（localStatus 0/1/2）→ u2/d.J() 组 content JSON → j() E2EE 包装
  ▼
Mi Cloud PDC   pdc.micloud.xiaomi.net
  /mic/pdc/v4.1/apps/passwords/spaces/default/{syncall | records | records/index}
  │ 下载：水位 token（pass_water_marker/passwords_sync_token）拉变更，push 触发
  ▼
P2/c.G() 解析 content JSON → g() E2EE 解包 → u2/d.d() 重建 ContentValues 落库
```

**问题**：上传序列化 `u2/d.J()` 与下载解析 `P2/c.G()` 的字段清单严格对称，
但都不含 TOTP 四列——行正常同步、动态令牌密钥静默丢失，且已同步行
（localStatus=-1）不会再传，丢失不可见。

## 2. content JSON 字段清单与通道评估

`u2/d.J()` 输出（`P2/c.G()` 按同名 key 解析）：

```
packageName name userName phone emailAddress password signatures secretKey
credentialName accountUUID domain label remarkNotes passkeyId captiveWifiSSID
captiveWifiBSSID syncExtensionStr1-3 syncExtensionNum1-3 creationTime modificationTime
```

| 候选载体 | 结构 | 实测结论 |
|---|---|---|
| syncExtensionStr1-3 / Num1-3 | 客户端双向（J/G 都处理），app 从不写入 | **被 PDC 服务器丢弃**：纯字符串探针入库、J() 原生序列化上云，对端记录 eTag 更新而字段未回。客户端 schema 对称 ≠ 服务器存储 |
| `password`（E2EE blob） | `{encryptedPassword, encryptedRecordKey, recordIV, appKeyVersion}` | **双向存取 ✓**（密码本体即靠它同步），选定为载体 |

## 3. E2EE blob 与钥匙栈

blob 的四个键即官方钥匙栈的三层包装（与 passkey 的 keybag/TA 同源，见
[xiaomi-passkey-flow.md](xiaomi-passkey-flow.md) 第 4 节）：

```
encryptedPassword = E2EE(record key, 明文)          ← 每条记录随机 record key + recordIV
encryptedRecordKey = AppKey 包装的 record key        ← AppKey 带版本（appKeyVersion）
AppKey ← master key ← keybag/TA（按设备 TA 公钥分别包装，KeyBox 通道）
```

blob JSON 对服务器不透明（只见密文）——**扩展明文就等于在官方 E2EE 通道里开新车道**。

## 4. 复合明文：TOTP 与密码同层

把 E2EE 明文从纯密码扩成复合体，长度前缀 + 标记双重判别：

```
复合明文 = <totpJson 长度> "\n" <totpJson> <密码>
totpJson = {"__mfptp":1, "s":"<secret>", "a":"HMACSHA1", "i":"<issuer>", "d":6}
```

长度前缀保证密码任意字符安全；解析失败/无标记即视为纯密码（误判概率≈0）。
**本地层永远只见纯密码**——w2/e（本地加密）、DB password 列、自动填充的
取密路径全部不受复合格式影响。

四个 hook（全部字符串锚点 + 方法形态定位，1.1.25/1.1.26 混淆映射相同
（u2.d / P2.c / H3.c 直名均命中））：

| hook | 定位锚点 | 时机 | 动作 |
|---|---|---|---|
| 上传 E2EE 包装入口 `P2/c.j(record, Cursor)` | `"decrypted password error by local key"` | before | record 的 ContentValues 成员按列名取 totp → 暂存 |
| 加解密边界 `H3.c.b(String, keyObj, mode)` | 直名 + 形态 `(String,?,int)→String` | mode=1 before | 明文 → 复合体（随后被 record key 加密） |
| 同上 | 同上 | mode=2 after | 剥出 totp、还原纯密码（setResult） |
| 下载解包出口 `P2/c.g(record)` | `"decrypted password is null"` | after | 暂存的 totp 写进 record 的 ContentValues 成员 |
| 落库出口 `u2.d.d(record)` | `"syncExtensionStr1"` | after | 成员里的 totp 四列带进落库 ContentValues |

落库出口是必需的一环：`d()` 重建 ContentValues 只认混淆字段名，而下载解析
（G()）不填 totp 字段——成员（基类的 ContentValues，按类型查找、不依赖字段名）
是两代代码之间唯一稳定的传值面。

**清空语义**：totp 移除后复合体不再生成，对端解出纯密码、成员无 totp，
落库时四列自然为 NULL——无需额外的"清空信号"。

**存量回灌**：装模块后一次性把已同步的 TOTP 行标 `localStatus=1`（MODIFIED）
强制重传（SharedPreferences 一次性闸防循环），让复合明文覆盖云端旧值。

## 5. 安全性

| 方案 | 小米服务器可见 | 密钥归属 |
|---|---|---|
| syncExtensionStr 明文 | **TOTP 明文** | —（已被服务器丢弃，不可用） |
| 外挂密文键 + 模块内置 AES | 密文 | 随 APK 走，APK+云端同时泄露即破 |
| **复合明文（现行）** | 密文 | 官方钥匙栈（record key→AppKey→keybag/TA），模块零密钥 |

TOTP 与密码获得完全相同的保护；不存在需要轮换的模块密钥。

## 6. 实测记录（双机闭环）

源机 4 行 TOTP（含测试期间新增的第 4 条）重传后，接收机全部原样回填
（密钥/算法/位数一一对应），密码管理 UI 动态令牌正常出码：

```
FuckMiuiPasswords: totp-sync wrap hook: P2.c->j
FuckMiuiPasswords: totp-sync crypto hook: H3.c->b
FuckMiuiPasswords: totp-sync unwrap hook: P2.c->g
FuckMiuiPasswords: totp-sync db-write hook: u2.d->d
FuckMiuiPasswords: totp-sync: 明文已复合（随 record key 加密）
FuckMiuiPasswords: totp-sync: 复合明文已剥离
FuckMiuiPasswords: totp-sync: download 解出 TOTP
```

同步方向语义实测：任一端编辑 TOTP → 同步 → 对端更新；任一端删除 → 对端清空；
新增条目自动携带。

## 7. 进程地图

| 进程 | 角色 | TotpSyncHook 价值 |
|---|---|---|
| `com.miui.passwords:sync` | PasswordSyncService：收发与落库 | **全部四个 hook** |
| `com.miui.passwords` | UI/本地编辑 | 落库出口（编辑重传路径同源）|
| `com.miui.cloudservice` | keybag/AppKey 版本链（见 passkey 文档） | 无（钥匙栈原生复用）|

## 8. 已知边界

- 两端都要装模块：只装上传端 = 云端有密文但对端不解；只装下载端 = 无密文可解。
- 目标混淆对照：密码管理 1.1.25 / 1.1.26（u2.d、P2.c、H3.c 映射一致）；
  换版本后看 `totp-sync: hook 不全` 日志重新定位。
- 模块 action 日志偶发不进 logcat（注册日志正常），验证以 DB 行为准：
  `content query --uri content://miui.autofill/password_record --where "totpSecret IS NOT NULL"`。
