# 小米密码管理 TOTP 云同步全流程

> 2026-11-19 于 HyperOS 双机实测逆向（源机 com.miui.passwords 1.1.26 / 接收机 1.1.25，
> Mi Cloud PDC 同步报文 + content provider 实测）。结论：动态令牌四列默认静默丢失，
> 可挂在 E2EE blob 的**独立信封（blob.t）**上随密码同步——FuckMiuiPasswords 的
> TotpSyncHook 已实现并双机闭环（6/6，UI 出码人工确认）。

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
| `password`（E2EE blob） | {encryptedPassword, encryptedRecordKey, recordIV, appKeyVersion} | **双向存取 ✓**（密码本体即靠它同步），选定为载体——现行方案在其 JSON 上加 `"t"` 键（见第 4 节） |

## 3. E2EE blob 与钥匙栈

blob 的四个键即官方钥匙栈的三层包装（与 passkey 的 keybag/TA 同源，见
[xiaomi-passkey-flow.md](xiaomi-passkey-flow.md) 第 4 节）：

```
encryptedPassword = E2EE(record key, 明文)          ← 每条记录随机 record key + recordIV
encryptedRecordKey = AppKey 包装的 record key        ← AppKey 带版本（appKeyVersion）
AppKey ← master key ← keybag/TA（按设备 TA 公钥分别包装，KeyBox 通道）
```

blob JSON 对服务器不透明（只见密文）——**扩展明文就等于在官方 E2EE 通道里开新车道**。

## 4. 独立信封：TOTP 自成一个 E2EE 信封挂在 blob["t"]

载体两代演进：

| 载体 | 机制 | 结局 |
|---|---|---|
| 复合明文（v1，已废弃） | E2EE 明文扩成 `<totpJson 长度>\n<totpJson><密码>` 复合体 | 能同步，但无模块/旧版客户端裸恢复把 json 前缀污染进密码；兼容剥离钩保留一轮后绝版 |
| **独立信封 blob.t（现行）** | blob JSON 新增 `"t"` 键 = 对 totpJson 原样跑官方 j() 产出的**完整第二信封** | 无模块/旧版客户端原生忽略 `"t"`、密码明文全程纯净 |

### 4.1 载体与 payload

```
"password" 列 = {
  "encryptedPassword":   E2EE(record key, 密码明文),        ← 官方四键，原样保留
  "encryptedRecordKey":  AppKey 包装的 record key,
  "recordIV": ..., "appKeyVersion": ...,
  "t": {                                                     ← 第二信封，与上完全同构
    "encryptedPassword":   E2EE(record key', totpJson),      ← 每次调用独立 record key' + IV
    "encryptedRecordKey":  AppKey 包装的 record key',
    "recordIV": ..., "appKeyVersion": ...
  }
}
```

键名以 j() 序列化器为准——dex 常量表只有 `encryptedPassword / encryptedRecordKey /
recordIV / appKeyVersion`（无 encryptedTotp）：第二信封与密码 blob **完全同构**，
g() 同一台机器原样可开。

totpJson（进 E2EE 前的明文）：

```
{"__mfptp":1, "s":"<secret>", "a":"HMACSHA1", "i":"<issuer>", "d":6}
```

`__mfptp` 标记 + JSON 解析双重判别（误判概率≈0）；a/i 可省略，d 缺省 6。

### 4.2 信封机复用（合成 record）与两个坑

上传/下载都不自己实现密码学——把 totpJson 当"密码"喂给官方 j()/g()，模块零密钥：

- **buildEnvelope(totpJson)**：`w2.e.b` 本地加密得 (cipher, iv) → 合成 record 的
  密码字段 = cipher → `j(合成record, 假Cursor{stringIv=iv})` → record 的
  ContentValues["password"] 里就是完整信封，取回挂到真实 record blob 的 `"t"`。
- **openEnvelope(t)**：合成 record 的密码字段 = 信封 → `g(合成record)` →
  解出明文并本地加密收进字段（+stringIv）→ `w2.e.a` 还原 totpJson。

两个坑（都实测踩过）：

1. **假 Cursor 必须 `moveToFirst()`**：j() 直接 `getString` 读当前行、不自行定位
   （真实调用方传入前已定位）；MatrixCursor 加完行游标停在首行之前，不定位就抛
   `CursorIndexOutOfBoundsException: Before first row`，信封注入**静默**失败
   （异常吞掉后整行裸传）——早期信封构建就死在这里，双机复测 0 行同步。
2. **重入让路**：buildEnvelope/openEnvelope 内部会再进 j()/g()，ThreadLocal
   `TL_FAKE` 标记合成流程，Wrap/Unwrap 钩子见标记即让路，防递归套娃。

### 4.3 四个 hook（字符串锚点 + 形态定位，1.1.25/1.1.26 混淆映射相同）

| hook | 定位锚点 | 时机 | 动作 |
|---|---|---|---|
| 上传包装入口 `P2.c.j(record, Cursor)` | `"decrypted password error by local key"` | before/after | before 取 totp 四列组 payload；after buildEnvelope 生成信封注入 blob["t"] |
| 下载解包出口 `P2.c.g(record)` | `"decrypted password is null"` | before/after | before 拆 blob["t"] openEnvelope 解出 payload；after totp 四列写进 record 的 ContentValues 成员 |
| 落库出口 `u2.d.d(record)` | `"syncExtensionStr1"` | after | 成员里的 totp 四列带进落库 ContentValues |
| 解密边界 `H3.c.b(String, keyObj, mode)` | 形态 `(String,?,int)→String`（实测全 dex 唯一）+ 直名兜底 | mode=2 after | 旧版复合明文（`<len>\n<totpJson><密码>`）剥离还原纯密码——兼容路径，重传一轮洗云后绝版 |

定位方式统一为**锚点/形态/探针自定位，直名（w2.e、s、H3.c）仅兜底**：信封工具
（本地加解密对、密码 setter）用 round-trip（`dec(enc(x))==x`）与哨兵探针自证，
落空响亮告警——目标 APK 换混淆名自动重定位。

落库出口是必需的一环：`d()` 重建 ContentValues 只认混淆字段名，而下载解析
（G()）不填 totp 字段——成员（基类的 ContentValues，按类型查找、不依赖字段名）
是两代代码之间唯一稳定的传值面。

**清空语义**：totp 移除后不再生成 "t"，对端落库钩见成员无 totpSecret 时
四列置 NULL——无需额外的"清空信号"。

**存量回灌**：装模块后一次性把已同步的 TOTP 行标 `localStatus=1`（MODIFIED）
强制重传，让 "t" 信封覆盖云端旧值；SharedPreferences（`fuckmiuipasswords_totp.xml`，
`resync_v4_done`）一次性闸防循环。载体升级（复合→信封）或修复旧构建裸 blob 后
需重传一轮洗云：删闸文件 + 重启密码管理即再触发。

## 5. 安全性

| 方案 | 小米服务器可见 | 密钥归属 |
|---|---|---|
| syncExtensionStr 明文 | **TOTP 明文** | —（已被服务器丢弃，不可用） |
| 外挂密文键 + 模块内置 AES | 密文 | 随 APK 走，APK+云端同时泄露即破 |
| 复合明文（v1，已废弃） | 密文 | 官方钥匙栈，模块零密钥；但裸恢复污染密码 |
| **独立信封 blob.t（现行）** | 密文（"t" 值是第二信封，服务器只见密文） | 官方钥匙栈（record key'→AppKey→keybag/TA），模块零密钥 |

TOTP 与密码获得完全相同的保护；不存在需要轮换的模块密钥。
无模块/旧版客户端对 `"t"` 原生忽略，密码明文全程纯净。

## 6. 实测记录（2026-11-19，双机闭环，两轮）

**第一轮（复合明文载体）**：源机 4 行 TOTP 重传，接收机 4/4 一一回填，UI 出码
人工验证通过；编辑/删除/新增语义双向验证通过（日志：`明文已复合` /
`复合明文已剥离`）。同日载体升级独立信封后首轮复测失败——假 Cursor 未定位，
信封注入静默失败（见 4.2）。

**第二轮（独立信封，现行）**：修复后源机 6 行（GitHub / Google /
Bitwarden（第三方）+ 3 条无 issuer 测试条目）：

```
FuckMiuiPasswords: totp-sync wrap hook: P2.c->j
FuckMiuiPasswords: totp-sync unwrap hook: P2.c->g
FuckMiuiPasswords: totp-sync db-write hook: u2.d->d
FuckMiuiPasswords: totp-sync: resync v4 标脏 rows=6
FuckMiuiPasswords: totp-sync: upload 注入 blob.t 信封   ×6（源机）
FuckMiuiPasswords: totp-sync: download 解出 TOTP        ×6（接收机）
```

6/6 注入、6/6 解出回填（issuer/位数一一对应）、UI 动态令牌出码人工确认通过。

同步方向语义（第一轮实测，信封同链路）：任一端编辑 TOTP → 同步 → 对端更新；
任一端删除 → 对端清空；新增条目自动携带。

## 7. 进程地图

| 进程 | 角色 | TotpSyncHook 价值 |
|---|---|---|
| `com.miui.passwords:sync` | PasswordSyncService：收发与落库 | **全部 hook**（信封注入/解出/落库/兼容剥离） |
| `com.miui.passwords` | UI/本地编辑 | 落库出口（编辑重传路径同源）|
| `com.miui.cloudservice` | keybag/AppKey 版本链（见 passkey 文档） | 无（钥匙栈原生复用）|

## 8. 已知边界

- 两端都要装模块：只装上传端 = 云端有信封但对端不解；只装下载端 = 无信封可解。
- 目标混淆对照：密码管理 1.1.25 / 1.1.26（u2.d、P2.c、H3.c 映射一致）；
  换版本后看 `totp-sync: hook 不全` / `信封工具定位失败` 日志重新定位。
- 动作日志走 logcat（tag `FuckMiuiPasswords`），缓冲轮转快：排障先 force-stop
  密码管理 + `logcat -c` 再拉起进程（密码管理无 LAUNCHER 入口，shell `am start`
  会被 OPEN_SETTINGS 权限拒——用 root `content query` 打一次 provider 即拉起）。
- 验证以 DB 行为准（shell uid 缺 CLOUD_MANAGER，需 root 跑 content，只投影非敏感列）：

  ```
  su -c 'content query --uri content://miui.autofill/password_record \
      --projection _id:totpIssuer:localStatus --where "totpSecret IS NOT NULL"'
  ```
