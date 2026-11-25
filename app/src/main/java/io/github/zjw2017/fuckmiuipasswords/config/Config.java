package io.github.zjw2017.fuckmiuipasswords.config;

/**
 * 模块开关与伪造/改写规则。改这里重新编译即可。
 */
public final class Config {

    /** 主开关：在网络层伪造小米 pass/verify/assetlink 的响应 */
    public static final boolean FORGE_ASSETLINK_RESPONSE = true;

    // ---------------- TOTP 云同步桥 ----------------

    /** TOTP 云同步桥总开关（上传注入 + 下载回填 + 一次性存量标脏） */
    public static final boolean SYNC_TOTP_ENABLED = true;

    /** 抗混淆定位锚点：序列化 put / 解析 optString 处均引用该常量 */
    public static final String EXT_STR_NEEDLE = "syncExtensionStr1";

    /** password_record 表 URI（一次性 resync 标脏用） */
    public static final String PASSWORD_RECORD_URI = "content://miui.autofill/password_record";

    /** 副开关：短路 vendor validate（DexStringLocator 定位后整体置空） */
    public static final boolean SHORT_CIRCUIT_VENDOR_VALIDATOR = true;

    /** 记录目标进程里“感兴趣”的 HTTP 请求/响应（排障用） */
    public static final boolean LOG_NETWORK = true;

    /** dump com.miui.passwords setResult 回传的凭据响应 JSON */
    public static final boolean DUMP_RESULT_INTENTS = true;

    /** clientDataJSON.origin 修正总开关 */
    public static final boolean ORIGIN_FIX_ENABLED = true;

    /**
     * 「web 源组」——rpId 命中的请求，origin 改写成 https://&lt;rpId&gt;。
     * <p>
     * 2026-11-24 实测：X、Telegram 创建与登录均接受原生 android:apk-key-hash
     * 源（base64url 归一后），web 改写已无启用对象——机制保留给未来确有
     * web-only 要求的 RP，名单空置。
     */
    public static final String[] WEB_RPS = {};

    /** 其它 App 的策略：保留 android:apk-key-hash: 形式，只修成规范 base64url */
    public static final String OTHER_APPS_MODE = "base64url";   // "base64url" | "none"

    /** 真机日志里观察到的服务端成功语义：code=0 即 trusted */
    public static final String FORGED_ASSETLINK_BODY =
            "{\"code\":0,\"desc\":\"\",\"clientCacheDurationMills\":180000}";

    // ---------------- 关卡一本地闸门（伪造 code:0 之前的 (rp, 包名, 签名指纹) 校验） ----------------

    /** 闸门模式取值 */
    public static final String GATE_MODE_OFF = "off";        // 无条件放行（拆门，旧行为）
    public static final String GATE_MODE_LOG = "log";        // 只校验记日志，仍放行（观察各调用方 DAL 裁决）
    public static final String GATE_MODE_ENFORCE = "enforce"; // 不过就伪造拒绝

    /**
     * 闸门模式：核验 = 每次抓 RP 的 assetlinks.json 按 DAL 语义比对
     * （get_login_creds + android_app + 包名 + 指纹），无静态白名单——
     * 调用方换签名、RP 更新声明自动跟上，零配置维护。建议先 "log" 跑几天，
     * 看 GATE 行确认各调用方都能过 DAL，再改 "enforce"。
     * "off" = 无条件 code:0（谁都能借道，慎用）。
     */
    public static final String ASSETLINK_GATE_MODE = GATE_MODE_ENFORCE;

    /** 短路定位常量串（p2.e.a 抛异常的 format 模板前缀） */
    public static final String VALIDATOR_NEEDLE = "vendor validate failed";

    /** 辅助定位串（只打日志帮认路） */
    public static final String AUTH_MANAGER_NEEDLE = "checkAppAuthenticationSync>>>cacheInfo:";

    /** 源级 clientData 改写定位串（ClientDataProcessor 所在类） */
    public static final String CLIENT_DATA_NEEDLE = "webauthn.";

    /** userHandle 保住钩定位串（PasskeyAuthenticator.setUserSelected 所在方法） */
    public static final String USER_SELECTED_NEEDLE = "setUserSelected isDiscoverCredential:";

    /** 伪造规则表：URL 包含 key 就用对应 body 顶掉真实响应 */
    public static String forgeBodyFor(String url) {
        if (url == null) return null;
        if (url.contains("/pass/verify/assetlink")) return FORGED_ASSETLINK_BODY;
        // 发现 keybox 类二次拦截后照抄一行：
        // if (url.contains("/pass/verify/keybox")) return "{\"code\":0}";
        return null;
    }

    /** 网络日志关注的关键词 */
    public static boolean isInterestingUrl(String url) {
        if (url == null) return false;
        String u = url.toLowerCase();
        return u.contains("account.xiaomi.com")
                || u.contains("/pass/")
                || u.contains("keybox")
                || u.contains("keychain")
                || u.contains("keyapi")
                || u.contains("micloud")
                || u.contains("passkeeper")
                || u.contains("fido")
                || u.contains("assetlink")
                || u.contains("verify");
    }

    private Config() {}
}
