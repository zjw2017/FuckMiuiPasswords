package io.github.zjw2017.fuckmiuipasswords.config;

/**
 * 模块开关与伪造/改写规则。改这里重新编译即可。
 */
public final class Config {

    /** 主开关：在网络层伪造小米 pass/verify/assetlink 的响应 */
    public static final boolean FORGE_ASSETLINK_RESPONSE = true;

    /** 副开关：短路 vendor validate（DexStringLocator 定位后整体置空） */
    public static final boolean SHORT_CIRCUIT_VENDOR_VALIDATOR = true;

    /** 记录目标进程里“感兴趣”的 HTTP 请求/响应（排障用） */
    public static final boolean LOG_NETWORK = true;

    /** dump com.miui.passwords setResult 回传的凭据响应 JSON */
    public static final boolean DUMP_RESULT_INTENTS = true;

    /** clientDataJSON.origin 修正总开关 */
    public static final boolean ORIGIN_FIX_ENABLED = true;

    /**
     * 「web 源组」：这些包名的 origin 改写成 WEB_ORIGIN。
     * Telegram 服务端只认 web 源（PASSKEY_ORIGIN_MISMATCH 对
     * android:apk-key-hash 的两种 base64 编码都拒），加其它 Telegram
     * 客户端时把包名追加进数组即可。
     */
    public static final String[] WEB_ORIGIN_PACKAGES = {
            "org.telegram.messenger",
            "org.telegram.messenger.web",
            "org.telegram.messenger.beta",
            // "org.thunderdog.challegram",
    };

    /** web 源组统一改写到的 origin */
    public static final String WEB_ORIGIN = "https://telegram.org";

    /** 其它 App 的策略：保留 android:apk-key-hash: 形式，只修成规范 base64url */
    public static final String OTHER_APPS_MODE = "base64url";   // "base64url" | "none"

    /** 真机日志里观察到的服务端成功语义：code=0 即 trusted */
    public static final String FORGED_ASSETLINK_BODY =
            "{\"code\":0,\"desc\":\"\",\"clientCacheDurationMills\":180000}";

    /** 短路定位常量串（p2.e.a 抛异常的 format 模板前缀） */
    public static final String VALIDATOR_NEEDLE = "vendor validate failed";

    /** 辅助定位串（只打日志帮认路） */
    public static final String AUTH_MANAGER_NEEDLE = "checkAppAuthenticationSync>>>cacheInfo:";

    /** 源级 clientData 改写定位串（ClientDataProcessor 所在类） */
    public static final String CLIENT_DATA_NEEDLE = "webauthn.";

    /** 按调用方包名决定 origin 策略："web" | "base64url" | "none" */
    public static String originModeFor(String pkg) {
        if (!ORIGIN_FIX_ENABLED) return "none";
        if (pkg != null) {
            for (String p : WEB_ORIGIN_PACKAGES) {
                if (p.equals(pkg)) return "web";
            }
        }
        return OTHER_APPS_MODE;
    }

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
