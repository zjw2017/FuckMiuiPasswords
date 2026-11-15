package io.github.zjw2017.fuckmiuipasswords.util;

import android.content.Intent;
import android.os.Bundle;
import android.util.Base64;

import io.github.zjw2017.fuckmiuipasswords.config.Config;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.lang.reflect.Method;

/**
 * clientDataJSON.origin 改写 + base64 工具。
 * <p>
 * 两层使用：源级（ClientDataFixHook，TEE 签名前，登录断言签名一致）与
 * 事后兜底（ResultDumpHook，注册响应 fmt=none 无签名绑定）。幂等。
 */
public final class OriginFix {

    /** 按 Config 策略改写；返回 null = 无需改 */
    public static String rewriteOrigin(String origin, String pkg) {
        if (origin == null || origin.isEmpty()) return null;
        String mode = Config.originModeFor(pkg);
        if ("web".equals(mode)) {
            if (origin.startsWith("https://")) return null;   // 已是 web 源（浏览器流程）不动
            return Config.WEB_ORIGIN;
        }
        if ("base64url".equals(mode) && origin.startsWith("android:apk-key-hash:")) {
            String hash = origin.substring("android:apk-key-hash:".length());
            String out = "android:apk-key-hash:" + b64encodeUrlSafe(b64decode(hash));
            return out.equals(origin) ? null : out;
        }
        return null;
    }

    /** 改写裸 clientDataJSON 文本；null = 无需改 */
    public static String fixClientData(String cjd) {
        try {
            JSONObject inner = new JSONObject(cjd);
            String pkg = inner.optString("androidPackageName", "");
            String oldOrigin = inner.optString("origin", "");
            String newOrigin = rewriteOrigin(oldOrigin, pkg);
            if (newOrigin == null || newOrigin.equals(oldOrigin)) return null;
            inner.put("origin", newOrigin);
            Log.i("ORIGIN FIX(src)[" + pkg + "]: " + oldOrigin + "\n                -> " + newOrigin);
            return inner.toString();
        } catch (Throwable t) {
            Log.e("fixClientData err", t);
            return null;
        }
    }

    /** 改写外层 registrationResponseJson（事后兜底）；null = 无需改 */
    public static String fixResponseJson(String registrationJson) {
        try {
            JSONObject root = new JSONObject(registrationJson);
            JSONObject resp = root.optJSONObject("response");
            if (resp == null) return null;
            String cjdB64 = resp.optString("clientDataJSON", null);
            if (cjdB64 == null) return null;

            String cjd = new String(b64decode(cjdB64), StandardCharsets.UTF_8);
            String fixedCjd = fixClientData(cjd);
            if (fixedCjd == null) return null;

            resp.put("clientDataJSON", b64encodeUrlSafe(fixedCjd.getBytes(StandardCharsets.UTF_8)));
            return root.toString();
        } catch (Throwable t) {
            Log.e("fixResponseJson err", t);
            return null;
        }
    }

    /** setResult 回传 Intent 的事后兜底改写 */
    public static void fixIntent(Intent data) {
        if (data == null) return;
        Bundle extras = data.getExtras();
        if (extras == null) return;
        for (String key : extras.keySet()) {
            Object v = extras.get(key);
            Bundle inner = (v instanceof Bundle) ? (Bundle) v : bundleGetter(v);
            if (inner == null) continue;
            for (String k : inner.keySet()) {
                Object s = inner.get(k);
                if (s instanceof String && ((String) s).contains("\"clientDataJSON\"")) {
                    String fixed = fixResponseJson((String) s);
                    if (fixed != null) inner.putString(k, fixed);
                }
            }
        }
    }

    private static Bundle bundleGetter(Object v) {
        for (String m : new String[]{"getData", "getExtras", "getBundle", "getCredentialData"}) {
            try {
                Method mm = v.getClass().getMethod(m);
                Object r = mm.invoke(v);
                if (r instanceof Bundle) return (Bundle) r;
            } catch (Throwable ignored) {}
        }
        return null;
    }

    /** 宽容解码：base64 / base64url 都认 */
    public static byte[] b64decode(String s) {
        String t = s.replace('-', '+').replace('_', '/');
        return Base64.decode(t, Base64.NO_PADDING | Base64.NO_WRAP);
    }

    public static String b64encodeUrlSafe(byte[] b) {
        return Base64.encodeToString(b, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
    }

    private OriginFix() {}
}
