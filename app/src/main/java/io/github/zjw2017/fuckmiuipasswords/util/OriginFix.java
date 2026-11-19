package io.github.zjw2017.fuckmiuipasswords.util;

import android.content.Intent;
import android.os.Bundle;
import android.util.Base64;

import io.github.zjw2017.fuckmiuipasswords.config.Config;

import org.json.JSONObject;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.IdentityHashMap;
import java.util.Set;

/**
 * clientDataJSON.origin 改写 + base64 工具。
 * <p>
 * 判定优先按 RP（rpId 命中 {@link Config#WEB_RPS} → web 源），第三方客户端
 * （Nekogram/Telegram X/...）rpId 同为 telegram.org，免逐个配置；
 * rpId 不可用时回退按包名（{@link Config#WEB_ORIGIN_PACKAGES}）。
 * 其它 App 保留 android:apk-key-hash 并修 base64url 编码。
 * <p>
 * 两层使用：源级（ClientDataFixHook，TEE 签名前，登录断言签名一致）与
 * 事后兜底（ResultDumpHook，注册响应 fmt=none 无签名绑定）。幂等。
 */
public final class OriginFix {

    /** RP 是否属于 web 源组 */
    public static boolean isWebRp(String rpId) {
        if (rpId == null) return false;
        for (String r : Config.WEB_RPS) {
            if (r.equals(rpId)) return true;
        }
        return false;
    }

    /** 按调用方包名决定兜底策略："web" | "base64url" | "none"（RP 判定优先于此） */
    private static String packageMode(String pkg) {
        return Config.originModeFor(pkg);
    }

    /** 改写；返回 null = 无需改 */
    public static String rewriteOrigin(String origin, String pkg, String rpId) {
        if (origin == null || origin.isEmpty()) return null;

        // 1) RP 分支（首选）
        if (isWebRp(rpId)) {
            return origin.startsWith("https://") ? null : "https://" + rpId;
        }
        // 2) 包名兜底
        String mode = packageMode(pkg);
        if ("web".equals(mode)) {
            return origin.startsWith("https://") ? null : Config.WEB_ORIGIN;
        }
        if ("base64url".equals(mode) && origin.startsWith("android:apk-key-hash:")) {
            // apk-key-hash 要求无 padding 的 base64url；客户端给出的编码不规范时会被
            // 严格校验拒，这里解码后重编码归一（幂等：已规范则返回 null 不动）
            String hash = origin.substring("android:apk-key-hash:".length());
            String out = "android:apk-key-hash:" + b64encodeUrlSafe(b64decode(hash));
            return out.equals(origin) ? null : out;
        }
        return null;
    }

    /**
     * 在请求对象图里扫字符串值，命中 WEB_RPS 即返回该 rpId（深度受限的 BFS）。
     * 不依赖混淆方法名——rp 对象的 String 字段值就是 rpId。
     */
    public static String findWebRpInObject(Object root, int maxDepth) {
        if (root == null) return null;
        Deque<Object[]> queue = new ArrayDeque<>();
        Set<Object> visited = java.util.Collections.newSetFromMap(new IdentityHashMap<>());
        queue.add(new Object[]{root, 0});
        while (!queue.isEmpty()) {
            Object[] item = queue.poll();
            Object o = item[0];
            int depth = (Integer) item[1];
            if (o == null || !visited.add(o)) continue;
            if (o instanceof String) {
                if (isWebRp((String) o)) return (String) o;
                continue;
            }
            Class<?> cls = o.getClass();
            if (cls.isPrimitive() || cls.isEnum() || cls.isArray()
                    || cls.getClassLoader() == null) {
                continue;   // 基础类型/数组/框架类不展开
            }
            if (depth >= maxDepth) continue;
            for (Field f : cls.getDeclaredFields()) {
                if (Modifier.isStatic(f.getModifiers())) continue;
                try {
                    f.setAccessible(true);
                    Object v = f.get(o);
                    if (v instanceof String) {
                        if (isWebRp((String) v)) return (String) v;
                    } else if (v != null && depth < maxDepth) {
                        queue.add(new Object[]{v, depth + 1});
                    }
                } catch (Throwable ignored) {
                }
            }
        }
        return null;
    }

    /** 从响应的 authenticatorData / attestationObject 字节里认 rpIdHash → rpId（WebAuthn 规定 rpIdHash = SHA-256(rpId)） */
    public static String detectWebRp(JSONObject response) {
        if (response == null) return null;
        for (String key : new String[]{"authenticatorData", "attestationObject"}) {
            String b64 = response.optString(key, null);
            if (b64 == null || b64.isEmpty()) continue;
            byte[] bytes = b64decode(b64);
            for (String rp : Config.WEB_RPS) {
                try {
                    byte[] hash = MessageDigest.getInstance("SHA-256")
                            .digest(rp.getBytes(StandardCharsets.UTF_8));
                    if (indexOf(bytes, hash) >= 0) return rp;
                } catch (Throwable ignored) {
                }
            }
        }
        return null;
    }

    /** 改写裸 clientDataJSON 文本；null = 无需改 */
    public static String fixClientData(String cjd, String rpId) {
        try {
            JSONObject inner = new JSONObject(cjd);
            String pkg = inner.optString("androidPackageName", "");
            String oldOrigin = inner.optString("origin", "");
            String newOrigin = rewriteOrigin(oldOrigin, pkg, rpId);
            if (newOrigin == null || newOrigin.equals(oldOrigin)) return null;
            inner.put("origin", newOrigin);
            Log.i("ORIGIN FIX(src)[" + pkg + ",rp=" + rpId + "]: " + oldOrigin
                    + "\n                -> " + newOrigin);
            return inner.toString();
        } catch (Throwable t) {
            Log.e("fixClientData err", t);
            return null;
        }
    }

    /** 改写外层 registration/authentication ResponseJson（事后兜底）；null = 无需改 */
    public static String fixResponseJson(String responseJson) {
        try {
            JSONObject root = new JSONObject(responseJson);
            JSONObject resp = root.optJSONObject("response");
            if (resp == null) return null;
            String cjdB64 = resp.optString("clientDataJSON", null);
            if (cjdB64 == null) return null;

            String rpId = detectWebRp(resp);
            String cjd = new String(b64decode(cjdB64), StandardCharsets.UTF_8);
            String fixedCjd = fixClientData(cjd, rpId);
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
            // 凭据响应对象(Parcelable)常把数据包在 Bundle 里，取不到就反射常见 getter 捞
            Bundle inner = (v instanceof Bundle) ? (Bundle) v : bundleGetter(v);
            if (inner == null) continue;
            for (String k : inner.keySet()) {
                Object s = inner.get(k);
                // 响应 JSON 串必含 "clientDataJSON" 特征，文本嗅探即可定位，不依赖类名
                if (s instanceof String && ((String) s).contains("\"clientDataJSON\"")) {
                    String fixed = fixResponseJson((String) s);
                    if (fixed != null) inner.putString(k, fixed);
                }
            }
        }
    }

    /** 反射常见取 Bundle 的 getter（getData/getExtras/getBundle/getCredentialData） */
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

    private static int indexOf(byte[] haystack, byte[] needle) {
        if (haystack == null || needle == null || needle.length == 0) return -1;
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) continue outer;
            }
            return i;
        }
        return -1;
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
