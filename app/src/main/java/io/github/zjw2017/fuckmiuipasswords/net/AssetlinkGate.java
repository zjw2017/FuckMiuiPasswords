package io.github.zjw2017.fuckmiuipasswords.net;

import io.github.zjw2017.fuckmiuipasswords.config.Config;
import io.github.zjw2017.fuckmiuipasswords.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * 关卡一本地复刻：伪造 code:0 之前的 (rp, packageName, 签名指纹) 闸门。
 * <p>
 * 小米服务端对 /pass/verify/assetlink 做两道检查——(rp, packageName) 注册库
 * + 调用方签名证书 SHA-256 比对（"fingerprints not match" 即第二道）。模块把
 * 核验搬到本地，伪造的 code:0 只发给过了闸门的调用方：<b>每次抓 RP 自己的
 * assetlinks.json 按标准 DAL 语义比对</b>（relation 含
 * delegate_permission/common.get_login_creds + namespace=android_app +
 * package_name + sha256_cert_fingerprints，与 MiFido 本地路径 p2.a 同款语义）。
 * 无静态白名单——调用方换签名、RP 更新声明即自动跟上，零配置维护。
 * <p>
 * 裁决与服务端报错一一对应：不在声明里 → asset_not_support；在声明里但指纹
 * 不符 → fingerprints not match。拒绝时伪造忠实失败体，上游 p2.e 抛原生的
 * "vendor validate failed : message=…。serialNo=…"，与真机拒批行为一致。
 * 浏览器流（namespace=web）比对声明里的 web 条目（namespace=web +
 * site=https://&lt;rpId&gt; + get_login_creds，网站认自己的源）。
 * <p>
 * 两层执行点共用本闸门：{@link NetForge}（网络层，解析 POST 表单）与
 * VendorValidateHook（短路层，直取 p2.e.a 入参）。模式见
 * {@link Config#ASSETLINK_GATE_MODE}——"log" 模式下只记日志仍放行。
 */
public final class AssetlinkGate {

    /** 裁决：通过 */
    public static final int PASS = 0;
    /** 裁决：(rp, 包名) 不在声明里 → asset_not_support */
    public static final int DENY_UNLISTED = 1;
    /** 裁决：在声明里但签名指纹不符 → fingerprints not match */
    public static final int DENY_FINGERPRINT = 2;

    private static final String REL_LOGIN_CREDS = "delegate_permission/common.get_login_creds";
    private static final int DAL_FETCH_TIMEOUT_MS = 5_000;
    private static final int DAL_MAX_BYTES = 65_536;

    /** 伪造响应入口：解析表单 → 裁决 → 通过体 / 忠实失败体（log 模式下裁决为拒也给通过体） */
    public static String forgeResponse(String formBody) {
        Map<String, String> f = parseForm(formBody);
        String rp = f.get("rp");
        String pkg = f.get("packageName");
        String fp = f.get("fingerprints");
        boolean isBrowser = "web".equals(f.get("namespace"));
        int verdict = check(rp, pkg, fp, f.get("assetlinkUrlList"), isBrowser);
        return (verdict == PASS || !isEnforced()) ? Config.FORGED_ASSETLINK_BODY : denyBody(verdict, pkg);
    }

    /** enforce 模式下拒绝才真正执行；off/log 模式一律放行 */
    public static boolean isEnforced() {
        return Config.GATE_MODE_ENFORCE.equals(Config.ASSETLINK_GATE_MODE);
    }

    /** 裁决名（日志用） */
    public static String verdictName(int verdict) {
        if (verdict == DENY_FINGERPRINT) return "FINGERPRINT-MISMATCH";
        if (verdict == DENY_UNLISTED) return "NOT-IN-DECLARATION";
        return "PASS";
    }

    /**
     * 闸门裁决，返回<b>真实裁决</b>（PASS / DENY_*），模式不折进返回值：
     * mode=off 不评估直接 PASS；mode=log 只记日志，放行与否由调用方按
     * {@link #isEnforced()} 决定（false = 一律放行）；mode=enforce 时
     * 调用方据裁决走失败路径。
     */
    public static int check(String rp, String pkg, String fp,
                            String assetlinkUrlListJson, boolean isBrowser) {
        if (Config.GATE_MODE_OFF.equals(Config.ASSETLINK_GATE_MODE)) return PASS;
        int verdict = evaluate(rp, pkg, fp, assetlinkUrlListJson, isBrowser);
        if (verdict == PASS) {
            Log.i("GATE PASS rp=" + rp + " pkg=" + pkg);
        } else {
            // 拒绝：日志给出裁决与调用方三元组（排障用）
            Log.i("GATE " + verdictName(verdict)
                    + " rp=" + rp + " pkg=" + pkg + " fp=" + fp
                    + (isEnforced() ? " -> DENY" : " -> 放行(log 模式)"));
        }
        return verdict;
    }

    // ------------------------------------------------------------------

    /** 真实裁决：DAL 实时核验（每次现查，无静态白名单） */
    private static int evaluate(String rp, String pkg, String fp,
                                String assetlinkUrlListJson, boolean isBrowser) {
        if (rp == null || rp.isEmpty()) return DENY_UNLISTED;
        // 浏览器流（namespace=web）比对声明里的 web 条目——网站认自己的源
        if (isBrowser) return webDalCheck(rp, assetlinkUrlListJson);
        if (pkg == null || pkg.isEmpty()) return DENY_UNLISTED;
        return dalCheck(rp, pkg, fp, assetlinkUrlListJson);
    }

    /**
     * 浏览器流的 DAL 比对：声明里找 namespace=web + site=https://&lt;rpId&gt; +
     * get_login_creds 条目；web 条目无指纹，故只有 PASS / NOT-IN-DECLARATION 两种裁决。
     */
    private static int webDalCheck(String rp, String assetlinkUrlListJson) {
        for (String url : declarationUrls(rp, assetlinkUrlListJson)) {
            String doc = httpGet(url);
            if (doc == null) continue;
            try {
                JSONArray arr = new JSONArray(doc);
                for (int i = 0; i < arr.length(); i++) {
                    JSONObject entry = arr.optJSONObject(i);
                    if (entry == null) continue;
                    if (!arrayContains(entry.optJSONArray("relation"), REL_LOGIN_CREDS)) continue;
                    JSONObject target = entry.optJSONObject("target");
                    if (target == null || !"web".equals(target.optString("namespace"))) continue;
                    if (siteMatches(target.optString("site", null), rp)) return PASS;
                }
            } catch (Throwable t) {
                Log.w("GATE dal parse err " + url + ": " + t);
            }
        }
        return DENY_UNLISTED;
    }

    /** 声明的 site 是否就是 rp 的 https 源（忽略尾斜杠与大小写） */
    private static boolean siteMatches(String declaredSite, String rp) {
        if (declaredSite == null) return false;
        String s = declaredSite.trim();
        while (s.endsWith("/")) s = s.substring(0, s.length() - 1);
        return s.equalsIgnoreCase("https://" + rp);
    }

    /** 抓 assetlinks.json 做标准 DAL 比对（每次现查） */
    private static int dalCheck(String rp, String pkg, String fp, String assetlinkUrlListJson) {
        int verdict = DENY_UNLISTED;
        boolean pkgSeen = false;
        for (String url : declarationUrls(rp, assetlinkUrlListJson)) {
            String doc = httpGet(url);
            if (doc == null) continue;
            try {
                JSONArray arr = new JSONArray(doc);
                for (int i = 0; i < arr.length(); i++) {
                    JSONObject entry = arr.optJSONObject(i);
                    if (entry == null) continue;
                    if (!arrayContains(entry.optJSONArray("relation"), REL_LOGIN_CREDS)) continue;
                    JSONObject target = entry.optJSONObject("target");
                    if (target == null || !"android_app".equals(target.optString("namespace"))) continue;
                    if (!pkg.equals(target.optString("package_name"))) continue;
                    pkgSeen = true;
                    JSONArray fps = target.optJSONArray("sha256_cert_fingerprints");
                    for (int k = 0; fps != null && k < fps.length(); k++) {
                        if (fpEquals(fps.optString(k, null), fp)) {
                            verdict = PASS;
                            break;
                        }
                    }
                    if (verdict == PASS) break;
                }
            } catch (Throwable t) {
                Log.w("GATE dal parse err " + url + ": " + t);
            }
            if (verdict == PASS) break;
        }
        if (verdict != PASS && pkgSeen) verdict = DENY_FINGERPRINT;
        return verdict;
    }

    /**
     * 声明地址：<rp>/.well-known/assetlinks.json 恒定核验；请求体里的
     * assetlinkUrlList 仅采信 rp 域名内（含子域）的 URL——防调用方塞
     * 私有 URL 伪造声明。
     */
    private static String[] declarationUrls(String rp, String assetlinkUrlListJson) {
        List<String> out = new ArrayList<>();
        // rp 来自调用方 options，拼 URL 前限制字符集防注入
        if (rp != null && rp.matches("[a-zA-Z0-9.-]+")) {
            out.add("https://" + rp + "/.well-known/assetlinks.json");
        }
        if (assetlinkUrlListJson != null && !assetlinkUrlListJson.isEmpty()) {
            try {
                JSONArray arr = new JSONArray(assetlinkUrlListJson);
                for (int i = 0; i < arr.length(); i++) {
                    String u = arr.optString(i, null);
                    if (u != null && u.startsWith("https://") && inRpDomain(u, rp) && !out.contains(u)) {
                        out.add(u);
                    }
                }
            } catch (Throwable ignored) {
            }
        }
        return out.toArray(new String[0]);
    }

    /** URL 主机是否为 rp 本身或其子域（防调用方塞私有 URL 伪造声明） */
    private static boolean inRpDomain(String url, String rp) {
        if (rp == null || rp.isEmpty()) return false;
        try {
            String host = new URL(url).getHost();
            return host != null && (host.equals(rp) || host.endsWith("." + rp));
        } catch (Throwable t) {
            return false;
        }
    }

    private static String httpGet(String url) {
        HttpURLConnection c = null;
        try {
            c = (HttpURLConnection) new URL(url).openConnection();
            c.setConnectTimeout(DAL_FETCH_TIMEOUT_MS);
            c.setReadTimeout(DAL_FETCH_TIMEOUT_MS);
            c.setUseCaches(false);
            c.setRequestProperty("Accept", "application/json");
            if (c.getResponseCode() != 200) return null;
            InputStream in = c.getInputStream();
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int total = 0, n;
            while (total < DAL_MAX_BYTES && (n = in.read(buf)) > 0) {
                bos.write(buf, 0, n);
                total += n;
            }
            try {
                in.close();
            } catch (Throwable ignored) {
            }
            return new String(bos.toByteArray(), StandardCharsets.UTF_8);
        } catch (Throwable t) {
            Log.w("GATE dal fetch err " + url + ": " + t);
            return null;
        } finally {
            if (c != null) c.disconnect();
        }
    }

    /** 忠实失败体：code/desc 语义照抄真机抓包（"fount" 为服务端原文 typo，故意保留） */
    public static String denyBody(int verdict, String pkg) {
        try {
            JSONObject o = new JSONObject();
            o.put("code", 210003);
            if (verdict == DENY_FINGERPRINT) {
                o.put("desc", "fingerprints not match");
                o.put("msg", "fingerprints not match");
            } else {
                o.put("desc", "asset_not_support");
                o.put("msg", "cannot be fount packagename:" + (pkg == null ? "" : pkg));
            }
            return o.toString();
        } catch (Throwable t) {
            return "{\"code\":210003,\"desc\":\"asset_not_support\"}";
        }
    }

    /** 表单解析：k=v&k=v 拆分。值原样取用（n5.c.d 拼表单时已解码、未编码上 wire），不再解码 */
    static Map<String, String> parseForm(String body) {
        Map<String, String> out = new HashMap<>();
        if (body == null) return out;
        for (String part : body.split("&")) {
            int eq = part.indexOf('=');
            if (eq <= 0) continue;
            out.put(part.substring(0, eq), part.substring(eq + 1));
        }
        return out;
    }

    /** 指纹比对：忽略大小写与冒号（assetlinks 声明 / 请求体两处格式统一） */
    private static boolean fpEquals(String a, String b) {
        String na = normalizeFp(a), nb = normalizeFp(b);
        return !na.isEmpty() && na.equals(nb);
    }

    private static String normalizeFp(String fp) {
        if (fp == null) return "";
        return fp.replace(":", "").replace(" ", "").toUpperCase(Locale.ROOT);
    }

    private static boolean arrayContains(JSONArray arr, String value) {
        if (arr == null) return false;
        for (int i = 0; i < arr.length(); i++) {
            if (value.equals(arr.optString(i, null))) return true;
        }
        return false;
    }

    private AssetlinkGate() {}
}
