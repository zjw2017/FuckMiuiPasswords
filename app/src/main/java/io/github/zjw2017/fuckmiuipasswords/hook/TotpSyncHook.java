package io.github.zjw2017.fuckmiuipasswords.hook;

import android.content.ContentValues;
import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;

import io.github.zjw2017.fuckmiuipasswords.config.Config;
import io.github.zjw2017.fuckmiuipasswords.util.DexStringLocator;
import io.github.zjw2017.fuckmiuipasswords.util.Log;
import com.hchen.hooktool.core.CoreTool;
import com.hchen.hooktool.hook.AbsHook;

import org.json.JSONObject;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Set;

/**
 * TOTP 云同步桥——补上密码管理同步时丢弃的动态令牌四列
 * （totpSecret/totpAlgorithm/totpIssuer/totpDigits）。
 * <p>
 * TOTP 与密码共用 record key：把 TOTP 并入 E2EE 明文（"password" 字段的
 * encryptedPassword 密文），明文从纯密码扩成复合体：
 * <pre>   复合明文 = payload长度 + "\n" + totpJson + 密码</pre>
 * 长度前缀保证密码任意字符安全；本地层（w2/e、DB password 列、自动填充）
 * 永远只见纯密码。
 * <p>
 * 四个 hook（字符串锚点/形态定位，H3.c 直名+形态）：
 * <ul>
 *   <li>上传 E2EE 包装入口（static boolean xxx(record, Cursor)，锚点
 *       "decrypted password error by local key"）before：record 的
 *       ContentValues 成员取 totp → 暂存；</li>
 *   <li>加解密边界（H3.c.b(String, keyObj, int mode)）：mode=1（加密）
 *       before 把明文变复合体；mode=2（解密）after 剥出 totp 并还原纯密码；</li>
 *   <li>下载解包出口（static boolean xxx(record)，锚点 "decrypted password
 *       is null"）after：暂存的 totp 写进 record 的 ContentValues 成员；</li>
 *   <li>落库出口（static ContentValues xxx(record)）after：成员里的 totp
 *       四列带进落库 ContentValues（落库重建只认混淆字段名，成员按类型找）。</li>
 * </ul>
 * 清空语义：totp 移除后复合体不生成，对端解出纯密码、成员无 totp，
 * 落库时 totp 列自然为 null。
 */
public final class TotpSyncHook {

    private static final String PAYLOAD_MARKER = "__mfptp";

    /** 上传：record → 加密边界的 totp payload */
    private static final ThreadLocal<String> TL_UPLOAD = new ThreadLocal<>();
    /** 下载：解密边界 → record 的 totp payload */
    private static final ThreadLocal<String> TL_DOWNLOAD = new ThreadLocal<>();

    public static void install(String apkPath, ClassLoader classLoader) {
        if (!Config.SYNC_TOTP_ENABLED) return;

        // ---------- 定位 ----------
        Method wrapM = null;    // 上传 E2EE 包装入口（j）
        Method unwrapM = null;  // 下载解包出口（g）
        Method writeM = null;   // 落库出口（d）
        Class<?> recordClass = null;

        // 落库出口：syncExtensionStr1 锚点 + 形态（顺带拿到 record 类）
        Set<String> refs = DexStringLocator.findMethodsWithConstant(apkPath, Config.EXT_STR_NEEDLE);
        Log.i("locator[totp-sync] anchor hits: " + refs);
        for (String ref : refs) {
            int hash = ref.lastIndexOf('#');
            if (hash <= 0) continue;
            Class<?> cls;
            try {
                cls = CoreTool.findClass(ref.substring(0, hash), classLoader);
            } catch (Throwable t) {
                continue;
            }
            for (Method m : cls.getDeclaredMethods()) {
                if (!m.getName().equals(ref.substring(hash + 1))) continue;
                Class<?>[] p = m.getParameterTypes();
                if (Modifier.isStatic(m.getModifiers()) && p.length == 1
                        && m.getReturnType() == ContentValues.class && writeM == null) {
                    writeM = m;
                    recordClass = p[0];
                }
            }
        }

        // 上传包装入口："decrypted password error by local key" 锚点 + 形态
        wrapM = findStatic(DexStringLocator.findMethodsWithConstant(apkPath, "decrypted password error by local key"),
                new Class<?>[]{recordClass, android.database.Cursor.class}, boolean.class, classLoader);
        // 下载解包出口："decrypted password is null" 锚点 + 形态
        unwrapM = findStatic(DexStringLocator.findMethodsWithConstant(apkPath, "decrypted password is null"),
                new Class<?>[]{null}, boolean.class, classLoader);

        // 加解密边界：H3.c.b(String, ?, int) -> String（直名 + 形态兜底）
        Method cryptoM = null;
        try {
            Class<?> cryptoCls = CoreTool.findClass("H3.c", classLoader);
            for (Method m : cryptoCls.getDeclaredMethods()) {
                Class<?>[] p = m.getParameterTypes();
                if (!Modifier.isStatic(m.getModifiers()) && p.length == 3
                        && p[0] == String.class && p[2] == int.class
                        && m.getReturnType() == String.class) {
                    cryptoM = m;
                    break;
                }
            }
        } catch (Throwable t) {
            Log.e("totp-sync: H3.c not found（混淆名变了？）", t);
        }

        // ---------- 注册 ----------
        int hooked = 0;
        if (wrapM != null) {
            Class<?>[] p = wrapM.getParameterTypes();
            CoreTool.hookMethod(wrapM.getDeclaringClass(), wrapM.getName(), p[0], p[1], new UploadStashHook());
            Log.i("totp-sync wrap hook: " + wrapM.getDeclaringClass().getName() + "->" + wrapM.getName());
            hooked++;
        }
        if (cryptoM != null) {
            Class<?>[] p = cryptoM.getParameterTypes();
            CoreTool.hookMethod(cryptoM.getDeclaringClass(), cryptoM.getName(),
                    p[0], p[1], p[2], new CryptoBoundaryHook());
            Log.i("totp-sync crypto hook: " + cryptoM.getDeclaringClass().getName() + "->" + cryptoM.getName());
            hooked++;
        }
        if (unwrapM != null) {
            Class<?>[] p = unwrapM.getParameterTypes();
            CoreTool.hookMethod(unwrapM.getDeclaringClass(), unwrapM.getName(), p[0], new DownloadApplyHook());
            Log.i("totp-sync unwrap hook: " + unwrapM.getDeclaringClass().getName() + "->" + unwrapM.getName());
            hooked++;
        }
        if (writeM != null) {
            CoreTool.hookMethod(writeM.getDeclaringClass(), writeM.getName(),
                    writeM.getParameterTypes()[0], new DbWriteHook());
            Log.i("totp-sync db-write hook: " + writeM.getDeclaringClass().getName() + "->" + writeM.getName());
            hooked++;
        }
        if (hooked < 4) {
            Log.w("totp-sync: hook 不全 (" + hooked + "/4)，目标 APK 可能升级改了结构");
        }

        scheduleResyncOnce();
    }

    /**
     * 锚点类里按形态找静态方法。want[i] 为 null 表示该位任意非原生参数，
     * 否须精确匹配；ret 为返回类型。
     */
    private static Method findStatic(Set<String> anchors, Class<?>[] want, Class<?> ret, ClassLoader cl) {
        for (String ref : anchors) {
            int hash = ref.lastIndexOf('#');
            if (hash <= 0) continue;
            Class<?> cls;
            try {
                cls = CoreTool.findClass(ref.substring(0, hash), cl);
            } catch (Throwable t) {
                continue;
            }
            for (Method m : cls.getDeclaredMethods()) {
                if (!m.getName().equals(ref.substring(hash + 1))) continue;
                Class<?>[] p = m.getParameterTypes();
                if (!Modifier.isStatic(m.getModifiers()) || m.getReturnType() != ret) continue;
                if (p.length != want.length) continue;
                boolean ok = true;
                for (int i = 0; i < p.length; i++) {
                    if (want[i] != null ? p[i] != want[i] : p[i].isPrimitive()) {
                        ok = false;
                        break;
                    }
                }
                if (ok) return m;
            }
        }
        return null;
    }

    // -------------------- 上传：record → 暂存 --------------------

    private static final class UploadStashHook extends AbsHook {
        @Override
        public void before() {
            try {
                ContentValues cv = findContentValues(getArgs()[0]);
                String secret = cv != null ? cv.getAsString("totpSecret") : null;
                if (secret != null && !secret.isEmpty()) {
                    String payload = buildPayload(cv);
                    TL_UPLOAD.set(payload);
                } else {
                    TL_UPLOAD.remove();
                }
            } catch (Throwable t) {
                Log.e("totp-sync upload-stash err", t);
            }
        }

        @Override
        public void after() {
            TL_UPLOAD.remove();
        }
    }

    /** 从 record 的 ContentValues 成员取 totp 四列组 payload（列名稳定，不受混淆影响） */
    private static String buildPayload(ContentValues cv) {
        try {
            JSONObject p = new JSONObject();
            p.put(PAYLOAD_MARKER, 1);
            p.put("s", cv.getAsString("totpSecret"));
            String alg = cv.getAsString("totpAlgorithm");
            if (alg != null && !alg.isEmpty()) p.put("a", alg);
            String issuer = cv.getAsString("totpIssuer");
            if (issuer != null && !issuer.isEmpty()) p.put("i", issuer);
            Integer digits = cv.getAsInteger("totpDigits");
            p.put("d", digits != null ? digits : 6);
            return p.toString();
        } catch (Throwable t) {
            Log.e("totp-sync buildPayload err", t);
            return null;
        }
    }

    // -------------------- 加解密边界：复合明文 --------------------

    private static final class CryptoBoundaryHook extends AbsHook {
        @Override
        public void before() {
            try {
                if (!(getArg(2) instanceof Integer) || ((Integer) getArg(2)) != 1) return;
                String payload = TL_UPLOAD.get();
                if (payload == null) return;
                Object plain = getArg(0);
                if (!(plain instanceof String)) return;
                setArg(0, payload.length() + "\n" + payload + plain);
                TL_UPLOAD.remove();   // 消费即清，防泄漏污染无关加密调用
                Log.i("totp-sync: 明文已复合（随 record key 加密）");
            } catch (Throwable t) {
                Log.e("totp-sync crypto-before err", t);
            }
        }

        @Override
        public void after() {
            try {
                if (!(getArg(2) instanceof Integer) || ((Integer) getArg(2)) != 2) return;
                Object r = getResult();
                if (!(r instanceof String)) return;
                String plain = (String) r;
                String[] split = splitComposite(plain);
                if (split == null) return;
                setResult(split[1]);          // 还原纯密码（本地层/自动填充只见密码）
                TL_DOWNLOAD.set(split[0]);    // totp 暂存，等解包出口落进 record
                Log.i("totp-sync: 复合明文已剥离");
            } catch (Throwable t) {
                Log.e("totp-sync crypto-after err", t);
            }
        }
    }

    /**
     * 复合明文 = {@code <len>\n<totpJson><password>}。
     * 长度前缀 + 标记校验双重判别，密码任意字符安全、误判概率≈0。
     * 返回 {payload, password}，不是复合体返回 null。
     */
    private static String[] splitComposite(String plain) {
        int nl = plain.indexOf('\n');
        if (nl <= 0 || nl > 9) return null;
        int n;
        try {
            n = Integer.parseInt(plain.substring(0, nl));
        } catch (NumberFormatException e) {
            return null;
        }
        int start = nl + 1;
        if (n <= 0 || start + n > plain.length()) return null;
        String payload = plain.substring(start, start + n);
        try {
            JSONObject p = new JSONObject(payload);
            if (p.optInt(PAYLOAD_MARKER, 0) != 1) return null;
        } catch (Throwable t) {
            return null;
        }
        return new String[]{payload, plain.substring(start + n)};
    }

    // -------------------- 下载：暂存 → record 成员 --------------------

    private static final class DownloadApplyHook extends AbsHook {
        @Override
        public void after() {
            try {
                String payload = TL_DOWNLOAD.get();
                TL_DOWNLOAD.remove();
                if (payload == null) return;
                ContentValues cv = findContentValues(getArgs()[0]);
                if (cv == null) return;
                JSONObject p = new JSONObject(payload);
                String s = p.optString("s", null);
                if (s == null || s.isEmpty()) return;
                cv.put("totpSecret", s);
                if (p.has("a")) cv.put("totpAlgorithm", p.optString("a"));
                if (p.has("i")) cv.put("totpIssuer", p.optString("i"));
                cv.put("totpDigits", p.optInt("d", 6));
                Log.i("totp-sync: download 解出 TOTP");
            } catch (Throwable t) {
                TL_DOWNLOAD.remove();
                Log.e("totp-sync download-apply err", t);
            }
        }
    }

    // -------------------- 落库：成员 → 落库 ContentValues --------------------

    /**
     * 下载导入的 insert/update 经静态 ContentValues xxx(record) 重建落库值，
     * 重建只认字段（混淆名）——把 ContentValues 成员里的 totp 四列带进结果。
     * 成员无 totp 键时不动（下载无复合体 → 字段本就为 null → 落库即清空）。
     */
    private static final class DbWriteHook extends AbsHook {
        @Override
        public void after() {
            try {
                Object r = getResult();
                if (!(r instanceof ContentValues)) return;
                ContentValues out = (ContentValues) r;
                ContentValues src = findContentValues(getArgs()[0]);
                if (src == null || !src.containsKey("totpSecret")) return;

                String s = src.getAsString("totpSecret");
                if (s != null && !s.isEmpty()) {
                    out.put("totpSecret", s);
                    out.put("totpAlgorithm", src.getAsString("totpAlgorithm"));
                    out.put("totpIssuer", src.getAsString("totpIssuer"));
                    Integer digits = src.getAsInteger("totpDigits");
                    out.put("totpDigits", digits != null ? digits : 6);
                } else {
                    out.putNull("totpSecret");
                    out.putNull("totpAlgorithm");
                    out.putNull("totpIssuer");
                    out.put("totpDigits", 6);
                }
            } catch (Throwable t) {
                Log.e("totp-sync db-write hook err", t);
            }
        }
    }

    /**
     * record 的基类持有一个 ContentValues 成员（构造/游标读入时同步积累
     * 整行的列值，setter 都往里 put）。按类型找，不依赖字段名。
     */
    private static ContentValues findContentValues(Object record) {
        if (record == null) return null;
        Class<?> c = record.getClass();
        while (c != null && c != Object.class) {
            for (Field f : c.getDeclaredFields()) {
                if (f.getType() == ContentValues.class) {
                    try {
                        f.setAccessible(true);
                        Object v = f.get(record);
                        if (v instanceof ContentValues) return (ContentValues) v;
                    } catch (Throwable ignored) {
                    }
                }
            }
            c = c.getSuperclass();
        }
        return null;
    }

    // -------------------- 一次性回灌：存量 TOTP 行标脏重传 --------------------

    /**
     * 装模块后跑一次：把已同步的存量 TOTP 行标 MODIFIED 强制重传。
     * SharedPreferences 一次性闸防循环；改版后需重新标脏时递增键名。
     */
    private static void scheduleResyncOnce() {
        new Thread(() -> {
            try {
                Context ctx = awaitContext();
                if (ctx == null) {
                    Log.w("totp-sync resync: 拿不到 Context，跳过");
                    return;
                }
                SharedPreferences sp = ctx.getSharedPreferences("fuckmiuipasswords_totp", 0);
                if (sp.getBoolean("resync_v3_done", false)) return;

                ContentValues cv = new ContentValues();
                cv.put("localStatus", 1);   // 1 = MODIFIED
                int n = ctx.getContentResolver().update(
                        Uri.parse(Config.PASSWORD_RECORD_URI), cv,
                        "totpSecret IS NOT NULL AND localStatus = ?", new String[]{"-1"});
                sp.edit().putBoolean("resync_v3_done", true).apply();
                Log.i("totp-sync: resync v3 标脏 rows=" + n);
            } catch (Throwable t) {
                Log.e("totp-sync resync err", t);
            }
        }, "mfptp-resync").start();
    }

    /** Application 建立前拿到的 currentApplication 是 null，给它一点耐心 */
    private static Context awaitContext() {
        for (int i = 0; i < 20; i++) {
            try {
                Object app = Class.forName("android.app.ActivityThread")
                        .getMethod("currentApplication").invoke(null);
                if (app instanceof Context) return (Context) app;
            } catch (Throwable ignored) {
            }
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                return null;
            }
        }
        return null;
    }

    private TotpSyncHook() {}
}
