package io.github.zjw2017.fuckmiuipasswords.hook;

import android.content.ContentValues;
import android.content.Context;
import android.content.SharedPreferences;
import android.database.MatrixCursor;
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
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * TOTP 云同步桥——补上密码管理同步时丢弃的动态令牌四列
 * （totpSecret/totpAlgorithm/totpIssuer/totpDigits）。
 * <p>
 * 载体："password" 字段的 E2EE blob JSON 新增 {@code "t"} 键，值是
 * <b>一个完整的第二信封</b>（与密码 blob 同构的 encryptedPassword/
 * encryptedRecordKey/recordIV/appKeyVersion，encryptedPassword 槽位承载
 * totpJson）——对 TOTP 字符串原样跑官方的 j()/g() 封装机器生成
 * （每次调用产生独立 record key + IV，与密码同层同钥匙栈，模块零密钥）。
 * 无模块/旧版客户端原生忽略 "t"，密码明文全程纯净——云端恢复、
 * 旧版本共存均不污染密码。
 * <p>
 * 三个主 hook（字符串锚点/形态定位）：
 * <ul>
 *   <li>上传包装入口 {@code static boolean j(record, Cursor)}（锚点
 *       "decrypted password error by local key"）：after 用合成 record
 *       封装 totpJson 生成信封，写进 record.q 的 blob["t"]；</li>
 *   <li>下载解包出口 {@code static boolean g(record)}（锚点 "decrypted
 *       password is null"）：before 从 blob["t"] 取信封经合成 record 解出
 *       totpJson；after 把它写进 record 的 ContentValues 成员；</li>
 *   <li>落库出口 {@code static ContentValues d(record)}（锚点
 *       "syncExtensionStr1"）after：成员里的 totp 四列带进落库值。</li>
 * </ul>
 * 兼容：解密边界（H3.c.b mode=2）保留一个剥离钩，把 1.0.4 时代
 * "复合明文"格式的旧云端数据拆回纯密码 + totp（重传一轮后自动绝版）。
 * <p>
 * 清空语义：totp 移除后不再生成 "t"，对端落库四列自然为 NULL。
 */
public final class TotpSyncHook {

    private static final String PAYLOAD_MARKER = "__mfptp";
    /** blob JSON 里的 TOTP 信封键 */
    private static final String BLOB_TOTP_KEY = "t";
    /** 密码 setter 探针哨兵值 */
    private static final String SETTER_SENTINEL = "__mfptp_setter_probe__";

    /** 上传：真实 record → 合成信封流程的 totp payload */
    private static final ThreadLocal<String> TL_TOTP = new ThreadLocal<>();
    /** 标记当前 j()/g() 调用是合成 record 的信封流程（hook 须让路） */
    private static final ThreadLocal<Boolean> TL_FAKE = new ThreadLocal<>();
    /** 下载：旧版复合明文剥离出的 totp payload（兼容路径） */
    private static final ThreadLocal<String> TL_LEGACY = new ThreadLocal<>();

    private static Method wrapM, unwrapM, writeM, cryptoM;
    private static Class<?> recordClass;
    /** 本地加密/解密对（明文→本地密文+iv / 本地密文+iv→明文）：形态+round-trip 探针自定位 */
    private static Method localEncM, localDecM;
    /** record 密码字段 setter（写 ContentValues["password"]）：哨兵探针自定位 */
    private static Method pwdSetterM;

    public static void install(String apkPath, ClassLoader classLoader) {
        if (!Config.SYNC_TOTP_ENABLED) return;

        // ---------- 定位 ----------
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

        // 上传包装入口 j(record, Cursor) / 下载解包出口 g(record)
        wrapM = findStatic(DexStringLocator.findMethodsWithConstant(apkPath, "decrypted password error by local key"),
                new Class<?>[]{recordClass, android.database.Cursor.class}, boolean.class, classLoader);
        unwrapM = findStatic(DexStringLocator.findMethodsWithConstant(apkPath, "decrypted password is null"),
                new Class<?>[]{recordClass}, boolean.class, classLoader);

        // 解密边界（仅旧版复合体兼容用）：形态 (String, ?, int)→String 定位
        //（实测该形态全 dex 唯一命中 H3.c.b；多候选时告警取首个，hook 自带 mode+标记双保险）
        try {
            Set<String> stripHits = DexStringLocator.findMethodsWithShape(apkPath,
                    "Ljava/lang/String;", "Ljava/lang/String;", null, "I");
            if (stripHits.size() > 1) {
                Log.w("totp-sync: legacy-strip 形态候选 " + stripHits.size() + " 个，取首个：" + stripHits);
            }
            for (String ref : stripHits) {
                int hash = ref.lastIndexOf('#');
                if (hash <= 0) continue;
                Class<?> cls = CoreTool.findClass(ref.substring(0, hash), classLoader);
                for (Method m : cls.getDeclaredMethods()) {
                    Class<?>[] p = m.getParameterTypes();
                    if (!Modifier.isStatic(m.getModifiers()) && p.length == 3
                            && p[0] == String.class && p[2] == int.class
                            && m.getReturnType() == String.class
                            && m.getName().equals(ref.substring(hash + 1))) {
                        cryptoM = m;
                        break;
                    }
                }
                if (cryptoM != null) break;
            }
        } catch (Throwable t) {
            Log.e("totp-sync: legacy-strip 形态定位 err", t);
        }
        if (cryptoM == null) {
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
                Log.w("totp-sync: 直名兜底 H3.c 未命中（混淆名已变？）");
            }
        }
        if (cryptoM == null) {
            Log.w("totp-sync: legacy-strip 未定位，旧版复合明文将不剥离（仅影响历史格式）");
        }

        // 本地加解密对 + 密码 setter：形态/探针自定位（旧构建写死 w2.e 与 s()，
        // 目标 APK 改混淆名即静默失效）；保留旧直名兜底，全落空则响亮告警
        locateLocalCryptoPair(apkPath, classLoader);
        if (localEncM == null || localDecM == null) {
            locateLocalCryptoByName("w2.e", classLoader);
        }
        pwdSetterM = findPasswordSetter(recordClass);
        if (pwdSetterM == null && recordClass != null) {
            pwdSetterM = findNamedSetter(recordClass, "s");
        }
        if (localEncM == null || localDecM == null || pwdSetterM == null) {
            Log.w("totp-sync: 信封工具定位失败（localEnc=" + (localEncM != null) + " localDec="
                    + (localDecM != null) + " pwdSetter=" + (pwdSetterM != null)
                    + "），TOTP 云同步将不生效——发 FuckMiuiPasswords 日志重新定位");
        } else {
            Log.i("totp-sync: 信封工具就位 local=" + localEncM.getDeclaringClass().getName()
                    + "." + localEncM.getName() + "/" + localDecM.getName()
                    + " pwdSetter=" + pwdSetterM.getName());
        }

        // ---------- 注册 ----------
        int hooked = 0;
        if (wrapM != null) {
            Class<?>[] p = wrapM.getParameterTypes();
            CoreTool.hookMethod(wrapM.getDeclaringClass(), wrapM.getName(), p[0], p[1], new WrapHook());
            Log.i("totp-sync wrap hook: " + wrapM.getDeclaringClass().getName() + "->" + wrapM.getName());
            hooked++;
        }
        if (cryptoM != null) {
            Class<?>[] p = cryptoM.getParameterTypes();
            CoreTool.hookMethod(cryptoM.getDeclaringClass(), cryptoM.getName(),
                    p[0], p[1], p[2], new LegacyStripHook());
            Log.i("totp-sync legacy-strip hook: " + cryptoM.getDeclaringClass().getName() + "->" + cryptoM.getName());
            hooked++;
        }
        if (unwrapM != null) {
            Class<?>[] p = unwrapM.getParameterTypes();
            CoreTool.hookMethod(unwrapM.getDeclaringClass(), unwrapM.getName(), p[0], new UnwrapHook());
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

    /** 锚点类里按形态找静态方法；want[i] 为 null 表示该位任意非原生参数 */
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

    // -------------------- 信封工具自定位（形态/探针，不依赖混淆名）--------------------

    /** 旧版直名兜底：类名 + 形态匹配本地加解密对 */
    private static void locateLocalCryptoByName(String className, ClassLoader classLoader) {
        try {
            Class<?> localCls = CoreTool.findClass(className, classLoader);
            for (Method m : localCls.getDeclaredMethods()) {
                Class<?>[] p = m.getParameterTypes();
                if (Modifier.isStatic(m.getModifiers()) && m.getReturnType() == String.class
                        && p.length == 2 && p[0] == String.class && p[1] == String[].class) {
                    localEncM = m;
                } else if (Modifier.isStatic(m.getModifiers()) && m.getReturnType() == String.class
                        && p.length == 2 && p[0] == String.class && p[1] == String.class) {
                    localDecM = m;
                }
            }
        } catch (Throwable t) {
            Log.w("totp-sync: 直名兜底 " + className + " 未命中（混淆名已变？）");
        }
    }

    /** 形态枚举 + round-trip 探针（dec(enc(x)) == x）定位本地加解密对 */
    private static void locateLocalCryptoPair(String apkPath, ClassLoader cl) {
        Set<String> encHits = DexStringLocator.findMethodsWithShape(apkPath,
                "Ljava/lang/String;", "Ljava/lang/String;", "[Ljava/lang/String;");
        Set<String> decHits = DexStringLocator.findMethodsWithShape(apkPath,
                "Ljava/lang/String;", "Ljava/lang/String;", "Ljava/lang/String;");
        Set<String> classes = classesOf(encHits);
        classes.retainAll(classesOf(decHits));
        for (String cn : classes) {
            try {
                Class<?> cls = CoreTool.findClass(cn, cl);
                Method enc = null, dec = null;
                for (Method m : cls.getDeclaredMethods()) {
                    Class<?>[] p = m.getParameterTypes();
                    if (!Modifier.isStatic(m.getModifiers()) || m.getReturnType() != String.class) continue;
                    if (p.length == 2 && p[0] == String.class && p[1] == String[].class) enc = m;
                    else if (p.length == 2 && p[0] == String.class && p[1] == String.class) dec = m;
                }
                if (enc == null || dec == null || !probeLocalCrypto(enc, dec)) continue;
                localEncM = enc;
                localDecM = dec;
                return;
            } catch (Throwable ignored) {
            }
        }
    }

    private static boolean probeLocalCrypto(Method enc, Method dec) {
        try {
            String probe = "__mfptp_probe__" + System.nanoTime();
            String[] ivOut = new String[1];
            String cipher = (String) enc.invoke(null, probe, ivOut);
            return cipher != null && ivOut[0] != null
                    && probe.equals(dec.invoke(null, cipher, ivOut[0]));
        } catch (Throwable t) {
            return false;
        }
    }

    private static Set<String> classesOf(Set<String> classHashMethod) {
        Set<String> out = new LinkedHashSet<>();
        for (String ref : classHashMethod) {
            int hash = ref.lastIndexOf('#');
            if (hash > 0) out.add(ref.substring(0, hash));
        }
        return out;
    }

    /** 哨兵探针找密码 setter：谁把哨兵写进 ContentValues["password"] 谁就是（不依赖方法名） */
    private static Method findPasswordSetter(Class<?> recCls) {
        if (recCls == null) return null;
        for (Method m : recCls.getDeclaredMethods()) {
            Class<?>[] p = m.getParameterTypes();
            if (Modifier.isStatic(m.getModifiers()) || m.getReturnType() != void.class
                    || p.length != 1 || p[0] != String.class) continue;
            try {
                Object rec = recCls.getDeclaredConstructor().newInstance();
                m.setAccessible(true);
                m.invoke(rec, SETTER_SENTINEL);
                ContentValues cv = findContentValues(rec);
                if (cv != null && SETTER_SENTINEL.equals(cv.getAsString("password"))) return m;
            } catch (Throwable ignored) {
            }
        }
        return null;
    }

    /** 旧版直名兜底：按名找 setter */
    private static Method findNamedSetter(Class<?> recCls, String name) {
        for (Method m : recCls.getDeclaredMethods()) {
            Class<?>[] p = m.getParameterTypes();
            if (!Modifier.isStatic(m.getModifiers()) && m.getReturnType() == void.class
                    && p.length == 1 && p[0] == String.class && m.getName().equals(name)) {
                return m;
            }
        }
        return null;
    }

    // -------------------- 合成信封工具 --------------------

    /** 新建合成 record（只用到 q 字段与本地加密封装，不触库） */
    private static Object newFakeRecord() {
        try {
            return recordClass.getDeclaredConstructor().newInstance();
        } catch (Throwable t) {
            Log.e("totp-sync newFakeRecord err", t);
            return null;
        }
    }

    /** record.s(x)：设置加密密码字段（字段名经 1.1.25/1.1.26 对照稳定） */
    private static void setRecordCipher(Object record, String cipher) {
        try {
            for (Method m : record.getClass().getDeclaredMethods()) {
                Class<?>[] p = m.getParameterTypes();
                if (!Modifier.isStatic(m.getModifiers()) && m.getReturnType() == void.class
                        && p.length == 1 && p[0] == String.class && m.getName().equals("s")) {
                    m.invoke(record, cipher);
                    return;
                }
            }
        } catch (Throwable t) {
            Log.e("totp-sync setRecordCipher err", t);
        }
    }

    /** 读 record 的 ContentValues 成员里的 "password"（blob 字符串） */
    private static String getRecordBlob(Object record) {
        ContentValues cv = findContentValues(record);
        return cv != null ? cv.getAsString("password") : null;
    }

    /**
     * 上传：totpJson → 第二信封 blob 字符串。
     * 复用官方 j()：合成 record 的 q = 本地加密(totpJson)，配假 Cursor 喂 stringIv，
     * j() 内部生成独立 record key 并封出完整信封。
     */
    private static String buildEnvelope(String totpJson) {
        try {
            if (wrapM == null || localEncM == null) return null;
            String[] ivOut = new String[1];
            String cipher = (String) localEncM.invoke(null, totpJson, ivOut);
            if (cipher == null || ivOut[0] == null) return null;

            Object fake = newFakeRecord();
            if (fake == null) return null;
            setRecordCipher(fake, cipher);

            MatrixCursor cursor = new MatrixCursor(new String[]{"stringIv"});
            cursor.addRow(new Object[]{ivOut[0]});
            // j() 直接 getString 读当前行、不自行定位（真实调用方传入前已定位）；
            // 新建 MatrixCursor 游标停在首行之前，必须 moveToFirst，否则 CursorIndexOutOfBounds
            cursor.moveToFirst();

            TL_FAKE.set(Boolean.TRUE);
            try {
                wrapM.invoke(null, fake, cursor);
            } finally {
                TL_FAKE.remove();
            }
            return getRecordBlob(fake);   // j() 收尾把信封写进 q
        } catch (Throwable t) {
            Log.e("totp-sync buildEnvelope err", t);
            return null;
        }
    }

    /**
     * 下载：第二信封 blob 字符串 → totpJson。
     * 复用官方 g()：合成 record 的 q = 信封，g() 解出明文并本地加密收进 q，
     * 再用 w2/e.a 还原出明文。
     */
    private static String openEnvelope(String envelope) {
        try {
            if (unwrapM == null || localDecM == null) return null;
            Object fake = newFakeRecord();
            if (fake == null) return null;
            setRecordCipher(fake, envelope);

            TL_FAKE.set(Boolean.TRUE);
            try {
                unwrapM.invoke(null, fake);
            } finally {
                TL_FAKE.remove();
            }
            ContentValues cv = findContentValues(fake);
            String cipher = getRecordBlob(fake);
            String iv = cv != null ? cv.getAsString("stringIv") : null;
            if (cipher == null || iv == null) {
                Log.w("totp-sync openEnvelope: g() 未产出 cipher/iv (cipher=" + (cipher != null)
                        + ", iv=" + (iv != null) + ")，信封格式可能不被 g() 认可");
                return null;
            }
            return (String) localDecM.invoke(null, cipher, iv);
        } catch (Throwable t) {
            Log.e("totp-sync openEnvelope err", t);
            return null;
        }
    }

    // -------------------- 上传：j() after 注入 blob["t"] --------------------

    private static final class WrapHook extends AbsHook {
        @Override
        public void before() {
            if (Boolean.TRUE.equals(TL_FAKE.get())) return;   // 合成信封流程让路
            try {
                ContentValues cv = findContentValues(getArgs()[0]);
                String secret = cv != null ? cv.getAsString("totpSecret") : null;
                TL_TOTP.set(secret != null && !secret.isEmpty() ? buildPayload(cv) : null);
            } catch (Throwable t) {
                Log.e("totp-sync wrap-before err", t);
            }
        }

        @Override
        public void after() {
            if (Boolean.TRUE.equals(TL_FAKE.get())) return;
            try {
                String payload = TL_TOTP.get();
                TL_TOTP.remove();
                if (payload == null) return;
                String envelope = buildEnvelope(payload);
                if (envelope == null) return;

                Object record = getArgs()[0];
                String blob = getRecordBlob(record);
                if (blob == null || blob.isEmpty()) return;
                JSONObject blobJson = new JSONObject(blob);
                blobJson.put(BLOB_TOTP_KEY, envelope);
                setRecordCipher(record, blobJson.toString());
                Log.i("totp-sync: upload 注入 blob.t 信封");
            } catch (Throwable t) {
                Log.e("totp-sync wrap-after err", t);
            }
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

    // -------------------- 下载：g() 前后拆 blob["t"] --------------------

    private static final class UnwrapHook extends AbsHook {
        @Override
        public void before() {
            if (Boolean.TRUE.equals(TL_FAKE.get())) return;
            try {
                String blob = getRecordBlob(getArgs()[0]);
                if (blob == null || blob.isEmpty()) return;
                JSONObject blobJson = new JSONObject(blob);
                if (!blobJson.has(BLOB_TOTP_KEY)) return;
                String payload = openEnvelope(blobJson.optString(BLOB_TOTP_KEY));
                if (payload != null) TL_TOTP.set(payload);
            } catch (Throwable t) {
                Log.e("totp-sync unwrap-before err", t);
            }
        }

        @Override
        public void after() {
            if (Boolean.TRUE.equals(TL_FAKE.get())) return;
            try {
                String payload = TL_TOTP.get() != null ? TL_TOTP.get() : TL_LEGACY.get();
                TL_TOTP.remove();
                TL_LEGACY.remove();
                if (payload == null) return;
                ContentValues cv = findContentValues(getArgs()[0]);
                if (cv == null) return;
                JSONObject p = new JSONObject(payload);
                if (p.optInt(PAYLOAD_MARKER, 0) != 1) return;
                String s = p.optString("s", null);
                if (s == null || s.isEmpty()) return;
                cv.put("totpSecret", s);
                if (p.has("a")) cv.put("totpAlgorithm", p.optString("a"));
                if (p.has("i")) cv.put("totpIssuer", p.optString("i"));
                cv.put("totpDigits", p.optInt("d", 6));
                Log.i("totp-sync: download 解出 TOTP");
            } catch (Throwable t) {
                TL_TOTP.remove();
                TL_LEGACY.remove();
                Log.e("totp-sync unwrap-after err", t);
            }
        }
    }

    // -------------------- 兼容：1.0.4 复合明文剥离 --------------------

    /** 解密边界 mode=2：旧版复合明文拆回纯密码 + 暂存 totp（新格式明文是纯密码，不进不出） */
    private static final class LegacyStripHook extends AbsHook {
        @Override
        public void after() {
            try {
                if (Boolean.TRUE.equals(TL_FAKE.get())) return;
                if (!(getArg(2) instanceof Integer) || ((Integer) getArg(2)) != 2) return;
                Object r = getResult();
                if (!(r instanceof String)) return;
                String[] split = splitComposite((String) r);
                if (split == null) return;
                setResult(split[1]);
                TL_LEGACY.set(split[0]);
                Log.i("totp-sync: 旧版复合明文已剥离（兼容）");
            } catch (Throwable t) {
                Log.e("totp-sync legacy-strip err", t);
            }
        }
    }

    /**
     * 旧版复合明文 = {@code <len>\n<totpJson><password>}；
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

    // -------------------- 落库：成员 → 落库 ContentValues --------------------

    /**
     * 下载导入的 insert/update 经静态 ContentValues xxx(record) 重建落库值，
     * 重建只认字段（混淆名）——把 ContentValues 成员里的 totp 四列带进结果。
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
     * 装模块后跑一次：把已同步的存量 TOTP 行标 MODIFIED 强制重传，
     * 让 "t" 信封版 blob 覆盖云端旧值。SharedPreferences 一次性闸防循环。
     * v4：载体换 blob["t"] 独立信封（v3 复合明文已废弃，需重传一次洗云）。
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
                if (sp.getBoolean("resync_v4_done", false)) return;

                ContentValues cv = new ContentValues();
                cv.put("localStatus", 1);   // 1 = MODIFIED
                int n = ctx.getContentResolver().update(
                        Uri.parse(Config.PASSWORD_RECORD_URI), cv,
                        "totpSecret IS NOT NULL AND localStatus = ?", new String[]{"-1"});
                sp.edit().putBoolean("resync_v4_done", true).apply();
                Log.i("totp-sync: resync v4 标脏 rows=" + n);
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
