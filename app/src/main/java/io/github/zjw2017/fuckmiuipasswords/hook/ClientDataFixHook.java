package io.github.zjw2017.fuckmiuipasswords.hook;

import io.github.zjw2017.fuckmiuipasswords.config.Config;
import io.github.zjw2017.fuckmiuipasswords.util.DexStringLocator;
import io.github.zjw2017.fuckmiuipasswords.util.Log;
import io.github.zjw2017.fuckmiuipasswords.util.OriginFix;
import com.hchen.hooktool.core.CoreTool;
import com.hchen.hooktool.hook.AbsHook;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Set;

/**
 * 源级改写 clientDataJSON.origin（第三道关：Telegram 只认 web 源）。
 * <p>
 * 在 TEE 签名/哈希之前生效，响应里的 clientDataJSON、TEE 签名覆盖的
 * clientDataHash、服务端重算的 hash 三处保持一致——注册（fmt=none）与
 * 登录断言（签名覆盖 clientDataJSON）都可用。
 * <p>
 * 定位：常量串 {@link Config#CLIENT_DATA_NEEDLE} 反查 ClientDataProcessor
 * （当前版本 = o2.b），按方法形态挂两类钩子：
 * <ul>
 *   <li>carrier —— 返回值类只有 byte[] 字段（clientDataJSON + hash 载体），出口处整体修复</li>
 *   <li>hash-input —— {@code ([B)[B} 哈希入口，改写入参保证与载体一致</li>
 * </ul>
 */
public final class ClientDataFixHook {

    public static void install(String apkPath, ClassLoader classLoader) {
        if (!Config.ORIGIN_FIX_ENABLED) return;

        Set<String> hits = DexStringLocator.findClassesWithConstant(apkPath, Config.CLIENT_DATA_NEEDLE);
        Log.i("locator[client-data] hits: " + hits);

        int hooked = 0;
        for (String className : hits) {
            Class<?> cls;
            try {
                cls = CoreTool.findClass(className, classLoader);
            } catch (Throwable t) {
                Log.e("load class failed " + className, t);
                continue;
            }
            for (Method m : cls.getDeclaredMethods()) {
                Class<?> ret = m.getReturnType();
                Class<?>[] p = m.getParameterTypes();

                // 形态1：返回 byte[] 载体的方法（create/get 的 clientData 构造出口）
                if (p.length <= 1 && ret != void.class && !ret.isPrimitive()
                        && !ret.isArray() && hasOnlyByteArrayFields(ret)) {
                    Object[] typesAndHook = new Object[p.length + 1];
                    System.arraycopy(p, 0, typesAndHook, 0, p.length);
                    typesAndHook[p.length] = new CarrierHook();
                    CoreTool.hookMethod(cls, m.getName(), typesAndHook);
                    Log.i("clientData hook: " + className + "->" + m.getName() + " (carrier)");
                    hooked++;
                }

                // 形态2：hash([B)[B —— 改写入参，保证哈希基于改写后的 JSON
                if (ret == byte[].class && p.length == 1 && p[0] == byte[].class) {
                    CoreTool.hookMethod(cls, m.getName(), byte[].class, new HashInputHook());
                    Log.i("clientData hook: " + className + "->" + m.getName() + " (hash-input)");
                    hooked++;
                }
            }
        }
        if (hooked == 0) {
            Log.w("clientData: NOTHING hooked —— 结构变了，发日志重新定位");
        }
    }

    private static boolean hasOnlyByteArrayFields(Class<?> cls) {
        Field[] fs = cls.getDeclaredFields();
        if (fs.length == 0) return false;
        for (Field f : fs) {
            if (f.getType() != byte[].class) return false;
        }
        return true;
    }

    // ------------------------------------------------------------------

    /** 载体出口：byte[] 字段里找出 clientDataJSON 与 32B hash，同步修复 */
    private static final class CarrierHook extends AbsHook {
        @Override
        public void after() {
            Object carrier = getResult();
            if (carrier == null) return;
            try {
                Field jsonField = null, hashField = null;
                byte[] json = null;
                for (Field f : carrier.getClass().getDeclaredFields()) {
                    f.setAccessible(true);
                    byte[] v = (byte[]) f.get(carrier);
                    if (v == null) continue;
                    String s = new String(v, StandardCharsets.UTF_8);
                    if (s.contains("\"origin\"")) {
                        json = v;
                        jsonField = f;
                    } else if (v.length == 32) {
                        hashField = f;
                    }
                }
                if (json == null) return;
                String fixed = OriginFix.fixClientData(new String(json, StandardCharsets.UTF_8));
                if (fixed == null) return;
                byte[] fixedBytes = fixed.getBytes(StandardCharsets.UTF_8);
                jsonField.set(carrier, fixedBytes);
                if (hashField != null) {
                    hashField.set(carrier, MessageDigest.getInstance("SHA-256").digest(fixedBytes));
                }
            } catch (Throwable t) {
                Log.e("fixCarrier err", t);
            }
        }
    }

    /** 哈希入口：改写入参 JSON，保证哈希与载体一致（幂等） */
    private static final class HashInputHook extends AbsHook {
        @Override
        public void before() {
            Object arg = getArg(0);
            if (!(arg instanceof byte[])) return;
            byte[] bytes = (byte[]) arg;
            String fixed = OriginFix.fixClientData(new String(bytes, StandardCharsets.UTF_8));
            if (fixed != null) setArg(0, fixed.getBytes(StandardCharsets.UTF_8));
        }
    }

    private ClientDataFixHook() {}
}
