package io.github.zjw2017.fuckmiuipasswords.hook;

import io.github.zjw2017.fuckmiuipasswords.config.Config;
import io.github.zjw2017.fuckmiuipasswords.net.AssetlinkGate;
import io.github.zjw2017.fuckmiuipasswords.util.DexStringLocator;
import io.github.zjw2017.fuckmiuipasswords.util.Log;
import com.hchen.hooktool.core.CoreTool;
import com.hchen.hooktool.hook.AbsHook;

import java.lang.reflect.Method;
import java.util.Set;

/**
 * 短路 vendor validate（第二道关：小米服务端 RP 白名单）。
 * <p>
 * 定位不写死混淆名：常量串 {@link Config#VALIDATOR_NEEDLE} 反查持有类
 * （当前版本 = p2.e / VendorValidator），再按方法形态
 * {@code void xxx(String, String, String, boolean, ?)} 匹配——入参即
 * (rpId, packageName, certSha256, isBrowser, listener)（p2.c.a → p2.e.a
 * 调用点实证）。整体置空 = 校验通过（成功路径本来也只是打一行日志返回）。
 * <p>
 * 短路前先过 {@link AssetlinkGate} 闸门：过了才置空；没过则放行原方法
 * 跑完真实失败路径（POST → NetForge 伪造忠实拒绝体 → 原生
 * "vendor validate failed : message=asset_not_support…serialNo=…" 异常），
 * 拒批语义与真机完全一致。两层与 NetForge 共用同一闸门规则。
 */
public final class VendorValidateHook extends AbsHook {

    @Override
    public void before() {
        String rp = strArg(0);
        String pkg = strArg(1);
        String fp = strArg(2);
        if (rp == null || pkg == null) {
            // 形态漂移认不出入参：按旧行为放行并报警（不影响可用性，排障后收紧）
            Log.w("GATE: validate args unreadable（目标 APK 形态漂移?）按旧行为放行");
            setResult(null);
            return;
        }
        boolean isBrowser = getArg(3) instanceof Boolean && (Boolean) getArg(3);
        int verdict = AssetlinkGate.check(rp, pkg, fp, null, isBrowser);
        if (verdict == AssetlinkGate.PASS) {
            setResult(null);
            Log.i("SHORT-CIRCUIT vendor validate [gate PASS] rp=" + rp + " pkg=" + pkg);
        } else {
            // 不短路：原方法 POST → NetForge 闸门伪造拒绝 → 原生失败异常
            Log.i("GATE DENY -> 走原生失败路径 rp=" + rp + " pkg=" + pkg + " fp=" + fp);
        }
    }

    private String strArg(int index) {
        try {
            Object a = getArgs().length > index ? getArg(index) : null;
            return a instanceof String ? (String) a : null;
        } catch (Throwable t) {
            return null;
        }
    }

    /** 在目标 APK 里定位并注册 */
    public static void install(String apkPath, ClassLoader classLoader) {
        if (!Config.SHORT_CIRCUIT_VENDOR_VALIDATOR) return;

        try {
            Set<String> mgr = DexStringLocator.findClassesWithConstant(apkPath, Config.AUTH_MANAGER_NEEDLE);
            Log.i("locator[auth-manager] hits: " + mgr);
        } catch (Throwable t) {
            Log.e("locator[auth-manager] err", t);
        }

        Set<String> hits = DexStringLocator.findClassesWithConstant(apkPath, Config.VALIDATOR_NEEDLE);
        Log.i("locator[vendor-validator] hits: " + hits);

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
                Class<?>[] p = m.getParameterTypes();
                if (m.getReturnType() == void.class
                        && p.length == 5
                        && p[0] == String.class
                        && p[1] == String.class
                        && p[2] == String.class
                        && p[3] == boolean.class) {
                    CoreTool.hookMethod(cls, m.getName(),
                            p[0], p[1], p[2], p[3], p[4], new VendorValidateHook());
                    Log.i("SHORT-CIRCUIT " + className + "->" + m.getName()
                            + "(String,String,String,boolean," + p[4].getName() + ")");
                    hooked++;
                }
            }
        }
        if (hooked == 0) {
            Log.w("SHORT-CIRCUIT: no method matched!（目标 APK 可能升级改了结构）");
        }
    }

    private VendorValidateHook() {}
}
