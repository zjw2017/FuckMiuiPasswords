package io.github.zjw2017.fuckmiuipasswords.hook;

import io.github.zjw2017.fuckmiuipasswords.config.Config;
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
 * {@code void xxx(String, String, String, boolean, ?)} 匹配后整体置空——
 * 成功路径本来也只是打一行日志返回，行为等价于校验通过。
 */
public final class VendorValidateHook extends AbsHook {

    @Override
    public void before() {
        setResult(null);
        Log.i("SHORT-CIRCUIT vendor validate");
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
