package io.github.zjw2017.fuckmiuipasswords;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import io.github.zjw2017.fuckmiuipasswords.hook.FidoAsmHook;
import io.github.zjw2017.fuckmiuipasswords.hook.PasswordsHook;
import io.github.zjw2017.fuckmiuipasswords.util.Log;
import com.hchen.hooktool.ModuleConfig;
import com.hchen.hooktool.ModuleData;
import com.hchen.hooktool.ModuleEntrance;

import java.util.HashMap;
import java.util.Map;

/**
 * FuckMiuiPasswords 模块入口（libxposed / HookTool）。
 * <p>
 * HyperOS 小米密码管理 passkey 两道服务端/格式关卡的绕过：
 * asset_not_support（RP 白名单）与 PASSKEY_ORIGIN_MISMATCH（origin 只认 web 源）。
 * 按目标包把生命周期分发给各功能单元；支持 API 102 热重载——
 * 模块 APK 更新后旧 Hook 由框架解除，本入口用保存的状态重放注册，
 * 无需 force-stop 目标进程。
 */
public class FidoEntrance extends ModuleEntrance {

    private static final String KEY_PKG = "pkg";
    private static final String KEY_APK = "apk";

    private final FidoAsmHook fidoAsmHook = new FidoAsmHook();
    private final PasswordsHook passwordsHook = new PasswordsHook();

    private volatile String currentPkg = "";
    private volatile String currentApk = "";
    private volatile boolean registered = false;

    @Override
    public void initModuleConfig() {
        ModuleConfig.setLogTag(Log.TAG);
        ModuleConfig.setLogLevel(ModuleConfig.LOG_D);
        ModuleConfig.setShowHookSuccessLog(true);
    }

    @Override
    public void handlePackageReady(@NonNull PackageReadyParam param) {
        ModuleData.setClassLoader(param.getClassLoader());
        // 按进程名归位（共享进程里可能混入其它包的 ready 事件，如 contentcatcher 跑在密码管理进程）
        String pkg = resolveProcessName();
        if (pkg == null || pkg.isEmpty()) {
            pkg = param.getPackageName();
        }
        currentPkg = pkg;
        currentApk = param.getApplicationInfo() != null ? param.getApplicationInfo().sourceDir : null;
        Log.i("package ready: " + param.getPackageName() + " (process=" + pkg + ")");
        if (!registered) {
            registered = true;
            dispatch(currentPkg, currentApk, param.getClassLoader());
        }
    }

    private void dispatch(String pkg, String apkPath, ClassLoader classLoader) {
        switch (pkg == null ? "" : pkg) {
            case "com.fido.asm":
                fidoAsmHook.register(apkPath, classLoader);
                break;
            case "com.miui.passwords":
                passwordsHook.register(apkPath, classLoader);
                break;
            default:
                break;
        }
    }

    // ------------------------- 热重载（API 102）-------------------------

    /**
     * 只允许对目标进程热重载。
     * 判定基准是进程名（共享进程里框架维护的包名会被后加载的包污染，
     * 热重载后的代码代里包名还可能为空）。
     */
    @Override
    public boolean isHotReloadingAllowed(@NonNull String packageName) {
        String pkg = resolveProcessName();
        if (pkg == null || pkg.isEmpty()) {
            pkg = !packageName.isEmpty() ? packageName : currentPkg;
        }
        return "com.fido.asm".equals(pkg) || "com.miui.passwords".equals(pkg);
    }

    /** 旧代码中执行：保存重放注册所需的状态 */
    @NonNull
    @Override
    public Map<String, Object> handleHotReloading(@Nullable android.os.Bundle extras) {
        Map<String, Object> state = new HashMap<>();
        state.put(KEY_PKG, currentPkg);
        state.put(KEY_APK, currentApk);
        Log.i("hot reloading: save state pkg=" + currentPkg + " apk=" + currentApk);
        return state;
    }

    /** 新代码中执行：用保存的状态重放注册（旧 Hook 句柄已由框架解除） */
    @Override
    public void handleHotReloaded(@NonNull HotReloadedParam param, @NonNull ClassLoader classLoader) {
        Map<?, ?> state = castState(param.getSavedInstanceState());
        String savedPkg = state != null ? (String) state.get(KEY_PKG) : null;
        String apk = state != null ? (String) state.get(KEY_APK) : null;

        // 进程名最可信（共享进程里保存的包名可能被污染）；其次才是保存的状态
        String pkg = resolveProcessName();
        if (pkg == null || pkg.isEmpty()) {
            String process = param.getProcessName();
            pkg = process != null ? process.split(":")[0] : savedPkg;
        }
        if (apk == null) {
            apk = resolveApkPath();
        }
        // 恢复字段，供本代代码后续的 isHotReloadingAllowed / handleHotReloading 使用
        currentPkg = pkg != null ? pkg : "";
        currentApk = apk;
        registered = true;
        Log.i("hot reloaded: pkg=" + pkg + " apk=" + apk);
        dispatch(pkg, apk, classLoader);
    }

    /** 当前进程的基础包名（ActivityThread.currentProcessName 反射，去掉 ":xxx" 子进程后缀） */
    private static String resolveProcessName() {
        try {
            Object name = Class.forName("android.app.ActivityThread")
                    .getMethod("currentProcessName").invoke(null);
            if (name instanceof String && !((String) name).isEmpty()) {
                return ((String) name).split(":")[0];
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    /** 运行中的进程里取本包 APK 路径（ActivityThread.currentApplication 反射） */
    private static String resolveApkPath() {
        try {
            Object app = Class.forName("android.app.ActivityThread")
                    .getMethod("currentApplication").invoke(null);
            if (app instanceof android.content.Context) {
                return ((android.content.Context) app).getApplicationInfo().sourceDir;
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    private static Map<?, ?> castState(Object saved) {
        return (saved instanceof Map) ? (Map<?, ?>) saved : null;
    }
}
