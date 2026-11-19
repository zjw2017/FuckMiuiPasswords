package io.github.zjw2017.fuckmiuipasswords.hook;

import androidx.annotation.NonNull;

import io.github.zjw2017.fuckmiuipasswords.net.NetForge;
import com.hchen.hooktool.AbsModule;

import io.github.libxposed.api.XposedModuleInterface;

/**
 * com.miui.passwords（密码管理）的功能单元：
 * <ol>
 *   <li>{@link TotpSyncHook}：TOTP 云同步桥</li>
 *   <li>{@link NetForge}：网络探测日志</li>
 *   <li>{@link ResultDumpHook}：回传凭据响应 dump + origin 事后兜底改写</li>
 * </ol>
 */
public class PasswordsHook extends AbsModule {

    @Override
    protected void onPackageReady(@NonNull XposedModuleInterface.PackageReadyParam param) {
        String apk = param.getApplicationInfo() != null ? param.getApplicationInfo().sourceDir : null;
        register(apk, param.getClassLoader());
    }

    public void register(String apkPath, ClassLoader classLoader) {
        TotpSyncHook.install(apkPath, classLoader);
        NetForge.install();
        ResultDumpHook.install();
    }
}
