package io.github.zjw2017.fuckmiuipasswords.hook;

import androidx.annotation.NonNull;

import io.github.zjw2017.fuckmiuipasswords.net.NetForge;
import com.hchen.hooktool.AbsModule;

import io.github.libxposed.api.XposedModuleInterface;

/**
 * com.miui.passwords（密码管理）的功能单元——只挂排障/兜底：
 * <ol>
 *   <li>{@link NetForge}：网络探测日志</li>
 *   <li>{@link ResultDumpHook}：回传凭据响应 dump + origin 事后兜底改写</li>
 * </ol>
 */
public class PasswordsHook extends AbsModule {

    @Override
    protected void onPackageReady(@NonNull XposedModuleInterface.PackageReadyParam param) {
        register();
    }

    public void register() {
        NetForge.install();
        ResultDumpHook.install();
    }
}
