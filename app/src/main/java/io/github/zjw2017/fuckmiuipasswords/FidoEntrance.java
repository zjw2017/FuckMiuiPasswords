package io.github.zjw2017.fuckmiuipasswords;

import androidx.annotation.NonNull;

import io.github.zjw2017.fuckmiuipasswords.hook.FidoAsmHook;
import io.github.zjw2017.fuckmiuipasswords.hook.PasswordsHook;
import io.github.zjw2017.fuckmiuipasswords.util.Log;
import com.hchen.hooktool.ModuleConfig;
import com.hchen.hooktool.ModuleData;
import com.hchen.hooktool.ModuleEntrance;

/**
 * FuckMiuiPasswords 模块入口（libxposed / HookTool）。
 * <p>
 * HyperOS 小米密码管理 passkey 两道服务端/格式关卡的绕过：
 * asset_not_support（RP 白名单）与 PASSKEY_ORIGIN_MISMATCH（origin 只认 web 源）。
 * 按目标包把生命周期分发给各功能单元。
 */
public class FidoEntrance extends ModuleEntrance {

    private final FidoAsmHook fidoAsmHook = new FidoAsmHook();
    private final PasswordsHook passwordsHook = new PasswordsHook();

    @Override
    public void initModuleConfig() {
        ModuleConfig.setLogTag(Log.TAG);
        ModuleConfig.setLogLevel(ModuleConfig.LOG_D);
        ModuleConfig.setShowHookSuccessLog(true);
    }

    @Override
    public void handlePackageReady(@NonNull PackageReadyParam param) {
        ModuleData.setClassLoader(param.getClassLoader());
        Log.i("package ready: " + param.getPackageName());

        switch (param.getPackageName()) {
            case "com.fido.asm":
                fidoAsmHook.handlePackageReady(param);
                break;
            case "com.miui.passwords":
                passwordsHook.handlePackageReady(param);
                break;
            default:
                break;
        }
    }
}
