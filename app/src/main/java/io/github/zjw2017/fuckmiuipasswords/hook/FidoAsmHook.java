package io.github.zjw2017.fuckmiuipasswords.hook;

import androidx.annotation.NonNull;

import io.github.zjw2017.fuckmiuipasswords.net.NetForge;
import com.hchen.hooktool.AbsModule;

import io.github.libxposed.api.XposedModuleInterface;

/**
 * com.fido.asm（MiFido 认证器）的功能单元——全部核心都在这：
 * <ol>
 *   <li>{@link NetForge}：伪造 assetlink 校验响应（绕过小米服务端 RP 白名单）</li>
 *   <li>{@link VendorValidateHook}：短路 vendor validate（双保险）</li>
 *   <li>{@link ClientDataFixHook}：源级改写 clientData origin（Telegram 只认 web 源）</li>
 * </ol>
 * 注册逻辑收敛在 {@link #register}，热重载后由入口以保存的状态重放。
 */
public class FidoAsmHook extends AbsModule {

    @Override
    protected void onPackageReady(@NonNull XposedModuleInterface.PackageReadyParam param) {
        String apk = param.getApplicationInfo() != null ? param.getApplicationInfo().sourceDir : null;
        register(apk, param.getClassLoader());
    }

    public void register(String apkPath, ClassLoader classLoader) {
        NetForge.install();
        if (apkPath != null) {
            VendorValidateHook.install(apkPath, classLoader);
            ClientDataFixHook.install(apkPath, classLoader);
        }
    }
}
