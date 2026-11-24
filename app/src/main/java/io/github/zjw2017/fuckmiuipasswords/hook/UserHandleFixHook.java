package io.github.zjw2017.fuckmiuipasswords.hook;

import io.github.zjw2017.fuckmiuipasswords.config.Config;
import io.github.zjw2017.fuckmiuipasswords.util.DexStringLocator;
import io.github.zjw2017.fuckmiuipasswords.util.Log;
import com.hchen.hooktool.core.CoreTool;
import com.hchen.hooktool.hook.AbsHook;

import java.lang.reflect.Method;
import java.util.Set;

/**
 * 保住登录断言的 userHandle（第三道坑：MiFido 自己把 user 抹了）。
 * <p>
 * PasskeyAuthenticator.setUserSelected（锚点 {@link Config#USER_SELECTED_NEEDLE}）
 * 在非 discoverable（allowList）断言里把 user 抹掉后重新序列化（严格照 CTAP2
 * 「allowList 断言不带 user」语义），但 WebAuthn 响应的 userHandle 正是这份
 * user.id，X / Telegram 等 RP 登录要求它——创建响应无此字段，表现为
 * 「创建成功、登录报错」。userHandle 不在 TEE 签名覆盖内（签名只盖
 * authData ‖ clientDataHash），补回安全。
 * <p>
 * 修法：isDiscoverCredential 翻成 true，走「保留 user + userSelected=true」分支；
 * userSelected 全下游无人消费，副作用为零，discoverable 原生流程行为不变。
 */
public final class UserHandleFixHook extends AbsHook {

    @Override
    public void before() {
        try {
            if (getArgs().length >= 2 && Boolean.FALSE.equals(getArg(1))) {
                setArg(1, true);
                Log.i("userHandle fix: isDiscoverCredential false->true（保住 user/userHandle）");
            }
        } catch (Throwable t) {
            Log.e("userHandle fix err", t);
        }
    }

    /** 在目标 APK 里定位并注册（字符串锚点 + 形态 ([BZ)[B，不依赖混淆名） */
    public static void install(String apkPath, ClassLoader classLoader) {
        Set<String> hits = DexStringLocator.findMethodsWithConstant(apkPath, Config.USER_SELECTED_NEEDLE);
        Log.i("locator[user-selected] hits: " + hits);

        int hooked = 0;
        for (String ref : hits) {
            int hash = ref.lastIndexOf('#');
            if (hash <= 0) continue;
            Class<?> cls;
            try {
                cls = CoreTool.findClass(ref.substring(0, hash), classLoader);
            } catch (Throwable t) {
                Log.e("load class failed " + ref, t);
                continue;
            }
            String mName = ref.substring(hash + 1);
            for (Method m : cls.getDeclaredMethods()) {
                Class<?>[] p = m.getParameterTypes();
                if (m.getName().equals(mName)
                        && m.getReturnType() == byte[].class
                        && p.length == 2
                        && p[0] == byte[].class
                        && p[1] == boolean.class) {
                    CoreTool.hookMethod(cls, mName, byte[].class, boolean.class, new UserHandleFixHook());
                    Log.i("userHandle fix hook: " + ref + "([BZ)[B");
                    hooked++;
                }
            }
        }
        if (hooked == 0) {
            Log.w("userHandle fix: NOT hooked —— 目标 APK 结构变了，发日志重新定位");
        }
    }

    private UserHandleFixHook() {}
}
