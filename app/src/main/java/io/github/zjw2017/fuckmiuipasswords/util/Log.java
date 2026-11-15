package io.github.zjw2017.fuckmiuipasswords.util;

import com.hchen.hooktool.log.AndroidLog;

/** 统一日志出口（走 HookTool 的 AndroidLog，adb logcat -s FuckMiuiPasswords 可查） */
public final class Log {
    public static final String TAG = "FuckMiuiPasswords";

    public static void i(String msg) {
        AndroidLog.logI(TAG, msg);
    }

    public static void d(String msg) {
        AndroidLog.logD(TAG, msg);
    }

    public static void w(String msg) {
        AndroidLog.logW(TAG, msg);
    }

    public static void e(String msg, Throwable t) {
        AndroidLog.logE(TAG, msg, t);
    }

    private Log() {}
}
