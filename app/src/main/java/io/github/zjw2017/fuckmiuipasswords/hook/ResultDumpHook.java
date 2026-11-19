package io.github.zjw2017.fuckmiuipasswords.hook;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;

import io.github.zjw2017.fuckmiuipasswords.config.Config;
import io.github.zjw2017.fuckmiuipasswords.util.Log;
import io.github.zjw2017.fuckmiuipasswords.util.OriginFix;
import com.hchen.hooktool.core.CoreTool;
import com.hchen.hooktool.hook.AbsHook;

/**
 * dump com.miui.passwords setResult 回传的凭据响应（排障），
 * 并做 origin 事后兜底改写（源级改写生效时这里幂等无操作）。
 */
public final class ResultDumpHook extends AbsHook {

    private static final int MAX_CHARS = 4000;

    @Override
    public void before() {
        if (getArgs().length < 2 || !(getArg(1) instanceof Intent)) return;
        Intent data = (Intent) getArg(1);
        OriginFix.fixIntent(data);      // 先改写，再 dump（dump 的是改写后内容）
        if (Config.DUMP_RESULT_INTENTS) dumpIntent(data);
    }

    public static void install() {
        CoreTool.hookMethod(Activity.class, "setResult", int.class, Intent.class, new ResultDumpHook());
        Log.i("ResultDump installed (Activity.setResult)");
    }

    // ------------------------------------------------------------------

    private static void dumpIntent(Intent data) {
        if (data == null) return;
        StringBuilder sb = new StringBuilder();
        sb.append("RESULT intent action=").append(data.getAction())
                .append(" component=").append(data.getComponent());
        Bundle extras = data.getExtras();
        if (extras == null) {
            Log.i(sb.append(" extras=null").toString());
            return;
        }
        for (String key : extras.keySet()) {
            dumpValue(sb, key, extras.get(key), 0);
        }
        Log.i(sb.toString());
    }

    /** 递归拆包：带 getData()/getExtras() 返回 Bundle 的（如 CreateCredentialResponse）继续往里拆 */
    private static void dumpValue(StringBuilder sb, String key, Object v, int depth) {
        if (v == null) {
            sb.append('\n').append("  [").append(key).append("] = null");
            return;
        }
        if (v instanceof Bundle) {
            Bundle b = (Bundle) v;
            sb.append('\n').append("  [").append(key).append("] <Bundle>");
            for (String k : b.keySet()) dumpValue(sb, key + "." + k, b.get(k), depth + 1);
            return;
        }
        if (v instanceof String) {
            String s = (String) v;
            if (s.length() > MAX_CHARS) s = s.substring(0, MAX_CHARS) + "...<" + s.length() + " chars>";
            sb.append('\n').append("  [").append(key).append("] = ").append(s);
            return;
        }
        if (v instanceof byte[]) {
            sb.append('\n').append("  [").append(key).append("] = <bytes " + ((byte[]) v).length + ">");
            return;
        }
        Bundle inner = (depth < 3) ? bundleGetter(v) : null;
        if (inner != null) {
            sb.append('\n').append("  [").append(key).append("] <")
                    .append(v.getClass().getName()).append('>');
            for (String k : inner.keySet()) dumpValue(sb, key + "." + k, inner.get(k), depth + 1);
            return;
        }
        String s = String.valueOf(v);
        if (s.length() > MAX_CHARS) s = s.substring(0, MAX_CHARS) + "...";
        sb.append('\n').append("  [").append(key).append("] = ").append(s);
    }

    /** 反射常见取 Bundle 的 getter（getData/getExtras/getBundle/getCredentialData） */
    private static Bundle bundleGetter(Object v) {
        for (String m : new String[]{"getData", "getExtras", "getBundle", "getCredentialData"}) {
            try {
                java.lang.reflect.Method mm = v.getClass().getMethod(m);
                Object r = mm.invoke(v);
                if (r instanceof Bundle) return (Bundle) r;
            } catch (Throwable ignored) {}
        }
        return null;
    }
}
