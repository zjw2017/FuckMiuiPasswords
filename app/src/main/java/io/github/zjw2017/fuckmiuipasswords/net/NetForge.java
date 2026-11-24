package io.github.zjw2017.fuckmiuipasswords.net;

import io.github.zjw2017.fuckmiuipasswords.config.Config;
import io.github.zjw2017.fuckmiuipasswords.util.Log;
import com.hchen.hooktool.core.CoreTool;
import com.hchen.hooktool.hook.AbsHook;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;

/**
 * 网络层：伪造小米 assetlink 校验响应 + 请求/响应探测日志。
 * <p>
 * 拦截 {@link URL#openConnection()}，在真实连接实现类上动态挂
 * connect/getResponseCode/getOutputStream/getHeaderFields/getInputStream——
 * 不依赖目标 APK 任何混淆类名，okhttp/HttpURLConnectionImpl 皆可。
 * 命中 {@link Config#forgeBodyFor(String)} 的请求被完全架空（不联网也生效）。
 * <p>
 * assetlink 请求的伪造响应经 {@link AssetlinkGate} 闸门裁决：解析 POST 表单的
 * (rp, packageName, fingerprints)，过了闸才给 code:0，否则伪造忠实失败体。
 */
public final class NetForge {

    /** 已挂载的连接实现类——每个类只挂一次（实现类要到首次 openConnection 才揭晓） */
    private static final Set<Class<?>> HOOKED_CONN_CLASSES =
            Collections.synchronizedSet(new HashSet<>());
    /** 伪造目标的请求体捕获：conn → 表单字节（getOutputStream 写入，getInputStream 裁决时取用） */
    private static final Map<Object, ByteArrayOutputStream> REQ_BODIES =
            Collections.synchronizedMap(new WeakHashMap<>());
    private static final int MAX_LOG_BODY = 600;

    public static void install() {
        AbsHook openHook = new AbsHook() {
            @Override
            public void after() {
                Object conn = getResult();
                if (conn instanceof URLConnection) {
                    hookConnClassOnce(conn.getClass());
                }
            }
        };
        CoreTool.hookMethod(URL.class, "openConnection", openHook);
        CoreTool.hookMethodIfExists(URL.class, "openConnection", Proxy.class, openHook);
        Log.i("NetHook installed (forge=" + Config.FORGE_ASSETLINK_RESPONSE
                + ", netlog=" + Config.LOG_NETWORK + ")");
    }

    // ------------------------------------------------------------------

    private static void hookConnClassOnce(Class<?> cls) {
        if (!HOOKED_CONN_CLASSES.add(cls)) return;
        boolean isHttp = HttpURLConnection.class.isAssignableFrom(cls);

        // connect()：伪造目标直接跳过真实连接
        CoreTool.hookMethodIfExists(cls, "connect", new AbsHook() {
            @Override
            public void before() {
                if (forgedUrl(getThisObject()) != null) setResult(null);
            }
        });

        // getResponseCode()：伪造目标直接 200
        if (isHttp) {
            CoreTool.hookMethodIfExists(cls, "getResponseCode", new AbsHook() {
                @Override
                public void before() {
                    if (forgedUrl(getThisObject()) != null) setResult(200);
                }
            });
        }

        // getOutputStream()：伪造目标把请求体收进捕获缓冲（闸门裁决要用）
        CoreTool.hookMethodIfExists(cls, "getOutputStream", new AbsHook() {
            @Override
            public void before() {
                if (forgedUrl(getThisObject()) != null) {
                    ByteArrayOutputStream bos = new ByteArrayOutputStream();
                    synchronized (REQ_BODIES) {
                        REQ_BODIES.put(getThisObject(), bos);
                    }
                    setResult(bos);
                }
            }
        });

        // getHeaderFields()：伪造目标给空表，避免 okhttp 因未连接抛异常
        CoreTool.hookMethodIfExists(cls, "getHeaderFields", new AbsHook() {
            @Override
            public void before() {
                if (forgedUrl(getThisObject()) != null) setResult(new java.util.HashMap<>());
            }
        });

        // getInputStream()：伪造响应体 / 截获日志（before 置结果会跳过 after，两分支互斥）
        CoreTool.hookMethodIfExists(cls, "getInputStream", new AbsHook() {
            @Override
            public void before() {
                String forge = forgedUrl(getThisObject());
                if (forge != null) {
                    String url = safeUrl(getThisObject());
                    String reqBody = takeRequestBody(getThisObject());
                    // assetlink 走闸门裁决（通过体 / 忠实失败体）；其它伪造目标用静态体
                    String resp = (url != null && url.contains("/pass/verify/assetlink"))
                            ? AssetlinkGate.forgeResponse(reqBody)
                            : forge;
                    Log.i("FORGE response <= " + describe(getThisObject())
                            + " req=" + preview(reqBody == null ? new byte[0]
                                    : reqBody.getBytes(StandardCharsets.UTF_8)));
                    setResult(new ByteArrayInputStream(
                            resp.getBytes(StandardCharsets.UTF_8)));
                }
            }

            @Override
            public void after() {
                Object r = getResult();
                if (!(r instanceof InputStream)) return;
                if (!Config.LOG_NETWORK) return;
                String url = safeUrl(getThisObject());
                if (!Config.isInterestingUrl(url)) return;
                try {
                    // 缓冲响应体记日志后换新流返回，app 侧照常读到完整内容；64KB 上限防大响应拖死
                    InputStream in = (InputStream) r;
                    ByteArrayOutputStream bos = new ByteArrayOutputStream();
                    byte[] buf = new byte[4096];
                    int total = 0, n;
                    while (total < 65536 && (n = in.read(buf)) > 0) {
                        bos.write(buf, 0, n);
                        total += n;
                    }
                    try { in.close(); } catch (IOException ignored) {}
                    byte[] body = bos.toByteArray();
                    Log.i("NET <= " + describe(getThisObject())
                            + " body(" + body.length + "B)=" + preview(body));
                    setResult(new ByteArrayInputStream(body));
                } catch (Throwable t) {
                    Log.e("netlog read err", t);
                }
            }
        });

        Log.i("conn class hooked: " + cls.getName());
    }

    // ------------------------------------------------------------------

    /** 若命中伪造规则返回伪造体（调用方据此短路）；否则 null */
    private static String forgedUrl(Object conn) {
        if (!Config.FORGE_ASSETLINK_RESPONSE) return null;
        return Config.forgeBodyFor(safeUrl(conn));
    }

    /** 取走该连接捕获的请求体（getOutputStream 时收进缓冲），无则 null */
    private static String takeRequestBody(Object conn) {
        synchronized (REQ_BODIES) {
            ByteArrayOutputStream bos = REQ_BODIES.remove(conn);
            return bos == null ? null : new String(bos.toByteArray(), StandardCharsets.UTF_8);
        }
    }

    private static String safeUrl(Object conn) {
        try {
            return ((URLConnection) conn).getURL().toString();
        } catch (Throwable t) {
            return null;
        }
    }

    private static String describe(Object conn) {
        String method = "?";
        try {
            Object m = CoreTool.callMethod(conn, "getRequestMethod");
            if (m != null) method = m.toString();
        } catch (Throwable ignored) {}
        return method + " " + safeUrl(conn);
    }

    private static String preview(byte[] body) {
        String s = new String(body, 0, Math.min(body.length, MAX_LOG_BODY), StandardCharsets.UTF_8);
        return s.replace('\n', ' ').replace('\r', ' ');
    }

    private NetForge() {}
}
