#!/usr/bin/env bash
# FuckMiuiPasswords 手工构建（libxposed / HookTool 版，不依赖 Gradle）：
# javac + d8 + aapt2 + apksigner
# 依赖在 manual-build/libs/（HookTool AAR classes、libxposed api、kotlin-stdlib 等）
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TC="$ROOT/toolchain"
SDK="$TC/sdk"
BT="$SDK/build-tools/36.0.0"
ANDROID_JAR="$SDK/platforms/android-37.0/android.jar"
BUILD="$ROOT/manual-build"
LIBS="$BUILD/libs"
OUT="$BUILD/out"

# 编译 classpath：HookTool + libxposed api（compileOnly）+ 注解 + android.jar
CP="$ANDROID_JAR:$LIBS/HookTool-3.2.2-classes.jar:$LIBS/api-102.0.0-classes.jar:$LIBS/annotation-jvm-1.10.0.jar:$LIBS/annotations-13.0.jar"

rm -rf "$OUT"; mkdir -p "$OUT"

echo "== [1/6] javac: 模块源码 =="
javac --release 21 -encoding UTF-8 -cp "$CP" \
    -d "$OUT/app-classes" \
    $(find "$ROOT/app/src/main/java" -name '*.java')

echo "== [2/6] d8: classes.dex（模块 + HookTool + kotlin-stdlib；libxposed api 不打包） =="
jar cf "$OUT/app.jar" -C "$OUT/app-classes" .
java -cp "$BT/lib/d8.jar" com.android.tools.r8.D8 \
    --min-api 36 \
    --lib "$ANDROID_JAR" --lib "$LIBS/api-102.0.0-classes.jar" \
    --output "$OUT" \
    "$OUT/app.jar" \
    "$LIBS/HookTool-3.2.2-classes.jar" \
    "$LIBS/kotlin-stdlib-2.2.10.jar" \
    "$LIBS/annotation-jvm-1.10.0.jar" \
    "$LIBS/annotations-13.0.jar"

echo "== [3/6] aapt2: 资源 + manifest =="
"$BT/aapt2.exe" compile --dir "$ROOT/app/src/main/res" -o "$OUT/res.zip"
"$BT/aapt2.exe" link -I "$ANDROID_JAR" \
    --manifest "$BUILD/AndroidManifest.xml" \
    -o "$OUT/base.apk" "$OUT/res.zip"

echo "== [4/6] 打包 classes.dex + META-INF/xposed/* =="
python - "$OUT" "$ROOT" <<'PY'
import sys, zipfile, shutil, os
out, root = sys.argv[1], sys.argv[2]
shutil.copy(os.path.join(out, 'base.apk'), os.path.join(out, 'packed.apk'))
meta = os.path.join(root, 'app/src/main/resources/META-INF/xposed')
with zipfile.ZipFile(os.path.join(out, 'packed.apk'), 'a', zipfile.ZIP_DEFLATED) as z:
    z.write(os.path.join(out, 'classes.dex'), 'classes.dex')
    for name in sorted(os.listdir(meta)):
        z.write(os.path.join(meta, name), 'META-INF/xposed/' + name)
PY

echo "== [5/6] zipalign + 签名 =="
"$BT/zipalign.exe" -f 4 "$OUT/packed.apk" "$OUT/aligned.apk"
# 正式签名：keystore/yz.jks（私钥不入库；密码不入库——读环境变量 KS_PASS
# 或 gitignored 的 keystore/yz.pass，二者都没有则报错）
KS="$ROOT/keystore/yz.jks"
if [ ! -f "$KS" ]; then
    echo "ERROR: 签名密钥不存在: $KS（从 E:\\\\yz.jks 复制）" >&2
    exit 1
fi
if [ -z "${KS_PASS:-}" ] && [ -f "$ROOT/keystore/yz.pass" ]; then
    KS_PASS=$(tr -d '\r\n' < "$ROOT/keystore/yz.pass")
fi
if [ -z "${KS_PASS:-}" ]; then
    echo "ERROR: 未提供密钥密码：export KS_PASS=... 或写入 keystore/yz.pass（不入库）" >&2
    exit 1
fi
java -cp "$BT/lib/apksigner.jar" com.android.apksigner.ApkSignerTool sign \
    --ks "$KS" --ks-key-alias yz --ks-pass "pass:$KS_PASS" --key-pass "pass:$KS_PASS" \
    --out "$ROOT/FuckMiuiPasswords.apk" "$OUT/aligned.apk"

echo "== [6/6] 校验 =="
java -cp "$BT/lib/apksigner.jar" com.android.apksigner.ApkSignerTool verify \
    --print-certs "$ROOT/FuckMiuiPasswords.apk" | head -5

echo
echo "OK => $ROOT/FuckMiuiPasswords.apk"
