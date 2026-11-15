#!/usr/bin/env bash
# 拉取构建依赖到 manual-build/libs/（一次性，之后 build.sh 直接用）
set -euo pipefail

LIBS="$(cd "$(dirname "$0")" && pwd)/libs"
mkdir -p "$LIBS"
cd "$LIBS"

echo "== HookTool 3.2.2 (JitPack) =="
curl -sL -o HookTool-3.2.2.aar "https://jitpack.io/com/github/HChenX/HookTool/3.2.2/HookTool-3.2.2.aar"
python -c "
import zipfile, os
zipfile.ZipFile('HookTool-3.2.2.aar').extract('classes.jar', '.')
os.rename('classes.jar', 'HookTool-3.2.2-classes.jar')
os.remove('HookTool-3.2.2.aar')
"

echo "== libxposed api 102.0.0 (Maven Central，仅编译不进 APK) =="
curl -sL -o api-102.0.0.aar "https://repo1.maven.org/maven2/io/github/libxposed/api/102.0.0/api-102.0.0.aar"
python -c "
import zipfile, os
zipfile.ZipFile('api-102.0.0.aar').extract('classes.jar', '.')
os.rename('classes.jar', 'api-102.0.0-classes.jar')
os.remove('api-102.0.0.aar')
"

echo "== kotlin-stdlib 2.2.10 / 注解 (Maven Central / Google) =="
curl -sL -o kotlin-stdlib-2.2.10.jar "https://repo1.maven.org/maven2/org/jetbrains/kotlin/kotlin-stdlib/2.2.10/kotlin-stdlib-2.2.10.jar"
curl -sL -o annotations-13.0.jar "https://repo1.maven.org/maven2/org/jetbrains/annotations/13.0/annotations-13.0.jar"
curl -sL -o annotation-jvm-1.10.0.jar "https://dl.google.com/dl/android/maven2/androidx/annotation/annotation-jvm/1.10.0/annotation-jvm-1.10.0.jar"

echo
ls -la
echo "OK: libs ready"
