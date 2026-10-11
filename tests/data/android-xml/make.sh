#!/bin/sh
# Builds tests/fixtures/external/android-xml/namespaces-layout.xml: a layout
# with android:, app: (res-auto), tools: and a custom namespace, compiled and
# linked by aapt2 from Android SDK build-tools 36.0.0 in a neutral directory.
# aapt2 keeps the app: and custom attributes (and their xmlns declarations)
# and drops the tools: attributes and declaration. Checked against
# `aapt2 dump xmltree --file res/layout/namespaces.xml ns.apk`.
#
#   sh tests/data/android-xml/make.sh [output directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
OUT=$(cd "${1:-$SRC/../../fixtures/external/android-xml}" && pwd)
SDK=${ANDROID_SDK:-"$HOME/Library/Android/sdk"}
BT="$SDK/build-tools/36.0.0"
JAR="$SDK/platforms/android-36.1/android.jar"
B=/tmp/fixtures/bytecode-android-xml
rm -rf "$B"
mkdir -p "$B"
cp -R "$SRC/src/." "$B/"
cd "$B"
mkdir compiled
"$BT/aapt2" compile --dir res -o compiled/
"$BT/aapt2" link -I "$JAR" --manifest AndroidManifest.xml -o ns.apk \
    --min-sdk-version 21 --target-sdk-version 35 compiled/*.flat
unzip -o -q ns.apk res/layout/namespaces.xml -d x
cp x/res/layout/namespaces.xml "$OUT/namespaces-layout.xml"
ls -l "$OUT/namespaces-layout.xml"
