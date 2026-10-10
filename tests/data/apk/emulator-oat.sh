#!/bin/sh
# Compiles tests/fixtures/external/apk/signed.apk ahead of time with the ART
# dex2oat of an Android emulator (SDK system image android-37.1
# google_apis_playstore_ps16k arm64-v8a, ART with OAT version 279, VDEX 027,
# image version 119) and pulls what it wrote: the OAT file (app.odex, an
# ELF), the VDEX (app.vdex) and the app image (app.art). oatdump on the
# device dumps all three for comparison (written next to them).
#
# A throwaway AVD lives in /tmp/fixtures/avd. The app image's load address
# is chosen at random, so reruns differ in those addresses.
#
#   sh tests/data/apk/emulator-oat.sh [fixtures directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
FIX=$(cd "${1:-$SRC/../../fixtures/external}" && pwd)
SDK=${ANDROID_SDK:-"$HOME/Library/Android/sdk"}
IMG=system-images/android-37.1/google_apis_playstore_ps16k/arm64-v8a/
B=/tmp/fixtures/mobile-oat
export ANDROID_SDK_ROOT="$SDK" ANDROID_AVD_HOME=/tmp/fixtures/avd
rm -rf "$B" "$ANDROID_AVD_HOME"
mkdir -p "$B" "$ANDROID_AVD_HOME/fillyfoal.avd"
cat > "$ANDROID_AVD_HOME/fillyfoal.ini" <<EOF
avd.ini.encoding=UTF-8
path=$ANDROID_AVD_HOME/fillyfoal.avd
target=android-37.1
EOF
cat > "$ANDROID_AVD_HOME/fillyfoal.avd/config.ini" <<EOF
abi.type=arm64-v8a
hw.cpu.arch=arm64
image.sysdir.1=$IMG
tag.id=google_apis_playstore
hw.ramSize=3072
disk.dataPartition.size=4G
hw.gpu.enabled=no
EOF
ADB="$SDK/platform-tools/adb -s emulator-5640"
"$SDK/emulator/emulator" -avd fillyfoal -no-window -no-audio -no-snapshot \
    -no-boot-anim -gpu swiftshader_indirect -wipe-data -port 5640 \
    > "$B/emulator.log" 2>&1 &
EMU=$!
trap 'kill $EMU 2>/dev/null || true' EXIT
$ADB wait-for-device
until [ "$($ADB shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; do
    sleep 3
done
$ADB push "$FIX/apk/signed.apk" /data/local/tmp/app.apk
$ADB shell 'cd /data/local/tmp &&
    /apex/com.android.art/bin/dex2oat64 --dex-file=app.apk \
        --dex-location=/data/app/app.apk --oat-file=app.odex \
        --instruction-set=arm64 --compiler-filter=speed \
        --app-image-file=app.art --class-loader-context=PCL[] &&
    /apex/com.android.art/bin/oatdump --oat-file=app.odex --output=app.oatdump.txt &&
    /apex/com.android.art/bin/oatdump --app-image=app.art --oat-file=app.odex \
        --output=app.imgdump.txt'
for f in app.odex app.vdex app.art app.oatdump.txt app.imgdump.txt; do
    $ADB pull "/data/local/tmp/$f" "$B/$f"
done
$ADB emu kill || true
mkdir -p "$FIX/oat" "$FIX/vdex" "$FIX/art-image"
cp "$B/app.odex" "$FIX/oat/app.odex"
cp "$B/app.vdex" "$FIX/vdex/app.vdex"
cp "$B/app.art" "$FIX/art-image/app.art"
ls -l "$B"
