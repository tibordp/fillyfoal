#!/bin/sh
# Builds tests/fixtures/external/android-resources/configs.arsc and
# configs-sparse-compact.arsc with aapt2 (Android SDK build-tools 36.0.0):
# one string resource in many qualifier directories (MCC/MNC, legacy and
# BCP 47 locales with scripts, 3-letter languages and numeric regions,
# grammatical gender, layout direction, sw/w/h dp, screen size and
# length, round, wide colour gamut and HDR, orientation, UI mode type and
# night, densities, touchscreen, keyboard, navigation and SDK versions),
# so every ResTable_config axis appears in a type chunk. The second file
# is linked with --enable-sparse-encoding and --enable-compact-entries
# (min SDK 34: aapt2 applies neither below that), giving sparse type
# chunks, an OFFSET16 type chunk and compact entries.
#
# Deterministic: rerunning gives the same bytes.
#
#   sh tests/data/android-resources/make-configs.sh [fixtures directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
FIX=$(cd "${1:-$SRC/../../fixtures/external}" && pwd)
SDK=${ANDROID_SDK:-"$HOME/Library/Android/sdk"}
BT="$SDK/build-tools/36.0.0"
JAR="$SDK/platforms/android-36.1/android.jar"
B=/tmp/fixtures/mobile-arsc-configs
rm -rf "$B"
mkdir -p "$B/res/values"
cd "$B"
cat > AndroidManifest.xml <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="org.example.configs">
    <application android:label="@string/greeting" />
</manifest>
EOF
cat > res/values/values.xml <<'EOF'
<resources>
    <string name="greeting">Hello</string>
    <string name="farewell">Goodbye</string>
    <string name="thanks">Thanks</string>
    <string name="yes">Yes</string>
    <string name="no">No</string>
    <string name="maybe">Maybe</string>
    <string name="later">Later</string>
    <string name="never">Never</string>
</resources>
EOF
n=0
for q in mcc310-mnc260 mcc262-mnc00 fr-rCA b+sr+Latn b+ast b+es+419 \
    b+de+DE+1901 feminine ldrtl sw600dp w720dp-h480dp large-long \
    small-notlong round widecg-highdr land night car-notnight television \
    watch tvdpi xxxhdpi anydpi notouch keyshidden-qwerty navhidden-dpad \
    nokeys trackball v26 de-land-v28; do
    n=$((n + 1))
    mkdir -p "res/values-$q"
    printf '<resources>\n    <string name="greeting">Hello %s</string>\n</resources>\n' \
        "$n" > "res/values-$q/values.xml"
done
mkdir compiled
"$BT/aapt2" compile --dir res -o compiled/
"$BT/aapt2" link -I "$JAR" --manifest AndroidManifest.xml -o plain.apk \
    --min-sdk-version 21 --target-sdk-version 35 compiled/*.flat
"$BT/aapt2" link -I "$JAR" --manifest AndroidManifest.xml -o sparse.apk \
    --min-sdk-version 34 --target-sdk-version 35 \
    --enable-sparse-encoding --enable-compact-entries compiled/*.flat
"$BT/aapt2" dump configurations plain.apk
mkdir -p "$FIX/android-resources"
unzip -o -q plain.apk resources.arsc -d plain
unzip -o -q sparse.apk resources.arsc -d sparse
cp plain/resources.arsc "$FIX/android-resources/configs.arsc"
cp sparse/resources.arsc "$FIX/android-resources/configs-sparse-compact.arsc"
