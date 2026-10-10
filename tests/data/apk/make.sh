#!/bin/sh
# Builds tests/fixtures/external/apk/signed.apk and its APK Signature
# Scheme v4 file apk-idsig/signed.apk.idsig with the Android SDK tools:
# aapt2 (resources, binary manifest), javac + d8 (classes.dex), zipalign and
# apksigner (v1 + v2 + v3 + v3.1 with a key rotation lineage, v4), from the
# sources in tests/data/apk/src, in a neutral directory with two fresh
# throwaway EC P-256 keys ("CN=fillyfoal test"). The real resources.arsc and
# AndroidManifest.xml are copied out of the package too.
#
# ECDSA signatures and the keys are random, so a rerun produces different
# signature and certificate bytes (same structure).
#
#   sh tests/data/apk/make.sh [fixtures directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
FIX=$(cd "${1:-$SRC/../../fixtures/external}" && pwd)
JAVA_HOME=${JAVA_HOME:-"/Applications/Android Studio.app/Contents/jbr/Contents/Home"}
SDK=${ANDROID_SDK:-"$HOME/Library/Android/sdk"}
BT="$SDK/build-tools/36.0.0"
JAR="$SDK/platforms/android-36.1/android.jar"
export JAVA_HOME
PATH="$JAVA_HOME/bin:$PATH"
B=/tmp/fixtures/mobile-apk
rm -rf "$B"
mkdir -p "$B"
cp -R "$SRC/src/." "$B/"
cd "$B"
mkdir compiled gen classes dex
"$BT/aapt2" compile --dir res -o compiled/
"$BT/aapt2" link -I "$JAR" --manifest AndroidManifest.xml -o base.apk \
    --java gen --min-sdk-version 21 --target-sdk-version 35 compiled/*.flat
javac --release 8 -encoding UTF-8 -cp "$JAR" -d classes \
    java/org/example/fillyfoal/Main.java gen/org/example/fillyfoal/R.java
"$BT/d8" --release --min-api 21 --lib "$JAR" --output dex \
    $(find classes -name '*.class' | sort)
touch -t 201001010000 dex/classes.dex
(cd dex && zip -X -q ../base.apk classes.dex)
"$BT/zipalign" -p -f 4 base.apk aligned.apk
for k in old new; do
    keytool -genkeypair -keystore $k.p12 -storetype PKCS12 -alias $k \
        -keyalg EC -groupname secp256r1 -validity 10000 \
        -dname "CN=fillyfoal test $k, O=Example, C=US" \
        -storepass fillyfoal -keypass fillyfoal >/dev/null 2>&1
done
"$BT/apksigner" rotate --out lineage \
    --old-signer --ks old.p12 --ks-pass pass:fillyfoal \
    --new-signer --ks new.p12 --ks-pass pass:fillyfoal
"$BT/apksigner" sign --ks old.p12 --ks-pass pass:fillyfoal \
    --next-signer --ks new.p12 --ks-pass pass:fillyfoal \
    --lineage lineage --rotation-min-sdk-version 33 \
    --v1-signing-enabled true --v2-signing-enabled true \
    --v3-signing-enabled true --v4-signing-enabled true \
    --out signed.apk aligned.apk
"$BT/apksigner" verify -v --print-certs --v4-signature-file signed.apk.idsig signed.apk
# A second signing: an RSA key, v1 + v2 + v3 and
# a source stamp (apksig signs the stamp with the
# signer's algorithms, so that key is RSA too).
keytool -genkeypair -keystore rsa.p12 -storetype PKCS12 -alias rsa \
    -keyalg RSA -keysize 2048 -validity 10000 \
    -dname "CN=fillyfoal test rsa, O=Example, C=US" \
    -storepass fillyfoal -keypass fillyfoal >/dev/null 2>&1
keytool -genkeypair -keystore stamp.p12 -storetype PKCS12 -alias stamp \
    -keyalg RSA -keysize 2048 -validity 10000 \
    -dname "CN=fillyfoal test stamp, O=Example, C=US" \
    -storepass fillyfoal -keypass fillyfoal >/dev/null 2>&1
"$BT/apksigner" sign --ks rsa.p12 --ks-pass pass:fillyfoal \
    --stamp-signer --ks stamp.p12 --ks-pass pass:fillyfoal \
    --v1-signing-enabled true --v2-signing-enabled true \
    --v3-signing-enabled true --v4-signing-enabled false \
    --out stamped.apk aligned.apk
"$BT/apksigner" verify -v --print-certs stamped.apk
mkdir -p "$FIX/apk" "$FIX/apk-idsig" "$FIX/apk-lineage" \
    "$FIX/android-resources" "$FIX/android-xml"
cp signed.apk "$FIX/apk/signed.apk"
cp stamped.apk "$FIX/apk/stamped.apk"
cp signed.apk.idsig "$FIX/apk-idsig/signed.apk.idsig"
cp lineage "$FIX/apk-lineage/rotation.lineage"
unzip -o -q signed.apk resources.arsc AndroidManifest.xml res/layout/main.xml -d x
cp x/resources.arsc "$FIX/android-resources/aapt2.arsc"
cp x/AndroidManifest.xml "$FIX/android-xml/aapt2-manifest.xml"
cp x/res/layout/main.xml "$FIX/android-xml/main-layout.xml"
ls -l signed.apk stamped.apk signed.apk.idsig lineage x/resources.arsc x/AndroidManifest.xml
