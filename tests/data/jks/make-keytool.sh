#!/bin/sh
# Writes the external jks/ and pkcs12/keytool.p12 fixtures with keytool
# (Eclipse Temurin 21 JRE) in Docker, with no network: a JKS and a JCEKS
# key store with an EC private key entry (self-signed certificate chain), a
# trusted certificate entry, and in JCEKS an AES secret key; and a PKCS#12
# key store with the same entries. Store and key password "fillyfoal".
# Keys are random: a re-run gives new bytes with the same structure.
#
#   sh tests/data/jks/make-keytool.sh <repo root>
set -eu
root=$(cd "${1:-.}" && pwd)
work=/tmp/fixtures/security-jks
rm -rf "$work"
mkdir -p "$work/out"
cat >"$work/run.sh" <<'RUN'
set -eu
cd /out
keytool -genkeypair -storetype PKCS12 -keystore ca.p12 -storepass fillyfoal -alias ca -keyalg EC \
    -groupname secp256r1 -dname "CN=Fillyfoal Keytool CA" -validity 365 -ext bc:c 2>/dev/null
keytool -exportcert -keystore ca.p12 -storepass fillyfoal -alias ca -rfc -file ca.pem 2>/dev/null
for type in JKS JCEKS PKCS12; do
    store=keytool.$(echo $type | tr A-Z a-z)
    kt() { keytool -storetype $type -keystore $store -storepass fillyfoal "$@"; }
    kt -genkeypair -alias signer -keyalg EC -groupname secp256r1 -dname "CN=fillyfoal keytool, O=Fillyfoal Test" \
        -validity 365 -keypass fillyfoal 2>/dev/null
    kt -importcert -alias trusted-ca -file ca.pem -noprompt 2>/dev/null
    if [ $type != JKS ]; then
        kt -genseckey -alias secret-aes -keyalg AES -keysize 128 -keypass fillyfoal 2>/dev/null
    fi
done
java -version 2>&1 | head -1 >version.txt
RUN
docker run --rm --network none -v "$work/out:/out" -v "$work/run.sh:/run.sh:ro" eclipse-temurin:21-jre-alpine sh /run.sh
cat "$work/out/version.txt"
mkdir -p "$root/tests/fixtures/external/jks" "$root/tests/fixtures/external/pkcs12"
cp "$work/out/keytool.jks" "$root/tests/fixtures/external/jks/keytool.jks"
cp "$work/out/keytool.jceks" "$root/tests/fixtures/external/jks/keytool.jceks"
cp "$work/out/keytool.pkcs12" "$root/tests/fixtures/external/pkcs12/keytool.p12"
