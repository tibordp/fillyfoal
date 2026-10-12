#!/bin/sh
# Builds tests/fixtures/external/pkpass/boarding.pkpass with passkit-generator
# 3.3.1 (npm) in Docker node:20-bookworm-slim, signed with throwaway
# certificates (a self-signed "fillyfoal WWDR" CA and a signer it issues,
# made with the image's OpenSSL). The signature, certificates and zip
# times differ between runs.
#
#   docker run --rm -v "$PWD/tests/data/pkpass:/src:ro" -v /tmp/fixtures/misc-pkpass:/out \
#     node:20-bookworm-slim sh /src/make.sh
set -e
apt-get update -qq >/dev/null && apt-get install -y -qq openssl >/dev/null
mkdir -p /work && cd /work
npm init -y >/dev/null
npm install --silent passkit-generator@3.3.1 >/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=fillyfoal WWDR" \
    -keyout wwdr.key -out wwdr.pem 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=fillyfoal pass signer" \
    -keyout signer.key -out signer.csr 2>/dev/null
openssl x509 -req -in signer.csr -CA wwdr.pem -CAkey wwdr.key -CAcreateserial \
    -days 3650 -out signer.pem 2>/dev/null
cp /src/gen.js .
node gen.js
cp boarding.pkpass /out/
