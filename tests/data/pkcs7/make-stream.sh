#!/bin/sh
# Writes BER-streamed CMS fixtures with the openssl CLI (OpenSSL 3.6):
# `openssl cms -stream -outform DER` writes indefinite lengths and
# segmented (constructed) OCTET STRINGs, as S/MIME streaming does.
#   pkcs7/signed-stream.p7m      SignedData with the content attached
#   pkcs7/enveloped-stream.p7m   EnvelopedData, AES-256-CBC, RSA recipient
# Keys are random: a re-run gives new bytes with the same structure.
# Subjects are neutral test names.
#
#   sh tests/data/pkcs7/make-stream.sh <repo root>
set -eu
root=$(cd "${1:-.}" && pwd)
work=/tmp/fixtures/security-pkcs7-stream
rm -rf "$work"
mkdir -p "$work"
cd "$work"
out=$root/tests/fixtures/external/pkcs7
mkdir -p "$out"

openssl req -x509 -newkey rsa:2048 -nodes -keyout signer.key -days 365 \
    -subj "/O=Fillyfoal Test/CN=stream.example.test" -set_serial 11 -out signer.pem 2>/dev/null
printf 'fillyfoal streamed cms message\n' >msg.txt
openssl cms -sign -stream -binary -in msg.txt -signer signer.pem -inkey signer.key -nocerts \
    -outform DER -out "$out/signed-stream.p7m"
openssl cms -encrypt -stream -binary -in msg.txt -aes256 -recip signer.pem \
    -outform DER -out "$out/enveloped-stream.p7m"
