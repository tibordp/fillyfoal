#!/bin/sh
# Writes tests/fixtures/external/sfnt/fonttools-cff2-svg-dsig.otf: OpenSSL
# makes a throwaway self-signed EC certificate (CN=fillyfoal) and a detached
# DER PKCS#7 SignedData over a fixed text; fontTools then builds the font
# around it (make_cff2_svg_dsig.py). The key, certificate and signing time
# are fresh each run, so the bytes differ between runs; the structure does
# not. The signature does not cover the font (DSIG's real digest scheme is
# not reproduced): it only gives the DSIG block a genuine PKCS#7 payload.
#
#   sh tests/data/sfnt/make_cff2_svg_dsig.sh <repo root>
set -eu
root=$(cd "${1:-.}" && pwd)
work=/tmp/fixtures/image-sfnt-cff2
rm -rf "$work"
mkdir -p "$work"
cd "$work"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout key.pem -out cert.pem -subj /CN=fillyfoal -days 3650 2>/dev/null
printf 'fillyfoal font signature\n' >data.txt
openssl cms -sign -binary -in data.txt -signer cert.pem -inkey key.pem \
    -outform DER -out sig.p7s -md sha256
uv run --no-project --with fonttools==4.66.1 python3 -I \
    "$root/tests/data/sfnt/make_cff2_svg_dsig.py" sig.p7s font.otf
mkdir -p "$root/tests/fixtures/external/sfnt"
cp font.otf "$root/tests/fixtures/external/sfnt/fonttools-cff2-svg-dsig.otf"
