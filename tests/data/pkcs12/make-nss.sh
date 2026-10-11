#!/bin/sh
# Writes tests/fixtures/external/pkcs12/nss-pk12util.p12 with NSS pk12util
# (Alpine 3.20 nss-tools, NSS 3.105) in Docker (network only to
# install the package): an EC P-256 key and its self-signed certificate,
# made with the host's openssl CLI, imported into a fresh NSS database and
# exported again. pk12util writes BER throughout: indefinite lengths and
# segmented (constructed) OCTET STRINGs; password "fillyfoal". NSS uses
# 600,000 PBKDF2 iterations for the MAC and both encryptions and has no
# option to lower them, so this fixture is slow in the robustness sweep
# (each mutated copy derives keys again). Keys are
# random: a re-run gives new bytes with the same structure. Subjects are
# neutral test names.
#
#   sh tests/data/pkcs12/make-nss.sh <repo root>
set -eu
root=$(cd "${1:-.}" && pwd)
work=/tmp/fixtures/security-pkcs12-nss
rm -rf "$work"
mkdir -p "$work/out"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$work/k.pem" -out "$work/c.pem" \
    -subj "/O=Fillyfoal Test/CN=nss.example.test" -days 365 2>/dev/null
openssl pkcs12 -export -inkey "$work/k.pem" -in "$work/c.pem" -name fillyfoal -passout pass:fillyfoal \
    -out "$work/out/in.p12"
cat >"$work/gen.sh" <<'GEN'
set -eu
cd /tmp
mkdir db
certutil -N -d sql:db --empty-password
pk12util -i /out/in.p12 -d sql:db -W fillyfoal
pk12util -o /out/nss.p12 -n fillyfoal -d sql:db -W fillyfoal
apk list -I nss-tools 2>/dev/null >/out/version.txt
GEN
docker run --rm -v "$work/out:/out" -v "$work/gen.sh:/gen.sh:ro" alpine:3.20 sh -c \
    'apk add --no-cache nss-tools >/dev/null && sh /gen.sh'
cat "$work/out/version.txt"
out=$root/tests/fixtures/external/pkcs12
mkdir -p "$out"
cp "$work/out/nss.p12" "$out/nss-pk12util.p12"
chmod 644 "$out/nss-pk12util.p12"
