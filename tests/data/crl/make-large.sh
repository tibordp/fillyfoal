#!/bin/sh
# Writes tests/fixtures/external/crl/large.crl with the openssl CLI
# (OpenSSL 3.6): `openssl ca -gencrl` over a CA database listing 1000 revoked
# certificates with 20-byte serial numbers, so the CRL (about 40 KB) is
# larger than the 36 KiB probe window and identification must not need the
# tbsCertList whole. The CA key is random: a re-run gives new bytes with the
# same structure. Subjects are neutral test names.
#
#   sh tests/data/crl/make-large.sh <repo root>
set -eu
root=$(cd "${1:-.}" && pwd)
work=/tmp/fixtures/security-crl-large
rm -rf "$work"
mkdir -p "$work/db"
cd "$work"
out=$root/tests/fixtures/external/crl
mkdir -p "$out"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -days 3650 \
    -subj "/O=Fillyfoal Test/CN=Fillyfoal Test Large CA" -set_serial 1 -out ca.pem 2>/dev/null
i=1
while [ $i -le 1000 ]; do
    printf 'R\t361231235959Z\t260101%02d%02d00Z\t7F%038X\tunknown\t/CN=revoked %d\n' \
        $((i / 60 % 24)) $((i % 60)) $i $i
    i=$((i + 1))
done >db/index.txt
echo 01 >db/crlnumber
cat >ca.cnf <<CNF
[ca]
default_ca = test
[test]
database = db/index.txt
crlnumber = db/crlnumber
default_md = sha256
default_crl_days = 30
CNF
openssl ca -config ca.cnf -cert ca.pem -keyfile ca.key -gencrl -out large.crl.pem 2>/dev/null
openssl crl -in large.crl.pem -outform DER -out "$out/large.crl"
