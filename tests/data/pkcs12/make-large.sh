#!/bin/sh
# Writes tests/fixtures/external/pkcs12/large-plain.p12 with the openssl CLI
# (OpenSSL 3.6): a password-less store (no encryption, no MAC) whose
# authSafe is larger than the 36 KiB probe window, so identification must
# not need it whole. The size comes from a certificate carrying a 40,000-byte
# private extension (a stand-in for a store of a hundred certificates, which
# would make the snapshot huge). Keys are random: a re-run gives new bytes
# with the same structure. Subjects are neutral test names.
#
#   sh tests/data/pkcs12/make-large.sh <repo root>
set -eu
root=$(cd "${1:-.}" && pwd)
work=/tmp/fixtures/security-pkcs12-large
rm -rf "$work"
mkdir -p "$work"
cd "$work"
out=$root/tests/fixtures/external/pkcs12
mkdir -p "$out"

filler=$(head -c 40000 /dev/zero | tr '\0' 'f' | od -An -v -tx1 | tr -d ' \n')
cat >ext.cnf <<CNF
[req]
distinguished_name = dn
[dn]
[big]
basicConstraints = CA:false
1.3.6.1.4.1.55555.9 = ASN1:FORMAT:HEX,OCTETSTRING:$filler
CNF
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout big.key -days 365 \
    -subj "/O=Fillyfoal Test/CN=large.example.test" -config ext.cnf -extensions big -set_serial 9 -out big.pem 2>/dev/null
openssl pkcs12 -export -inkey big.key -in big.pem -name large -keypbe NONE -certpbe NONE -nomac \
    -passout pass: -out "$out/large-plain.p12"
