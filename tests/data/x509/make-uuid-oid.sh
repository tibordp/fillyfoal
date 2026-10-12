#!/bin/sh
# Writes the external x509/uuid-oid.cer fixture with the openssl CLI
# (OpenSSL 3.6): a self-signed Ed25519 certificate whose certificate policy
# and one private extension are UUID OIDs (2.25.<128-bit integer>, X.667),
# arcs too large for 64 bits. The key is random: a re-run gives new bytes
# with the same structure. The subject is a neutral test name.
#
#   sh tests/data/x509/make-uuid-oid.sh <repo root>
set -eu
root=$(cd "${1:-.}" && pwd)
work=/tmp/fixtures/security-x509-uuid
rm -rf "$work"
mkdir -p "$work"
cd "$work"
out=$root/tests/fixtures/external/x509
mkdir -p "$out"

cat >uuid.cnf <<CNF
[req]
distinguished_name = dn
[dn]
[ext]
basicConstraints = critical, CA:false
certificatePolicies = 2.25.329800735698586629295641978511506172918
2.25.223621002425208232339052434370469093187 = ASN1:UTF8String:fillyfoal
CNF
openssl req -x509 -newkey ed25519 -nodes -keyout uuid.key -days 365 -subj "/CN=uuid-oid.example.test" \
    -config uuid.cnf -extensions ext -set_serial 8 -out uuid.pem 2>/dev/null
openssl x509 -in uuid.pem -outform DER -out "$out/uuid-oid.cer"
