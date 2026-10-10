#!/bin/sh
# Writes the external openssh-keys/certificates.pub and openssh-krl/
# fixtures with ssh-keygen (OpenSSH_10.2p1 on macOS). Keys are random: a
# re-run gives new bytes with the same structure.
#
#   sh tests/data/openssh-cert/make.sh <repo root>
set -eu
root=$(cd "${1:-.}" && pwd)
work=/tmp/fixtures/security-openssh-cert
rm -rf "$work"
mkdir -p "$work"
cd "$work"
out=$root/tests/fixtures/external
mkdir -p "$out/openssh-keys" "$out/openssh-krl"

ssh-keygen -q -t rsa -b 1024 -N '' -C rsa-ca@fillyfoal -f ca_rsa
ssh-keygen -q -t ed25519 -N '' -C ed25519-ca@fillyfoal -f ca_ed
ssh-keygen -q -t ed25519 -N '' -C host@fillyfoal -f host
ssh-keygen -q -t ecdsa -b 384 -N '' -C alice@fillyfoal -f alice

# A host certificate signed by the RSA CA (rsa-sha2-512), and a user
# certificate with critical options and a trimmed extension list.
ssh-keygen -q -s ca_rsa -I host.example.test -h -n host.example.test,192.0.2.1 \
    -V 20260101:20270101 -z 42 host.pub
ssh-keygen -q -s ca_ed -I alice@example.test -n alice,admin -z 7 -V always:forever \
    -O clear -O permit-pty -O force-command=/usr/bin/true -O source-address=192.0.2.0/24,2001:db8::/32 \
    alice.pub
cat host-cert.pub alice-cert.pub >"$out/openssh-keys/certificates.pub"

# A key revocation list: serials, a serial range and key IDs under the
# Ed25519 CA, an explicit key, a key by SHA-256 and a fingerprint.
cat >spec.txt <<SPEC
serial: 7
serial: 100-199
id: alice@example.test
id: lost-laptop
SPEC
printf 'key: ' >>spec.txt
cat host.pub >>spec.txt
printf 'sha256: ' >>spec.txt
cat alice.pub >>spec.txt
printf 'hash: ' >>spec.txt
ssh-keygen -l -E sha256 -f ca_rsa.pub | awk '{print $2}' >>spec.txt
ssh-keygen -q -k -f "$out/openssh-krl/revoked.krl" -s ca_ed.pub -z 3 spec.txt
