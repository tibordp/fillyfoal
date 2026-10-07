#!/bin/sh
# Writes the external openssh-key, openssh-keys and pem/openssh-* fixtures
# with ssh-keygen (OpenSSH_10.2p1 on macOS). Keys are random, so a re-run
# gives new bytes with the same structure. Encrypted keys use the test
# passphrase "fillyfoal" and 4 bcrypt rounds (fast tests).
#
#   sh tests/data/openssh-key/make.sh <repo root>
set -eu
root=$(cd "${1:-.}" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

key() { # name, ssh-keygen options...
    name=$1
    shift
    ssh-keygen -q "$@" -f "$name"
}
key ed25519 -t ed25519 -N '' -C plain@fillyfoal
key ed25519_ctr -t ed25519 -N fillyfoal -a 4 -C ctr@fillyfoal -Z aes256-ctr
key ed25519_chacha -t ed25519 -N fillyfoal -a 4 -C chacha@fillyfoal -Z chacha20-poly1305@openssh.com
key ed25519_gcm -t ed25519 -N fillyfoal -a 4 -C gcm@fillyfoal -Z aes256-gcm@openssh.com
key ecdsa_cbc -t ecdsa -b 256 -N fillyfoal -a 4 -C cbc@fillyfoal -Z aes256-cbc
key rsa -t rsa -b 1024 -N '' -C rsa@fillyfoal
key ca -t ed25519 -N '' -C ca@fillyfoal
ssh-keygen -q -s ca -I fillyfoal-user -n alice,bob -V 20260101:20270101 ed25519.pub

# The binary format inside the PEM armor.
unarmor() {
    sed '1d;$d' "$1" | base64 -d >"$2"
}
out=$root/tests/fixtures/external
mkdir -p "$out/openssh-key" "$out/openssh-keys" "$out/pem"
unarmor ed25519 "$out/openssh-key/ed25519.bin"
unarmor ed25519_ctr "$out/openssh-key/ed25519-aes256-ctr.bin"
unarmor ed25519_chacha "$out/openssh-key/ed25519-chacha20-poly1305.bin"
unarmor ed25519_gcm "$out/openssh-key/ed25519-aes256-gcm.bin"
unarmor ecdsa_cbc "$out/openssh-key/ecdsa-aes256-cbc.bin"
cp rsa "$out/pem/openssh-rsa.key"
cat ed25519.pub rsa.pub ecdsa_cbc.pub ed25519-cert.pub >"$out/openssh-keys/ssh-keygen.pub"
