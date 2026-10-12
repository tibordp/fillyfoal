#!/bin/sh
# Writes keybox/gnupg-2.4-v5.kbx: the pubring.kbx of a fresh GNUPGHOME,
# written by GnuPG 2.4 (Alpine 3.20's gnupg) in Docker (network only to
# install the package). It holds a version 5 OpenPGP key (Ed25519 with a
# Curve25519 subkey, made with --rfc4880bis and Key-Version: 5), which GnuPG
# stores in a version 2 blob (32-byte fingerprints), and an Ed25519 v4 key,
# which it still stores in a version 1 blob. Throwaway, unprotected keys with
# neutral user IDs. Keys are random: a re-run gives new bytes with the same
# structure. `kbxutil` output is kept next to the file in the work directory.
#
#   sh tests/data/keybox/make-v5.sh <repo root>
set -eu
root=$(cd "${1:-.}" && pwd)
work=/tmp/fixtures/security-keybox-v5
rm -rf "$work"
mkdir -p "$work/out"
cat >"$work/gen.sh" <<'GEN'
apk add -q gnupg >/dev/null 2>&1
set -eu
export GNUPGHOME=/tmp/gnupg
mkdir -m 700 -p $GNUPGHOME
cd /tmp
cat >params <<EOF
%no-protection
Key-Type: eddsa
Key-Curve: ed25519
Key-Usage: sign
Key-Version: 5
Subkey-Type: ecdh
Subkey-Curve: cv25519
Subkey-Usage: encrypt
Subkey-Version: 5
Name-Real: Fillyfoal V5
Name-Email: v5@example.test
Expire-Date: 2y
%commit
EOF
gpg --batch --rfc4880bis --gen-key params
gpg --batch --pinentry-mode loopback --passphrase '' --no-tty \
    --quick-gen-key "Fillyfoal V4 <v4@example.test>" ed25519 sign never
gpgconf --kill all
cp $GNUPGHOME/pubring.kbx /out/pubring.kbx
kbxutil /out/pubring.kbx >/out/kbxutil.txt 2>&1 || true
gpg --version | head -1 >/out/version.txt
GEN
docker run --rm -v "$work/out:/out" -v "$work/gen.sh:/gen.sh:ro" alpine:3.20 sh /gen.sh
cat "$work/out/version.txt"
mkdir -p "$root/tests/fixtures/external/keybox"
cp "$work/out/pubring.kbx" "$root/tests/fixtures/external/keybox/gnupg-2.4-v5.kbx"
chmod 644 "$root/tests/fixtures/external/keybox/gnupg-2.4-v5.kbx"
