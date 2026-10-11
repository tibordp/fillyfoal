#!/bin/sh
# Writes pgp/gpg-bzip2.gpg with GnuPG 2.4 (Alpine's gnupg) in Docker (network
# only to install the package) with a throwaway GNUPGHOME and an unprotected
# throwaway key: `gpg --compress-algo bzip2 -s`, a BZip2 Compressed Data
# packet holding the one-pass signature, literal data and signature.
# `gpg --list-packets` output is kept next to the file in the work directory.
# Keys are random: a re-run gives new bytes with the same structure.
#
#   sh tests/data/pgp/make-gpg-bzip2.sh <repo root>
set -eu
root=$(cd "${1:-.}" && pwd)
work=/tmp/fixtures/security-pgp-bzip2
rm -rf "$work"
mkdir -p "$work/out"
cat >"$work/gen.sh" <<'GEN'
set -eu
export GNUPGHOME=/tmp/gnupg
mkdir -m 700 -p $GNUPGHOME
cd /out
g() { gpg --batch --pinentry-mode loopback --passphrase '' --no-tty "$@"; }
g --quick-gen-key "Fillyfoal Test <test@example.test>" ed25519 sign,cert 2y
fpr=$(gpg --list-keys --with-colons test@example.test | awk -F: '/^fpr/ {print $10; exit}')
printf 'fillyfoal pgp bzip2 test message\nfillyfoal pgp bzip2 test message\n' >msg.txt
g -u "$fpr" --compress-algo bzip2 --set-filename msg.txt -s -o bzip2.gpg msg.txt
gpg --list-packets --verbose bzip2.gpg >bzip2.gpg.txt 2>&1 || true
gpg --version | head -1 >version.txt
GEN
docker run --rm -v "$work/out:/out" -v "$work/gen.sh:/gen.sh:ro" alpine:3.20 sh -c 'apk add --no-cache gnupg >/dev/null && sh /gen.sh'
cat "$work/out/version.txt"
mkdir -p "$root/tests/fixtures/external/pgp"
cp "$work/out/bzip2.gpg" "$root/tests/fixtures/external/pgp/gpg-bzip2.gpg"
chmod 644 "$root/tests/fixtures/external/pgp/gpg-bzip2.gpg"
