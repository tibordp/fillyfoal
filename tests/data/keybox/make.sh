#!/bin/sh
# Writes keybox/gnupg-2.2.kbx: the pubring.kbx of a fresh GNUPGHOME, written
# by GnuPG 2.2 (Debian bookworm's gnupg and gpgsm) in Docker (network only to
# install the packages). It holds two OpenPGP blobs (an Ed25519 key with a
# Curve25519 subkey and two user IDs; an
# RSA-2048 key) and one X.509 blob (a P-256 certificate made with openssl and
# imported with gpgsm). Throwaway, unprotected keys with neutral user IDs and
# subjects. Keys are random: a re-run gives new bytes with the same
# structure. `kbxutil` output is kept next to the file in the work directory.
#
#   sh tests/data/keybox/make.sh <repo root>
set -eu
root=$(cd "${1:-.}" && pwd)
work=/tmp/fixtures/security-keybox
rm -rf "$work"
mkdir -p "$work/out"
cat >"$work/gen.sh" <<'GEN'
set -eu
export GNUPGHOME=/tmp/gnupg
mkdir -m 700 -p $GNUPGHOME
cd /tmp
g() { gpg --batch --pinentry-mode loopback --passphrase '' --no-tty "$@"; }
g --quick-gen-key "Fillyfoal Test <test@example.test>" future-default default 2y
fpr=$(gpg --list-keys --with-colons test@example.test | awk -F: '/^fpr/ {print $10; exit}')
g --quick-add-uid "$fpr" "Fillyfoal Second <second@example.test>"
g --quick-gen-key "Fillyfoal RSA <rsa@example.test>" rsa2048 sign,cert never
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout x509.key -sha256 -days 365 \
    -subj "/O=Fillyfoal Test/CN=Fillyfoal Test X.509" -addext "subjectAltName=email:x509@example.test" \
    -set_serial 9 -outform DER -out x509.cer 2>/dev/null
gpgsm --batch --disable-crl-checks --import x509.cer
gpgconf --kill all
cp $GNUPGHOME/pubring.kbx /out/pubring.kbx
kbxutil /out/pubring.kbx >/out/kbxutil.txt 2>&1 || true
gpg --version | head -1 >/out/version.txt
GEN
docker run --rm -v "$work/out:/out" -v "$work/gen.sh:/gen.sh:ro" debian:bookworm sh -c \
    'apt-get update -qq >/dev/null && apt-get install -y -qq --no-install-recommends gnupg gpgsm openssl >/dev/null 2>&1 && sh /gen.sh'
cat "$work/out/version.txt"
mkdir -p "$root/tests/fixtures/external/keybox"
cp "$work/out/pubring.kbx" "$root/tests/fixtures/external/keybox/gnupg-2.2.kbx"
chmod 644 "$root/tests/fixtures/external/keybox/gnupg-2.2.kbx"
