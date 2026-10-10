#!/bin/sh
# Writes the external pgp/ fixtures with GnuPG 2.4 (Alpine's gnupg) in
# Docker (network only to install the package) with a throwaway GNUPGHOME: a public key with
# signing, encryption and authentication subkeys, an expiry, notations and
# a second user ID; a message signed, compressed and encrypted to it; a
# symmetrically encrypted message (passphrase "fillyfoal"); and a detached
# signature. `gpg --list-packets` output is kept next to the files in the
# work directory for comparison. Keys are random: a re-run gives new bytes
# with the same structure.
#
#   sh tests/data/pgp/make-gpg.sh <repo root>
set -eu
root=$(cd "${1:-.}" && pwd)
work=/tmp/fixtures/security-pgp
rm -rf "$work"
mkdir -p "$work/out"
cat >"$work/gen.sh" <<'GEN'
set -eu
export GNUPGHOME=/tmp/gnupg
mkdir -m 700 -p $GNUPGHOME
cd /out
g() { gpg --batch --pinentry-mode loopback --passphrase '' --no-tty "$@"; }
g --quick-gen-key "Fillyfoal Test <test@example.test>" ed25519 cert 2y
fpr=$(gpg --list-keys --with-colons test@example.test | awk -F: '/^fpr/ {print $10; exit}')
g --quick-add-key "$fpr" ed25519 sign 1y
g --quick-add-key "$fpr" cv25519 encr 1y
g --quick-add-key "$fpr" ed25519 auth 1y
g --quick-add-uid "$fpr" "Fillyfoal Second <second@example.test>"
g --quick-set-primary-uid "$fpr" "Fillyfoal Test <test@example.test>"
g --export "$fpr" >key.gpg
printf 'fillyfoal pgp test message\n' >msg.txt
g --sig-notation test@example.test=fillyfoal --set-filename msg.txt -u "$fpr" -r "$fpr" \
    --compress-algo zlib --sign --encrypt -o signed-encrypted.gpg msg.txt
gpg --batch --pinentry-mode loopback --passphrase fillyfoal --no-tty --symmetric --cipher-algo AES256 \
    --s2k-mode 3 --s2k-count 65536 -o symmetric.gpg msg.txt
g -u "$fpr" --detach-sign -o msg.sig msg.txt
for f in key.gpg signed-encrypted.gpg symmetric.gpg msg.sig; do
    gpg --list-packets --verbose $f >$f.txt 2>&1 || true
done
gpg --version | head -1 >version.txt
GEN
docker run --rm -v "$work/out:/out" -v "$work/gen.sh:/gen.sh:ro" alpine:3.20 sh -c 'apk add --no-cache gnupg >/dev/null && sh /gen.sh'
cat "$work/out/version.txt"
out=$root/tests/fixtures/external/pgp
mkdir -p "$out"
cp "$work/out/key.gpg" "$out/gpg-key.gpg"
cp "$work/out/signed-encrypted.gpg" "$out/gpg-signed-encrypted.gpg"
cp "$work/out/symmetric.gpg" "$out/gpg-symmetric.gpg"
cp "$work/out/msg.sig" "$out/gpg-detached.sig"
