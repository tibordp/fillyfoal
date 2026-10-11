#!/bin/sh
# Writes more external pgp/ and pgp-armor/ fixtures with GnuPG 2.4 (Alpine's
# gnupg) in Docker (network only to install the package) with a throwaway
# GNUPGHOME and an unprotected throwaway key (empty passphrase):
#   pgp/gpg-signed.gpg              plain `gpg -s` (ZIP Compressed Data packet
#                                   of indeterminate length, old format)
#   pgp/gpg-secret-subkeys.gpg      `--export-secret-subkeys` (the primary key
#                                   is a GNU-dummy S2K 101 stub)
#   pgp-armor/gpg-clearsigned.asc   `--clearsign` of a text with a line that
#                                   needs dash-escaping
# `gpg --list-packets` output is kept next to the files in the work
# directory for comparison. Keys are random: a re-run gives new bytes with
# the same structure.
#
#   sh tests/data/pgp/make-gpg-wave-a.sh <repo root>
set -eu
root=$(cd "${1:-.}" && pwd)
work=/tmp/fixtures/security-pgp-wave-a
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
g --quick-add-key "$fpr" cv25519 encr 1y
printf 'fillyfoal pgp test message\n' >msg.txt
printf 'fillyfoal clearsigned text\n- a line starting with a dash\nFrom the last line\n' >clear.txt
g -u "$fpr" --set-filename msg.txt -s -o signed.gpg msg.txt
g --export-secret-subkeys -o secret-subkeys.gpg "$fpr"
g -u "$fpr" --clearsign -o clearsigned.asc clear.txt
for f in signed.gpg secret-subkeys.gpg clearsigned.asc; do
    gpg --list-packets --verbose $f >$f.txt 2>&1 || true
done
gpg --version | head -1 >version.txt
GEN
docker run --rm -v "$work/out:/out" -v "$work/gen.sh:/gen.sh:ro" alpine:3.20 sh -c 'apk add --no-cache gnupg >/dev/null && sh /gen.sh'
cat "$work/out/version.txt"
mkdir -p "$root/tests/fixtures/external/pgp" "$root/tests/fixtures/external/pgp-armor"
cp "$work/out/signed.gpg" "$root/tests/fixtures/external/pgp/gpg-signed.gpg"
cp "$work/out/secret-subkeys.gpg" "$root/tests/fixtures/external/pgp/gpg-secret-subkeys.gpg"
cp "$work/out/clearsigned.asc" "$root/tests/fixtures/external/pgp-armor/gpg-clearsigned.asc"
chmod 644 "$root/tests/fixtures/external/pgp/gpg-signed.gpg" \
    "$root/tests/fixtures/external/pgp/gpg-secret-subkeys.gpg" \
    "$root/tests/fixtures/external/pgp-armor/gpg-clearsigned.asc"
