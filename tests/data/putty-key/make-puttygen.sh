#!/bin/sh
# Writes the external putty-key/ fixtures with PuTTYgen (Debian trixie's
# putty-tools) in Docker, with no network: PPK version 3 keys (Ed25519 and
# ECDSA P-384 unencrypted, RSA-1024 encrypted with Argon2id at small test
# parameters) and a version 2 encrypted Ed25519 key. Passphrase "fillyfoal".
# Keys are random: a re-run gives new bytes with the same structure.
#
#   sh tests/data/putty-key/make-puttygen.sh <repo root>
set -eu
root=$(cd "${1:-.}" && pwd)
work=/tmp/fixtures/security-putty
rm -rf "$work"
mkdir -p "$work/out"
cd "$work"
cat >Dockerfile <<'DOCKER'
FROM debian:trixie-slim
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq putty-tools >/dev/null \
    && rm -rf /var/lib/apt/lists/*
DOCKER
docker build -q -t fillyfoal-putty . >/dev/null
cat >run.sh <<'RUN'
set -eu
cd /out
printf fillyfoal >/tmp/pass
: >/tmp/empty
puttygen -q -t ed25519 -C "puttygen ed25519" --new-passphrase /tmp/empty -o ed25519.ppk
puttygen -q -t ecdsa -b 384 -C "puttygen ecdsa" --new-passphrase /tmp/empty -o ecdsa-p384.ppk
puttygen -q -t rsa -b 1024 -C "puttygen rsa" --new-passphrase /tmp/pass \
    --ppk-param kdf=argon2id,memory=64,passes=1,parallelism=1 -o rsa-argon2id.ppk
puttygen -q -t ed25519 -C "puttygen v2" --new-passphrase /tmp/pass --ppk-param version=2 -o ed25519-v2.ppk
puttygen --version | head -1 >version.txt
RUN
docker run --rm --network none -v "$work/out:/out" -v "$work/run.sh:/run.sh:ro" fillyfoal-putty sh /run.sh
cat "$work/out/version.txt"
out=$root/tests/fixtures/external/putty-key
mkdir -p "$out"
for f in ed25519 ecdsa-p384 rsa-argon2id ed25519-v2; do
    cp "$work/out/$f.ppk" "$out/puttygen-$f.ppk"
done
