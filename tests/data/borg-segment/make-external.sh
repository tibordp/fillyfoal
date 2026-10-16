#!/bin/sh
# Rebuilds the BorgBackup segment fixtures in
# tests/fixtures/external/borg-segment/ with Debian bookworm's borgbackup
# (1.2.4), in a plain Debian container with host name "fillyfoal":
#
#   sh tests/data/borg-segment/make-external.sh [scratch dir]
#
# inner.sh makes three repositories (`none`, `repokey` and `authenticated`
# encryption, passphrase "fillyfoal"), backs up a few neutral text files
# with each compressor and copies one segment per step. Not reproducible
# byte for byte: object IDs of encrypted and authenticated repositories,
# nonces, ciphertext, timestamps in the metadata and obfuscation padding
# vary between runs.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
work=${1:-/tmp/fixtures/borg-segment}
mkdir -p "$work/out"
docker run --rm --hostname fillyfoal -v "$work/out:/work" -v "$here:/data:ro" \
  debian:bookworm-slim bash /data/inner.sh
mkdir -p "$repo/tests/fixtures/external/borg-segment"
for f in lz4 zstd zlib lzma none obfuscate delete manifest commit repokey authenticated; do
  cp "$work/out/$f" "$repo/tests/fixtures/external/borg-segment/$f"
done
