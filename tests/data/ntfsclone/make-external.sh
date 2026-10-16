#!/bin/sh
# Rebuilds the ntfsclone fixtures made by the real tool:
#
#   tests/fixtures/external/ntfsclone/ntfsclone.img.raw.zst
#     `ntfsclone --save-image` of a 2 MiB NTFS volume (stored with
#     `zstd -19`; the harness decompresses it);
#   tests/fixtures/external/gzip/ntfsclone.img.gz
#     the same volume saved to standard output and piped through `gzip -9 -n`.
#
# Runs a plain Debian container (no FUSE or loop devices: mkntfs works on a
# file and ntfscp writes into it), host name "fillyfoal", in a scratch
# directory outside the home directory:
#
#   sh tests/data/ntfsclone/make-external.sh [scratch dir]
#
# mkntfs -T zeroes every timestamp and the script sets a fixed volume
# serial; ntfscp runs under `faketime -f` (a frozen clock), so the output is
# reproducible for the same package versions (inner.sh prints them). Then
# run make-truncated.sh, whose fixture is cut from the first image.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
work=${1:-/tmp/fixtures/ntfsclone}
mkdir -p "$work"
docker run --rm --hostname fillyfoal -v "$work:/w" -v "$here:/data:ro" -w /w \
  debian:trixie-slim sh /data/inner.sh
mkdir -p "$repo/tests/fixtures/external/ntfsclone" "$repo/tests/fixtures/external/gzip"
zstd -19 -q -f "$work/out/ntfsclone.img" -o "$repo/tests/fixtures/external/ntfsclone/ntfsclone.img.raw.zst"
cp "$work/out/ntfsclone-stdout.img.gz" "$repo/tests/fixtures/external/gzip/ntfsclone.img.gz"
