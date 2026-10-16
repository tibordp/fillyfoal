#!/bin/sh
# Rebuilds tests/fixtures/external/ntfsclone/ntfs-far.img.raw.zst:
# `ntfsclone --save-image` of a 32 MiB NTFS volume holding a 12 MiB file
# (inner-far.sh says what it holds), stored with `zstd -19`. A plain Debian
# container (mkntfs and ntfscp work on a file), host name "fillyfoal", in a
# scratch directory outside the home directory:
#
#   sh tests/data/ntfsclone/make-far.sh [scratch dir]
#
# mkntfs -T zeroes every timestamp, the volume serial is fixed and ntfscp
# runs under `faketime -f`, so the output is reproducible for the same
# package versions (the script prints them).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
work=${1:-/tmp/fixtures/disk-backup-ntfsclone}
mkdir -p "$work"
rm -rf "$work/out"
docker run --rm --hostname fillyfoal -v "$work:/w" -v "$here:/data:ro" -w /w \
  debian:trixie-slim sh /data/inner-far.sh
zstd -19 -q -f "$work/out/ntfs-far.img" -o "$repo/tests/fixtures/external/ntfsclone/ntfs-far.img.raw.zst"
chmod 644 "$repo/tests/fixtures/external/ntfsclone/ntfs-far.img.raw.zst"
