#!/bin/sh
# Rebuilds tests/fixtures/external/partclone/ext4-far.img.raw.zst:
# `partclone.extfs -c` of a 32 MiB ext4 volume whose data runs to about
# 13 MiB in (inner-far.sh says what it holds), stored with `zstd -19`.
# A plain Debian container (mkfs.ext4 -d works on a file), host name
# "fillyfoal", in a scratch directory outside the home directory:
#
#   sh tests/data/partclone/make-far.sh [scratch dir]
#
# Timestamps come from faketime and touch and the UUIDs are fixed, so the
# output is reproducible for the same package versions (the script prints
# them).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
work=${1:-/tmp/fixtures/disk-backup-partclone}
mkdir -p "$work"
rm -rf "$work/out"
docker run --rm --hostname fillyfoal -v "$work:/w" -v "$here:/data:ro" -w /w \
  debian:trixie-slim sh /data/inner-far.sh
zstd -19 -q -f "$work/out/ext4-far.img" -o "$repo/tests/fixtures/external/partclone/ext4-far.img.raw.zst"
chmod 644 "$repo/tests/fixtures/external/partclone/ext4-far.img.raw.zst"
