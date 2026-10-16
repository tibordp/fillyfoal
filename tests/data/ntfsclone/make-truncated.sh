#!/bin/sh
# Writes tests/fixtures/synthetic/ntfsclone/truncated.img.raw.zst: the first
# 100352 bytes of the real-tool image made by make-external.sh, which cuts
# the command stream inside cluster 70 (the third of the run of data
# clusters from 68): the volume's boot sector and MFT are whole, what
# follows is missing. Run from anywhere:
#
#   sh tests/data/ntfsclone/make-truncated.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
mkdir -p "$repo/tests/fixtures/synthetic/ntfsclone"
zstd -dcq "$repo/tests/fixtures/external/ntfsclone/ntfsclone.img.raw.zst" | head -c 100352 |
  zstd -19 -q -f -o "$repo/tests/fixtures/synthetic/ntfsclone/truncated.img.raw.zst"
