#!/bin/sh
# Rebuilds tests/fixtures/external/ntfs-mft/ntfs3g.mft.raw.zst: the $MFT of a
# 2 MiB NTFS volume made with mkntfs and filled through ntfs-3g (hard
# links in extension records, named streams, an object id) and ntfs3 (symbolic links as
# reparse points), copied out byte for byte by raw-mft.py (the clusters
# record 0's $DATA runlist names). Runs a privileged Debian
# container (FUSE and loop devices), host name "fillyfoal", in a scratch
# directory outside the home directory:
#
#   sh tests/data/ntfs-mft/make-mft.sh [scratch dir]
#
# Timestamps are those of the run and the volume serial is random, so the
# file is not byte-reproducible.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
work=${1:-/tmp/fixtures/forensics-ntfs-mft}
mkdir -p "$work"
docker run --rm --privileged --hostname fillyfoal -v "$work:/w" -v "$here:/data:ro" -w /w \
  debian:trixie-slim sh /data/inner.sh
dest="$repo/tests/fixtures/external/ntfs-mft"
mkdir -p "$dest"
zstd -19 -q -f "$work/out/MFT" -o "$dest/ntfs3g.mft.raw.zst"
