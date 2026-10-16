#!/bin/sh
# Rebuilds the xfsdump fixtures made by the real tool,
# tests/fixtures/external/xfsdump/: a level 0 and a level 1 dump of a
# small XFS filesystem (inner.sh says what it holds), stored with
# `zstd -19` (the harness decompresses them).
#
# xfsdump needs a mounted XFS filesystem, so this runs a privileged Debian
# container (a loop device and a mount in the Docker VM's kernel), host
# name "fillyfoal", in a scratch directory outside the home directory:
#
#   sh tests/data/xfsdump/make-external.sh [scratch dir]
#
# Not reproducible byte for byte: the dump session and media ids are
# random, and the inode generation numbers come from the kernel.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
work=${1:-/tmp/fixtures/xfsdump}
mkdir -p "$work"
docker run --rm --privileged --hostname fillyfoal -v "$work:/w" -v "$here:/data:ro" -w /w \
  debian:trixie-slim sh /data/inner.sh
mkdir -p "$repo/tests/fixtures/external/xfsdump"
for f in level0 level1; do
  zstd -19 -q -f "$work/out/$f.xfsdump" -o "$repo/tests/fixtures/external/xfsdump/$f.xfsdump.raw.zst"
done
