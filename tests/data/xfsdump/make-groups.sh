#!/bin/sh
# Rebuilds tests/fixtures/external/xfsdump/groups.xfsdump.raw.zst: a level
# 0 dump with a file of 16 MiB + 8 KiB, which xfsdump writes as two extent
# groups (inner-groups.sh), stored with `zstd -19`. Runs a privileged
# Debian container like make-external.sh:
#
#   sh tests/data/xfsdump/make-groups.sh [scratch dir]
#
# Not reproducible byte for byte: the dump session and media ids are
# random, and the inode generation numbers come from the kernel.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
work=${1:-/tmp/fixtures/xfsdump-groups}
mkdir -p "$work"
docker run --rm --privileged --hostname fillyfoal -v "$work:/w" -v "$here:/data:ro" -w /w \
  debian:trixie-slim sh /data/inner-groups.sh
zstd -19 -q -f "$work/out/groups.xfsdump" \
  -o "$repo/tests/fixtures/external/xfsdump/groups.xfsdump.raw.zst"
