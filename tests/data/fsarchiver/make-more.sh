#!/bin/sh
# Rebuilds the fsarchiver fixtures of inner-more.sh: a split archive of two
# volumes (split.fsa.raw.zst, split.f01.raw.zst, stored with `zstd -19`)
# and a savefs archive of two filesystems (two.fsa). A privileged Debian
# container, host name "fillyfoal", in a scratch directory outside the
# home directory:
#
#   sh tests/data/fsarchiver/make-more.sh [scratch dir]
#
# Not byte-for-byte reproducible: the archive id and some access times
# come from the real clock, and two.fsa records the mount points fsarchiver
# made (named after the time) and the loop devices.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
work=${1:-/tmp/fixtures/fsarchiver-more}
mkdir -p "$work"
docker run --rm --privileged --hostname fillyfoal -v "$work:/w" -v "$here:/data:ro" -w /w \
  debian:trixie-slim sh /data/inner-more.sh
dest="$repo/tests/fixtures/external/fsarchiver"
mkdir -p "$dest"
zstd -19 -q -f "$work/out/split.fsa" -o "$dest/split.fsa.raw.zst"
zstd -19 -q -f "$work/out/split.f01" -o "$dest/split.f01.raw.zst"
cp "$work/out/two.fsa" "$dest/"
