#!/bin/sh
# Rebuilds the fsarchiver fixtures made by the real tool,
# tests/fixtures/external/fsarchiver/*.fsa: `fsarchiver savedir` of one
# small directory tree (two small files packed into a shared block, a
# 312.5 KiB file of zeros in blocks of its own, a symbolic link, a subdirectory) with
# each compression algorithm (zstd, lz4, lzo, gzip, bzip2, xz), and one
# encrypted with the password `fillyfoal` (Blowfish); and savefs-ext2.fsa,
# `fsarchiver savefs` of a 4 MiB ext2 filesystem.
#
# Runs plain Debian containers, host name "fillyfoal", in a scratch
# directory outside the home directory; the savefs one is privileged, for a
# loop device and the mount fsarchiver makes (inner-savefs.sh):
#
#   sh tests/data/fsarchiver/make-external.sh [scratch dir]
#
# Everything but some access times (those fsarchiver's own reads leave, the
# real time) is reproducible for the same package versions (the inner
# scripts print them).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
work=${1:-/tmp/fixtures/fsarchiver}
mkdir -p "$work"
docker run --rm --hostname fillyfoal -v "$work:/w" -v "$here:/data:ro" -w /w \
  debian:trixie-slim sh /data/inner.sh
docker run --rm --privileged --hostname fillyfoal -v "$work:/w" -v "$here:/data:ro" -w /w \
  debian:trixie-slim sh /data/inner-savefs.sh
mkdir -p "$repo/tests/fixtures/external/fsarchiver"
cp "$work"/out/*.fsa "$repo/tests/fixtures/external/fsarchiver/"
