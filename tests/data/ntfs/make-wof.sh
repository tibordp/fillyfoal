#!/bin/sh
# Rebuilds tests/fixtures/synthetic/ntfs/wof.img.raw.zst: a 2 MiB NTFS
# volume (mkntfs, ntfs-3g) holding files in the layout Windows' WOF
# driver ("compact /exe", Compact OS) writes: an IO_REPARSE_TAG_WOF
# reparse point naming the file provider and algorithm, the content in
# the named stream WofCompressedData, and a sparse unnamed $DATA of the
# content's size. Nothing on Linux writes this layout, so wof-inner.sh
# assembles it: wimlib compresses each file into a WIM, whose resource
# (chunk table and chunks, the same framing WOF uses) wim-resource.py
# copies out; ntfs-3g then stores it as the named stream and sets the
# reparse data. Synthetic for that reason.
#
#   sh tests/data/ntfs/make-wof.sh [scratch dir]
#
# Runs a privileged Debian container (FUSE), host name "fillyfoal", in a
# scratch directory outside the home directory. Timestamps are those of
# the run and the volume serial is random: not byte-reproducible.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
work=${1:-/tmp/fixtures/disk-a-ntfs-wof}
mkdir -p "$work"
docker run --rm --privileged --hostname fillyfoal -v "$work:/w" -v "$here:/data:ro" -w /w \
  debian:trixie-slim sh /data/wof-inner.sh
dest="$repo/tests/fixtures/synthetic/ntfs"
mkdir -p "$dest"
zstd -19 -q -f "$work/out/wof.img" -o "$dest/wof.img.raw.zst"
