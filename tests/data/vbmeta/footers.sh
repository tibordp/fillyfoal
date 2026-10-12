#!/bin/sh
# Builds partition images ending in an AVB hashtree footer with AOSP
# avbtool in a Debian container (inside-footers.sh): an ext4 file system
# (mke2fs), an EROFS image (mkfs.erofs) and a bare data partition, each
# given `add_hashtree_footer` (hash tree, no FEC, unsigned vbmeta with a
# property, footer in the last 64 bytes). Their dissectors show what
# follows the file system, which is identified as `avb-footer`. Times,
# UUIDs and hash seeds are fixed, so the images are the same on every run.
#
# avbtool is not packaged in Debian: fetch it first as make.sh says
# (into /tmp/avbtool; MIT licence, used only to generate, not committed).
#
#   sh tests/data/vbmeta/footers.sh [fixtures directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
FIX=$(cd "${1:-$SRC/../../fixtures/external}" && pwd)
B=/tmp/fixtures/system-avb-footers
rm -rf "$B"
mkdir -p "$B/out"
docker run --rm -v "$B:/work" -v "$SRC:/scripts:ro" -v /tmp/avbtool:/avb:ro \
    -w /work debian:trixie-slim sh /scripts/inside-footers.sh
mkdir -p "$FIX/ext" "$FIX/erofs" "$FIX/avb-footer"
# Mostly zeros: stored gzip'd.
gzip -9 -n -c "$B/out/ext4-avb.img" > "$FIX/ext/ext4-avb.img.gz"
gzip -9 -n -c "$B/out/erofs-avb.erofs" > "$FIX/erofs/avb-hashtree.erofs.gz"
gzip -9 -n -c "$B/out/data-avb.img" > "$FIX/avb-footer/data.img.gz"
ls -l "$B/out"
