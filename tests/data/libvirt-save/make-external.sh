#!/bin/sh
# Rebuilds tests/fixtures/external/libvirt-save/: `virsh save` of a running
# diskless 4 MiB TCG domain named "fillyfoal" (libvirt and QEMU from Debian
# 13, libvirtd in a privileged Docker container, host name "fillyfoal"),
# once per `save_image_format` in qemu.conf:
#   fillyfoal-xz.sav           xz-compressed migration stream
#   fillyfoal-zstd.sav         zstd-compressed migration stream
#   fillyfoal-raw.sav.raw.zst  the uncompressed (default, "raw") save, stored
#                              with `zstd -19` (the harness decompresses it)
#
#   sh tests/data/libvirt-save/make-external.sh [scratch dir]
#
# Uses the image built from tests/data/qemu-vmstate/Dockerfile. Not
# byte-for-byte reproducible (guest clocks, firmware progress).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
work=${1:-/tmp/fixtures/libvirt-save}
mkdir -p "$work/out"
docker build -q -t fillyfoal-vmstate-tools "$repo/tests/data/qemu-vmstate"
for fmt in xz zstd raw; do
  docker run --rm --privileged --hostname fillyfoal -v "$work/out:/out" -v "$here:/scripts:ro" \
    fillyfoal-vmstate-tools sh /scripts/inner.sh "fillyfoal-$fmt.sav" "$fmt"
done
dst="$repo/tests/fixtures/external/libvirt-save"
mkdir -p "$dst"
cp "$work/out/fillyfoal-xz.sav" "$work/out/fillyfoal-zstd.sav" "$dst/"
zstd -19 -q -f "$work/out/fillyfoal-raw.sav" -o "$dst/fillyfoal-raw.sav.raw.zst"
