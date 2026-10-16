#!/bin/sh
# Rebuilds tests/fixtures/external/libvirt-save/fillyfoal-xz.sav: `virsh
# save` of a running diskless 4 MiB TCG domain named "fillyfoal" (libvirt
# and QEMU from Debian 13, libvirtd in a privileged Docker container, host
# name "fillyfoal"), with `save_image_format = "xz"` in qemu.conf, so the
# migration stream after the header and domain XML is xz-compressed.
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
docker run --rm --privileged --hostname fillyfoal -v "$work/out:/out" -v "$here:/scripts:ro" \
  fillyfoal-vmstate-tools sh /scripts/inner.sh fillyfoal-xz.sav xz
mkdir -p "$repo/tests/fixtures/external/libvirt-save"
cp "$work/out/fillyfoal-xz.sav" "$repo/tests/fixtures/external/libvirt-save/fillyfoal-xz.sav"
