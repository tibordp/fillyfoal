#!/bin/sh
# Rebuilds tests/fixtures/external/qemu-vmstate/microvm.vmstate.raw.zst:
# the saved state of a diskless 2 MiB `microvm` guest under TCG (QEMU from
# Debian 13, run in Docker, host name "fillyfoal"), written by a QMP
# `migrate "exec:cat > ..."` after `stop`, stored with `zstd -19` (the
# harness decompresses it).
#
#   sh tests/data/qemu-vmstate/make-external.sh [scratch dir]
#
# The image (Dockerfile next to this script) also serves the libvirt-save
# and criu-image fixtures. Not byte-for-byte reproducible: the guest's
# clocks and the firmware's progress differ between runs.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
work=${1:-/tmp/fixtures/qemu-vmstate}
mkdir -p "$work/out"
docker build -q -t fillyfoal-vmstate-tools "$here"
docker run --rm --hostname fillyfoal -v "$work/out:/out" -v "$here:/scripts:ro" \
  fillyfoal-vmstate-tools sh /scripts/inner.sh microvm 2 microvm.vmstate
mkdir -p "$repo/tests/fixtures/external/qemu-vmstate"
zstd -19 -q -f "$work/out/microvm.vmstate" \
  -o "$repo/tests/fixtures/external/qemu-vmstate/microvm.vmstate.raw.zst"
