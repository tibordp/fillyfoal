#!/bin/sh
# Rebuilds tests/fixtures/external/qemu-vmstate/: saved states of diskless
# guests under TCG (QEMU 10.0 from Debian 13, run in Docker, host name
# "fillyfoal"), written by a QMP `migrate "exec:cat > ..."` after `stop`
# (inner.sh, inner-ext.sh) or by a postcopy migration to a socket
# (inner-postcopy.sh), each stored with `zstd -19` (the harness
# decompresses them):
#   microvm.vmstate             2 MiB `microvm`
#   q35-virtio.vmstate          16 MiB `q35` with a virtio-net (user
#                               networking, no option ROM) and a virtio-blk
#                               (null-co) device
#   virt-aarch64.vmstate        8 MiB aarch64 `virt`, `-cpu max` (sends the
#                               target-page-bits configuration subsection)
#   microvm-nofooter.vmstate    `microvm` with
#                               `-global migration.send-section-footer=off`
#   microvm-postcopy.vmstate    `microvm` migrated with postcopy-ram: the
#                               device state in a MIG_CMD_PACKAGED blob
#   sparc64-sun4u.vmstate       16 MiB SPARC64 `sun4u` (8 KiB pages, which
#                               the stream gives only in its VM description)
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
run() {
  docker run --rm --hostname fillyfoal -v "$work/out:/out" -v "$here:/scripts:ro" \
    fillyfoal-vmstate-tools sh "$@"
}
run /scripts/inner.sh microvm 2 microvm.vmstate
run /scripts/inner-ext.sh qemu-system-x86_64 q35-virtio.vmstate -machine q35 -m 16 \
  -netdev user,id=n -device virtio-net-pci,netdev=n,romfile=,mac=52:54:00:00:00:01 \
  -drive if=none,id=d,file=null-co://,format=raw -device virtio-blk-pci,drive=d
run /scripts/inner-ext.sh qemu-system-aarch64 virt-aarch64.vmstate -machine virt -cpu max -m 8
run /scripts/inner-ext.sh qemu-system-x86_64 microvm-nofooter.vmstate -machine microvm -m 2 \
  -global migration.send-section-footer=off
run /scripts/inner-postcopy.sh microvm-postcopy.vmstate
run /scripts/inner-ext.sh qemu-system-sparc64 sparc64-sun4u.vmstate -machine sun4u -m 16
dst="$repo/tests/fixtures/external/qemu-vmstate"
mkdir -p "$dst"
for f in microvm q35-virtio virt-aarch64 microvm-nofooter microvm-postcopy sparc64-sun4u; do
  zstd -19 -q -f "$work/out/$f.vmstate" -o "$dst/$f.vmstate.raw.zst"
done
