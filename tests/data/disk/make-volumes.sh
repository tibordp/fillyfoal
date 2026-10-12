#!/bin/sh
# Rebuilds the fixtures that need a mounted file system or a loop device:
# an NTFS volume with $ATTRIBUTE_LIST records and freed index records
# (ntfs-3g), an LVM2 physical volume whose metadata wraps around its
# circular buffer (lvm2), and a hybrid ISO with an appended GPT partition
# plus a raw-sector copy of an ISO (xorriso, then raw-sectors.py).
#
# Runs a privileged Debian container (FUSE and loop devices), host name
# "fillyfoal", in a scratch directory outside the home directory:
#
#   sh tests/data/disk/make-volumes.sh [scratch dir [part...]]
#
# Parts: ntfs, lvm, iso (default: all); only the images built are
# replaced.
#
# Images are stored as `<name>.raw.zst` (zstd -19). Timestamps in the NTFS
# and LVM images are those of the run, and LVM and NTFS write random
# UUIDs and serial numbers, so the images are not byte-reproducible.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
work=${1:-/tmp/fixtures/disk-volumes}
[ $# -gt 0 ] && shift
mkdir -p "$work"
docker run --rm --privileged --hostname fillyfoal -v "$work:/w" -v "$here:/data:ro" -w /w \
  debian:trixie-slim sh /data/volumes-inner.sh "$@"

put() {
  [ -f "$3" ] || return 0
  dest="$repo/tests/fixtures/$1/$2"
  mkdir -p "$dest"
  zstd -19 -q -f "$3" -o "$dest/$(basename "$3").raw.zst"
}
put external ntfs "$work/out/ntfs3g-attrlist.img"
put external lvm2 "$work/out/lvm-wrapped.img"
put external iso9660 "$work/out/xorriso-gpt.iso"
put synthetic iso9660-raw "$work/out/mode1.bin"
put synthetic iso9660-raw "$work/out/mode2.bin"
