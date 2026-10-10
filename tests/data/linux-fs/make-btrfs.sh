#!/bin/sh
# Btrfs fixtures (tests/fixtures/external/btrfs/). From the repository root:
#
#   docker build -t fillyfoal-fs-tools tests/data/linux-fs
#   mkdir -p /tmp/fixtures/fs-btrfs
#   docker run --rm --hostname fillyfoal \
#     -v /tmp/fixtures/fs-btrfs:/w -v "$PWD/tests/data/linux-fs:/src:ro" -w /w \
#     fillyfoal-fs-tools sh /src/make-btrfs.sh
#
# mkfs.btrfs (btrfs-progs 6.14) populates the image from a directory
# (--rootdir) and shrinks it to its smallest size (about 100 MiB, nearly
# all zeros; stored with zstd -19).
set -eu
export TZ=UTC
sh /src/tree.sh /tmp/tree
setfattr -n user.comment -v 'an attribute' /tmp/tree/hello.txt
rm -f ./*.img ./*.zst
for v in plain zstd; do
  truncate -s 128m $v.img
  if [ $v = zstd ]; then comp="--compress zstd"; else comp=""; fi
  mkfs.btrfs -q -f -r /tmp/tree --shrink $comp \
    -U 00000000-0000-4000-8000-0000000000b0 -L fillyfoal $v.img
  btrfs inspect-internal dump-super -f $v.img > $v.super.txt
  btrfs inspect-internal dump-tree $v.img > $v.tree.txt
  btrfs check $v.img
  zstd -q -19 -f $v.img -o $v.btrfs.raw.zst
done
ls -l ./*.zst
