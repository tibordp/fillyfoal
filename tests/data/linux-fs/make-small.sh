#!/bin/sh
# CramFS, Minix and JFS fixtures (tests/fixtures/external/{cramfs,minix,jfs}/).
# From the repository root:
#
#   docker build -t fillyfoal-fs-tools tests/data/linux-fs
#   mkdir -p /tmp/fixtures/fs-small
#   docker run --rm --hostname fillyfoal \
#     -v /tmp/fixtures/fs-small:/w -v "$PWD/tests/data/linux-fs:/src:ro" -w /w \
#     fillyfoal-fs-tools sh /src/make-small.sh
#
# mkfs.cramfs (util-linux 2.41) builds from a directory. mkfs.minix and
# mkfs.jfs (jfsutils 1.1.15) can only make empty filesystems, and the
# kernel used here cannot mount either, so those fixtures hold just the
# root directory (and, for JFS, its aggregate and fileset metadata).
set -eu
export TZ=UTC
sh /src/tree.sh /tmp/tree
rm -f ./*.img ./*.cramfs ./*.zst
mkfs.cramfs -N little -n fillyfoal /tmp/tree tree.cramfs
fsck.cramfs -v tree.cramfs > tree.cramfs.txt
for v in 1 2 3; do
  truncate -s 64k minix$v.img
  mkfs.minix -$v minix$v.img > /dev/null
done
truncate -s 16m jfs.img
mkfs.jfs -q -L fillyfoal jfs.img > /dev/null
jfs_fsck -n jfs.img > /dev/null || true
zstd -q -19 -f jfs.img -o jfs.img.raw.zst
ls -l tree.cramfs minix*.img jfs.img.raw.zst
