#!/bin/sh
# JFS and NILFS2 fixtures with files (tests/fixtures/external/jfs/tree.jfs.raw.zst,
# tests/fixtures/external/nilfs2/tree.nilfs2.raw.zst). Both need the kernel
# to write them: run as root on a disposable Linux VM (Ubuntu 26.04, kernel
# 7.0, jfsutils 1.1.15, nilfs-tools 2.2.11, host name "fillyfoal"):
#
#   sudo sh make-jfs-nilfs-tree.sh /tmp/fixtures
#
# The tree: a file of several extents, a sparse file, nested directories, a
# directory of 40 entries (past JFS's in-inode dtree root, into dtree
# pages), an empty file, and a short and a long symbolic link (JFS keeps a
# short target in the inode). NILFS2: a checkpoint is made a snapshot, then
# hello.txt is changed, so the snapshot and the head differ. Timestamps are
# those of the run.
set -eu
export TZ=UTC LC_ALL=C
D=$1
M=$D/mnt
rm -rf "$D"; mkdir -p "$M"
cd "$D"

populate() {
  mkdir -p "$1/a/b/c" "$1/many"
  printf 'Hello, fillyfoal!\n' > "$1/hello.txt"
  printf 'deep\n' > "$1/a/b/c/deep.txt"
  seq 1 40000 > "$1/big.txt"
  : > "$1/empty"
  truncate -s 200k "$1/sparse.bin"
  printf 'end\n' >> "$1/sparse.bin"
  for i in $(seq -w 1 40); do
    printf '%s\n' "$i" > "$1/many/entry-with-a-longer-name-$i.txt"
  done
  ln -s hello.txt "$1/link"
  ln -s "$(seq -f 'long-symlink-target-%02g' 1 10 | tr '\n' '/')end" "$1/longlink"
}

modprobe jfs
truncate -s 32M tree.jfs
mkfs.jfs -q -L fillyfoal tree.jfs >/dev/null
mount -o loop tree.jfs "$M"
populate "$M"
umount "$M"

modprobe nilfs2
truncate -s 64M tree.nilfs2
mkfs.nilfs2 -q -B 512 -L fillyfoal tree.nilfs2
mount -o loop tree.nilfs2 "$M"
populate "$M"
sync
mkcp -s "$(losetup -j "$D/tree.nilfs2" | cut -d: -f1)"
printf 'changed after the snapshot\n' >> "$M/hello.txt"
sync
lscp "$(losetup -j "$D/tree.nilfs2" | cut -d: -f1)" > tree.nilfs2.lscp.txt
umount "$M"

for f in tree.jfs tree.nilfs2; do zstd -q -19 -f "$f" -o "$f.raw.zst"; done
ls -l ./*.zst
