#!/bin/sh
# UFS fixtures for the directory walker (tests/fixtures/external/ufs/
# makefs-tree-ufs1.img.raw.zst, makefs-tree-be-ufs2.img.raw.zst). From the
# repository root:
#
#   mkdir -p /tmp/fixtures/disk-ufs-tree
#   docker run --rm --hostname fillyfoal \
#     -v /tmp/fixtures/disk-ufs-tree:/w -v "$PWD/tests/data/linux-fs:/src:ro" -w /w \
#     debian:trixie-slim sh /src/make-ufs-tree.sh
#
# makefs (NetBSD's, Debian 20190105) from one tree: a file past the 12
# direct blocks (single indirect), a sparse file, nested directories, a
# directory whose records fill several 512-byte chunks, a short and a long
# symbolic link (the long one in a block). UFS1 little-endian with 4 KiB
# blocks and 512-byte fragments in several cylinder groups (so inodes are
# found past the first group, with UFS1's group stagger); UFS2 big-endian
# (`-B be`). makefs stamps inode change times with the time of the run,
# so the images are not reproducible byte for byte.
set -eu
export TZ=UTC
apt-get update -qq
apt-get install -y -qq --no-install-recommends makefs zstd >/dev/null
rm -rf tree ./*.img ./*.zst
mkdir -p tree/a/b/c tree/many
printf 'Hello, fillyfoal!\n' > tree/hello.txt
printf 'deep\n' > tree/a/b/c/deep.txt
seq 1 40000 > tree/big.txt
truncate -s 200k tree/sparse.bin
printf 'end\n' >> tree/sparse.bin
for i in $(seq -w 1 40); do
  printf '%s\n' "$i" > "tree/many/entry-with-a-longer-name-$i.txt"
done
ln -s hello.txt tree/link
ln -s "$(seq -f 'long-symlink-target-%02g' 1 10 | tr '\n' '/')end" tree/longlink
touch -h -d '2024-01-01 00:00:00' tree tree/* tree/*/* tree/a/b/* tree/a/b/c/*
makefs -t ffs -o version=1,bsize=4096,fsize=512,maxbpcg=512 -s 8m -T 1704067200 tree-ufs1.img tree
makefs -t ffs -B be -o version=2,maxbpcg=128 -s 2m -T 1704067200 tree-be-ufs2.img tree
for f in tree-ufs1 tree-be-ufs2; do
  zstd -q -19 -f $f.img -o makefs-$f.img.raw.zst
done
ls -l ./*.zst
