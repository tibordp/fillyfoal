#!/bin/sh
# XFS fixtures (tests/fixtures/external/xfs/). From the repository root:
#
#   docker build -t fillyfoal-fs-tools tests/data/linux-fs
#   mkdir -p /tmp/fixtures/fs-xfs
#   docker run --rm --privileged --hostname fillyfoal \
#     -v /tmp/fixtures/fs-xfs:/w -v "$PWD/tests/data/linux-fs:/src:ro" -w /w \
#     fillyfoal-fs-tools sh /src/make-xfs.sh
#
# v4.xfs.raw.zst is populated by mkfs.xfs from a prototype file (no mount).
# v5.xfs.raw.zst needs a loop mount (--privileged): extended attributes,
# B-tree extent maps, unwritten and shared extents cannot be made by mkfs.
# The kernel stamps inode change/creation times and the log with the time
# of the run, so v5 is not reproducible byte for byte.
set -eu
# mkfs.xfs refuses filesystems under 300 MiB unless it runs under fstests.
export TEST_DIR=1 TEST_DEV=1 QA_CHECK_FS=1
export TZ=UTC
STAMP='2024-01-01 00:00:00'
rm -rf v4 v5 mnt proto ./*.img ./*.zst

# --- v4: 2 allocation groups, 4 KiB blocks, populated by prototype ----------
mkdir v4
printf 'Hello, fillyfoal!\n' > v4/hello.txt
seq -s ' ' 1 2000 > v4/numbers.txt
{
  echo /dev/null
  echo 0 0
  echo 'd--755 0 0'
  echo 'hello.txt ---644 0 0 /w/v4/hello.txt'
  echo 'numbers.txt ---600 0 0 /w/v4/numbers.txt'
  echo 'link l--777 0 0 hello.txt'
  echo 'null c--666 0 0 1 3'
  echo 'pipe p--644 0 0'
  echo 'setuid -u-755 0 0 /w/v4/hello.txt'
  echo 'small d--755 0 0'
  echo '  a ---644 0 0 /w/v4/hello.txt'
  echo '  b ---644 0 0 /w/v4/hello.txt'
  echo '$'
  echo 'block d--755 0 0'
  for i in $(seq -w 1 12); do echo "  entry-number-$i ---644 0 0 /w/v4/hello.txt"; done
  echo '$'
  echo '$'
} > proto
truncate -s 32m v4.img
mkfs.xfs -q -f -m crc=0,uuid=00000000-0000-4000-8000-0000000000f4 \
  -b size=4096 -d agcount=2 -i size=256 -L fillyfoal-v4 -p proto v4.img

# --- v5: 2 allocation groups, 1 KiB blocks, every default v5 feature -------
truncate -s 32m v5.img
mkfs.xfs -q -f -m uuid=00000000-0000-4000-8000-0000000000f5 \
  -b size=1024 -d agcount=2 -i size=512 -L fillyfoal v5.img
mkdir mnt
mount -o loop v5.img mnt
cd mnt
printf 'Hello, fillyfoal!\n' > hello.txt
setfattr -n user.comment -v 'a short attribute' hello.txt
setfacl -m u:1000:r hello.txt
: > empty
ln -s hello.txt link
ln -s "$(seq -f 'long-symlink-target-%02g' 1 30 | tr '\n' '/')end" longlink
# Directories: short-form (in the inode), one block, and leaf form (data
# blocks plus a leaf block; 4 KiB directory blocks hold 16 such long names).
mkdir sf block leaf
for i in 1 2 3; do ln empty "sf/f$i"; done
for i in $(seq -w 1 8); do ln empty "block/block-directory-entry-$i"; done
for i in $(seq -w 1 18); do
  ln empty "leaf/$(printf "leaf-entry-$i-%0200d" 0)"
done
# A file whose extents do not fit in the inode: a B-tree extent map.
xfs_io -f -c 'pwrite -S 0x66 -b 1k 0 1k' fragmented >/dev/null
for i in $(seq 1 39); do
  xfs_io -c "pwrite -S 0x66 -b 1k $((i * 2048)) 1k" fragmented >/dev/null
done
xfs_io -f -c 'pwrite -S 0x61 0 4k' -c 'pwrite -S 0x62 64k 4k' sparse >/dev/null
xfs_io -f -c 'falloc 0 16k' -c 'pwrite -S 0x63 0 1k' prealloc >/dev/null
xfs_io -f -c 'pwrite -S 0x64 0 8k' original >/dev/null
cp --reflink=always original clone
# Attributes: inline (above), a leaf block, a node tree, a remote value.
: > attrs
for i in $(seq -w 1 20); do
  setfattr -n "user.attribute-$i" -v "value of attribute number $i" attrs
done
: > bigattr
setfattr -n user.big -v "$(seq -s ' ' 1 700)" bigattr
setfattr -n trusted.note -v 'trusted namespace' bigattr
mknod null c 1 3
mkfifo pipe
touch -h -d "$STAMP" ./* ./*/* .
touch -d '2200-01-01 00:00:00' future
touch -d '1960-06-01 00:00:00' past
cd ..
umount mnt

xfs_db -r -c 'sb 0' -c p v5.img > v5.sb.txt
xfs_db -r -c 'sb 0' -c p v4.img > v4.sb.txt
zstd -q -19 -f v4.img -o v4.xfs.raw.zst
zstd -q -19 -f v5.img -o v5.xfs.raw.zst
ls -l ./*.zst
