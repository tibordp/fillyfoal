#!/bin/sh
# F2FS fixture (tests/fixtures/external/f2fs/). From the repository root:
#
#   docker build -t fillyfoal-fs-tools tests/data/linux-fs
#   mkdir -p /tmp/fixtures/fs-f2fs
#   docker run --rm --privileged --hostname fillyfoal \
#     -v /tmp/fixtures/fs-f2fs:/w -v "$PWD/tests/data/linux-fs:/src:ro" -w /w \
#     fillyfoal-fs-tools sh /src/make-f2fs.sh
#
# mkfs.f2fs (f2fs-tools 1.16) makes the smallest image it allows (64 MiB,
# nearly all zeros; stored with zstd -19) and sload.f2fs populates it from
# a directory without mounting. -T fixes the timestamps. The superblock
# records the running kernel's /proc/version: --privileged lets the script
# put a neutral one in its place.
set -eu
printf 'Linux version 6.12.0 (fillyfoal@fillyfoal)\n' > /tmp/version
mount --bind /tmp/version /proc/version
export TZ=UTC
sh /src/tree.sh /tmp/tree
rm -f ./*.img ./*.zst
truncate -s 64m f2fs.img
mkfs.f2fs -q -f -T 1704067200 -U 00000000-0000-4000-8000-0000000000f2 \
  -l fillyfoal -O extra_attr,inode_checksum,sb_checksum,inode_crtime f2fs.img
sload.f2fs -f /tmp/tree -T 1704067200 f2fs.img
fsck.f2fs f2fs.img
dump.f2fs -i 3 f2fs.img > f2fs.root.txt 2>&1 || true
zstd -q -19 -f f2fs.img -o f2fs.img.raw.zst
ls -l ./*.zst
