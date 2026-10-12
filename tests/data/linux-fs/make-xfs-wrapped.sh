#!/bin/sh
# XFS with a log that has wrapped (tests/fixtures/external/xfs/
# wrapped-log.xfs.raw.zst). From the repository root:
#
#   docker build -t fillyfoal-fs-tools tests/data/linux-fs
#   mkdir -p /tmp/fixtures/disk-b-xfs
#   docker run --rm --privileged --hostname fillyfoal \
#     -v /tmp/fixtures/disk-b-xfs:/w -v "$PWD/tests/data/linux-fs:/src:ro" -w /w \
#     fillyfoal-fs-tools sh /src/make-xfs-wrapped.sh
#
# A 16 MiB filesystem with the smallest log mkfs.xfs (xfsprogs 6.13)
# allows; the kernel's XFS driver (a loop mount, hence --privileged) then
# creates and removes files until the log has gone round more than once,
# and the filesystem is shut down without a checkpoint (xfs_io shutdown),
# so the log ends mid-way, after a record split over the log's end or
# not, with older cycles' records behind the head. TEST_DIR/TEST_DEV let
# mkfs make a filesystem under 300 MiB.
set -eu
export TEST_DIR=1 TEST_DEV=1 QA_CHECK_FS=1
export TZ=UTC
rm -rf mnt ./*.img ./*.zst
truncate -s 16m wrapped.img
mkfs.xfs -q -f -m uuid=00000000-0000-4000-8000-0000000000f6 \
  -b size=1024 -d agcount=1 -i size=512 -L fillyfoal wrapped.img
mkdir mnt
mount -o loop wrapped.img mnt
i=0
while [ $i -lt 240 ]; do
  mkdir mnt/d
  j=0
  while [ $j -lt 50 ]; do
    : > "mnt/d/f$j"
    j=$((j + 1))
  done
  sync
  rm -r mnt/d
  sync
  i=$((i + 1))
done
printf 'Hello, fillyfoal!\n' > mnt/hello.txt
sync
xfs_io -x -c 'shutdown' mnt
umount mnt
xfs_logprint -t wrapped.img 2>&1 | head -20
zstd -q -19 -f wrapped.img -o wrapped-log.xfs.raw.zst
ls -l wrapped-log.xfs.raw.zst
