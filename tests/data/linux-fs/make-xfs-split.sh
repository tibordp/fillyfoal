#!/bin/sh
# XFS with a dirty log whose last record is split over the log's end
# (tests/fixtures/external/xfs/split-log.xfs.raw.zst). From the
# repository root:
#
#   docker build -t fillyfoal-fs-tools tests/data/linux-fs
#   mkdir -p /tmp/fixtures/disk-xfs-split
#   docker run --rm --privileged --hostname fillyfoal \
#     -v /tmp/fixtures/disk-xfs-split:/w -v "$PWD/tests/data/linux-fs:/src:ro" -w /w \
#     fillyfoal-fs-tools sh /src/make-xfs-split.sh
#
# Like make-xfs-wrapped.sh (16 MiB, the smallest log), but the kernel's
# XFS driver creates and removes files one at a time, and after each sync
# xfs-split-check.py reads the log: once the newest record's header sits
# so near the log's end that its data continues at the log's start (the
# driver splits the write, xlog_sync), the filesystem is shut down without
# a checkpoint (xfs_io shutdown), so that record stays the head. Where the
# split lands depends on the kernel's timing, so the image differs between
# runs (the check prints the record found).
set -eu
export TEST_DIR=1 TEST_DEV=1 QA_CHECK_FS=1
export TZ=UTC
rm -rf mnt ./*.img ./*.zst
truncate -s 16m split.img
mkfs.xfs -q -f -m uuid=00000000-0000-4000-8000-0000000000f7 \
  -b size=1024 -d agcount=1 -i size=512 -L fillyfoal split.img
mkdir mnt
mount -o loop split.img mnt
mkdir mnt/d
i=0
found=no
while [ $i -lt 40000 ]; do
  : > "mnt/d/file-$i"
  rm -f "mnt/d/file-$((i - 40))"
  sync
  if python3 /src/xfs-split-check.py split.img; then
    found=yes
    break
  fi
  i=$((i + 1))
done
printf 'Hello, fillyfoal!\n' > mnt/hello.txt
xfs_io -x -c 'shutdown' mnt
umount mnt
[ "$found" = yes ]
python3 /src/xfs-split-check.py split.img
xfs_logprint -t split.img 2>&1 | head -12
zstd -q -19 -f split.img -o split-log.xfs.raw.zst
ls -l split-log.xfs.raw.zst
