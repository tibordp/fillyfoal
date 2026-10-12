#!/bin/sh
# ext4 with a journal that needs recovery (tests/fixtures/external/ext/
# jbd2-dirty.img.raw.zst). From the repository root:
#
#   docker build -t fillyfoal-fs-tools tests/data/linux-fs
#   mkdir -p /tmp/fixtures/disk-b-jbd2
#   docker run --rm --hostname fillyfoal \
#     -v /tmp/fixtures/disk-b-jbd2:/w -v "$PWD/tests/data/linux-fs:/src:ro" -w /w \
#     fillyfoal-fs-tools sh /src/make-jbd2.sh
#
# debugfs (e2fsprogs 1.47.2) writes JBD2 transactions without a kernel:
# three (data blocks, a revoke block, one more data block) with v3
# checksums, which e2fsck then replays; then one more transaction of the
# same length as the first, which overwrites it, so the log ends with a
# stale revoke block of transaction 2 (behind transaction 5) that a reader
# must not take as part of the log.
set -eu
export TZ=UTC
export E2FSPROGS_FAKE_TIME=1704067200 # 2024-01-01 00:00:00 UTC
rm -f jbd2-dirty.img jbd2-dirty.img.raw.zst
head -c 3072 /dev/zero | tr '\0' A > /tmp/a
mke2fs -q -F -b 1024 -t ext4 -U 00000000-0000-4000-8000-0000000000e6 \
  -E root_owner=0:0,hash_seed=00000000-0000-4000-8000-0000000000a6 -J size=1 -N 32 -L fillyfoal-jbd2 jbd2-dirty.img 4M
printf 'jo -c\njw -b 3000,3001,3002 /tmp/a\njw -r 3003,3004\njw -b 3005 /tmp/a\njc\n' > /tmp/cmds
debugfs -w -f /tmp/cmds jbd2-dirty.img
e2fsck -fy jbd2-dirty.img || true
printf 'jo -c\njw -b 3010,3011,3012 /tmp/a\njc\n' > /tmp/cmds
debugfs -w -f /tmp/cmds jbd2-dirty.img
debugfs -R logdump jbd2-dirty.img
dumpe2fs -h jbd2-dirty.img
zstd -q -19 -f jbd2-dirty.img -o jbd2-dirty.img.raw.zst
ls -l jbd2-dirty.img.raw.zst
