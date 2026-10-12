#!/bin/sh
# Runs inside debian:trixie-slim (see make.sh); writes /work/out/ext4.simg.
set -eu
export DEBIAN_FRONTEND=noninteractive E2FSPROGS_FAKE_TIME=1700000000
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends e2fsprogs \
    android-sdk-libsparse-utils >/dev/null
dpkg-query -W e2fsprogs android-sdk-libsparse-utils
cd /work
mkdir -p root/etc
printf 'hello from fillyfoal\n' > root/hello.txt
printf 'ro.fillyfoal.sparse=1\n' > root/etc/build.prop
head -c 16384 /dev/zero | tr '\0' '\377' > root/ones.bin
find root -exec touch -h -d @1700000000 {} +
mke2fs -q -t ext4 -b 4096 -N 16 -O ^has_journal,^resize_inode -L fillyfoal \
    -U 0f111f0a-1111-4a11-8a11-f111f0a1f111 \
    -E root_owner=0:0,hash_seed=0f111f0a-2222-4a22-8a22-f111f0a1f222 \
    -d root out/ext4.img 2M
# mke2fs -d copies each file's change time (which touch cannot set) and
# the creation time is the clock's: pin both so the image is reproducible.
for f in / /lost+found /etc /etc/build.prop /hello.txt /ones.bin; do
    for field in ctime atime mtime crtime; do
        echo "sif $f $field 0x6553f080"
        echo "sif $f ${field}_extra 0"
    done
done > pin.cmd
debugfs -w -f pin.cmd out/ext4.img >/dev/null 2>&1
e2fsck -fn out/ext4.img
img2simg out/ext4.img out/ext4.simg
simg2img out/ext4.simg out/round.img
cmp out/ext4.img out/round.img && echo "round trip ok"
