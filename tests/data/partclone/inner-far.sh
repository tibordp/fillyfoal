#!/bin/sh
# Runs inside the trixie container started by make-far.sh: a 32 MiB ext4
# volume (1 KiB blocks, so four 8 MiB block groups) holding a 12 MiB file
# and a small text file written after it, saved with partclone. The data
# runs well past the codec's first 4 MiB resume points, with free space
# between it and the backup superblocks of the later groups, so far reads
# and skipped free blocks are exercised on a real image. The large file is
# four bytes (NUL, 0xff, 0x80, 0x01) repeated: not text nor any format,
# and the image compresses to almost nothing. (No resize inode: its
# hundreds of fragments would fill the snapshot.)
set -eu
apt-get update -qq > /dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
  partclone e2fsprogs faketime python3-minimal > /dev/null 2>&1
for p in partclone e2fsprogs faketime; do dpkg-query -W -f '${Package} ${Version}\n' $p; done
OUT=/w/out
mkdir -p "$OUT"
rm -rf /tmp/f
mkdir -p /tmp/f/tree
cd /tmp/f
perl -e 'print "\x00\xff\x80\x01" x 3145728' > tree/big.bin
printf 'fillyfoal far file, after 12 MiB of data\n' > tree/far.txt
touch -d '2024-01-01 00:00:00' tree/big.bin tree/far.txt tree
truncate -s 32M ext.img
faketime -f '2024-01-01 00:00:00' mkfs.ext4 -q -F -b 1024 -N 64 -I 256 -O ^resize_inode -L fillyfoal \
  -U 01234567-89ab-cdef-0123-456789abcdef -E hash_seed=01234567-89ab-cdef-0123-456789abcdef \
  -d tree ext.img
partclone.extfs -q -c -s ext.img -o "$OUT/ext4-far.img" 2> /dev/null
rm -f r.img
partclone.restore -q -C -s "$OUT/ext4-far.img" -O r.img 2> /dev/null
truncate -s "$(stat -c %s ext.img)" r.img
cmp ext.img r.img
# Where far.txt's data is (tests/partclone.rs reads it there), and the
# volume's length and CRC-32.
echo "far.txt block: $(debugfs -R 'bmap far.txt 0' ext.img 2> /dev/null)"
python3 -c 'import sys, zlib
d = open(sys.argv[1], "rb").read(); print(len(d), hex(zlib.crc32(d)))' ext.img
ls -l "$OUT"
