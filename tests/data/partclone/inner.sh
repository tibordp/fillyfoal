#!/bin/sh
# Runs inside the trixie container started by make-external.sh: makes a
# 4 MiB FAT16 volume and a 1 MiB ext2 volume on plain files (no mount
# needed) and saves them with partclone 0.3.x (image format 0002) in several
# checksum layouts, to files and to standard output through gzip and zstd.
# (FAT16, not FAT12: partclone 0.3.36's FAT12 bitmap leaves out clusters a
# file uses, so its images do not restore the volume.)
set -eu
apt-get update -qq > /dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
  partclone dosfstools mtools e2fsprogs faketime gzip zstd python3-minimal > /dev/null 2>&1
for p in partclone dosfstools mtools e2fsprogs faketime gzip zstd; do
  dpkg-query -W -f '${Package} ${Version}\n' $p
done
OUT=/w/out
mkdir -p "$OUT"
rm -rf /tmp/v
mkdir -p /tmp/v
cd /tmp/v
export TZ=UTC
sh /data/files.sh
# FAT16 with one sector per cluster: a label, a fixed volume id, two files.
truncate -s 4M fat.img
faketime -f '2024-01-01 00:00:00' mkfs.fat -F 16 -s 1 -n FILLYFOAL -i 12345678 fat.img > /dev/null
faketime -f '2024-01-01 00:00:00' mcopy -m -i fat.img readme.txt ::readme.txt
faketime -f '2024-01-01 00:00:00' mcopy -m -i fat.img lines.txt ::lines.txt
# ext2 with 1 KiB blocks and few inodes, holding the same two files.
truncate -s 1M ext.img
faketime -f '2024-01-01 00:00:00' mkfs.ext2 -q -F -b 1024 -N 16 -I 128 -L fillyfoal \
  -U 01234567-89ab-cdef-0123-456789abcdef -E hash_seed=01234567-89ab-cdef-0123-456789abcdef \
  -d /tmp/v/tree ext.img
fat() { partclone.fat16 -q -c "$@" 2> /dev/null; }
ext() { partclone.extfs -q -c "$@" 2> /dev/null; }
# The default layout: CRC32, reseeded, one checksum per buffer of blocks
# (here more than the volume has, so one checksum after the last block).
fat -s fat.img -o "$OUT/fat16.img"
# One checksum every 8 blocks, the CRC carried on from one to the next
# (--no-reseed), so the checksums are interleaved with the blocks.
ext -k 8 -K -s ext.img -o "$OUT/ext2-k8-noreseed.img"
# No checksums at all.
ext -a 0 -s ext.img -o "$OUT/ext2-nocrc.img"
# Saved to standard output and compressed.
ext -k 16 -s ext.img -o - | gzip -9 -n > "$OUT/partclone-ext2.img.gz"
fat -s fat.img -o - | zstd -19 -q > "$OUT/partclone-fat16.img.zst"
# What partclone restores is the volume byte for byte; tests/partclone.rs
# checks the decoded volumes against these lengths and CRC-32s.
# (partclone.restore writes up to the last used block; the rest is zeros.)
restore() {
  rm -f r.img
  partclone.restore -q -C -s "$1" -O r.img 2> /dev/null
  truncate -s "$(stat -c %s "$2")" r.img
  cmp "$2" r.img
}
restore "$OUT/fat16.img" fat.img
restore "$OUT/ext2-k8-noreseed.img" ext.img
restore "$OUT/ext2-nocrc.img" ext.img
gzip -dc "$OUT/partclone-ext2.img.gz" > s.img
restore s.img ext.img
zstd -dcq "$OUT/partclone-fat16.img.zst" > s.img
restore s.img fat.img
python3 -c 'import sys, zlib
for p in sys.argv[1:]:
    d = open(p, "rb").read(); print(p, len(d), hex(zlib.crc32(d)))' fat.img ext.img
ls -l "$OUT"
