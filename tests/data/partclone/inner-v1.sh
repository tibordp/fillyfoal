#!/bin/sh
# Runs inside the Debian 8 (jessie) container started by make-external.sh:
# saves a 4 MiB FAT16 volume (as inner.sh makes it) with partclone 0.2.73,
# which writes image format 0001 (a byte per block in the bitmap, a check
# value after every block). partclone.restore 0.2.73 fails to restore to a
# regular file here, so tests/partclone.rs checks the decoded volume against
# the length and CRC-32 printed.
set -eu
apt-get update -qq > /dev/null 2>&1 || true
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --force-yes --no-install-recommends \
  partclone dosfstools mtools faketime python3-minimal > /dev/null 2>&1
for p in partclone dosfstools mtools faketime; do
  dpkg-query -W -f '${Package} ${Version}\n' $p
done
OUT=/w/out
mkdir -p "$OUT"
rm -rf /tmp/v
mkdir -p /tmp/v
cd /tmp/v
export TZ=UTC
sh /data/files.sh
truncate -s 4M fat.img
faketime -f '2024-01-01 00:00:00' mkfs.fat -F 16 -s 1 -n FILLYFOAL -i 12345678 fat.img > /dev/null
faketime -f '2024-01-01 00:00:00' mcopy -m -i fat.img readme.txt ::readme.txt
faketime -f '2024-01-01 00:00:00' mcopy -m -i fat.img lines.txt ::lines.txt
partclone.fat16 -c -s fat.img -o "$OUT/fat16-v1.img" > /dev/null 2>&1
python3 -c 'import sys, zlib
d = open(sys.argv[1], "rb").read(); print(sys.argv[1], len(d), hex(zlib.crc32(d)))' fat.img
ls -l "$OUT/fat16-v1.img"
