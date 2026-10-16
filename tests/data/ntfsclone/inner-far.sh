#!/bin/sh
# Runs inside the container started by make-far.sh: a 32 MiB NTFS volume
# holding a 12 MiB file and a 4.6 KiB text file copied after it, saved with
# ntfsclone. The data and the metadata mkntfs puts in the middle of the
# volume ($MFTMirr, the $LogFile) are megabytes apart, with gaps between,
# so far reads and skipped gaps are exercised on a real image. The large
# file is four bytes (NUL, 0xff, 0x80, 0x01) repeated: not text nor any
# format, and the image compresses to almost nothing.
set -eu
apt-get update -qq > /dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
  ntfs-3g faketime python3-minimal > /dev/null 2>&1
for p in ntfs-3g faketime; do dpkg-query -W -f '${Package} ${Version}\n' $p; done
OUT=/w/out
mkdir -p "$OUT"
rm -rf /tmp/v
mkdir -p /tmp/v
cd /tmp/v
truncate -s 32M vol.img
mkntfs -q -T -F -f -L fillyfoal -s 512 -c 4096 -p 0 -H 0 -S 0 vol.img
ntfslabel -q --new-serial=0123456789abcdef vol.img
perl -e 'print "\x00\xff\x80\x01" x 3145728' > big.bin
# 100 lines (4.6 KiB): too large to be resident in its MFT record.
i=0
while [ $i -lt 100 ]; do
  printf 'fillyfoal far line %05d, after 12 MiB of data\n' $i
  i=$((i + 1))
done > far.txt
export TZ=UTC
faketime -f '2024-01-01 00:00:00' ntfscp -q vol.img big.bin big.bin
faketime -f '2024-01-01 00:00:00' ntfscp -q vol.img far.txt far.txt
ntfsclone -q --save-image -o "$OUT/ntfs-far.img" vol.img
ntfsclone -q --restore-image -O restored.img "$OUT/ntfs-far.img"
cmp vol.img restored.img
# Where far.txt's data is (tests/ntfsclone.rs reads it there), and the
# volume's length and CRC-32.
python3 -c 'import sys, zlib
d = open(sys.argv[1], "rb").read()
print("far.txt at", hex(d.find(b"fillyfoal far line 00000")), len(d), hex(zlib.crc32(d)))' vol.img
ls -l "$OUT"
