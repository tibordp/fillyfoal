#!/bin/sh
# Runs inside the container started by make-external.sh: makes a small NTFS
# volume with mkntfs, copies two files into it with ntfscp, and saves it
# with ntfsclone, to a file and to standard output through gzip.
set -eu
apt-get update -qq > /dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
  ntfs-3g faketime gzip python3-minimal > /dev/null 2>&1
for p in ntfs-3g faketime gzip; do dpkg-query -W -f '${Package} ${Version}\n' $p; done
OUT=/w/out
rm -rf "$OUT" /tmp/v
mkdir -p "$OUT" /tmp/v
cd /tmp/v
# 2 MiB and three sectors: the last cluster, which holds the backup boot
# sector, is partial (1536 bytes), and ntfsclone saves only what the device
# holds of it.
truncate -s 2098688 vol.img
mkntfs -q -T -F -f -L fillyfoal -s 512 -c 4096 -p 0 -H 0 -S 0 vol.img
ntfslabel -q --new-serial=0123456789abcdef vol.img
# A small (resident) file and an 18 400-byte one, whose data takes clusters
# of its own past the metadata.
printf 'fillyfoal ntfsclone fixture\n' > readme.txt
i=0
while [ $i -lt 400 ]; do
  printf 'fillyfoal line %05d of the ntfsclone fixture\n' $i
  i=$((i + 1))
done > lines.txt
export TZ=UTC
faketime -f '2024-01-01 00:00:00' ntfscp -q vol.img readme.txt readme.txt
faketime -f '2024-01-01 00:00:00' ntfscp -q vol.img lines.txt lines.txt
ntfsclone -q --save-image -o "$OUT/ntfsclone.img" vol.img
ntfsclone -q --save-image -o - vol.img | gzip -9 -n > "$OUT/ntfsclone-stdout.img.gz"
# What ntfsclone restores is the volume byte for byte; tests/ntfsclone.rs
# checks the decoded volume against this length and CRC-32.
ntfsclone -q --restore-image -O restored.img "$OUT/ntfsclone.img"
cmp vol.img restored.img
python3 -c 'import sys, zlib; d = open(sys.argv[1], "rb").read(); print("restored", len(d), hex(zlib.crc32(d)))' restored.img
ls -l vol.img "$OUT"
