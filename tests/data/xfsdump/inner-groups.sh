#!/bin/sh
# Runs inside the privileged container started by make-groups.sh: dumps an
# XFS filesystem holding one file larger than xfsdump's 16 MiB extent
# group (written as several file records of one inode) and a small file.
# The large file is four bytes (NUL, 0xff, 0x80, 0x01) repeated: not text
# nor any format, and it compresses to almost nothing.
set -eu
apt-get update -qq > /dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
  xfsprogs xfsdump mount faketime > /dev/null 2>&1
for p in xfsprogs xfsdump faketime; do dpkg-query -W -f '${Package} ${Version}\n' $p; done
OUT=/w/out
rm -rf "$OUT" /tmp/x
mkdir -p "$OUT" /tmp/x
printf '\001\000\372\021' > /etc/hostid
cd /tmp/x
truncate -s 300M xfs.img
mkfs.xfs -q -f -L fillyfoal -m uuid=01234567-89ab-cdef-0123-456789abcdef xfs.img
mnt=/mnt/fillyfoal
mkdir -p "$mnt"
mount -o loop xfs.img "$mnt"
trap 'umount "$mnt" 2> /dev/null || true' EXIT
# 16 MiB + 8 KiB.
perl -e 'print "\x00\xff\x80\x01" x 4196352' > "$mnt/groups.bin"
printf 'fillyfoal small file\n' > "$mnt/small.txt"
touch -h -d '2024-01-01 00:00:00' "$mnt/groups.bin" "$mnt/small.txt" "$mnt"
sync
faketime -f '2024-01-02 00:00:00' xfsdump -l 0 -L fillyfoal -M fillyfoal \
  -f "$OUT/groups.xfsdump" "$mnt" > /dev/null 2>&1
umount "$mnt"
trap - EXIT
ls -l "$OUT"
