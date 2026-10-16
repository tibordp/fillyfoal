#!/bin/sh
# Runs inside the privileged container started by make-external.sh: makes a
# 300 MiB XFS filesystem (the smallest mkfs.xfs makes) on a file, mounts it
# on a loop device of the container (the Docker VM's kernel), fills it with
# a few neutral files and dumps it with xfsdump, a full (level 0) dump and
# an incremental (level 1) one after a change.
set -eu
apt-get update -qq > /dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
  xfsprogs xfsdump attr mount faketime > /dev/null 2>&1
for p in xfsprogs xfsdump attr faketime; do dpkg-query -W -f '${Package} ${Version}\n' $p; done
OUT=/w/out
rm -rf "$OUT" /tmp/x
mkdir -p "$OUT" /tmp/x
# gethostid(3) reads /etc/hostid if there is one, rather than deriving an
# id from the container's IP address; xfsdump records it.
printf '\001\000\372\021' > /etc/hostid
cd /tmp/x
truncate -s 300M xfs.img
mkfs.xfs -q -f -L fillyfoal -m uuid=01234567-89ab-cdef-0123-456789abcdef xfs.img
mnt=/mnt/fillyfoal
mkdir -p "$mnt"
mount -o loop xfs.img "$mnt"
trap 'umount "$mnt" 2> /dev/null || true' EXIT
printf 'fillyfoal xfsdump fixture\n' > "$mnt/readme.txt"
mkdir "$mnt/sub"
i=0
while [ $i -lt 100 ]; do
  printf 'fillyfoal line %05d of the xfsdump fixture\n' $i
  i=$((i + 1))
done > "$mnt/sub/lines.txt"
ln -s readme.txt "$mnt/link"
: > "$mnt/empty"
# A sparse file: 4 KiB of data, a 1 MiB hole, 4 KiB of data.
printf 'fillyfoal sparse head\n' | dd of="$mnt/sparse" bs=4096 conv=sync status=none
printf 'fillyfoal sparse tail\n' | dd of="$mnt/sparse" bs=4096 seek=257 conv=sync status=none
setfattr -n user.comment -v 'fillyfoal attribute' "$mnt/readme.txt"
touch -h -d '2024-01-01 00:00:00' "$mnt/readme.txt" "$mnt/sub/lines.txt" "$mnt/link" \
  "$mnt/empty" "$mnt/sparse" "$mnt/sub" "$mnt"
sync
faketime -f '2024-01-02 00:00:00' xfsdump -l 0 -L fillyfoal -M fillyfoal \
  -f "$OUT/level0.xfsdump" "$mnt" > /dev/null 2>&1
printf 'fillyfoal changed after the full dump\n' > "$mnt/changed.txt"
touch -d '2024-01-03 00:00:00' "$mnt/changed.txt" "$mnt"
sync
faketime -f '2024-01-04 00:00:00' xfsdump -l 1 -L fillyfoal-1 -M fillyfoal-1 \
  -f "$OUT/level1.xfsdump" "$mnt" > /dev/null 2>&1
umount "$mnt"
trap - EXIT
ls -l "$OUT"
