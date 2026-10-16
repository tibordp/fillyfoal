#!/bin/sh
# Runs inside the privileged container started by make-external.sh:
# `fsarchiver savefs` needs a block device (it mounts the filesystem
# itself), so a 4 MiB ext2 image filled by mkfs.ext2 -d is attached to a
# loop device of the container (the Docker VM's kernel) and saved.
set -eu
apt-get update -qq > /dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
  fsarchiver libcom-err2 e2fsprogs mount faketime > /dev/null 2>&1
for p in fsarchiver e2fsprogs faketime; do dpkg-query -W -f '${Package} ${Version}\n' $p; done
OUT=/w/out
mkdir -p "$OUT"
rm -rf /tmp/s
mkdir -p /tmp/s/tree
cd /tmp/s
printf 'fillyfoal fsarchiver savefs fixture\n' > tree/readme.txt
touch -d '2024-01-01 00:00:00' tree/readme.txt tree
truncate -s 4M ext.img
faketime -f '2024-01-01 00:00:00' mkfs.ext2 -q -F -b 1024 -N 16 -I 128 -L fillyfoal \
  -U 01234567-89ab-cdef-0123-456789abcdef -E hash_seed=01234567-89ab-cdef-0123-456789abcdef \
  -d tree ext.img
dev=$(losetup -f --show ext.img)
faketime -f '2024-01-01 00:00:00' fsarchiver savefs -Z 3 "$OUT/savefs-ext2.fsa" "$dev" > /dev/null 2>&1 ||
  { losetup -d "$dev"; exit 1; }
losetup -d "$dev"
ls -l "$OUT/savefs-ext2.fsa"
