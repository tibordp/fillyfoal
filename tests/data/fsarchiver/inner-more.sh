#!/bin/sh
# Runs inside the privileged container started by make-more.sh:
#
# - split.fsa, split.f01: `fsarchiver savedir -s 1` (1 MiB volumes) of a
#   tree holding a 1.1 MB file and a small one. The large file's blocks
#   straddle the two volumes. Its content is a 49,153-byte pseudo-random
#   run (perl, seed 1) repeated: LZO1X-1 (`-z 1`) cannot reach back that
#   far, so the blocks are stored as they are, but `zstd -19` stores the
#   run once.
# - two.fsa: `fsarchiver savefs` of two filesystems, a 16 MiB ext4
#   (4 KiB blocks, 256-byte inodes) and an 8 MiB ext2 (1 KiB blocks), both
#   empty, on loop devices of the container (the Docker VM's kernel).
set -eu
apt-get update -qq > /dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
  fsarchiver libcom-err2 e2fsprogs mount faketime > /dev/null 2>&1
for p in fsarchiver e2fsprogs faketime; do dpkg-query -W -f '${Package} ${Version}\n' $p; done
OUT=/w/out
rm -rf "$OUT" /tmp/m
mkdir -p "$OUT" /tmp/m/tree
cd /tmp/m
perl -e 'srand(1); my $r = join("", map { chr(int(rand(256))) } 1..49153);
  print substr($r x 23, 0, 1100000)' > tree/large.bin
printf 'fillyfoal\n' > tree/small.txt
touch -d '2024-01-01 00:00:00' tree/large.bin tree/small.txt tree
faketime -f '2024-01-01 00:00:00' fsarchiver savedir -z 1 -s 1 "$OUT/split.fsa" tree > /dev/null 2>&1
truncate -s 16M a.img
truncate -s 8M b.img
faketime -f '2024-01-01 00:00:00' mkfs.ext4 -q -F -b 4096 -I 256 -L fillyfoal-a \
  -U 01234567-89ab-cdef-0123-456789abcdef -E hash_seed=01234567-89ab-cdef-0123-456789abcdef a.img
faketime -f '2024-01-01 00:00:00' mkfs.ext2 -q -F -b 1024 -I 128 -L fillyfoal-b \
  -U 89abcdef-0123-4567-89ab-cdef01234567 -E hash_seed=89abcdef-0123-4567-89ab-cdef01234567 b.img
da=$(losetup -f --show a.img)
db=$(losetup -f --show b.img)
faketime -f '2024-01-01 00:00:00' fsarchiver savefs -Z 3 "$OUT/two.fsa" "$da" "$db" > /dev/null 2>&1 ||
  { losetup -d "$da" "$db"; exit 1; }
losetup -d "$da" "$db"
dumpe2fs -h a.img 2> /dev/null | grep -E 'features|mount options|Inode size|Block size|revision'
dumpe2fs -h b.img 2> /dev/null | grep -E 'features|mount options|Inode size|Block size|revision'
ls -l "$OUT"
