#!/bin/sh
# Runs inside the privileged container started by make-specials.sh:
# `fsarchiver savefs` of a 16 MiB ext4 filesystem holding what the other
# fixtures lack: a file with two user extended attributes, one with a
# POSIX ACL, a hard link, a character and a block device, a FIFO and a
# socket.
set -eu
apt-get update -qq > /dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
  fsarchiver libcom-err2 e2fsprogs mount attr acl faketime > /dev/null 2>&1
for p in fsarchiver e2fsprogs attr acl faketime; do dpkg-query -W -f '${Package} ${Version}\n' $p; done
OUT=/w/out
rm -rf "$OUT" /tmp/p
mkdir -p "$OUT" /tmp/p
cd /tmp/p
truncate -s 16M ext.img
faketime -f '2024-01-01 00:00:00' mkfs.ext4 -q -F -b 1024 -N 64 -I 256 -L fillyfoal \
  -U 01234567-89ab-cdef-0123-456789abcdef -E hash_seed=01234567-89ab-cdef-0123-456789abcdef ext.img
mnt=/mnt/fillyfoal
mkdir -p "$mnt"
mount -o loop ext.img "$mnt"
trap 'umount "$mnt" 2> /dev/null || true' EXIT
printf 'fillyfoal file with extended attributes\n' > "$mnt/xattr.txt"
setfattr -n user.comment -v 'fillyfoal attribute' "$mnt/xattr.txt"
setfattr -n user.second -v 'another value' "$mnt/xattr.txt"
printf 'fillyfoal file with an ACL\n' > "$mnt/acl.txt"
setfacl -m u:1000:r,g:100:rw "$mnt/acl.txt"
printf 'fillyfoal hard-linked file\n' > "$mnt/hard.txt"
ln "$mnt/hard.txt" "$mnt/hard-link.txt"
mknod "$mnt/chr" c 1 3
mknod "$mnt/blk" b 7 0
mkfifo "$mnt/fifo"
perl -e 'use Socket; socket(my $s, PF_UNIX, SOCK_STREAM, 0) or die; bind($s, pack_sockaddr_un($ARGV[0])) or die' "$mnt/sock"
rmdir "$mnt/lost+found"
touch -h -d '2024-01-01 00:00:00' "$mnt"/* "$mnt"
sync
umount "$mnt"
dev=$(losetup -f --show ext.img)
faketime -f '2024-01-01 00:00:00' fsarchiver savefs -Z 3 "$OUT/specials.fsa" "$dev" > /dev/null 2>&1 ||
  { losetup -d "$dev"; exit 1; }
losetup -d "$dev"
trap - EXIT
ls -l "$OUT"
