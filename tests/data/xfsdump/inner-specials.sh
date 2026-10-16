#!/bin/sh
# Runs inside the privileged container started by make-specials.sh: dumps
# an XFS filesystem holding what the other fixtures lack: a file with a
# POSIX ACL (stored by XFS as root-namespace SGI_ACL_FILE) and one with a
# trusted. attribute, a hard link, a character and a block device, a FIFO
# and a socket; then a dump of one subtree (-s, the SUBTREE attribute).
set -eu
apt-get update -qq > /dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
  xfsprogs xfsdump attr acl mount faketime > /dev/null 2>&1
for p in xfsprogs xfsdump attr acl faketime; do dpkg-query -W -f '${Package} ${Version}\n' $p; done
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
mkdir "$mnt/sub"
printf 'fillyfoal file with an ACL\n' > "$mnt/sub/acl.txt"
setfacl -m u:1000:r,g:100:rw "$mnt/sub/acl.txt"
printf 'fillyfoal file with a trusted attribute\n' > "$mnt/sub/trusted.txt"
setfattr -n trusted.comment -v 'fillyfoal attribute' "$mnt/sub/trusted.txt"
printf 'fillyfoal hard-linked file\n' > "$mnt/hard.txt"
ln "$mnt/hard.txt" "$mnt/sub/hard-link.txt"
mknod "$mnt/chr" c 1 3
mknod "$mnt/blk" b 7 0
mkfifo "$mnt/fifo"
perl -e 'use Socket; socket(my $s, PF_UNIX, SOCK_STREAM, 0) or die; bind($s, pack_sockaddr_un($ARGV[0])) or die' "$mnt/sock"
touch -h -d '2024-01-01 00:00:00' "$mnt"/* "$mnt"/sub/* "$mnt/sub" "$mnt"
sync
faketime -f '2024-01-02 00:00:00' xfsdump -l 0 -L fillyfoal -M fillyfoal \
  -f "$OUT/specials.xfsdump" "$mnt" > /dev/null 2>&1
faketime -f '2024-01-02 00:00:00' xfsdump -l 0 -s sub -L fillyfoal-sub -M fillyfoal-sub \
  -f "$OUT/subtree.xfsdump" "$mnt" > /dev/null 2>&1
umount "$mnt"
trap - EXIT
ls -l "$OUT"
