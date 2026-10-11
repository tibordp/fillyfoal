#!/bin/sh
# Runs inside the container started by make-mft.sh: builds a small NTFS
# volume with ntfs-3g and the kernel's ntfs3 driver, then copies its $MFT
# out as stored (raw-mft.py).
set -eu
apt-get update -qq > /dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
  ntfs-3g attr python3-minimal > /dev/null 2>&1
for p in ntfs-3g attr; do dpkg-query -W -f '${Package} ${Version}\n' $p; done
OUT=/w/out
rm -rf "$OUT" /tmp/v
mkdir -p "$OUT" /tmp/v /mnt/n
cd /tmp/v
truncate -s 2M vol.img
mkntfs -q -F -f -L fillyfoal -c 4096 vol.img
# Through ntfs-3g: a file with two named streams and a file with an
# object id.
ntfs-3g -o streams_interface=windows vol.img /mnt/n
cd /mnt/n
echo 'base stream' > ads.txt
for i in 1 2; do echo "stream $i" > "ads.txt:stream_$i"; done
echo 'object' > objid.txt
setfattr -n system.ntfs_object_id -v 0x00112233445566778899aabbccddeeff objid.txt
echo 'target' > target.txt
cd /
umount /mnt/n
# Through ntfs3: symbolic links, stored as IO_REPARSE_TAG_SYMLINK reparse
# points (one relative, one absolute), and a file with 12 hard links (its
# names overflow into extension records, listed in an $ATTRIBUTE_LIST,
# which ntfs3, like ntfs-3g, makes non-resident). ntfs3 also gives files
# it creates $EA_INFORMATION and $EA attributes (Linux owner and mode).
mount -t ntfs3 -o loop /tmp/v/vol.img /mnt/n
echo 'linked' > /mnt/n/linked.txt
for i in $(seq 1 12); do ln /mnt/n/linked.txt "/mnt/n/hard_link_with_quite_a_long_name_number_$i.txt"; done
ln -s target.txt /mnt/n/relative-link
ln -s /mnt/n/target.txt /mnt/n/absolute-link
umount /mnt/n
cd /tmp/v
# ntfscat would return the records with their fixups applied: copy the
# clusters record 0's runlist names instead.
python3 /data/raw-mft.py vol.img "$OUT/MFT"
ls -l "$OUT/MFT"
