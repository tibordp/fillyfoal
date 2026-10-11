#!/bin/sh
# Runs inside the privileged container started by make-volumes.sh, in /w.
# Writes the raw images to /w/out.
set -eu
export TZ=UTC
export SOURCE_DATE_EPOCH=1700000000
apt-get update -qq > /dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
  ntfs-3g lvm2 xorriso dosfstools python3-minimal > /dev/null 2>&1
OUT=/w/out
rm -rf "$OUT" /tmp/v
mkdir -p "$OUT" /tmp/v /mnt/n
cd /tmp/v
for p in ntfs-3g lvm2 xorriso; do dpkg-query -W -f '${Package} ${Version}\n' $p; done

# ---------------------------------------------------------------- NTFS
# Through ntfs-3g: a file with 30 named streams and one with 12 hard links
# (their attributes overflow the base record into extension records,
# listed in an $ATTRIBUTE_LIST); a directory of 300 files of which 270
# are deleted (freed index records keep stale entries). Through the
# kernel's ntfs3 (mount option sparse): a file of 300 blocks with a hole
# after each, whose runlist is split over three records.
truncate -s 8M ntfs3g-attrlist.img
mkntfs -q -F -f -L fillyfoal -c 4096 ntfs3g-attrlist.img
ntfs-3g -o streams_interface=windows ntfs3g-attrlist.img /mnt/n
cd /mnt/n
echo 'base stream' > ads.txt
for i in $(seq 1 30); do echo "stream $i" > "ads.txt:stream_number_$i"; done
echo 'linked' > linked.txt
for i in $(seq 1 12); do ln linked.txt "hard_link_with_quite_a_long_name_number_$i.txt"; done
mkdir big
for i in $(seq 1 300); do echo "$i" > "big/file_with_a_reasonably_long_name_$i.txt"; done
for i in $(seq 1 300); do
  [ $((i % 10)) -ne 0 ] && rm "big/file_with_a_reasonably_long_name_$i.txt"
done
cd /
umount /mnt/n
mount -t ntfs3 -o loop,sparse /tmp/v/ntfs3g-attrlist.img /mnt/n
# 4 KiB blocks naming their number, then dots: compressible.
block() {
  h=$(printf 'sparse block %06d' "$1")
  printf '%s\n' "$h"
  head -c $((4095 - ${#h})) /dev/zero | tr '\0' '.'
}
for k in $(seq 0 299); do
  block "$k" | dd of=/mnt/n/sparse.bin bs=4096 iflag=fullblock seek=$((2 * k)) conv=notrunc 2> /dev/null
done
umount /mnt/n
for f in /ads.txt /linked.txt /sparse.bin /big; do
  printf '%s: ' "$f"
  ntfsinfo -F "$f" /tmp/v/ntfs3g-attrlist.img 2> /dev/null | grep -c ATTRIBUTE_LIST || true
done
cd /tmp/v
mv ntfs3g-attrlist.img "$OUT/"

# ---------------------------------------------------------------- LVM2
# A PV with a small metadata area: commit until a new copy of the text
# wraps around the circular buffer early in the text, so the volume group
# section continues after the area's header.
truncate -s 8M lvm-wrapped.img
LOOP=$(losetup -f --show lvm-wrapped.img)
trap 'losetup -d "$LOOP"' EXIT
# Only this device: the kernel (and its loop devices) may be shared.
D="--devices $LOOP"
pvcreate $D -q --dataalignment 64k --metadatasize 40k "$LOOP"
vgcreate $D -q -s 1M vgw "$LOOP"
for i in 1 2 3 4; do lvcreate $D -q -an -Zn -L 1M -n "lv$i" vgw > /dev/null; done
mda=$(od -A n -t u8 -j $((4096 + 32)) -N 8 "$LOOP" | tr -d ' ')
wrapped=
for i in $(seq 1 600); do
  lvchange $D -q --addtag "t$i" vgw/lv1 > /dev/null
  set -- $(od -A n -t u8 -j $((4096 + 40)) -N 16 "$LOOP")
  if [ $(($1 + $2)) -gt "$mda" ] && [ $((mda - $1)) -lt 1024 ]; then
    echo "LVM: commit $i wraps: offset $1, size $2, area $mda"
    wrapped=1
    break
  fi
done
[ -n "$wrapped" ] || { echo "LVM metadata never wrapped early enough"; exit 1; }
vgchange $D -q -an vgw > /dev/null
sync
losetup -d "$LOOP"
trap - EXIT
mv lvm-wrapped.img "$OUT/"

# ---------------------------------------------------------------- ISO 9660
mkdir -p tree/sub
printf 'Hello, fillyfoal!\n' > tree/hello.txt
printf 'nested\n' > tree/sub/nested.txt
touch -d @1700000000 tree tree/* tree/sub/*
truncate -s 1M efi.img
mkfs.fat -n EFIBOOT -i 0e5f0e5f efi.img > /dev/null
# A hybrid image: GPT (with the appended EFI partition) and ISO 9660.
xorriso -report_about WARNING -as mkisofs -o "$OUT/xorriso-gpt.iso" -R -J -V FILLYFOAL \
  -append_partition 2 0xef efi.img -appended_part_as_gpt tree
# A plain image, then its sectors as a raw (2352-byte) CD image.
xorriso -report_about WARNING -as mkisofs -o plain.iso -R -V RAWCD tree
python3 /data/raw-sectors.py plain.iso "$OUT/mode1.bin" 1
python3 /data/raw-sectors.py plain.iso "$OUT/mode2.bin" 2
ls -l "$OUT"
