#!/bin/sh
# FAT, exFAT and NTFS fixtures (tests/fixtures/external/{fat,exfat,ntfs}/).
# From the repository root:
#
#   docker build -t fillyfoal-fs-tools tests/data/linux-fs
#   mkdir -p /tmp/fixtures/fs-fat
#   docker run --rm --privileged --hostname fillyfoal \
#     -v /tmp/fixtures/fs-fat:/w -v "$PWD/tests/data/linux-fs:/src:ro" -w /w \
#     fillyfoal-fs-tools sh /src/make-fat.sh
#
# FAT images are made by mkfs.fat (dosfstools 4.2) and filled by mcopy
# (mtools 4.0), with fixed volume ids and a fixed clock (MTOOLS_DATE...).
# exFAT (exfatprogs 1.2) and NTFS (mkntfs from ntfs-3g 2022.10) are filled
# through the kernel's exfat and ntfs3 drivers on a loop mount
# (--privileged); their timestamps are those of the run. Images over
# 64 KiB are stored with zstd -19.
set -eu
export TZ=UTC
sh /src/tree.sh /tmp/tree --no-special
rm -f ./*.img ./*.zst
# mtools: a fixed timestamp for new entries, no case mangling.
export SOURCE_DATE_EPOCH=1704067200
echo 'mtools_skip_check=1' > /tmp/mtoolsrc
export MTOOLSRC=/tmp/mtoolsrc
fill_fat() {
  mcopy -i "$1" -s -m /tmp/tree/hello.txt /tmp/tree/numbers.txt /tmp/tree/pattern.bin /tmp/tree/dir ::/
  mmd -i "$1" ::/many
  mcopy -i "$1" -s -m /tmp/tree/many/* ::/many/
  mcopy -i "$1" -m /tmp/tree/hello.txt "::/A file with a long name.txt"
  mlabel -i "$1" ::FILLYFOAL
}
mkfs.fat -C -F 12 -i 0f12f12f -n FILLYFOAL fat12.img 1440 > /dev/null
fill_fat fat12.img
mkfs.fat -C -F 16 -i 0f16f16f -n FILLYFOAL fat16.img 16384 > /dev/null
fill_fat fat16.img
mkfs.fat -C -F 32 -S 512 -s 1 -i 0f32f32f -n FILLYFOAL fat32.img 40000 > /dev/null
fill_fat fat32.img
for f in fat12 fat16 fat32; do fsck.fat -n $f.img > /dev/null; done

mkdir -p /mnt/x
truncate -s 4m exfat.img
mkfs.exfat -q -L fillyfoal -c 4K -b 4K exfat.img
mount -o loop exfat.img /mnt/x
cp -r /tmp/tree/. /mnt/x/
cp /tmp/tree/hello.txt "/mnt/x/A file with a long name.txt"
umount /mnt/x
fsck.exfat -n exfat.img > /dev/null

truncate -s 1100k ntfs.img
mkntfs -q -F -T -L fillyfoal ntfs.img > /dev/null
mount -t ntfs3 -o loop ntfs.img /mnt/x
cp -r /tmp/tree/. /mnt/x/
cp /tmp/tree/hello.txt "/mnt/x/A file with a long name.txt"
umount /mnt/x
ntfsfix -n ntfs.img > /dev/null || true

for f in fat12 fat16 fat32 exfat ntfs; do zstd -q -19 -f $f.img -o $f.img.raw.zst; done
ls -l ./*.zst
