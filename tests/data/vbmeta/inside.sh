#!/bin/sh
# Runs inside debian:trixie-slim (see make.sh); writes /work/out/*.img.
set -eu
export DEBIAN_FRONTEND=noninteractive SOURCE_DATE_EPOCH=0
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends mkbootimg python3 openssl \
    gzip >/dev/null
dpkg-query -W mkbootimg openssl
AVB="python3 /avb/avbtool.py"
cd /work
mkdir -p in out
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out in/key.pem 2>/dev/null
$AVB extract_public_key --key in/key.pem --output in/vendor.avbpubkey

# A boot image (v2 header, fake kernel and ramdisk) with a hash footer.
printf 'fillyfoal fake kernel\n' > in/kernel
printf 'fillyfoal fake ramdisk\n' | gzip -9 -n > in/ramdisk.gz
mkbootimg --header_version 2 --pagesize 2048 --os_version 14.0.0 \
    --os_patch_level 2024-05 --cmdline console=ttyS0 --kernel in/kernel \
    --ramdisk in/ramdisk.gz --dtb in/kernel -o out/boot-avb.img
$AVB add_hash_footer --image out/boot-avb.img --partition_size 81920 \
    --partition_name boot --algorithm SHA256_RSA2048 --key in/key.pem \
    --salt 66696c6c79666f616c --prop com.fillyfoal.boot:1

# A vendor_boot image (v3) with a hash footer.
printf 'fillyfoal vendor ramdisk\n' | gzip -9 -n > in/vendor.gz
mkbootimg --header_version 3 --pagesize 2048 --vendor_ramdisk in/vendor.gz \
    --dtb in/kernel --vendor_cmdline androidboot.fillyfoal=1 \
    --vendor_boot out/vendor_boot-avb.img
$AVB add_hash_footer --image out/vendor_boot-avb.img --partition_size 81920 \
    --partition_name vendor_boot --algorithm SHA256_RSA2048 --key in/key.pem \
    --salt 66696c6c79666f616c

# A data partition with a hashtree footer (descriptor source only).
for i in $(seq 1 600); do echo "fillyfoal system block line $i"; done | head -c 20480 > in/system.img
$AVB add_hashtree_footer --image in/system.img --partition_size 102400 \
    --partition_name system --hash_algorithm sha256 --salt 66696c6c79666f616c \
    --do_not_generate_fec --algorithm NONE

$AVB make_vbmeta_image --output out/vbmeta.img --algorithm SHA256_RSA2048 \
    --key in/key.pem --rollback_index 3 \
    --include_descriptors_from_image out/boot-avb.img \
    --include_descriptors_from_image in/system.img \
    --chain_partition vendor:1:in/vendor.avbpubkey \
    --kernel_cmdline 'androidboot.fillyfoal=1' \
    --prop com.fillyfoal.build:test --padding_size 4096
for f in out/*.img; do
    echo "== $f"
    $AVB info_image --image "$f"
done
