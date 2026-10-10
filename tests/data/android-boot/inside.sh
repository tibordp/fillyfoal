#!/bin/sh
# Runs inside debian:trixie-slim (see make.sh); writes /work/out/*.img.
set -eu
export DEBIAN_FRONTEND=noninteractive SOURCE_DATE_EPOCH=0
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends mkbootimg cpio lz4 gzip \
    device-tree-compiler openssl >/dev/null
cd /work
mkdir -p in rd vrd out

# A fake arm64 kernel: the 64-byte Image header (text offset, image size,
# flags, "ARM\x64") and zeros, gzip-compressed.
python3 - <<'EOF'
import struct
hdr = struct.pack('<IIQQQQQQ4sI', 0x91005a4d, 0x14000000, 0x80000, 0x2000,
                  0xa, 0, 0, 0, b'ARM\x64', 0)
open('in/Image', 'wb').write(hdr + bytes(0x2000 - len(hdr)))
EOF
gzip -9 -n -c in/Image > in/Image.gz

# Generic ramdisk: a tiny init and a property file.
mkdir -p rd/system/etc rd/dev rd/proc
printf '#!/system/bin/sh\necho fillyfoal\n' > rd/init
chmod 755 rd/init
printf 'ro.fillyfoal.test=1\n' > rd/system/etc/prop.default
find rd -exec touch -h -d @0 {} +
(cd rd && find . | LC_ALL=C sort | cpio -o -H newc -R 0:0 --reproducible --quiet) > in/ramdisk.cpio
gzip -9 -n -c in/ramdisk.cpio > in/ramdisk.cpio.gz
lz4 -l -9 -q -f in/ramdisk.cpio in/ramdisk.cpio.lz4

# Vendor ramdisk.
mkdir -p vrd/vendor/etc
printf 'on early-init\n    setprop ro.fillyfoal.vendor 1\n' > vrd/vendor/etc/init.rc
find vrd -exec touch -h -d @0 {} +
(cd vrd && find . | LC_ALL=C sort | cpio -o -H newc -R 0:0 --reproducible --quiet) > in/vendor.cpio
lz4 -l -9 -q -f in/vendor.cpio in/vendor.cpio.lz4
printf 'androidboot.hardware=fillyfoal\nandroidboot.console=ttyS0\n' > in/bootconfig

# Device tree and an overlay.
cat > in/board.dts <<'EOF'
/dts-v1/;
/ {
    compatible = "example,fillyfoal";
    model = "fillyfoal test board";
    #address-cells = <1>;
    #size-cells = <1>;
    memory@80000000 { device_type = "memory"; reg = <0x80000000 0x10000000>; };
    chosen { bootargs = "console=ttyS0"; };
};
EOF
dtc -q -I dts -O dtb -o in/board.dtb in/board.dts
cat > in/overlay.dts <<'EOF'
/dts-v1/;
/plugin/;
&{/} { fillyfoal-overlay = "yes"; };
EOF
dtc -q -@ -I dts -O dtb -o in/overlay.dtbo in/overlay.dts

COMMON="--os_version 14.0.0 --os_patch_level 2024-05"
OLD="--pagesize 2048 --base 0x40000000 --board fillyfoal --cmdline console=ttyS0"
mkbootimg --header_version 0 $OLD $COMMON --kernel in/Image.gz \
    --ramdisk in/ramdisk.cpio.gz --second in/board.dtb -o out/boot-v0.img
mkbootimg --header_version 1 $OLD $COMMON --kernel in/Image.gz \
    --ramdisk in/ramdisk.cpio.gz --recovery_dtbo in/overlay.dtbo -o out/boot-v1.img
mkbootimg --header_version 2 $OLD $COMMON --kernel in/Image.gz \
    --ramdisk in/ramdisk.cpio.gz --dtb in/board.dtb -o out/boot-v2.img
mkbootimg --header_version 3 $COMMON --kernel in/Image.gz \
    --ramdisk in/ramdisk.cpio.lz4 --cmdline console=ttyS0 -o out/boot-v3.img
mkbootimg --header_version 4 $COMMON --kernel in/Image.gz \
    --cmdline console=ttyS0 -o out/boot-v4.img
mkbootimg --header_version 4 $COMMON --ramdisk in/ramdisk.cpio.lz4 -o out/init_boot.img
mkbootimg --header_version 3 --pagesize 2048 --base 0x40000000 --board fillyfoal \
    --vendor_cmdline androidboot.selinux=permissive \
    --vendor_ramdisk in/vendor.cpio.lz4 --dtb in/board.dtb \
    --vendor_boot out/vendor_boot-v3.img
mkbootimg --header_version 4 --pagesize 2048 --base 0x40000000 --board fillyfoal \
    --vendor_cmdline androidboot.selinux=permissive --dtb in/board.dtb \
    --ramdisk_type platform --ramdisk_name fillyfoal \
    --vendor_ramdisk_fragment in/vendor.cpio.lz4 \
    --ramdisk_type dlkm --ramdisk_name modules \
    --vendor_ramdisk_fragment in/ramdisk.cpio.lz4 \
    --vendor_bootconfig in/bootconfig \
    --vendor_boot out/vendor_boot-v4.img
# unpack_bootimg (same package) prints every header field: the oracle.
for f in out/*.img; do
    echo "== $f"
    unpack_bootimg --boot_img "$f" --out "unpacked/$(basename "$f")"
done
ls -l out
