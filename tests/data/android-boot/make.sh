#!/bin/sh
# Builds the Android boot image fixtures with AOSP mkbootimg (Debian's
# `mkbootimg` package) in a Debian container: boot images v0-v4, an
# init_boot image, vendor_boot v3 and v4 (vendor ramdisk table,
# bootconfig), around a small fake arm64 kernel, gzip/lz4 cpio ramdisks
# and a tiny DTB; unpack_bootimg prints each header for comparison.
#
#   sh tests/data/android-boot/make.sh [fixtures directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
FIX=$(cd "${1:-$SRC/../../fixtures/external}" && pwd)
B=/tmp/fixtures/mobile-boot
rm -rf "$B"
mkdir -p "$B/out"
cp "$SRC/inside.sh" "$B/"
docker run --rm -v "$B:/work" -w /work debian:trixie-slim sh /work/inside.sh
mkdir -p "$FIX/android-boot" "$FIX/android-vendor-boot"
for f in boot-v0.img boot-v1.img boot-v2.img boot-v3.img boot-v4.img init_boot.img; do
    cp "$B/out/$f" "$FIX/android-boot/$f"
done
cp "$B/out/vendor_boot-v3.img" "$B/out/vendor_boot-v4.img" "$FIX/android-vendor-boot/"
ls -l "$B/out"
