#!/bin/sh
# Builds the Android Verified Boot fixtures with AOSP avbtool in a Debian
# container: a vbmeta image carrying hash, hashtree, kernel command line,
# chain partition and property descriptors, and boot and vendor_boot
# images (AOSP mkbootimg) with an AVB hash footer, filling avbtool's
# smallest partition (80 KiB: the image, then 68 KiB reserved for vbmeta). `avbtool info_image`
# prints each for comparison.
#
# avbtool is not packaged in Debian: fetch the single script from AOSP
# first (MIT licence; used only to generate, not committed):
#
#   mkdir -p /tmp/avbtool && curl -sf 'https://android.googlesource.com/platform/external/avb/+/761178607206f4cb2af79ed9eec52d8cbd814adb/avbtool.py?format=TEXT' | base64 -d > /tmp/avbtool/avbtool.py
#   sh tests/data/vbmeta/make.sh [fixtures directory]
#
# The RSA-2048 signing key is made fresh in the container on every run,
# so the public keys and signatures differ between runs.
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
FIX=$(cd "${1:-$SRC/../../fixtures/external}" && pwd)
B=/tmp/fixtures/system-avb
rm -rf "$B"
mkdir -p "$B/out"
docker run --rm -v "$B:/work" -v "$SRC:/scripts:ro" -v /tmp/avbtool:/avb:ro \
    -w /work debian:trixie-slim sh /scripts/inside.sh
mkdir -p "$FIX/vbmeta" "$FIX/android-boot" "$FIX/android-vendor-boot"
cp "$B/out/vbmeta.img" "$FIX/vbmeta/avbtool.img"
# The footed images fill their 80 KiB partitions, mostly zeros: stored
# gzip'd.
gzip -9 -n -c "$B/out/boot-avb.img" > "$FIX/android-boot/boot-avb.img.gz"
gzip -9 -n -c "$B/out/vendor_boot-avb.img" > "$FIX/android-vendor-boot/vendor_boot-avb.img.gz"
ls -l "$B/out"
