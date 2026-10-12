#!/bin/sh
# Builds the Android sparse image fixture: a 2 MiB ext4 file system made by
# mke2fs from a small directory (two text files and a 16 KiB file of 0xff
# bytes, which img2simg stores as a fill chunk), converted with AOSP
# img2simg (Debian's android-sdk-libsparse-utils) in a Debian container.
# simg2img turns it back into the original image for comparison.
#
#   sh tests/data/android-sparse/make.sh [fixtures directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
FIX=$(cd "${1:-$SRC/../../fixtures/external}" && pwd)
B=/tmp/fixtures/system-android-sparse
rm -rf "$B"
mkdir -p "$B/out"
docker run --rm -v "$B:/work" -v "$SRC:/scripts:ro" -w /work debian:trixie-slim sh /scripts/inside.sh
mkdir -p "$FIX/android-sparse"
cp "$B/out/ext4.simg" "$FIX/android-sparse/ext4.simg"
ls -l "$B/out"
