#!/bin/sh
# tests/fixtures/external/jpeg/ultrahdr-gainmap.jpg: an Ultra HDR JPEG
# (gain map JPEG with MPF and ISO 21496-1 metadata, libultrahdr's default
# build) written by libultrahdr 1.4.0's ultrahdr_app, built from the v1.4.0
# tag in Debian trixie (Docker), against Debian's libjpeg-turbo. The HDR
# input is a 32x24 RGBA1010102 PQ gradient this script writes.
# tests/fixtures/external/jpeg/ultrahdr-xmp.jpg: the same image from a build
# with -DUHDR_WRITE_XMP=ON -DUHDR_WRITE_ISO=OFF, which writes the gain-map
# metadata as hdrgm XMP only, as libultrahdr 1.0 and Android 14 did.
#
#   sh tests/data/jpeg/ultrahdr.sh <repo root>
set -eu
root=$(cd "${1:-.}" && pwd)
work=/tmp/fixtures/image-jpeg-ultrahdr
rm -rf "$work"
mkdir -p "$work"
cat >"$work/run.sh" <<'EOF'
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends git ca-certificates cmake ninja-build \
    g++ libjpeg62-turbo-dev pkg-config python3 >/dev/null
cd /tmp
git clone -q --depth 1 --branch v1.4.0 https://github.com/google/libultrahdr.git
cmake -S libultrahdr -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DUHDR_BUILD_DEPS=OFF >/dev/null
ninja -C build ultrahdr_app >/dev/null
cmake -S libultrahdr -B build-xmp -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DUHDR_BUILD_DEPS=OFF -DUHDR_WRITE_XMP=ON -DUHDR_WRITE_ISO=OFF >/dev/null
ninja -C build-xmp ultrahdr_app >/dev/null
cd /w
python3 -I - <<'PY'
import struct
w, h = 32, 24
out = bytearray()
for y in range(h):
    for x in range(w):
        r = 64 + x * 28
        g = 64 + y * 36
        b = 900 - x * 20
        out += struct.pack("<I", r | g << 10 | b << 20 | 3 << 30)
open("hdr.raw", "wb").write(out)
PY
/tmp/build/ultrahdr_app -m 0 -p hdr.raw -a 5 -t 2 -C 2 -R 1 -w 32 -h 24 \
    -q 80 -Q 80 -s 4 -M 0 -z ultrahdr-gainmap.jpg >/dev/null
/tmp/build-xmp/ultrahdr_app -m 0 -p hdr.raw -a 5 -t 2 -C 2 -R 1 -w 32 -h 24 \
    -q 80 -Q 80 -s 4 -M 0 -z ultrahdr-xmp.jpg >/dev/null
EOF
docker run --rm -v "$work":/w debian:trixie-slim sh /w/run.sh
mkdir -p "$root/tests/fixtures/external/jpeg"
cp "$work/ultrahdr-gainmap.jpg" "$work/ultrahdr-xmp.jpg" "$root/tests/fixtures/external/jpeg/"
