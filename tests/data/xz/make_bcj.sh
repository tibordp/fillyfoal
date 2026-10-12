#!/bin/sh
# Real-tool fixtures for the xz/7z branch converters (BCJ filters) and the
# xz BCJ start offset. Writes into a neutral scratch directory; copy the
# results to tests/fixtures/external/{xz,7z}/ by hand.
#
#   XZ Utils 5.8.4 (xz), 7-Zip 26.03 (7zz), macOS arm64
#
# Usage: sh tests/data/xz/make_bcj.sh [outdir]   (default /tmp/fixtures/codecs-bcj)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:-/tmp/fixtures/codecs-bcj}
mkdir -p "$out"
cd "$out"
rm -f code.bin ./*.xz ./*.7z

python3 -I "$here/bcjdata.py" code.bin
TZ=UTC touch -t 202401020304 code.bin

for f in powerpc ia64 armthumb sparc riscv; do
  xz -k -c --format=xz --check=crc64 "--$f" --lzma2=preset=6 code.bin > "bcj-$f.xz"
done
# A start offset (the property liblzma stores as 4 bytes).
xz -k -c --format=xz --check=crc64 --x86=start=4096 --lzma2=preset=6 code.bin > bcj-x86-start.xz
xz -k -c --format=xz --check=crc64 --riscv=start=4096 --lzma2=preset=6 code.bin > bcj-riscv-start.xz

# 7z folders: the long and short coder IDs.
7zz a -t7z -m0=ARMT -m1=LZMA2 -mhc=off bcj-armthumb.7z code.bin > /dev/null
7zz a -t7z -m0=SPARC -m1=LZMA2 -mhc=off bcj-sparc.7z code.bin > /dev/null
7zz a -t7z -m0=RISCV -m1=LZMA2 -mhc=off bcj-riscv.7z code.bin > /dev/null
# 7z coder properties with a start offset (7-Zip takes one for ARM64 and
# RISC-V).
7zz a -t7z -m0=ARM64:4096 -m1=LZMA2 -mhc=off bcj-arm64-start.7z code.bin > /dev/null
7zz a -t7z -m0=RISCV:4096 -m1=LZMA2 -mhc=off bcj-riscv-start.7z code.bin > /dev/null
ls -l ./*.xz ./*.7z
