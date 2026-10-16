#!/bin/sh
# Real-tool fixtures for 7z AES-256 (7zAES) cases beyond make_aes.sh and
# make_aes_stored.sh, password `fillyfoal`, plain headers (tests patch
# them). Writes into a neutral scratch directory; copy the results to
# tests/fixtures/external/7z/ by hand. Not byte-for-byte reproducible:
# 7-Zip draws a random IV for every AES coder.
#
#   7-Zip 26.03 (7zz), macOS arm64
#
# Usage: sh tests/data/7z/make_aes_more.sh [outdir]
#        (default /tmp/fixtures/dev-tooling-7z-more)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:-/tmp/fixtures/dev-tooling-7z-more}
mkdir -p "$out"
cd "$out"
rm -f blocks.txt small.txt code.bin aes-stored-blocks.7z aes-bcj2.7z

# Two stored folders: 32 bytes (whole AES blocks, no padding), then 6
# bytes (10 bytes of zero padding). tests/sevenzip_aes.rs removes the
# first file's CRC, so its folder can only be checked on the second.
printf 'thirty-two bytes of plain text.\n' > blocks.txt
printf 'small\n' > small.txt
TZ=UTC touch -t 202401020304 blocks.txt small.txt
7zz a -t7z -mx0 -mhe=off -mhc=off -mtc=off -mta=off -pfillyfoal \
  aes-stored-blocks.7z blocks.txt small.txt > /dev/null

# BCJ2 with encryption: BCJ2 + LZMA2 + 2 x LZMA, and an AES coder in
# front of each of the four packed streams (the range coder's stream is
# AES only), over the pseudo machine code of tests/data/xz/bcjdata.py.
python3 -I "$here/../xz/bcjdata.py" code.bin
TZ=UTC touch -t 202401020304 code.bin
7zz a -t7z -mf=BCJ2 -m0=LZMA2 -mhe=off -mhc=off -mtc=off -mta=off -pfillyfoal \
  aes-bcj2.7z code.bin > /dev/null
rm -f blocks.txt small.txt code.bin
ls -l aes-stored-blocks.7z aes-bcj2.7z
7zz l -slt aes-bcj2.7z | grep -E '^(Method|Solid|Blocks)'
