#!/bin/sh
# Real-tool fixtures for stored (-mx0) 7z AES-256 folders, password
# `fillyfoal`: the folder is AES + Copy, so no decompressor can reject a
# wrong key, and the first file is past the 64 KiB a compressed folder is
# checked on. Writes into a neutral scratch directory; copy the results to
# tests/fixtures/external/7z/ by hand. Not byte-for-byte reproducible:
# 7-Zip draws a random IV for every encrypted folder.
#
#   7-Zip 26.03 (7zz), macOS arm64
#
# Usage: sh tests/data/7z/make_aes_stored.sh [outdir]
#        (default /tmp/fixtures/dev-tooling-7z)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:-/tmp/fixtures/dev-tooling-7z}
mkdir -p "$out"
cd "$out"
rm -f salad.txt big.txt small.txt aes-stored.7z aes-stored-two.7z

# 65 600 bytes (a whole number of AES blocks, so the folder has no padding
# to check) of the deterministic word salad, and a 6-byte file.
python3 -I "$here/salad.py" salad.txt
head -c 65600 salad.txt > big.txt
printf 'small\n' > small.txt
TZ=UTC touch -t 202401020304 big.txt small.txt

# One stored folder.
7zz a -t7z -mx0 -mhe=off -mtc=off -mta=off -pfillyfoal aes-stored.7z big.txt > /dev/null
# Two stored folders (7-Zip writes one per file when it does not
# compress): big.txt, then small.txt.
7zz a -t7z -mx0 -mhe=off -mtc=off -mta=off -pfillyfoal aes-stored-two.7z big.txt small.txt > /dev/null
rm -f salad.txt
ls -l aes-stored.7z aes-stored-two.7z
