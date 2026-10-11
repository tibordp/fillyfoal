#!/bin/sh
# Real-tool fixtures for the 7z/ZIP codecs added in wave B (Deflate64, PPMd).
# Writes into a neutral scratch directory; copy the results to
# tests/fixtures/external/{zip,7z}/ by hand.
#
#   7-Zip 26.03 (7zz), macOS arm64
#
# Usage: sh tests/data/7z/make_codecs.sh [outdir]   (default /tmp/fixtures/codecs-7z)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:-/tmp/fixtures/codecs-7z}
mkdir -p "$out"
cd "$out"
rm -f salad.txt words.txt deflate64.zip deflate64.7z ppmd.7z

# Deterministic word salad: 40 000 bytes, repeated (distances past 32 KiB),
# a 70 000-byte run (lengths past 258) and a 5 000-byte tail.
python3 -I "$here/salad.py" salad.txt
head -c 20000 salad.txt > words.txt
TZ=UTC touch -t 202401020304 salad.txt words.txt

7zz a -tzip -mm=Deflate64 -mx=9 deflate64.zip salad.txt > /dev/null
7zz a -t7z -m0=Deflate64 -mx=9 deflate64.7z salad.txt > /dev/null
7zz a -t7z -m0=PPMd:o=6:mem=1m -mhc=off ppmd.7z words.txt > /dev/null
ls -l deflate64.zip deflate64.7z ppmd.7z
