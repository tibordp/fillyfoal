#!/bin/sh
# Builds tests/fixtures/external/j2k/opj-tile-parts.j2k with OpenJPEG's
# opj_compress: a 64x64 greyscale gradient in 32x32 tiles, each tile split
# into one tile-part per resolution level (-TP R), so the SOT markers carry
# TPsot 0..2 and TNsot 3.
# Usage: tile_parts.sh OUT.j2k (run in a scratch directory)
set -e
out=$1
python3 -I -c '
import sys
w = h = 64
px = bytes((x * 4 + y * 2) & 0xff for y in range(h) for x in range(w))
sys.stdout.buffer.write(b"P5\n%d %d\n255\n" % (w, h) + px)
' > gradient.pgm
opj_compress -i gradient.pgm -o "$out" -t 32,32 -TP R -n 3
