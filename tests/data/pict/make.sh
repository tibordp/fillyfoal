#!/bin/sh
# Writes the external PICT fixtures with ImageMagick 6.9.11 (Debian
# bookworm's imagemagick package; needs Docker):
#
#   sh tests/data/pict/make.sh OUTDIR
#
# - pict/imagemagick-direct.pict: a 48x32 red-to-blue gradient, 24-bit,
#   written as a version 2 PICT with DirectBitsRect (opcode 0x009A)
# - pict/imagemagick-packbits.pict: the same reduced to 4 colours, written
#   with a colour table and PackBitsRect (opcode 0x0098)
# IMAGE may name a prepared image that already has imagemagick.
set -eu
out=$(cd "$1" && pwd)
docker run --rm -v "$out:/out" "${IMAGE:-debian:bookworm-slim}" sh -c '
set -eu
if ! command -v convert >/dev/null; then
    apt-get update -q >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends imagemagick >/dev/null 2>&1
fi
mkdir -p /out/pict
convert -size 48x32 gradient:red-blue -depth 8 PICT:/out/pict/imagemagick-direct.pict
convert -size 48x32 gradient:red-blue -colors 4 PICT:/out/pict/imagemagick-packbits.pict
'
