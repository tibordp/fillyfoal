#!/bin/sh
# MP4 files written by GPAC's MP4Box 2.4.0, built from the release tarball
# in a Debian trixie container (gpac-inner.sh), from FFmpeg 8.1.2 raw
# streams made on the host:
#
#     sh tests/data/mp4/make-gpac.sh            # writes into tests/fixtures/external
#     sh tests/data/mp4/make-gpac.sh /tmp/out   # or elsewhere
#
# - mp4/gpac.mp4:       MP4Box -add in.h264:fps=10 -add in.aac -new
# - mp4/gpac-frag.mp4:  the same with -frag 200 (moof/traf/trun fragments)
set -e
OUT="${1:-$(dirname "$0")/../../fixtures/external}"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK=/tmp/fixtures/av-gpac
mkdir -p "$WORK" "$OUT/mp4"
cp "$HERE/gpac-inner.sh" "$WORK/"
F="-hide_banner -loglevel error -y"
ffmpeg $F -f lavfi -i testsrc=size=32x32:rate=10 -frames:v 4 -c:v libx264 -pix_fmt yuv420p -g 2 \
  -bitexact "$WORK/in.h264"
ffmpeg $F -f lavfi -i sine=frequency=440:sample_rate=16000:duration=0.4 -c:a aac -b:a 16k \
  -bitexact "$WORK/in.aac"
docker run --rm -v "$WORK:/w" debian:trixie-slim sh /w/gpac-inner.sh
cp "$WORK/gpac.mp4" "$WORK/gpac-frag.mp4" "$OUT/mp4/"
