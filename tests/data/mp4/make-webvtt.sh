#!/bin/sh
# mp4/webvtt.mp4: a WebVTT track (wvtt sample entry, vttc/vtte samples)
# written by GPAC's MP4Box 2.4.0, built from the release tarball in a
# Debian trixie container (gpac-inner.sh builds it the same way), from the
# cue file below: two cues, the first with an identifier, settings and two
# lines, and a gap between them.
#
#     sh tests/data/mp4/make-webvtt.sh            # writes into tests/fixtures/external
#     sh tests/data/mp4/make-webvtt.sh /tmp/out   # or elsewhere
set -e
OUT="${1:-$(dirname "$0")/../../fixtures/external}"
WORK=/tmp/fixtures/av-webvtt
mkdir -p "$WORK" "$OUT/mp4"
printf 'WEBVTT\n\ncue-1\n00:00:00.000 --> 00:00:00.400 align:start line:0\nHello\nworld\n\n00:00:00.600 --> 00:00:00.900\nSecond cue\n' \
  > "$WORK/cues.vtt"
cat > "$WORK/inner.sh" <<'EOF'
set -e
apt-get update -qq
apt-get install -y -qq build-essential pkg-config zlib1g-dev ca-certificates curl >/dev/null 2>&1
mkdir -p /src && cd /src
curl -sL https://github.com/gpac/gpac/archive/refs/tags/v2.4.0.tar.gz | tar xz --strip-components=1
./configure --static-bin >/dev/null
make -j8 >/dev/null 2>&1
cd /w
/src/bin/gcc/MP4Box -quiet -add cues.vtt:lang=eng -new webvtt.mp4
EOF
docker run --rm -v "$WORK:/w" debian:trixie-slim sh /w/inner.sh
cp "$WORK/webvtt.mp4" "$OUT/mp4/"
