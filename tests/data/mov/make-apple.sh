#!/bin/sh
# QuickTime and M4A files written by Apple's AVFoundation muxer (macOS
# avconvert) from an FFmpeg source; not byte-reproducible (creation times).
#
#     sh tests/data/mov/make-apple.sh            # writes into tests/fixtures/external
#     sh tests/data/mov/make-apple.sh /tmp/out   # or elsewhere
#
# - mov/avconvert-aac.mov: PresetLowQuality re-encodes the audio to HE-AAC
#   in a version 1 sound description with a `wave` atom (frma, mp4a, esds,
#   terminator) and passes the H.264 video through, adding `tapt`
#   (clef/prof/enof for the 4:3 sample aspect).
# - mov/avconvert-prores.mov: PresetAppleProRes422LPCM, ProRes 422 video
#   (`colr` nclc, `fiel`) and 32-bit float LPCM in a version 2 sound
#   description.
# - m4a/avconvert.m4a: PresetAppleM4A, AAC-LC with an iTunSMPB tag.
set -e
OUT="${1:-$(dirname "$0")/../../fixtures/external}"
WORK=/tmp/fixtures/av-apple
mkdir -p "$WORK" "$OUT/mov" "$OUT/m4a"
ffmpeg -hide_banner -loglevel error -y -f lavfi -i testsrc=size=64x48:rate=10 \
  -f lavfi -i sine=frequency=440:sample_rate=16000:duration=0.3 -frames:v 3 \
  -c:v libx264 -pix_fmt yuv420p -vf setsar=4/3 -c:a pcm_s16le -bitexact "$WORK/src.mov"
avconvert -s "$WORK/src.mov" -p PresetLowQuality -o "$OUT/mov/avconvert-aac.mov" --replace
avconvert -s "$WORK/src.mov" -p PresetAppleProRes422LPCM -o "$OUT/mov/avconvert-prores.mov" \
  --replace --duration 0.1
avconvert -s "$WORK/src.mov" -p PresetAppleM4A -o "$OUT/m4a/avconvert.m4a" --replace
