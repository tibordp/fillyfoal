#!/bin/bash
# Video and container fixtures written by FFmpeg 8.1.2 (with libx264,
# libx265, libsvtav1, libvpx-vp9 and libopus); reproduces them byte for byte.
#
#     sh tests/data/video/make.sh            # writes into tests/fixtures/external
#     sh tests/data/video/make.sh /tmp/out   # or elsewhere, to compare
set -e
OUT="${1:-$(dirname "$0")/../../fixtures/external}"
F="-hide_banner -loglevel error -y"
T="-f lavfi -i"
mkdir -p "$OUT"/{h264,hevc,ivf,mpegts,mpeg-ps,flv,y4m}
ffmpeg $F $T testsrc=size=40x30:rate=25 -frames:v 3 -c:v libx264 -profile:v high -pix_fmt yuv420p \
  -color_primaries bt709 -color_trc bt709 -colorspace bt709 -color_range tv -vf setsar=4/3 \
  -x264-params cqm=jvt -bitexact -f h264 "$OUT/h264/high-vui-crop.h264"
ffmpeg $F $T testsrc=size=32x32:rate=25 -frames:v 2 -c:v libx264 -pix_fmt yuv422p10le \
  -flags +ildct+ilme -x264-params nal-hrd=vbr -b:v 100k -maxrate 100k -bufsize 200k -bitexact -f h264 "$OUT/h264/high422-10-interlaced-hrd.h264"
ffmpeg $F $T testsrc=size=64x48:rate=24000/1001 -frames:v 3 -c:v libx265 -pix_fmt yuv420p10le \
  -x265-params "log-level=error:hdr10=1:master-display=G(13250,34500)B(7500,3000)R(34000,16000)WP(15635,16450)L(10000000,1):max-cll=1000,400:colorprim=bt2020:transfer=smpte2084:colormatrix=bt2020nc:range=limited" \
  -bitexact -f hevc "$OUT/hevc/main10-hdr10.hevc"
ffmpeg $F $T testsrc=size=64x48:rate=24 -frames:v 2 -c:v libsvtav1 -pix_fmt yuv420p10le \
  -color_primaries bt2020 -color_trc smpte2084 -colorspace bt2020nc \
  -svtav1-params "mastering-display=G(0.265,0.690)B(0.150,0.060)R(0.680,0.320)WP(0.3127,0.3290)L(1000,0.0050):content-light=1000,400" \
  -bitexact -f ivf "$OUT/ivf/av1-10bit-hdr.ivf" 2>/dev/null
ffmpeg $F $T testsrc=size=32x24:rate=10 -frames:v 3 -c:v libvpx-vp9 -pix_fmt yuv420p10le -bitexact -f ivf "$OUT/ivf/vp9-profile2.ivf"
ffmpeg $F $T testsrc=size=64x48:rate=25 $T sine=sample_rate=48000:duration=0.2 \
  -frames:v 4 -c:v libx265 -x265-params log-level=error -c:a ac3 -b:a 96k \
  -metadata:s:a:0 language=deu -metadata service_name="Test Channel" -metadata service_provider="fillyfoal" \
  -bitexact -f mpegts "$OUT/mpegts/hevc-ac3.ts"
ffmpeg $F $T testsrc=size=32x32:rate=25 $T sine=sample_rate=48000:duration=0.1 \
  -frames:v 2 -map 0:v -map 1:a -map 1:a -c:v libx264 -pix_fmt yuv420p -c:a:0 mp2 -c:a:1 eac3 \
  -metadata:s:a:0 language=eng -metadata:s:a:1 language=fra -bitexact -f mpegts "$OUT/mpegts/h264-mp2-eac3.ts"
ffmpeg $F $T testsrc=size=32x32:rate=25 $T sine=sample_rate=48000:duration=0.08 \
  -frames:v 2 -map 0:v -map 1:a -map 1:a -c:v mpeg2video -c:a:0 ac3 -b:a:0 64k -c:a:1 pcm_s16be \
  -bitexact -f vob "$OUT/mpeg-ps/mpeg2-ac3-lpcm.vob"
ffmpeg $F $T testsrc=size=32x32:rate=25 $T sine=sample_rate=44100:duration=0.1 \
  -frames:v 2 -c:v libx265 -x265-params log-level=error -c:a aac -b:a 32k -bitexact -f flv "$OUT/flv/hevc-aac.flv"
ffmpeg $F $T testsrc=size=32x32:rate=25 $T sine=sample_rate=48000:duration=0.1 \
  -frames:v 2 -c:v libsvtav1 -c:a libopus -b:a 24k -bitexact -f flv "$OUT/flv/av1-opus.flv" 2>/dev/null
ffmpeg $F $T testsrc=size=32x32:rate=25 -frames:v 2 -c:v libvpx-vp9 -bitexact -f flv "$OUT/flv/vp9.flv"
ffmpeg $F $T testsrc=size=8x4:rate=30000/1001 -frames:v 2 -pix_fmt yuv420p10le \
  -vf setsar=10/11,setfield=tff -strict -1 -f yuv4mpegpipe "$OUT/y4m/420p10-tff.y4m"
