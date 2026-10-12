#!/bin/sh
# Runs in debian:bookworm-slim; see make.sh. /src caches the tsMuxer clone.
set -eu
COMMIT=c6b1186209e42c877052e762c9185f3226ef8ea2
apt-get update -qq >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends git ca-certificates \
    build-essential cmake ninja-build zlib1g-dev libfreetype-dev libfontconfig-dev fonts-dejavu-core \
    ffmpeg >/dev/null 2>&1
if [ ! -d /src/tsMuxer ]; then
    git clone -q https://github.com/justdan96/tsMuxer.git /src/tsMuxer
fi
cd /src/tsMuxer
git checkout -q "$COMMIT"
mkdir -p build
cd build
cmake -G Ninja -DTSMUXER_GUI=OFF -DCMAKE_BUILD_TYPE=Release .. >/dev/null
ninja >/dev/null
TSMUXER=/src/tsMuxer/build/tsMuxer/tsmuxer
cd /work
ffmpeg -nostdin -loglevel error -f lavfi -i testsrc2=size=1920x1080:rate=24000/1001 -t 2 \
    -c:v libx264 -preset ultrafast -profile:v high -level 4.1 \
    -x264-params keyint=24:bluray-compat=1 -bitexact -f h264 v.264
ffmpeg -nostdin -loglevel error -f lavfi -i testsrc2=size=1920x1080:rate=24000/1001 -t 1 \
    -c:v libx265 -preset ultrafast -x265-params keyint=24:pools=none:log-level=error -bitexact -f hevc v.hevc
ffmpeg -nostdin -loglevel error -f lavfi -i sine=frequency=440:sample_rate=48000 -ac 2 -t 2 \
    -c:a ac3 -b:a 192k -bitexact -f ac3 a.ac3
printf '1\n00:00:00,500 --> 00:00:01,500\nfillyfoal\n' > s.srt
cat > hd.meta <<'M'
MUXOPT --no-pcr-on-video-pid --new-audio-pes --blu-ray --vbr --custom-chapters=00:00:00.000;00:00:01.000 --vbv-len=500
V_MPEG4/ISO/AVC, "/work/v.264", fps=23.976, insertSEI, contSPS
A_AC3, "/work/a.ac3", lang=eng
S_TEXT/UTF8, "/work/s.srt", font-name="DejaVu Sans", font-size=48, font-color=0xffffffff, bottom-offset=24, font-border=2, text-align=center, video-width=1920, video-height=1080, fps=23.976, lang=fra
M
cat > uhd.meta <<'M'
MUXOPT --no-pcr-on-video-pid --new-audio-pes --blu-ray-v3 --vbr --vbv-len=500
V_MPEGH/ISO/HEVC, "/work/v.hevc", fps=23.976
A_AC3, "/work/a.ac3", lang=deu
M
"$TSMUXER" hd.meta /work/hd >hd.log 2>&1
"$TSMUXER" uhd.meta /work/uhd >uhd.log 2>&1
