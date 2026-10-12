#!/bin/sh
# Runs in debian:trixie-slim with the work directory at /w: builds MP4Box
# 2.4.0 (static, no optional libraries) and muxes the two fixtures.
set -e
apt-get update -qq
apt-get install -y -qq build-essential pkg-config zlib1g-dev ca-certificates curl >/dev/null 2>&1
mkdir -p /src && cd /src
curl -sL https://github.com/gpac/gpac/archive/refs/tags/v2.4.0.tar.gz | tar xz --strip-components=1
./configure --static-bin >/dev/null
make -j8 >/dev/null 2>&1
cd /w
/src/bin/gcc/MP4Box -quiet -add in.h264:fps=10 -add in.aac -new gpac.mp4
/src/bin/gcc/MP4Box -quiet -add in.h264:fps=10 -add in.aac -frag 200 -new gpac-frag.mp4
