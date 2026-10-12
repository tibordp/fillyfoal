#!/bin/sh
# Writes the external Blu-ray (BDMV) fixtures with tsMuxer, built from
# source in a Debian container (tsMuxer is not packaged in Debian; needs
# Docker and network access for the clone; nothing of it is committed):
#
#   sh tests/data/bdmv/make.sh [fixtures directory]
#
# inside.sh clones tsMuxer (Apache-2.0) at a pinned commit, builds the
# command-line tool, encodes two seconds of H.264 (x264, Blu-ray
# compatible) and AC-3 with FFmpeg, adds an SRT subtitle that tsMuxer
# renders to PGS, and muxes a Blu-ray structure with two chapters. A
# second run muxes an HEVC stream as a UHD (version 0300) structure.
#
# - bdmv-index/tsmuxer-index.bdmv, bdmv-movieobject/tsmuxer-MovieObject.bdmv,
#   bdmv-playlist/tsmuxer.mpls, bdmv-clipinfo/tsmuxer.clpi: the HD disc
# - bdmv-index/tsmuxer-uhd-index.bdmv, bdmv-playlist/tsmuxer-uhd.mpls,
#   bdmv-clipinfo/tsmuxer-uhd.clpi: the UHD disc
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
FIX=$(cd "${1:-$SRC/../../fixtures/external}" && pwd)
B=/tmp/fixtures/discs-bd
mkdir -p "$B/src"
rm -rf "$B/work"
mkdir -p "$B/work"
docker run --rm -v "$B/work:/work" -v "$B/src:/src" -v "$SRC:/scripts:ro" -w /work \
    debian:bookworm-slim sh /scripts/inside.sh
mkdir -p "$FIX/bdmv-index" "$FIX/bdmv-movieobject" "$FIX/bdmv-playlist" "$FIX/bdmv-clipinfo"
cp "$B/work/hd/BDMV/index.bdmv" "$FIX/bdmv-index/tsmuxer-index.bdmv"
cp "$B/work/hd/BDMV/MovieObject.bdmv" "$FIX/bdmv-movieobject/tsmuxer-MovieObject.bdmv"
cp "$B/work/hd/BDMV/PLAYLIST/00000.mpls" "$FIX/bdmv-playlist/tsmuxer.mpls"
cp "$B/work/hd/BDMV/CLIPINF/00000.clpi" "$FIX/bdmv-clipinfo/tsmuxer.clpi"
cp "$B/work/uhd/BDMV/index.bdmv" "$FIX/bdmv-index/tsmuxer-uhd-index.bdmv"
cp "$B/work/uhd/BDMV/PLAYLIST/00000.mpls" "$FIX/bdmv-playlist/tsmuxer-uhd.mpls"
cp "$B/work/uhd/BDMV/CLIPINF/00000.clpi" "$FIX/bdmv-clipinfo/tsmuxer-uhd.clpi"
