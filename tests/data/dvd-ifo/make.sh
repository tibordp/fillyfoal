#!/bin/sh
# Writes the external DVD-Video IFO fixtures with dvdauthor 0.7.2 (Debian
# bookworm's dvdauthor package; needs Docker):
#
#   sh tests/data/dvd-ifo/make.sh [fixtures directory]
#
# inside.sh encodes two short PAL clips with FFmpeg (-target pal-dvd) and
# authors a DVD from dvd.xml: a VMG with a first-play command and a title
# menu PGC, one title set with a root menu (a still cell) and a chapter
# menu, and two titles (two programs and three cells over two VOBs; one
# cell) whose post commands branch and call menus. It also writes
# `lsdvd -x` and `dvdunauthor` dumps to compare against.
#
# - dvd-ifo/dvdauthor-vmg.ifo: VIDEO_TS/VIDEO_TS.IFO
# - dvd-ifo/dvdauthor-vts.ifo: VIDEO_TS/VTS_01_0.IFO
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
FIX=$(cd "${1:-$SRC/../../fixtures/external}" && pwd)
B=/tmp/fixtures/discs-dvd
rm -rf "$B"
mkdir -p "$B"
docker run --rm -v "$B:/work" -v "$SRC:/scripts:ro" -w /work debian:bookworm-slim sh /scripts/inside.sh
mkdir -p "$FIX/dvd-ifo"
cp "$B/out/VIDEO_TS/VIDEO_TS.IFO" "$FIX/dvd-ifo/dvdauthor-vmg.ifo"
cp "$B/out/VIDEO_TS/VTS_01_0.IFO" "$FIX/dvd-ifo/dvdauthor-vts.ifo"
