#!/bin/sh
# Builds tests/fixtures/external/ne/fillyne.exe with Open Watcom V2
# (2026-10-01-Build, the project's ow-snapshot.tar.xz release, unpacked in
# $OW) in a Debian container: a Windows 3.x large-model program with two
# code segments, a data segment and imports by ordinal and by name, so the
# segments carry relocation records of several kinds.
#
#   OW=/path/to/unpacked/ow-snapshot sh tests/data/ne/make.sh [output directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
OUT=$(cd "${1:-$SRC/../../fixtures/external/ne}" && pwd)
: "${OW:?set OW to the unpacked Open Watcom snapshot}"
B=/tmp/fixtures/executable-ne/build
rm -rf "$B"
mkdir -p "$B"
cp "$SRC"/fillyne.c "$SRC"/fillyne2.c "$B"
docker run --rm -v "$OW":/ow:ro -v "$B":/build/ne -w /build/ne "${IMAGE:-debian:trixie}" sh -c '
    set -e
    export WATCOM=/ow PATH=/ow/binl64:$PATH INCLUDE=/ow/h:/ow/h/win
    wcc -q -bt=windows -ml -zW -s -d0 -fo=fillyne.obj fillyne.c
    wcc -q -bt=windows -ml -zW -s -d0 -nt=FILLY_TEXT -fo=fillyne2.obj fillyne2.c
    wlink option quiet system windows name fillyne.exe \
        file fillyne.obj, fillyne2.obj \
        import FillyHelper FILLYHLP.FillyHelper \
        option description fillyfoal option packcode=0 option map=fillyne.map
'
cp "$B"/fillyne.exe "$OUT"/
