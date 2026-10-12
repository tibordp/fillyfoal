#!/bin/sh
# Builds tests/fixtures/external/ne/fillyne.exe with Open Watcom V2
# (2026-10-01-Build, the project's ow-snapshot.tar.xz release, unpacked in
# $OW) in a Debian container: a Windows 3.x large-model program linked
# without any C runtime or default library (wcc -zl, wlink option
# nodefaultlibs), so the image holds only the code of fillyne.c and
# fillyne2.c. Two code segments, a data segment and imports by ordinal
# (KERNEL.4, USER.1) and by name
# (FILLYHLP.FILLYHELPER) give relocation records of several kinds.
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
    export WATCOM=/ow PATH=/ow/binl64:$PATH
    wcc -q -bt=windows -ml -zl -zW -s -d0 -fo=fillyne.obj fillyne.c
    wcc -q -bt=windows -ml -zl -zW -s -d0 -nt=FILLY_TEXT -fo=fillyne2.obj fillyne2.c
    wlink option quiet system windows name fillyne.exe \
        file fillyne.obj, fillyne2.obj \
        option nodefaultlibs option start=filly_start_ option stack=4096 \
        import FillyBox USER.1 \
        import FillyExit KERNEL.4 \
        import FillyHelper FILLYHLP.FillyHelper \
        option description fillyfoal option packcode=0 option map=fillyne.map
'
cp "$B"/fillyne.exe "$OUT"/
