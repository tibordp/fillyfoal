#!/bin/sh
# Builds tests/fixtures/external/elf/mips64{,el}.o from obj.c with Debian
# trixie's clang 19 (Docker): N64 PIC objects whose relocations compose
# three types in one r_info (e.g. R_MIPS_GPREL16/R_MIPS_SUB/R_MIPS_HI16).
# No debug info and no .comment, so no paths end up in the objects.
#
#   sh tests/data/elf/make-mips64.sh [output directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
OUT=$(cd "${1:-$SRC/../../fixtures/external/elf}" && pwd)
B=/tmp/fixtures/executable-elf
rm -rf "$B"
mkdir -p "$B"
cp "$SRC"/obj.c "$B"
docker run --rm -v "$B":/build/elf -w /build/elf "${IMAGE:-debian:trixie}" sh -c '
    set -e
    command -v clang >/dev/null || {
        apt-get update -qq && apt-get install -y -qq --no-install-recommends clang llvm >/dev/null
    }
    for t in mips64 mips64el; do
        clang --target=$t-linux-gnuabi64 -O2 -fPIC -fno-ident -c obj.c -o $t.o
        llvm-readelf -r $t.o
    done
'
cp "$B"/mips64.o "$B"/mips64el.o "$OUT"/
