#!/bin/sh
# Builds tests/fixtures/external/pe/mingw-symbols.exe with Debian trixie's
# mingw-w64 GCC (Docker), without a C runtime. The build runs in
# /build/mingw inside the container and the prefix maps rewrite it to ".",
# so no local path ends up in the DWARF; --no-insert-timestamp makes the
# image reproducible.
#
#   sh tests/data/pe/make-mingw.sh [output directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
OUT=$(cd "${1:-$SRC/../../fixtures/external/pe}" && pwd)
B=/tmp/fixtures/executable-mingw
rm -rf "$B"
mkdir -p "$B"
cp "$SRC"/fillymingw.c "$B"
docker run --rm -v "$B":/build/mingw -w /build/mingw "${IMAGE:-debian:trixie}" sh -c '
    set -e
    command -v x86_64-w64-mingw32-gcc >/dev/null || {
        apt-get update -qq && apt-get install -y -qq --no-install-recommends gcc-mingw-w64-x86-64 binutils-mingw-w64-x86-64 >/dev/null
    }
    x86_64-w64-mingw32-gcc --version | head -1
    x86_64-w64-mingw32-gcc -g -O1 -nostdlib -ffreestanding \
        -ffile-prefix-map=/build/mingw=. -fdebug-prefix-map=/build/mingw=. \
        -Wl,-e,filly_start -Wl,--no-insert-timestamp \
        -o mingw-symbols.exe fillymingw.c
    x86_64-w64-mingw32-objdump -h -t mingw-symbols.exe
'
cp "$B"/mingw-symbols.exe "$OUT"/
