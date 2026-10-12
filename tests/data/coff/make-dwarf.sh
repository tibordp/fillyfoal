#!/bin/sh
# Builds the COFF objects with DWARF in tests/fixtures/external/coff/ from
# tests/data/dwarf/shapes.c, in Docker:
#
# - shapes-mingw-x64.o: Debian trixie mingw-w64 GCC (`gcc-mingw-w64-x86-64`),
#   GNU as relocations (SECREL and ADDR64 against section symbols, the
#   addends stored in place);
# - shapes-clang-arm64.o: Debian trixie clang (`--target=aarch64-w64-windows-gnu`),
#   LLVM's COFF writer.
#
#   sh tests/data/coff/make-dwarf.sh [repo]
#
# The build runs in /build/dwarf inside the containers and the prefix maps
# rewrite it to ".", so no local path ends up in the DWARF.
set -eu
SRC=$(cd "$(dirname "$0")/../dwarf" && pwd)
OUT=$(cd "${1:-$SRC/../../..}" && pwd)/tests/fixtures/external/coff
B=/tmp/fixtures/dwarf-coff
rm -rf "$B"
mkdir -p "$B"
cp "$SRC"/shapes.c "$SRC"/shapes.h "$B"
MAP="-ffile-prefix-map=/build/dwarf=. -fdebug-prefix-map=/build/dwarf=."
docker run --rm -e MAP="$MAP" -v "$B":/build/dwarf -w /build/dwarf debian:trixie sh -c '
    set -e
    apt-get update -qq && apt-get install -y -qq --no-install-recommends gcc-mingw-w64-x86-64 binutils-mingw-w64-x86-64 >/dev/null
    x86_64-w64-mingw32-gcc --version | head -1
    x86_64-w64-mingw32-gcc -g -O1 $MAP -c -o shapes-mingw-x64.o shapes.c
    x86_64-w64-mingw32-objdump -h -r shapes-mingw-x64.o
'
docker run --rm -e MAP="$MAP" -v "$B":/build/dwarf -w /build/dwarf "${CLANG_IMAGE:-fillyfoal-clang:trixie}" sh -c '
    set -e
    clang --version | head -1
    clang --target=aarch64-w64-windows-gnu -g -O1 $MAP -c -o shapes-clang-arm64.o shapes.c
    llvm-objdump -h -r shapes-clang-arm64.o
    llvm-dwarfdump --verify shapes-mingw-x64.o shapes-clang-arm64.o
'
cp "$B"/shapes-mingw-x64.o "$B"/shapes-clang-arm64.o "$OUT"/
