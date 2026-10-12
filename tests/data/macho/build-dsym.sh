#!/bin/sh
# Builds tests/fixtures/external/macho/shapes-arm64.dwarf, the DWARF
# companion file of a dSYM bundle (MH_DSYM), with Apple's clang, ld and
# dsymutil, from tests/data/dwarf/shapes.c.
#
#   sh tests/data/macho/build-dsym.sh <repo>
#
# Builds in a neutral directory with prefix maps (the DWARF says /src),
# -oso_prefix for the executable's debug map and ZERO_AR_DATE=1 for the
# object timestamps in it; only the DWARF file from inside the bundle
# (shapes.dSYM/Contents/Resources/DWARF/shapes) is kept.
set -ex
REPO=${1:?usage: build-dsym.sh <repo>}
B=/tmp/fixtures/dwarf-macho
rm -rf "$B" && mkdir -p "$B"
cp "$REPO"/tests/data/dwarf/shapes.c "$REPO"/tests/data/dwarf/shapes.h "$B"
cd "$B"
export ZERO_AR_DATE=1
MAP="-ffile-prefix-map=$B=/src -fdebug-prefix-map=/private$B=/src"
clang -arch arm64 -g -O1 $MAP -mmacosx-version-min=14.0 -c -o shapes.o shapes.c
clang -arch arm64 -mmacosx-version-min=14.0 -Wl,-segalign,0x1000 \
  -Wl,-oso_prefix,/private$B/ -o shapes shapes.o
dsymutil shapes -o shapes.dSYM
xcrun llvm-dwarfdump --verify shapes.dSYM
cp shapes.dSYM/Contents/Resources/DWARF/shapes "$REPO/tests/fixtures/external/macho/shapes-arm64.dwarf"
