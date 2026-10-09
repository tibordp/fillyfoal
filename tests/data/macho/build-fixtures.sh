#!/bin/sh
# Builds the Mach-O fixtures in tests/fixtures/external/macho{,-fat}/ with
# Apple's toolchain (clang, ld, lipo, codesign, swiftc).
#
# Run from anywhere: sh tests/data/macho/build-fixtures.sh <repo>
# Builds in a neutral directory so no user paths end up in the files:
# prefix maps for the compilers, -oso_prefix for the linker's debug map,
# ZERO_AR_DATE=1 for the object timestamps in it, ad-hoc signatures only.
# -segalign 0x1000 keeps the arm64 files small (they are not meant to run).
set -ex
REPO=${1:?usage: build-fixtures.sh <repo>}
DATA="$REPO/tests/data/macho"
B=/tmp/fixtures/macho
rm -rf "$B" && mkdir -p "$B/out"
cp "$DATA"/hello.c "$DATA"/filly.c "$DATA"/reloc.c "$DATA"/hello.swift "$DATA"/entitlements.plist "$B"
cd "$B"
export ZERO_AR_DATE=1
MAP="-ffile-prefix-map=$B=/src -fdebug-prefix-map=$B=/src"
SMALL="-Wl,-segalign,0x1000"

# arm64 executable: chained fixups (the default), linker-signed.
clang -arch arm64 -Os $MAP -mmacosx-version-min=14.0 $SMALL \
  -Wl,-rpath,@executable_path/../lib -Wl,-source_version,1.2.3.4.5 \
  -o out/hello-arm64 hello.c

# The same with classic dyld info opcodes, and stabs (a debug map).
clang -arch arm64 -g -Os $MAP -mmacosx-version-min=11.0 -c -o hello.o hello.c
clang -arch arm64 -mmacosx-version-min=11.0 $SMALL -Wl,-no_fixup_chains \
  -Wl,-oso_prefix,/private$B/ -o out/hello-arm64-classic hello.o

# Signed ad hoc with entitlements and an explicit designated requirement.
cp out/hello-arm64 out/hello-signed
codesign -f -s - -i org.fillyfoal.fixture --entitlements entitlements.plist \
  -r='designated => identifier "org.fillyfoal.fixture" and (cdhash H"0123456789abcdef0123456789abcdef01234567" or anchor apple generic and certificate leaf[subject.OU] = "FILLYFOAL1" and info[CFBundleVersion] >= "1.0")' \
  out/hello-signed

# Universal binary with a 64-bit fat header: x86_64 (macOS 10.13, so
# LC_VERSION_MIN_MACOSX) and arm64e (pointer authentication).
clang -arch x86_64 -Os $MAP -mmacosx-version-min=10.13 $SMALL -o hello-x86_64 hello.c
clang -arch arm64e -Os $MAP -mmacosx-version-min=14.0 $SMALL -o hello-arm64e hello.c
lipo -create -fat64 -output out/hello-fat64 hello-x86_64 hello-arm64e

# A dylib with exports, a weak definition, a thread-local and a weak library.
clang -arch arm64 -Os $MAP -mmacosx-version-min=14.0 $SMALL -dynamiclib \
  -install_name @rpath/libfilly.dylib -current_version 1.2.3 -compatibility_version 1.0 \
  -weak-lz -o out/libfilly.dylib filly.c

# Objects with relocations: x86_64 with debug info, i386 for scattered
# relocations.
clang -arch x86_64 -g -O1 $MAP -mmacosx-version-min=14.0 -c -o out/reloc-x86_64.o reloc.c
clang -target i386-apple-macos10.13 -O1 $MAP -c -o out/reloc-i386.o reloc.c

# Swift.
swiftc -Osize -target arm64-apple-macos14.0 -file-prefix-map $B=/src \
  -Xlinker -segalign -Xlinker 0x1000 -o out/hello-swift hello.swift

cp out/hello-arm64 out/hello-arm64-classic out/hello-signed out/libfilly.dylib \
  out/reloc-x86_64.o out/reloc-i386.o out/hello-swift "$REPO/tests/fixtures/external/macho/"
cp out/hello-fat64 "$REPO/tests/fixtures/external/macho-fat/"
