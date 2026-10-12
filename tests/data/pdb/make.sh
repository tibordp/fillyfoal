#!/bin/sh
# Builds tests/fixtures/external/pdb/lld-link.pdb (from fillypdb.c) and
# lld-link-cpp.pdb (from fillycpp.cpp) and lld-link-x86.pdb (i386 build of
# fillypdb.c with frame pointer omission, plus fpo.s) with Debian trixie's
# clang 19 + lld-link 19 (Docker), without a C runtime. The build runs in
# /build/pdb inside the container, so the only paths in the PDB (module and
# object names, the linker's environment block) are under that neutral
# directory; /Brepro makes the PDB signature and age deterministic.
#
#   sh tests/data/pdb/make.sh [output directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
OUT=$(cd "${1:-$SRC/../../fixtures/external/pdb}" && pwd)
B=/tmp/fixtures/executable-pdb
rm -rf "$B"
mkdir -p "$B"
cp "$SRC"/fillypdb.c "$SRC"/fillycpp.cpp "$SRC"/fpo.s "$B"
docker run --rm -v "$B":/build/pdb -w /build/pdb "${IMAGE:-debian:trixie}" sh -c '
    set -e
    command -v lld-link >/dev/null || {
        apt-get update -qq && apt-get install -y -qq --no-install-recommends clang lld llvm >/dev/null
    }
    clang --target=x86_64-pc-windows-msvc -O1 -gcodeview -g -fno-ident \
        -ffile-prefix-map=/build/pdb=. -fdebug-prefix-map=/build/pdb=. \
        -c fillypdb.c -o fillypdb.obj
    lld-link /nologo /nodefaultlib /entry:filly_main /subsystem:console \
        /debug /pdb:lld-link.pdb /pdbaltpath:lld-link.pdb /Brepro \
        /out:fillypdb.exe fillypdb.obj
    llvm-pdbutil dump -summary -streams lld-link.pdb
    clang --target=x86_64-pc-windows-msvc -O1 -gcodeview -g -fno-ident \
        -fno-exceptions -fno-rtti \
        -ffile-prefix-map=/build/pdb=. -fdebug-prefix-map=/build/pdb=. \
        -c fillycpp.cpp -o fillycpp.obj
    lld-link /nologo /nodefaultlib /entry:filly_main /subsystem:console \
        /debug /pdb:lld-link-cpp.pdb /pdbaltpath:lld-link-cpp.pdb /Brepro \
        /out:fillycpp.exe fillycpp.obj
    llvm-pdbutil dump -summary -streams lld-link-cpp.pdb
    clang --target=i686-pc-windows-msvc -O2 -gcodeview -g -fno-ident \
        -fomit-frame-pointer \
        -ffile-prefix-map=/build/pdb=. -fdebug-prefix-map=/build/pdb=. \
        -c fillypdb.c -o fillypdb32.obj
    clang --target=i686-pc-windows-msvc -c fpo.s -o fpo.obj
    lld-link /nologo /nodefaultlib /entry:filly_main /subsystem:console \
        /debug /pdb:lld-link-x86.pdb /pdbaltpath:lld-link-x86.pdb /Brepro \
        /safeseh:no /out:fillypdb32.exe fillypdb32.obj fpo.obj
    llvm-pdbutil dump -summary -streams -fpo lld-link-x86.pdb
'
cp "$B"/lld-link.pdb "$B"/lld-link-cpp.pdb "$B"/lld-link-x86.pdb "$OUT"/
