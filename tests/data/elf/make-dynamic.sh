#!/bin/sh
# Builds tests/fixtures/external/elf/s390x-versioned.so and s390x-dynamic
# with Debian trixie's clang 19 and LLD (Docker): a big-endian shared object
# with symbol versions (.gnu.version_d, from versioned.map and .symver) and a
# big-endian, dynamically linked executable using it (PT_INTERP, .dynamic,
# .gnu.version_r, PLT and GOT relocations). No libc, no debug info, no
# .comment and no build ID, so no paths end up in the files.
#
#   sh tests/data/elf/make-dynamic.sh [output directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
OUT=$(cd "${1:-$SRC/../../fixtures/external/elf}" && pwd)
B=/tmp/fixtures/executable-elf-dynamic
rm -rf "$B"
mkdir -p "$B"
cp "$SRC"/versioned.c "$SRC"/versioned.map "$SRC"/dynamic.c "$B"
docker run --rm -v "$B":/build/elf -w /build/elf "${IMAGE:-debian:trixie}" sh -c '
    set -e
    command -v clang >/dev/null || {
        apt-get update -qq && apt-get install -y -qq --no-install-recommends clang lld llvm >/dev/null
    }
    T="--target=s390x-linux-gnu -O1 -fno-ident -nostdlib -fuse-ld=lld -Wl,--build-id=none"
    clang $T -fPIC -shared -Wl,--version-script=versioned.map -Wl,-soname,libfilly.so.2 \
        versioned.c -o s390x-versioned.so
    clang $T -fPIE -pie -Wl,--dynamic-linker=/lib/ld64.so.1 dynamic.c s390x-versioned.so \
        -o s390x-dynamic
    clang --version | head -1
    llvm-readelf -h -l -d -r -V --dyn-syms s390x-versioned.so s390x-dynamic
'
cp "$B"/s390x-versioned.so "$B"/s390x-dynamic "$OUT"/
