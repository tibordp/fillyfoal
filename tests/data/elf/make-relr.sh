#!/bin/sh
# Builds tests/fixtures/external/elf/x86_64-relr.so from relr.c with Debian
# trixie's clang 19 and LLD (Docker): a shared object linked with
# -z pack-relative-relocs (.relr.dyn with address and bitmap entries), a
# SysV and a GNU hash table, and .eh_frame with .eh_frame_hdr. No libc, no
# debug info and no .comment, so no paths end up in the file.
#
#   sh tests/data/elf/make-relr.sh [output directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
OUT=$(cd "${1:-$SRC/../../fixtures/external/elf}" && pwd)
B=/tmp/fixtures/executable-elf-relr
rm -rf "$B"
mkdir -p "$B"
cp "$SRC"/relr.c "$B"
docker run --rm -v "$B":/build/elf -w /build/elf "${IMAGE:-debian:trixie}" sh -c '
    set -e
    command -v clang >/dev/null || {
        apt-get update -qq && apt-get install -y -qq --no-install-recommends clang lld llvm >/dev/null
    }
    clang --target=x86_64-linux-gnu -O1 -fPIC -fno-ident -shared -nostdlib \
        -fuse-ld=lld -Wl,-z,pack-relative-relocs -Wl,--hash-style=both \
        -Wl,--build-id=none relr.c -o x86_64-relr.so
    clang --version | head -1
    llvm-readelf -r --section-headers x86_64-relr.so
    llvm-dwarfdump --eh-frame x86_64-relr.so | grep -E "CIE|FDE"
'
cp "$B"/x86_64-relr.so "$OUT"/
