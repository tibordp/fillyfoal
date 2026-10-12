#!/bin/sh
# Builds tests/fixtures/external/elf/x86_64-dwarf5 and aarch64-gcc-dwarf4
# from dwarf.c in Docker (Debian trixie), without libc:
#
# - x86_64-dwarf5: clang 19 + LLD, DWARF 5 (-gdwarf-aranges for
#   .debug_aranges): .debug_info with strx/addrx forms, .debug_str_offsets,
#   .debug_addr, .debug_rnglists, .debug_loclists, .debug_line (version 5)
#   with .debug_line_str, and (freestanding, so no unwind tables) the frames
#   in .debug_frame.
# - aarch64-gcc-dwarf4: GCC 14 + GNU ld, DWARF 4: DW_FORM_strp,
#   .debug_aranges, .debug_ranges, .debug_loc, a version 4 line table, and
#   .eh_frame (AArch64 GCC keeps unwind tables despite
#   -fno-asynchronous-unwind-tables).
#
# The build directory is /build/elf inside the container and the prefix
# maps turn it into ".", so no host path ends up in the files.
#
#   sh tests/data/elf/make-dwarf.sh [output directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
OUT=$(cd "${1:-$SRC/../../fixtures/external/elf}" && pwd)
B=/tmp/fixtures/executable-elf-dwarf
rm -rf "$B"
mkdir -p "$B"
cp "$SRC"/dwarf.c "$B"
docker run --rm --platform linux/arm64 -v "$B":/build/elf -w /build/elf "${IMAGE:-debian:trixie}" sh -c '
    set -e
    command -v clang >/dev/null && command -v gcc >/dev/null || {
        apt-get update -qq && apt-get install -y -qq --no-install-recommends clang lld llvm gcc binutils >/dev/null
    }
    clang --target=x86_64-linux-gnu -O1 -g -gdwarf-5 -gdwarf-aranges -fno-ident \
        -ffreestanding -nostdlib -static -fuse-ld=lld -Wl,--build-id=none \
        -Wl,-e,filly_start \
        -ffile-prefix-map=/build/elf=. -fdebug-prefix-map=/build/elf=. \
        dwarf.c -o x86_64-dwarf5
    gcc -O1 -g -gdwarf-4 -gno-variable-location-views \
        -fno-asynchronous-unwind-tables -fno-ident \
        -ffreestanding -nostdlib -static -Wl,--build-id=none \
        -Wl,-z,max-page-size=0x1000 -Wl,-e,filly_start \
        -ffile-prefix-map=/build/elf=. -fdebug-prefix-map=/build/elf=. \
        dwarf.c -o aarch64-gcc-dwarf4
    clang --version | head -1
    gcc --version | head -1
    llvm-dwarfdump --debug-info x86_64-dwarf5 aarch64-gcc-dwarf4 | grep -c DW_TAG
'
cp "$B"/x86_64-dwarf5 "$B"/aarch64-gcc-dwarf4 "$OUT"/
