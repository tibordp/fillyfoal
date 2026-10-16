#!/bin/bash
# A BPF object with CO-RE relocations in its .BTF.ext: core.c compiled with
# clang for the little-endian BPF target in Debian trixie (clang 19, llvm 19).
# The object keeps its DWARF; llvm-objdump -S on a copy stripped of it prints
# the source lines from .BTF.ext's line information, the cross-check.
# Output lands in $OUT (default /tmp/fixtures/btf-core).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-/tmp/fixtures/btf-core}
mkdir -p "$OUT"
cp "$HERE/core.c" "$OUT/"
docker run --rm --hostname fillyfoal -v "$OUT:/src" -w /src debian:trixie bash -euc '
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq clang llvm bpftool > /dev/null
    clang --version | head -1
    clang -g -O2 -target bpfel -ffile-prefix-map=/src=. -c core.c -o core.o
    llvm-objcopy --strip-debug core.o nodebug.o
    llvm-objdump -S --no-show-raw-insn nodebug.o > lines.txt
    llvm-readelf -x .BTF.ext core.o > ext.txt
    bpftool btf dump file core.o format raw > core.txt
'
