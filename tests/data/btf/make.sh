#!/bin/bash
# BTF fixtures: kinds.c compiled with clang for the little- and big-endian
# BPF targets in Debian trixie (clang 19, llvm-objcopy 19), the .BTF section
# extracted raw; the little-endian object itself is the ELF fixture.
# Output lands in $OUT (default /tmp/fixtures/btf).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-/tmp/fixtures/btf}
mkdir -p "$OUT"
cp "$HERE/kinds.c" "$OUT/"
docker run --rm --hostname fillyfoal -v "$OUT:/src" -w /src debian:trixie bash -euc '
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq clang llvm bpftool > /dev/null
    clang --version | head -1
    for t in bpfel bpfeb; do
        clang -g -O2 -target $t -ffile-prefix-map=/src=. -c kinds.c -o kinds-$t.o
        llvm-objcopy --dump-section .BTF=kinds-$t.btf kinds-$t.o
    done
    bpftool btf dump file kinds-bpfel.btf format raw > kinds.txt
'
