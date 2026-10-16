#!/bin/bash
# Split BTF fixtures: base.c's BTF stands in for vmlinux, module.c's is
# encoded by pahole split against it, the way the kernel build makes
# /sys/kernel/btf/<module> and the .BTF section of a .ko (added with
# objcopy, as the kernel build does). Debian trixie (gcc 14, pahole from
# dwarves, bpftool for the cross-check). Output lands in $OUT (default
# /tmp/fixtures/btf-split): module.btf (raw split BTF), module.o (the object
# with DWARF stripped and module.btf added as its .BTF section).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-/tmp/fixtures/btf-split}
mkdir -p "$OUT"
cp "$HERE/base.c" "$HERE/module.c" "$OUT/"
docker run --rm --hostname fillyfoal -v "$OUT:/src" -w /src debian:trixie bash -euc '
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq gcc dwarves bpftool binutils > /dev/null
    gcc --version | head -1; pahole --version
    for f in base module; do
        gcc -g -O2 -ffile-prefix-map=/src=. -fno-ident -c $f.c -o $f.o
    done
    pahole --btf_encode_detached=base.btf base.o
    pahole --btf_base=base.btf --btf_encode_detached=module.btf module.o
    objcopy --strip-debug --add-section .BTF=module.btf \
        --set-section-flags .BTF=readonly module.o
    bpftool btf dump file base.btf format raw > base.txt
    bpftool -B base.btf btf dump file module.btf format raw > module.txt
'
