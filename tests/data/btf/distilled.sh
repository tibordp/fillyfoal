#!/bin/bash
# Split BTF on a distilled base, as kernel module builds make it since Linux
# 6.12: pahole -J encodes module.c's BTF split against base.c's (which
# stands in for vmlinux) and with --btf_features=distilled_base writes, next
# to the module's .BTF, a .BTF.base section holding the minimal base the
# module refers to (libbpf relocates it onto the running kernel's at load
# time). Debian trixie (gcc 14, pahole 1.30 from dwarves, llvm-objcopy, which
# pahole -J runs to add the sections, and bpftool for the cross-check).
# Output lands in $OUT (default /tmp/fixtures/btf-distilled): module.o (the
# object with DWARF stripped, .BTF and .BTF.base), base.txt and module.txt
# (bpftool's raw dumps of the distilled base and of the module on it).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-/tmp/fixtures/btf-distilled}
mkdir -p "$OUT"
cp "$HERE/base.c" "$HERE/module.c" "$OUT/"
docker run --rm --hostname fillyfoal -v "$OUT:/src" -w /src debian:trixie bash -euc '
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq gcc dwarves bpftool binutils llvm > /dev/null
    gcc --version | head -1; pahole --version
    for f in base module; do
        gcc -g -O2 -ffile-prefix-map=/src=. -fno-ident -c $f.c -o $f.o
    done
    pahole --btf_encode_detached=base.btf base.o
    pahole -J --btf_base=base.btf --btf_features=distilled_base module.o
    objcopy --strip-debug module.o
    objcopy --dump-section .BTF.base=distilled.btf module.o
    bpftool btf dump file distilled.btf format raw > base.txt
    bpftool btf dump file module.o format raw > module.txt
'
