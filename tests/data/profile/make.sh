#!/bin/sh
# Builds the coverage and profile fixtures from prog.c (a loop over two
# small functions) with real compilers in Docker:
#
#   gcno/prog.gcno, gcda/prog.gcda              GCC 14.2 (debian:trixie)
#   gcno/prog-gcc10.gcno, gcda/prog-gcc10.gcda  GCC 10.3 (alpine:3.14): the
#       older layout (lengths in words, padded strings, no checksum)
#   profraw/prog.profraw     clang 19 -fprofile-instr-generate -fcoverage-mapping
#   profraw/prog-ir.profraw  clang 19 -fprofile-generate (IR instrumentation)
#   profdata/prog.profdata, profdata/prog-ir.profdata
#                            llvm-profdata 19 merge of the two raw profiles
#
#   sh tests/data/profile/make.sh [fixtures directory]
#
# Sources are compiled in /src so no host path reaches the files. The .gcno
# stamp is the compile time and the .profraw files hold the binary's build ID
# and address deltas, so reruns differ in those bytes.
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
FIX=$(cd "${1:-$SRC/../../fixtures/external}" && pwd)
B=/tmp/fixtures/exec-profile
rm -rf "$B"
mkdir -p "$B/out"
docker run --rm -v "$B/out:/out" -v "$SRC:/scripts:ro" debian:trixie sh -euc '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null
    apt-get install -y -qq --no-install-recommends gcc clang llvm libclang-rt-19-dev libc6-dev >/dev/null
    mkdir /src && cp /scripts/prog.c /src && cd /src
    gcc --version | head -1; clang --version | head -1
    gcc --coverage -O0 -c prog.c -o prog.o
    gcc --coverage prog.o -o prog
    ./prog
    cp prog.gcno /out/prog.gcno
    cp prog.gcda /out/prog.gcda
    clang -fprofile-instr-generate -fcoverage-mapping -O0 prog.c -o prog-fe
    LLVM_PROFILE_FILE=prog.profraw ./prog-fe
    clang -fprofile-generate -O0 prog.c -o prog-ir
    LLVM_PROFILE_FILE=prog-ir.profraw ./prog-ir
    llvm-profdata merge -o prog.profdata prog.profraw
    llvm-profdata merge -o prog-ir.profdata prog-ir.profraw
    cp prog.profraw prog-ir.profraw prog.profdata prog-ir.profdata /out/
'
docker run --rm -v "$B/out:/out" -v "$SRC:/scripts:ro" alpine:3.14 sh -euc '
    apk add -q gcc musl-dev
    mkdir /src && cp /scripts/prog.c /src && cd /src
    gcc --version | head -1
    gcc --coverage -O0 -c prog.c -o prog.o
    gcc --coverage prog.o -o prog
    ./prog
    cp prog.gcno /out/prog-gcc10.gcno
    cp prog.gcda /out/prog-gcc10.gcda
'
for f in prog.gcno prog-gcc10.gcno; do mkdir -p "$FIX/gcno"; cp "$B/out/$f" "$FIX/gcno/"; done
for f in prog.gcda prog-gcc10.gcda; do mkdir -p "$FIX/gcda"; cp "$B/out/$f" "$FIX/gcda/"; done
for f in prog.profraw prog-ir.profraw; do mkdir -p "$FIX/profraw"; cp "$B/out/$f" "$FIX/profraw/"; done
for f in prog.profdata prog-ir.profdata; do mkdir -p "$FIX/profdata"; cp "$B/out/$f" "$FIX/profdata/"; done
ls -l "$B/out"
