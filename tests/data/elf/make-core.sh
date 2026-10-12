#!/bin/sh
# Builds tests/fixtures/external/elf/aarch64-kernel.core.gz: the core dump
# the Linux kernel writes (core_pattern "core", as in the Docker VM) when a
# tiny static process (core.c, built with Debian trixie's clang 19 and LLD,
# no libc) is killed with SIGSEGV, in Docker. The process runs from
# /build/elf with an empty environment, so the only paths in the dump (the
# NT_FILE mapping list, NT_PRPSINFO, the auxiliary vector) name that
# neutral directory. The stack's AT_RANDOM bytes and the address-space
# layout differ per run, so the dump is not reproducible byte for byte.
# scrub_core.py then zeroes the dumped vDSO (the running kernel's code).
# Stored gzipped (gzip -9 -n): the anonymous mappings are mostly zeros.
#
#   sh tests/data/elf/make-core.sh [output directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
OUT=$(cd "${1:-$SRC/../../fixtures/external/elf}" && pwd)
B=/tmp/fixtures/executable-elf-core
rm -rf "$B"
mkdir -p "$B"
cp "$SRC"/core.c "$B"
docker run --rm --platform linux/arm64 -v "$B":/build/elf -w /build/elf "${IMAGE:-debian:trixie}" sh -c '
    set -e
    command -v clang >/dev/null || {
        apt-get update -qq && apt-get install -y -qq --no-install-recommends clang lld >/dev/null
    }
    clang --target=aarch64-linux-gnu -O1 -fno-ident -static -nostdlib -fuse-ld=lld \
        -Wl,--build-id=none core.c -o filly-core
    test "$(cat /proc/sys/kernel/core_pattern)" = core
    ulimit -c unlimited
    env -i ./filly-core &
    pid=$!
    sleep 1
    kill -SEGV $pid
    wait $pid || true
    if [ -f core.$pid ]; then mv core.$pid aarch64-kernel.core; else mv core aarch64-kernel.core; fi
    chmod 644 aarch64-kernel.core
'
python3 -I "$SRC"/scrub_core.py "$B"/aarch64-kernel.core
gzip -9 -n -f "$B"/aarch64-kernel.core
cp "$B"/aarch64-kernel.core.gz "$OUT"/
