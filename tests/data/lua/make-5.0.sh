#!/bin/sh
# Builds tests/fixtures/external/lua/sample-5.0.luac and
# sample-5.0-stripped.luac (`luac -s`) from sample-5.0.lua with luac 5.0.3,
# compiled from lua.org's source tarball (checked against its published
# SHA-256) in Docker debian:bookworm-slim, in a neutral directory so the
# chunk name is "@sample-5.0.lua". `luac -l -l` (written next to the
# outputs as sample-5.0.txt) lists what the snapshot should show. luac
# output has no timestamps: a rerun gives the same bytes.
#
#   sh tests/data/lua/make-5.0.sh [fixtures directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
FIX=$(cd "${1:-$SRC/../../fixtures/external}" && pwd)
B=/tmp/fixtures/bytecode-lua50/build
rm -rf "$B"
mkdir -p "$B"
cp "$SRC/sample-5.0.lua" "$B/sample-5.0.lua"
cat > "$B/inner.sh" <<'IN'
set -eu
apt-get update -qq
apt-get install -y -qq --no-install-recommends gcc make libc6-dev curl ca-certificates >/dev/null
cd /tmp
curl -sSfLO https://www.lua.org/ftp/lua-5.0.3.tar.gz
echo "1193a61b0e08acaa6eee0eecf29709179ee49c71baebc59b682a25c3b5a45671  lua-5.0.3.tar.gz" | sha256sum -c
tar xzf lua-5.0.3.tar.gz
cd lua-5.0.3
make -s >/dev/null
cd /w
L=/tmp/lua-5.0.3/bin/luac
$L -v
# $1: output suffix ("" on the 64-bit host, "-i386" on 32-bit x86).
$L -o "sample-5.0$1.luac" sample-5.0.lua
$L -l -l "sample-5.0$1.luac" > "sample-5.0$1.txt"
if [ -z "$1" ]; then
    $L -s -o sample-5.0-stripped.luac sample-5.0.lua
    $L -l -l sample-5.0-stripped.luac > sample-5.0-stripped.txt
fi
IN
# LP64 (sizeof(Instruction) and sizeof(size_t) are 8, as on any 64-bit
# Linux), and ILP32 i386 (4 and 4, the layout of most 5.0-era chunks).
docker run --rm -v "$B:/w" debian:bookworm-slim sh /w/inner.sh ""
docker run --rm --platform linux/386 -v "$B:/w" debian:bookworm-slim sh /w/inner.sh -i386
mkdir -p "$FIX/lua"
cp "$B/sample-5.0.luac" "$B/sample-5.0-stripped.luac" "$B/sample-5.0-i386.luac" "$FIX/lua/"
