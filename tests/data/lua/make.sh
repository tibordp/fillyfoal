#!/bin/sh
# Builds tests/fixtures/external/lua/sample-5.{1,2,3,4,5}.luac (and a
# stripped sample-5.4-stripped.luac) from sample.lua, and ops-5.*.luac (an
# opcode sampler for the disassembly) from ops.lua, with the reference
# luac of each version (Docker alpine:edge packages lua5.1 5.1.5, lua5.2
# 5.2.4, lua5.3 5.3.6, lua5.4 5.4.9, lua5.5 5.5.1), in a neutral
# directory so the chunk name is "@sample.lua". `luac -l -l` lists what
# the snapshots should show. luac output has no timestamps: a rerun gives
# the same bytes.
#
#   sh tests/data/lua/make.sh [fixtures directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
FIX=$(cd "${1:-$SRC/../../fixtures/external}" && pwd)
B=/tmp/fixtures/bytecode-lua
rm -rf "$B"
mkdir -p "$B"
cp "$SRC/sample.lua" "$B/sample.lua"
cp "$SRC/ops.lua" "$B/ops.lua"
cat > "$B/inner.sh" <<'EOF'
set -eu
apk add --no-cache -q lua5.1 lua5.2 lua5.3 lua5.4 lua5.5
cd /w
for v in 5.1 5.2 5.3 5.4 5.5; do
    "luac$v" -v
    "luac$v" -o "sample-$v.luac" sample.lua
    "luac$v" -l -l "sample-$v.luac" > "sample-$v.txt"
    "luac$v" -o "ops-$v.luac" ops.lua
    "luac$v" -l -l "ops-$v.luac" > "ops-$v.txt"
done
luac5.4 -s -o sample-5.4-stripped.luac sample.lua
EOF
docker run --rm -v "$B:/w" alpine:edge sh /w/inner.sh
mkdir -p "$FIX/lua"
for v in 5.1 5.2 5.3 5.4 5.5 5.4-stripped; do
    cp "$B/sample-$v.luac" "$FIX/lua/sample-$v.luac"
done
for v in 5.1 5.2 5.3 5.4 5.5; do
    cp "$B/ops-$v.luac" "$FIX/lua/ops-$v.luac"
done
