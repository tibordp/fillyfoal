#!/bin/sh
# Regenerates crates/exec/src/formats/bytecode/spirv_tables.rs (opcode,
# capability, execution model and source language names) from the Khronos
# SPIR-V grammar, spirv.core.grammar.json of the Docker alpine:edge
# `spirv-headers` package; tables_gen.py turns it into Rust.
#
#   sh tests/data/spirv/make-tables.sh
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
OUT="$SRC/../../../crates/exec/src/formats/bytecode/spirv_tables.rs"
B=/tmp/fixtures/bytecode-spirv-tables
rm -rf "$B"
mkdir -p "$B"
docker run --rm -v "$B:/w" alpine:edge sh -c '
    set -e
    apk add --no-cache -q spirv-headers
    apk list --installed spirv-headers | cut -d" " -f1 > /w/version.txt
    cp /usr/include/spirv/unified1/spirv.core.grammar.json /w/'
python3 -I "$SRC/tables_gen.py" "$B/spirv.core.grammar.json" "$(cat "$B/version.txt")" > "$OUT"
