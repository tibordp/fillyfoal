#!/bin/sh
# Regenerates crates/exec/src/formats/bytecode/pyc_ops.rs, the per-version
# CPython opcode tables used by the pyc disassembly, from the interpreters
# themselves: opcodes_dump.py runs in each python:X.Y-slim Docker image and
# prints its `dis`/`opcode` tables; opcodes_gen.py turns them into Rust.
#
#   sh tests/data/pyc/make-opcodes.sh
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
OUT="$SRC/../../../crates/exec/src/formats/bytecode/pyc_ops.rs"
B=/tmp/fixtures/bytecode-pyc-opcodes
rm -rf "$B"
mkdir -p "$B"
cp "$SRC/opcodes_dump.py" "$B/"
for v in 2.7 3.6 3.7 3.8 3.9 3.10 3.11 3.12 3.13 3.14; do
    docker run --rm -v "$B:/w:ro" "python:$v-slim" python /w/opcodes_dump.py \
        > "$B/ops-$v.json.tmp"
    mv "$B/ops-$v.json.tmp" "$B/ops-$v.json"
done
python3 -I "$SRC/opcodes_gen.py" "$B" > "$OUT"
