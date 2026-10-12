#!/bin/sh
# Writes tests/fixtures/external/bsa/*.bsa and tests/fixtures/external/ba2/*.ba2
# with the ba2 crate 3.0.1 (Rust, 0BSD; a port of Ryan McKenzie's C++ bsa
# library), through tests/data/bsa/main.rs, in Docker:
#
#   mkdir -p /tmp/fixtures/games-retro-bsa && cp tests/data/bsa/make.sh tests/data/bsa/main.rs /tmp/fixtures/games-retro-bsa/
#   docker run --rm -v /tmp/fixtures/games-retro-bsa:/w rust:1-bookworm sh /w/make.sh
#
# Outputs land in /tmp/fixtures/games-retro-bsa/out.
set -e
cd /w
rm -rf in out && mkdir -p in out
printf 'A Bethesda archive written by the ba2 crate for the fillyfoal tests.\n' > in/readme.txt
printf 'Notes: nothing to see here.\n' > in/notes.txt
i=0
while [ $i -lt 64 ]; do printf 'data block %02d ' $i; i=$((i + 1)); done > in/data.bin
# A 4x4 A8R8G8B8 DDS with three mips (legacy header, no DX10 extension).
python3 - <<'PY'
import struct
pf = struct.pack("<IIIIIIII", 32, 0x41, 0, 32, 0x00FF0000, 0x0000FF00, 0x000000FF, 0xFF000000)
hdr = struct.pack("<IIIIIII", 124, 0x1 | 0x2 | 0x4 | 0x1000 | 0x20000 | 0x8, 4, 4, 16, 0, 3)
hdr += b"\0" * 44 + pf + struct.pack("<IIIII", 0x1000 | 0x400000 | 0x8, 0, 0, 0, 0)
pixels = bytes((i * 7) & 0xFF for i in range(64 + 16 + 4))
open("in/tiny.dds", "wb").write(b"DDS " + hdr + pixels)
PY
[ -d ba2w ] || cargo new -q --name ba2w ba2w
cd ba2w
grep -q '^ba2 ' Cargo.toml || cargo add -q ba2@=3.0.1 anyhow@1
cp /w/main.rs src/main.rs
cargo run -q --release -- /w/in /w/out
ls -l /w/out
