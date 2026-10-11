"""Synthetic SNES ROMs for header placements other than plain LoROM:

- hirom.sfc.gz: a 128 KiB HiROM image (map mode $21), internal header at
  $FFC0, no copier header.
- sdd1.sfc.gz: a 64 KiB LoROM image with map mode $32 (S-DD1, FastROM),
  internal header at $7FC0.

    python3 tests/data/snes/synthetic.py

Stored gzipped (no name, mtime 0) because the probe needs the full image.
Written from the SNES internal header layout (title, map mode, cartridge
type, ROM and RAM size, country, developer, version, checksum complement
and checksum, then the vectors). The checksum is computed the usual way:
the 16-bit sum of all bytes, with the complement pair counted as $FF $FF
$00 $00.
"""

import gzip
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "..", "fixtures", "synthetic", "snes")


def rom(size, base, title, map_mode, rom_size):
    data = bytearray(size)
    header = title.encode().ljust(21, b" ")
    header += bytes([map_mode, 0x02, rom_size, 0x03, 0x01, 0x33, 0x00])
    data[base : base + 28] = header
    data[base + 28 : base + 32] = b"\xff\xff\x00\x00"
    # Native-mode and emulation-mode vectors pointing at a reset stub.
    vectors = struct.pack("<16H", *([0x8000] * 16))
    data[base + 32 : base + 64] = vectors
    stub = 0 if base == 0x7FC0 else 0x8000  # where $00:8000 lies
    data[stub : stub + 4] = b"\x78\x18\xfb\x5c"  # sei; clc; xce; jml
    checksum = sum(data) & 0xFFFF
    data[base + 28 : base + 32] = struct.pack("<HH", checksum ^ 0xFFFF, checksum)
    return bytes(data)


def main():
    os.makedirs(OUT, exist_ok=True)
    files = {
        "hirom.sfc.gz": rom(0x20000, 0xFFC0, "FILLYFOAL HIROM", 0x21, 0x07),
        "sdd1.sfc.gz": rom(0x10000, 0x7FC0, "FILLYFOAL SDD1", 0x32, 0x06),
    }
    for name, content in files.items():
        with open(os.path.join(OUT, name), "wb") as f:
            f.write(gzip.compress(content, compresslevel=9, mtime=0))


if __name__ == "__main__":
    main()
