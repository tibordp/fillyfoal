"""Synthetic NES 2.0 ROM: nes2-exp.nes, PRG size in exponent-multiplier form.

    python3 tests/data/nes/synthetic.py

Byte 9's low nibble is 0xF, so byte 4 is EEEEEEMM and the PRG ROM is
2^E * (2*MM + 1) bytes: E = 13, MM = 0 gives 8 KiB. CHR ROM is one 8 KiB
unit (byte 9's high nibble 0). Mapper 0 (NROM). Written from the NES 2.0
header description (nesdev wiki).
"""

import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "..", "fixtures", "synthetic", "nes")


def main():
    header = b"NES\x1a" + bytes([13 << 2 | 0, 1, 0x00, 0x08, 0x00, 0x0F, 0, 0, 0, 0, 0, 0])
    prg = bytearray(b"\xea" * 8192)
    prg[-4:] = b"\x00\xe0\x00\xe0"  # reset and IRQ vectors at $E000
    chr_rom = bytes(8192)
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "nes2-exp.nes"), "wb") as f:
        f.write(header + bytes(prg) + chr_rom)


if __name__ == "__main__":
    main()
