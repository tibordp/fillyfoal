"""Deterministic pseudo machine code for the BCJ filter fixtures (make_bcj.sh).

8 KiB of bytes drawn by a fixed LCG from sixteen values that include the
opcode bytes every branch converter looks for (x86 E8/E9, PowerPC 0x48-0x4B
with LK=1, SPARC 0x40/0x7F, ARM Thumb F0/F8, ARM EB, IA-64 templates 0x10
and 0x16, RISC-V JAL 0xEF and AUIPC 0x17), so each filter converts a good
number of "instructions" while the data still compresses.
"""

import sys

VOCAB = bytes(
    [0x00, 0x01, 0x05, 0x10, 0x16, 0x17, 0x40, 0x48, 0x4B, 0x7F, 0xC0, 0xE8, 0xEB, 0xEF, 0xF0, 0xF8]
)


def code(n: int = 8192) -> bytes:
    x = 2024
    out = bytearray()
    for _ in range(n):
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        out.append(VOCAB[(x >> 16) & 15])
    return bytes(out)


if __name__ == "__main__":
    with open(sys.argv[1], "wb") as f:
        f.write(code())
