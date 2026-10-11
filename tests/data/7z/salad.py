"""Deterministic word salad for the 7z/ZIP codec fixtures (make_codecs.sh).

40 000 bytes of NATO-alphabet words from a fixed LCG, then the same block
again, a 70 000-byte run of '=' and the first 5 000 bytes once more:
155 000 bytes, CRC-32 0x5555a130.
"""

import sys

WORDS = (
    b"alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mike "
    b"november oscar papa quebec romeo sierra tango uniform victor whiskey xray yankee zulu"
).split()


def salad() -> bytes:
    x = 12345
    out = bytearray()
    while len(out) < 40000:
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        out += WORDS[(x >> 16) % len(WORDS)] + (b"\n" if (x >> 8) % 11 == 0 else b" ")
    block = bytes(out[:40000])
    return block + block + b"=" * 70000 + block[:5000]


if __name__ == "__main__":
    with open(sys.argv[1], "wb") as f:
        f.write(salad())
