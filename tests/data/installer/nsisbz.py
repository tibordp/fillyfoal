"""NSIS's bzip2 variant, made from real bzip2 output.

NSIS (Source/bzip2, as 7-Zip's NSIS decoder reads it) drops the "BZh"
stream header, replaces each 48-bit block magic and its CRC and randomised
bit with the single byte 0x31, and the end magic and combined CRC with 0x17.
This rewrites Python's bz2 output that way, bit for bit.
"""

import bz2

BLOCK = f"{0x314159265359:048b}"
END = f"{0x177245385090:048b}"


def nsis_bzip2(data, level=9):
    std = bz2.compress(data, level)
    bits = "".join(f"{b:08b}" for b in std)
    assert bits[32:80] == BLOCK
    pos = 32
    out = ""
    while True:
        if bits[pos : pos + 48] == BLOCK:
            nxt = min(
                i for i in (bits.find(BLOCK, pos + 48), bits.find(END, pos + 48)) if i >= 0
            )
            out += "00110001" + bits[pos + 48 + 32 + 1 : nxt]
            pos = nxt
        else:
            assert bits[pos : pos + 48] == END
            out += "00010111"
            break
    out += "0" * (-len(out) % 8)
    return bytes(int(out[i : i + 8], 2) for i in range(0, len(out), 8))


if __name__ == "__main__":
    d = nsis_bzip2(b"hello hello hello hello, nsis bzip2!\n" * 3)
    print(len(d))
    print(", ".join(f"0x{b:02x}" for b in d))
