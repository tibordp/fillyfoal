"""Writes tests/fixtures/synthetic/ms-money/Finances.mny: the smallest
MSISAM (Microsoft Money) file the dissector accepts, laid out by hand,
since nothing we can run writes MSISAM (Jackcess only reads it).

    python3 tests/data/ms-money/make.py OUT

Two 4 KiB pages. Page 0 is a Jet 4 header with the MSISAM format ID; its
128 bytes at 0x18 are obfuscated with the same RC4 mask as Jet 4 (Jackcess
4.0.5: MSISAMFormat extends Jet4Format without its own header mask, and
PageChannel.readRootPage demasks page 0 for every format), holding code
page 1252 at 0x3c and sort order 0x409 (General) at 0x6e. Page 1 is an
empty data page owned by page 2.

Real Money files also encrypt their other pages (Jackcess hands MSISAM to
an external codec); this file leaves them plain, and its encoding key at
0x3e is 0.
"""
import struct
import sys

PAGE = 4096


def rc4(key, data):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray()
    for c in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out.append(c ^ s[(s[i] + s[j]) % 256])
    return bytes(out)


def main(out):
    page0 = bytearray(PAGE)
    page0[0:4] = b"\x00\x01\x00\x00"
    page0[4:20] = b"MSISAM Database\x00"
    struct.pack_into("<I", page0, 0x14, 1)
    header = bytearray(128)
    struct.pack_into("<H", header, 0x3C - 0x18, 1252)
    struct.pack_into("<H", header, 0x6E - 0x18, 0x409)
    page0[0x18:0x98] = rc4(bytes([0xC7, 0xDA, 0x39, 0x6B]), bytes(header))
    page1 = bytearray(PAGE)
    page1[0:2] = b"\x01\x01"
    struct.pack_into("<HI", page1, 2, PAGE - 96, 2)
    with open(out, "wb") as f:
        f.write(page0 + page1)


if __name__ == "__main__":
    main(sys.argv[1])
