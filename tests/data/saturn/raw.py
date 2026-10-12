#!/usr/bin/env python3
"""Builds tests/fixtures/synthetic/saturn/raw-mode1.bin.gz: a raw (2352-byte
sector) Mode 1 dump of a small ISO 9660 image with a Saturn system area.

    sh tests/data/saturn/make-raw.sh      # writes /tmp/fixtures/games-retro-saturn/base.iso
    python3 tests/data/saturn/raw.py /tmp/fixtures/games-retro-saturn/base.iso OUT.bin
    gzip -9 -n OUT.bin

The ISO comes from xorriso; everything else is ours, so the result is
synthetic: the Saturn system ID (laid out as in Sega's "Disc Format
Standards Specification Sheet") replaces sectors 0-15, the IP is 0x1800
bytes, so the security code that follows the system ID crosses into the
next sectors, and each 2048-byte block is framed as a Mode 1 sector: the
12-byte sync, the BCD minute/second/frame address (from 00:02:00), mode 1,
the user data, then 288 bytes of EDC/ECC left zero.
"""
import sys


def system_id():
    def pad(s, n):
        b = s.encode("ascii")
        return b + b" " * (n - len(b))

    out = pad("SEGA SEGASATURN", 16) + pad("SEGA TP T-999", 16)
    out += pad("T-99999G", 10) + pad("V1.000", 6) + b"20261012" + pad("CD-1/1", 8)
    out += pad("JTUE", 10) + b" " * 6 + pad("J", 16)
    out += pad("FILLYFOAL RAW SECTOR TEST", 112) + b"\0" * 16
    out += (0x1800).to_bytes(4, "big") + b"\0" * 4 + (0x06002000).to_bytes(4, "big")
    out += (0x06001000).to_bytes(4, "big") + (0x06004000).to_bytes(4, "big")
    out += (0).to_bytes(4, "big") + b"\0" * 8
    assert len(out) == 0x100
    # The security code and area code: a recognisable pattern across the
    # sector boundary at 0x800.
    code = b"".join(b"SECURITY CODE %04X " % i for i in range(0x1700 // 19 + 1))[:0x1700]
    return out + code


def bcd(n):
    return ((n // 10) << 4) | (n % 10)


def main():
    iso = bytearray(open(sys.argv[1], "rb").read())
    area = system_id()
    iso[: len(area)] = area
    out = bytearray()
    for i in range(len(iso) // 2048):
        lba = i + 150
        m, s, f = lba // (75 * 60), (lba // 75) % 60, lba % 75
        out += b"\0" + b"\xff" * 10 + b"\0" + bytes([bcd(m), bcd(s), bcd(f), 1])
        out += iso[i * 2048 : (i + 1) * 2048]
        out += b"\0" * 288
    open(sys.argv[2], "wb").write(out)


if __name__ == "__main__":
    main()
