"""Writes an ISO 9660 image's 2048-byte blocks as raw 2352-byte CD sectors.

    python3 raw-sectors.py IN.iso OUT.bin MODE

MODE 1: sync, header (BCD address with the 2-second pregap, mode 1), the
user data, EDC (ECMA-130 CRC-32), 8 zero bytes, ECC. MODE 2: Mode 2 Form 1,
with the subheader (data, form 1) twice before the user data. The ECC
(P and Q parity) is left as zeros: our dissector does not check it.
"""

import sys

SYNC = b"\x00" + b"\xff" * 10 + b"\x00"


def edc_table():
    table = []
    for i in range(256):
        r = i
        for _ in range(8):
            r = (r >> 1) ^ 0xD8018001 if r & 1 else r >> 1
        table.append(r)
    return table


TABLE = edc_table()


def edc(data):
    r = 0
    for b in data:
        r = TABLE[(r ^ b) & 0xFF] ^ (r >> 8)
    return r.to_bytes(4, "little")


def bcd(n):
    return (n // 10) << 4 | n % 10


def header(lba, mode):
    a = lba + 150
    return SYNC + bytes([bcd(a // 4500), bcd(a // 75 % 60), bcd(a % 75), mode])


def sector(lba, data, mode):
    if mode == 1:
        body = header(lba, 1) + data
        return body + edc(body) + bytes(8) + bytes(276)
    sub = bytes([0, 0, 0x08, 0]) * 2
    body = header(lba, 2) + sub + data
    return body + edc(body[16:]) + bytes(276)


def main():
    src, dst, mode = sys.argv[1], sys.argv[2], int(sys.argv[3])
    data = open(src, "rb").read()
    out = bytearray()
    for lba in range(len(data) // 2048):
        out += sector(lba, data[lba * 2048 : (lba + 1) * 2048], mode)
    open(dst, "wb").write(out)


main()
