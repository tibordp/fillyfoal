"""Writes tests/fixtures/synthetic/xls/encrypted-xor.xls: a BIFF8 workbook
with XOR obfuscation (MS-OFFCRYPTO 2.3.7, method 1), password `fillyfoal`.

No tool at hand writes XOR obfuscation (LibreOffice and msoffcrypto-tool
only read it; Excel writes it when asked for the weak "XOR" scheme), so
this script obfuscates a workbook stream from xlwt itself: it inserts
FILEPASS (type 0, key, verifier) after the first BOF, moves the absolute
stream offsets the insertion shifts (BoundSheet8 lbPlyPos, INDEX, EXTSST)
and XORs every record body after FILEPASS except those MS-XLS 2.2.10
leaves in the clear (and lbPlyPos), each byte at stream position p
rotated left by 5 and XORed with XorArray[(p + record size) % 16].

The result was checked with msoffcrypto-tool 6.0.0, which decrypts it
with the password back to the plaintext stream (FILEPASS zeroed):

    uv run --with xlwt==1.3.0 python tests/data/xls/make_xor.py [out.xls]
    uv run --with msoffcrypto-tool==6.0.0 msoffcrypto-tool -p fillyfoal out.xls plain.xls
"""

import os
import struct
import sys
from pathlib import Path

import xlwt

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "cfb"))
import cfbwriter  # noqa: E402

out = (
    Path(sys.argv[1])
    if len(sys.argv) > 1
    else Path(__file__).parents[2] / "fixtures/synthetic/xls/encrypted-xor.xls"
)
PASSWORD = b"fillyfoal"

# MS-OFFCRYPTO 2.3.7.1-2.3.7.2.
INITIAL = [0xE1F0, 0x1D0F, 0xCC9C, 0x84C0, 0x110C, 0x0E10, 0xF1CE, 0x313E,
           0x1872, 0xE139, 0xD40F, 0x84F9, 0x280C, 0xA96A, 0x4EC3]
MATRIX = [
    0xAEFC, 0x4DD9, 0x9BB2, 0x2745, 0x4E8A, 0x9D14, 0x2A09, 0x7B61, 0xF6C2, 0xFDA5, 0xEB6B,
    0xC6F7, 0x9DCF, 0x2BBF, 0x4563, 0x8AC6, 0x05AD, 0x0B5A, 0x16B4, 0x2D68, 0x5AD0, 0x0375,
    0x06EA, 0x0DD4, 0x1BA8, 0x3750, 0x6EA0, 0xDD40, 0xD849, 0xA0B3, 0x5147, 0xA28E, 0x553D,
    0xAA7A, 0x44D5, 0x6F45, 0xDE8A, 0xAD35, 0x4A4B, 0x9496, 0x390D, 0x721A, 0xEB23, 0xC667,
    0x9CEF, 0x29FF, 0x53FE, 0xA7FC, 0x5FD9, 0x47D3, 0x8FA6, 0x0F6D, 0x1EDA, 0x3DB4, 0x7B68,
    0xF6D0, 0xB861, 0x60E3, 0xC1C6, 0x93AD, 0x377B, 0x6EF6, 0xDDEC, 0x45A0, 0x8B40, 0x06A1,
    0x0D42, 0x1A84, 0x3508, 0x6A10, 0xAA51, 0x4483, 0x8906, 0x022D, 0x045A, 0x08B4, 0x1168,
    0x76B4, 0xED68, 0xCAF1, 0x85C3, 0x1BA7, 0x374E, 0x6E9C, 0x3730, 0x6E60, 0xDCC0, 0xA9A1,
    0x4363, 0x86C6, 0x1DAD, 0x3331, 0x6662, 0xCCC4, 0x89A9, 0x0373, 0x06E6, 0x0DCC, 0x1021,
    0x2042, 0x4084, 0x8108, 0x1231, 0x2462, 0x48C4,
]
PAD = [0xBB, 0xFF, 0xFF, 0xBA, 0xFF, 0xFF, 0xB9, 0x80, 0x00, 0xBE, 0x0F, 0x00, 0xBF, 0x0F, 0x00]


def verifier(pw):
    v = 0
    for b in reversed(bytes([len(pw)]) + pw):
        v = (((v >> 14) & 1) | ((v << 1) & 0x7FFF)) ^ b
    return v ^ 0xCE4B


def xor_key(pw):
    key = INITIAL[len(pw) - 1]
    element = 0x68
    for c in reversed(pw):
        for _ in range(7):
            if c & 0x40:
                key ^= MATRIX[element]
            c = (c << 1) & 0xFF
            element -= 1
    return key


def ror(b, n):
    return ((b >> n) | (b << (8 - n))) & 0xFF


def rol(b, n):
    return ror(b, 8 - n)


def xor_array(pw):
    key = xor_key(pw)
    src = list(pw) + PAD[: 16 - len(pw)]
    return [ror(s ^ (key & 0xFF if i % 2 == 0 else key >> 8), 1) for i, s in enumerate(src)]


CLEAR = {0x0809, 0x002F, 0x0194, 0x0195, 0x00E1, 0x0196, 0x0138, 0x000A}


def records(stream):
    pos = 0
    while pos + 4 <= len(stream):
        kind, size = struct.unpack_from("<HH", stream, pos)
        yield kind, bytearray(stream[pos + 4 : pos + 4 + size])
        pos += 4 + size


def workbook():
    wb = xlwt.Workbook(encoding="utf-8")
    wb.owner = "fillyfoal"
    s = wb.add_sheet("Secret")
    o = wb.add_sheet("Notes")
    s.write(0, 0, "Item")
    s.write(0, 1, "Count")
    for i, (name, n) in enumerate([("apple", 3), ("pear", 120), ("plum", -7)], start=1):
        s.write(i, 0, name)
        s.write(i, 1, n)
    s.write(4, 0, "Total")
    s.write(4, 1, xlwt.Formula("SUM(B2:B4)"))
    o.write(0, 0, "obfuscated, not encrypted")
    return wb.get_biff_data()


plain = workbook()
recs = list(records(plain))
assert recs[0][0] == 0x0809
pw = PASSWORD
filepass = struct.pack("<HHH", 0, xor_key(pw), verifier(pw))
shift = 4 + len(filepass)

# Shift the absolute stream offsets that point past the insertion.
for kind, body in recs:
    if kind == 0x0085:  # BoundSheet8.lbPlyPos
        struct.pack_into("<I", body, 0, struct.unpack_from("<I", body, 0)[0] + shift)
    elif kind == 0x020B:  # INDEX: reserved, rwMic, rwMac, ibXF, rgibRw[]
        n = (len(body) - 16) // 4
        for at in [12] + [16 + 4 * i for i in range(n)]:
            v = struct.unpack_from("<I", body, at)[0]
            if v:
                struct.pack_into("<I", body, at, v + shift)
    elif kind == 0x00FF:  # EXTSST: dsst, then (ib, cbOffset, reserved)
        for at in range(2, len(body) - 7, 8):
            struct.pack_into("<I", body, at, struct.unpack_from("<I", body, at)[0] + shift)

recs.insert(1, (0x002F, bytearray(filepass)))

array = xor_array(pw)
outbuf = bytearray()
encrypting = False
for kind, body in recs:
    outbuf += struct.pack("<HH", kind, len(body))
    start = len(outbuf)
    for i, b in enumerate(body):
        p = start + i
        if encrypting and kind not in CLEAR and not (kind == 0x0085 and i < 4):
            b = rol(b, 5) ^ array[(p + len(body)) % 16]
        outbuf.append(b)
    if kind == 0x002F:
        encrypting = True

cfbwriter.write(out, {"Workbook": bytes(outbuf)})
print(out, len(outbuf))
