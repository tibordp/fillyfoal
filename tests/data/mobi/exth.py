"""Writes `exth.mobi` (synthetic): a minimal uncompressed Mobipocket book
whose EXTH block mixes text and numeric records, laid out as calibre's
MOBI writer does: 100 author, 501 CDE type ("EBOK", four ASCII bytes),
201 cover offset and 204 creator software (big-endian u32), 524 language.

Usage: python3 exth.py OUT
"""

import struct
import sys


def exth(records):
    body = b"".join(struct.pack(">II", k, 8 + len(v)) + v for k, v in records)
    block = b"EXTH" + struct.pack(">II", 12 + len(body), len(records)) + body
    return block + b"\0" * (-len(block) % 4)


def main(out):
    text = b"Hello."
    title = b"EXTH sample"
    meta = exth(
        [
            (100, b"Fillyfoal Author"),
            (501, b"EBOK"),
            (201, struct.pack(">I", 0xFFFFFFFF)),
            (204, struct.pack(">I", 201)),
            (524, b"en"),
        ]
    )
    mobi_len = 0xE8
    palmdoc = struct.pack(">HHIHHHH", 1, 0, len(text), 1, 4096, 0, 0)
    mobi = bytearray(mobi_len)
    mobi[0:4] = b"MOBI"
    struct.pack_into(">IIII", mobi, 4, mobi_len, 2, 65001, 0x12345678)
    struct.pack_into(">I", mobi, 0x14, 6)
    title_at = 16 + mobi_len + len(meta)
    struct.pack_into(">II", mobi, 0x44, title_at, len(title))
    struct.pack_into(">I", mobi, 0x70, 0x40)
    record0 = palmdoc + bytes(mobi) + meta + title + b"\0\0"
    records = [record0, text]
    first = 78 + 8 * len(records) + 2
    header = bytearray(78)
    header[0:14] = b"EXTH_sample\0\0\0"
    struct.pack_into(">HH", header, 32, 0, 0)
    struct.pack_into(">III", header, 36, 0xE0000000, 0xE0000000, 0)
    header[60:68] = b"BOOKMOBI"
    struct.pack_into(">H", header, 76, len(records))
    table, at = b"", first
    for i, r in enumerate(records):
        table += struct.pack(">II", at, 2 * i)
        at += len(r)
    with open(out, "wb") as f:
        f.write(bytes(header) + table + b"\0\0" + b"".join(records))


if __name__ == "__main__":
    main(sys.argv[1])
