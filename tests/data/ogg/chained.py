"""A chained Ogg file: three Ogg files concatenated, as stream recorders
write them.

    python3 tests/data/ogg/chained.py

Writes tests/fixtures/synthetic/ogg/chained.ogg from the external
fixtures ogg/vorbis.ogg, opus/tone.opus and ogg-flac/tone.oga (FFmpeg
output). FFmpeg's bit-exact mode gives every stream serial number 0, and
the links of a chain need distinct ones, so each file's pages get a new
serial number (and CRC) before they are concatenated.
"""

import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.abspath(os.path.join(HERE, "..", "..", "fixtures"))


def crc_table():
    table = []
    for i in range(256):
        r = i << 24
        for _ in range(8):
            r = ((r << 1) ^ 0x04C11DB7) if r & 0x80000000 else (r << 1)
        table.append(r & 0xFFFFFFFF)
    return table


TABLE = crc_table()


def ogg_crc(data):
    crc = 0
    for b in data:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ TABLE[(crc >> 24) ^ b]
    return crc


def reserial(data, serial):
    out = bytearray()
    pos = 0
    while pos < len(data):
        assert data[pos : pos + 4] == b"OggS"
        segments = data[pos + 26]
        body = sum(data[pos + 27 : pos + 27 + segments])
        page = bytearray(data[pos : pos + 27 + segments + body])
        page[14:18] = struct.pack("<I", serial)
        page[22:26] = b"\0\0\0\0"
        page[22:26] = struct.pack("<I", ogg_crc(page))
        out += page
        pos += len(page)
    return bytes(out)


def read(*path):
    with open(os.path.join(FIXTURES, *path), "rb") as f:
        return f.read()


links = [
    (("external", "ogg", "vorbis.ogg"), 0x1001),
    (("external", "opus", "tone.opus"), 0x1002),
    (("external", "ogg-flac", "tone.oga"), 0x1003),
]
out = os.path.join(FIXTURES, "synthetic", "ogg", "chained.ogg")
with open(out, "wb") as f:
    for path, serial in links:
        f.write(reserial(read(*path), serial))
