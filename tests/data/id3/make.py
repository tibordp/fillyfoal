"""Hand-built ID3v2 tags exercising what taggers rarely write.

    python3 tests/data/id3/make.py

Writes to tests/fixtures/synthetic/id3/:

- v24-flags.id3: ID3v2.4 with an extended header (CRC and restrictions),
  a footer, and frames using every frame flag: per-frame
  unsynchronisation with a data length indicator, zlib compression,
  grouping (with its GRID registration), encryption (with its ENCR
  registration); UTF-16 with either BOM, several values per frame.
- v23-compressed.id3: ID3v2.3, unsynchronised as a whole, with an
  extended header (CRC), a compressed frame and a grouped frame.
- v24-plain-sizes.id3: ID3v2.4 whose frame sizes are plain integers (as
  old iTunes wrote them), with a frame of 256 bytes so that reading them
  as syncsafe goes wrong.
"""

import os
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.abspath(os.path.join(HERE, "..", "..", "fixtures", "synthetic", "id3"))


def syncsafe(n, width=4):
    return bytes((n >> (7 * i)) & 0x7F for i in reversed(range(width)))


def unsync(data):
    out = bytearray()
    for i, b in enumerate(data):
        out.append(b)
        nxt = data[i + 1] if i + 1 < len(data) else None
        if b == 0xFF and (nxt is None or nxt & 0xE0 == 0xE0 or nxt == 0):
            out.append(0)
    return bytes(out)


def frame24(fid, data, flags=0, plain=False):
    size = struct.pack(">I", len(data)) if plain else syncsafe(len(data))
    return fid + size + struct.pack(">H", flags) + data


def frame23(fid, data, flags=0):
    return fid + struct.pack(">I", len(data)) + struct.pack(">H", flags) + data


def write(name, data):
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(data)


# --- ID3v2.4 with every flag ---------------------------------------------------
frames = b""
frames += frame24(b"TIT2", b"\x03Flags")
raw = b"\x00Ar\xff\xe0tist"
frames += frame24(b"TPE1", syncsafe(len(raw)) + unsync(raw), flags=0x0003)
raw = b"\x03desc\x00" + b"value " * 8
frames += frame24(b"TXXX", syncsafe(len(raw)) + zlib.compress(raw, 9), flags=0x0009)
frames += frame24(b"GRID", b"http://example.com/group\x00\x81group data")
frames += frame24(b"TALB", b"\x81\x03Grouped album", flags=0x0040)
frames += frame24(b"ENCR", b"http://example.com/enc\x00\x80key")
frames += frame24(b"TCOM", b"\x80\x13\x37\xca\xfe", flags=0x0004)
frames += frame24(
    b"COMM",
    b"\x01eng" + b"\xfe\xff" + "desc".encode("utf-16-be") + b"\x00\x00"
    + b"\xff\xfe" + "Kommentar äöü".encode("utf-16-le") + b"\x00\x00",
)
frames += frame24(b"TCON", b"\x0317\x00RX\x00Synthwave")
frames += frame24(
    b"TXXX",
    b"\x01" + b"\xff\xfe" + "multi".encode("utf-16-le") + b"\x00\x00"
    + b"\xff\xfe" + "one".encode("utf-16-le") + b"\x00\x00"
    + b"\xfe\xff" + "two".encode("utf-16-be"),
)
frames += b"\x00" * 20
crc = zlib.crc32(frames) & 0xFFFFFFFF
ext = bytes([1, 0x30]) + bytes([5]) + syncsafe(crc, 5) + bytes([1, 0b01_1_01_1_01])
ext = syncsafe(len(ext) + 4) + ext
body = ext + frames
write(
    "v24-flags.id3",
    b"ID3\x04\x00\x50" + syncsafe(len(body)) + body + b"3DI\x04\x00\x50" + syncsafe(len(body)),
)

# --- ID3v2.3, unsynchronised, compressed and grouped frames ------------------
frames = b""
frames += frame23(b"TIT2", b"\x00Compressed \xff\xfb")
raw = b"\x00desc\x00" + b"compressed text, " * 6
frames += frame23(b"TXXX", struct.pack(">I", len(raw)) + zlib.compress(raw, 9), flags=0x0080)
frames += frame23(b"GRID", b"http://example.com/group\x00\x82")
frames += frame23(b"TPE1", b"\x82\x00Grouped artist", flags=0x0020)
frames += b"\x00" * 10
crc = zlib.crc32(frames) & 0xFFFFFFFF
ext = struct.pack(">IHII", 10, 0x8000, 10, crc)
body = unsync(ext + frames)
write("v23-compressed.id3", b"ID3\x03\x00\xc0" + syncsafe(len(body)) + body)

# --- ID3v2.4 with plain-integer frame sizes -----------------------------------
frames = b""
frames += frame24(b"TIT2", b"\x03Plain sizes", plain=True)
frames += frame24(b"TXXX", b"\x03long\x00" + b"x" * 250, plain=True)
frames += frame24(b"TPE1", b"\x03iTunes", plain=True)
frames += b"\x00" * 16
write("v24-plain-sizes.id3", b"ID3\x04\x00\x00" + syncsafe(len(frames)) + frames)
