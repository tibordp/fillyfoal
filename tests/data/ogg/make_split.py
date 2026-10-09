"""An Ogg Vorbis file re-paginated so that packets span several pages.

    python3 tests/data/ogg/make_split.py

Reads tests/fixtures/external/ogg/vorbis.ogg (FFmpeg), reassembles its
packets and writes them again in pages of at most four lacing values
(1020 bytes), so the comment and setup headers and the audio packets
continue across pages, to tests/fixtures/synthetic/ogg/split-packets.ogg.
Granule positions are kept on the page where each packet ends; pages
where none ends get -1. CRCs are recomputed.
"""

import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.abspath(os.path.join(HERE, "..", "..", "fixtures"))


def crc32(data):
    crc = 0
    for b in data:
        crc ^= b << 24
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04C11DB7) if crc & 0x80000000 else crc << 1
            crc &= 0xFFFFFFFF
    return crc


with open(os.path.join(FIX, "external", "ogg", "vorbis.ogg"), "rb") as f:
    data = f.read()

# Packets with the granule of the page they end on (or None).
packets = []
serial = None
pos = 0
pending = b""
while pos + 27 <= len(data):
    assert data[pos : pos + 4] == b"OggS"
    granule, serial, _seq = struct.unpack_from("<qII", data, pos + 6)
    n = data[pos + 26]
    lacing = data[pos + 27 : pos + 27 + n]
    body = pos + 27 + n
    ends = []
    for l in lacing:
        pending += data[body : body + l]
        body += l
        if l < 255:
            ends.append(pending)
            pending = b""
    for i, p in enumerate(ends):
        packets.append((p, granule if i == len(ends) - 1 else None))
    pos = body

MAX = 4
out = b""
seq = 0


def page(flags, granule, lacing, body):
    global out, seq
    header = struct.pack("<4sBBqIIIB", b"OggS", 0, flags, granule, serial, seq, 0, len(lacing))
    raw = header + bytes(lacing) + body
    raw = raw[:22] + struct.pack("<I", crc32(raw)) + raw[26:]
    out += raw
    seq += 1


for index, (packet, granule) in enumerate(packets):
    lacing = [255] * (len(packet) // 255) + [len(packet) % 255]
    chunks = [lacing[i : i + MAX] for i in range(0, len(lacing), MAX)]
    offset = 0
    for c, chunk in enumerate(chunks):
        size = sum(chunk)
        flags = 0
        if index == 0 and c == 0:
            flags |= 2
        if c > 0:
            flags |= 1
        last = c == len(chunks) - 1
        if index == len(packets) - 1 and last:
            flags |= 4
        g = (granule if granule is not None else 0) if last else -1
        if index < 3 and last:
            g = 0
        page(flags, g, chunk, packet[offset : offset + size])
        offset += size

os.makedirs(os.path.join(FIX, "synthetic", "ogg"), exist_ok=True)
with open(os.path.join(FIX, "synthetic", "ogg", "split-packets.ogg"), "wb") as f:
    f.write(out)
