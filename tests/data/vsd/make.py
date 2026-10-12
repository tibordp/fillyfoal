"""Writes tests/fixtures/synthetic/vsd/pointers.vsd: a hand-built Visio
2002+ (version 11) compound file. No Visio writer runs here (LibreOffice
only imports .vsd), so the layout follows what libvisio reads: the
VisioDocument stream starts with "Visio (TM) Drawing\\r\\n", a NUL, the
version byte at 0x1A and the trailer pointer at 0x24 (type, a skipped
dword, offset, length, format; format bit 1 = compressed). A pointer
stream holds (after a 4-byte prefix when compressed) the offset of its
list plus 4; the list is the order-list size, the pointer count, a
reserved dword, the pointers and the order list. Compressed streams use
VSDInternalStream's LZSS (4 KiB ring of zeros written from 4078, a flag
byte per eight items, least significant bit first, 1 = literal; a match is
the low position byte, then the high position nibble and length - 3).

The trailer points at a colour blob, a compressed pages stream (one page
pointer to a compressed chunk stream), an unused (type 0) pointer and an
OLE data blob. The payloads are placeholders, not real Visio chunks.

    python tests/data/vsd/make.py <out>
"""

import os
import struct
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "cfb"))
import cfbwriter  # noqa: E402


def lzss(data):
    """Greedy LZSS encoder for VSDInternalStream's decoder."""
    out = bytearray()
    pos = 0
    while pos < len(data):
        flag_at = len(out)
        out.append(0)
        flags = 0
        for bit in range(8):
            if pos >= len(data):
                break
            best_len, best_from = 0, 0
            lo = max(0, pos - 4000)
            for q in range(lo, pos):
                n = 0
                while n < 18 and pos + n < len(data) and data[q + n] == data[pos + n]:
                    n += 1
                if n > best_len:
                    best_len, best_from = n, q
            if best_len >= 3:
                p = (best_from + 4078) & 4095
                out += bytes([p & 0xFF, ((p >> 4) & 0xF0) | (best_len - 3)])
                pos += best_len
            else:
                flags |= 1 << bit
                out.append(data[pos])
                pos += 1
        out[flag_at] = flags
    return bytes(out)


def pointer(kind, offset, length, fmt):
    return struct.pack("<IIIIH", kind, 0, offset, length, fmt)


def pointer_stream(pointers, order, compressed):
    # The list follows the offset field, which counts from 4 bytes before
    # the list (and after the prefix): 8 either way.
    body = struct.pack("<I", 8)
    body += struct.pack("<IiI", len(order), len(pointers), 0)
    body += b"".join(pointers)
    body += b"".join(struct.pack("<I", i) for i in order)
    if compressed:
        body = struct.pack("<I", len(body) + 4) + body
        return lzss(body)
    return body


doc = bytearray(b"Visio (TM) Drawing\r\n\0")
doc += b"\0" * 5 + bytes([11]) + b"\0" * 9
assert len(doc) == 0x24
doc += b"\0" * 18  # trailer pointer, patched below


def add(data):
    at = len(doc)
    doc.extend(data)
    while len(doc) % 4:
        doc.append(0)
    return at, len(data)


colours = bytes(range(0, 96))
colours_at = add(colours)
page_chunks = b"fillyfoal page chunk " * 12
# Compressed streams are read from 4 bytes in, as for pointer streams.
page_packed = lzss(struct.pack("<I", len(page_chunks) + 4) + page_chunks)
page_at = add(page_packed)
pages = pointer_stream([pointer(0x15, page_at[0], page_at[1], 0xD2)], [], True)
pages_at = add(pages)
ole = b"fillyfoal OLE data placeholder\n"
ole_at = add(ole)
trailer = pointer_stream(
    [
        pointer(0x16, colours_at[0], colours_at[1], 0x40),
        pointer(0x27, pages_at[0], pages_at[1], 0x52),
        pointer(0, 0, 0, 0),
        pointer(0x1F, ole_at[0], ole_at[1], 0x40),
    ],
    [1, 0, 3],
    True,
)
trailer_at = add(trailer)
doc[0x24 : 0x24 + 18] = pointer(0x14, trailer_at[0], trailer_at[1], 0x52)

cfbwriter.write(sys.argv[1], {"VisioDocument": bytes(doc)})
