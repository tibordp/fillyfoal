"""Builds tests/fixtures/synthetic/emf/records.emf.

    python3 tests/data/emf/gen.py

Written from [MS-EMF] and [MS-EMFPLUS] as remembered: an EMR_HEADER with
both header extensions and a description, an EMR_COMMENT holding EMF+
records (header, a brush object, end of file), mapping and object records,
a font, text (EMR_EXTTEXTOUTW), EMR_BITBLT and EMR_STRETCHBLT each with a
2x1 24-bit DIB, a rectangle and EMR_EOF.
"""

import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "..", "fixtures", "synthetic", "emf")


def rec(kind, body):
    body += b"\0" * (-len(body) % 4)
    return struct.pack("<II", kind, 8 + len(body)) + body


def utf16(s):
    return s.encode("utf-16-le")


def dib_2x1():
    header = struct.pack("<IiiHHIIiiII", 40, 2, 1, 1, 24, 0, 8, 2835, 2835, 0, 0)
    bits = bytes([0, 0, 255, 0, 255, 0, 0, 0])  # red, green, row padding
    return header, bits


def emfplus(kind, flags, data):
    return struct.pack("<HHII", kind, flags, 12 + len(data), len(data)) + data


def blt(kind, extra):
    """EMR_BITBLT (76) or EMR_STRETCHBLT (77) with a source DIB."""
    header, bits = dib_2x1()
    fixed = 100 + len(extra)  # up to cbBitsSrc, then cxSrc/cySrc
    body = struct.pack("<iiii", 0, 0, 1, 0)  # bounds
    body += struct.pack("<iiii", 0, 0, 2, 1)  # dest
    body += struct.pack("<I", 0x00CC0020)  # SRCCOPY
    body += struct.pack("<ii", 0, 0)  # source origin
    body += struct.pack("<6f", 1, 0, 0, 1, 0, 0)  # XformSrc
    body += struct.pack("<II", 0, 0)  # BkColorSrc, UsageSrc
    body += struct.pack("<IIII", fixed, len(header), fixed + len(header), len(bits))
    body += extra
    return rec(kind, body + header + bits)


def main():
    description = utf16("gen.py\0records\0\0")
    records = []
    plus = (
        emfplus(0x4001, 1, struct.pack("<IIII", 0xDBC01002, 1, 96, 96))
        + emfplus(0x4008, 0x0100, struct.pack("<III", 0xDBC01002, 0, 0xFF336699))
        + emfplus(0x4002, 0, b"")
    )
    records.append(rec(70, struct.pack("<I", 4 + len(plus)) + b"EMF+" + plus))
    records.append(rec(17, struct.pack("<I", 8)))  # MM_ANISOTROPIC
    records.append(rec(9, struct.pack("<ii", 100, 80)))
    records.append(rec(10, struct.pack("<ii", 0, 0)))
    face = utf16("Arial").ljust(64, b"\0")
    logfont = struct.pack("<iiiii8B", -16, 0, 0, 0, 400, 0, 0, 0, 0, 0, 0, 0, 0) + face
    records.append(rec(82, struct.pack("<I", 1) + logfont))
    records.append(rec(37, struct.pack("<I", 1)))
    records.append(rec(37, struct.pack("<I", 0x80000007)))  # BLACK_PEN
    records.append(rec(39, struct.pack("<IIBBBBI", 2, 0, 0xFF, 0x80, 0x00, 0, 0)))
    records.append(rec(24, struct.pack("<BBBB", 0x10, 0x20, 0x30, 0)))
    text = utf16("Hello")
    emrtext = struct.pack("<iiIIIiiiiI", 10, 20, 5, 76, 0, 0, 0, 0, 0, 88)
    body = struct.pack("<iiii", 10, 4, 60, 24) + struct.pack("<Iff", 1, 0, 0) + emrtext
    body += text + b"\0\0" + struct.pack("<5i", 8, 8, 8, 8, 8)
    records.append(rec(84, body))
    records.append(blt(76, b""))
    records.append(blt(77, struct.pack("<ii", 2, 1)))
    records.append(rec(43, struct.pack("<iiii", 10, 10, 90, 70)))
    eof = rec(14, struct.pack("<III", 0, 16, 20))

    header_size = 108 + len(description)
    body = b"".join(records) + eof
    total = header_size + len(body)
    count = len(records) + 2
    header = struct.pack("<II", 1, header_size)
    header += struct.pack("<iiii", 0, 0, 99, 79)  # bounds
    header += struct.pack("<iiii", 0, 0, 2646, 2117)  # frame, 0.01 mm
    header += b" EMF" + struct.pack("<IIIHH", 0x10000, total, count, 3, 0)
    header += struct.pack("<III", len(description) // 2, 108, 0)
    header += struct.pack("<iiii", 1920, 1080, 508, 286)
    header += struct.pack("<III", 0, 0, 0)  # pixel format, OpenGL
    header += struct.pack("<II", 508000, 286000)  # micrometers
    data = header + description + body
    assert len(data) == total
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "records.emf"), "wb") as f:
        f.write(data)


if __name__ == "__main__":
    main()
