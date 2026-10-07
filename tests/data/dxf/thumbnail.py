"""Writes tests/fixtures/synthetic/dxf/thumbnail.dxf.

    python3 tests/data/dxf/thumbnail.py tests/fixtures/synthetic/dxf/thumbnail.dxf

ezdxf drops THUMBNAILIMAGE sections, so this one is hand-made: a minimal
R2000 DXF whose THUMBNAILIMAGE holds a 4x2 24-bit DIB (BITMAPINFOHEADER and
rows, no file header) as code 310 hex lines after its byte count (code 90),
the way AutoCAD stores the preview, as remembered from the DXF reference.
"""

import struct
import sys


def dib():
    header = struct.pack("<IiiHHIIiiII", 40, 4, 2, 1, 24, 0, 24, 2835, 2835, 0, 0)
    rows = bytes([0, 0, 255] * 4) + bytes([255, 255, 255, 0, 128, 0] * 2)
    return header + rows


def main(path):
    image = dib()
    pairs = [
        (999, "hand-made by tests/data/dxf/thumbnail.py"),
        (0, "SECTION"), (2, "HEADER"),
        (9, "$ACADVER"), (1, "AC1015"),
        (9, "$INSBASE"), (10, "0.0"), (20, "0.0"), (30, "0.0"),
        (0, "ENDSEC"),
        (0, "SECTION"), (2, "ENTITIES"),
        (0, "LINE"), (5, "20"), (8, "0"), (10, "0.0"), (20, "0.0"), (30, "0.0"),
        (11, "1.0"), (21, "2.0"), (31, "0.0"),
        (0, "ENDSEC"),
        (0, "SECTION"), (2, "THUMBNAILIMAGE"),
        (90, str(len(image))),
    ]
    hexed = image.hex().upper()
    for i in range(0, len(hexed), 64):
        pairs.append((310, hexed[i : i + 64]))
    pairs += [(0, "ENDSEC"), (0, "EOF")]
    with open(path, "w", newline="\r\n") as f:
        for code, value in pairs:
            f.write(f"{code:>3}\n{value}\n")


if __name__ == "__main__":
    main(sys.argv[1])
