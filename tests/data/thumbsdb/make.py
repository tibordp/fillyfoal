"""Writes tests/fixtures/synthetic/thumbsdb/xp.db: a Windows XP style
Thumbs.db with a Catalog and three JPEG thumbnails (Pillow), one with index
10 to show the reversed stream names.

    uv run --with Pillow==11.3.0 python tests/data/thumbsdb/make.py <out>
"""

import io
import os
import struct
import sys

from PIL import Image

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "cfb"))
import cfbwriter  # noqa: E402

FILES = [(1, "photo.jpg", (200, 40, 40)), (2, "diagram.png", (40, 160, 40)), (10, "scan.tif", (40, 40, 200))]
TIME = 127_000_000_000_000_000  # 2003-06-16

catalog = struct.pack("<HHIII", 16, 5, len(FILES), 96, 96)
streams = {}
for index, name, color in FILES:
    entry = struct.pack("<IQ", index, TIME + index * 10_000_000) + name.encode("utf-16-le") + b"\0\0"
    entry += b"\0\0"  # padding written by Windows XP
    catalog += struct.pack("<I", len(entry) + 4) + entry
    buf = io.BytesIO()
    Image.new("RGB", (24, 16), color).save(buf, "JPEG", quality=50)
    jpeg = buf.getvalue()
    streams[str(index)[::-1]] = struct.pack("<III", 12, 1, len(jpeg)) + jpeg
streams["Catalog"] = catalog
cfbwriter.write(sys.argv[1], streams)
