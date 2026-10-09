"""Binary inputs for filly.rc: icon (Pillow), cursor, bitmap, manifest and a
compiled message table. Usage: resources.py <output directory>."""

import struct
import sys
from pathlib import Path

from PIL import Image

out = Path(sys.argv[1])

# Icon: 16x16 and 32x32, stored as BMP (DIB) entries.
icon = Image.new("RGBA", (32, 32), (0x20, 0x60, 0xc0, 0xff))
for i in range(32):
    icon.putpixel((i, i), (0xff, 0xff, 0x00, 0xff))
icon.save(out / "filly.ico", sizes=[(16, 16), (32, 32)], bitmap_format="bmp")

# Bitmap: 8x4, 24-bit.
bmp = Image.new("RGB", (8, 4), (0x80, 0x10, 0x10))
bmp.save(out / "filly.bmp")

# Cursor: a CUR file (ICO with type 2 and a hotspot) holding one 16x16
# 1-bit DIB (XOR mask and AND mask).
w = h = 16
header = struct.pack("<IiiHHIIiiII", 40, w, h * 2, 1, 1, 0, 0, 0, 0, 2, 0)
palette = bytes([0, 0, 0, 0, 0xff, 0xff, 0xff, 0])
xor = bytes([0x80, 0x01, 0, 0] * h)
and_ = bytes([0x7f, 0xfe, 0, 0] * h)
dib = header + palette + xor + and_
cur = struct.pack("<HHH", 0, 2, 1) + struct.pack("<BBBBHHII", w, h, 2, 0, 3, 5, len(dib), 22) + dib
(out / "filly.cur").write_bytes(cur)

(out / "filly.manifest").write_text(
    """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="fillyfoal.filly" version="1.2.3.4"/>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security><requestedPrivileges>
      <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
    </requestedPrivileges></security>
  </trustInfo>
</assembly>
"""
)


# Message table (what mc.exe writes): MESSAGE_RESOURCE_DATA with two blocks,
# ANSI and UTF-16 entries, each padded to 4 bytes.
def entry(text, unicode):
    data = text.encode("utf-16-le" if unicode else "latin-1") + (b"\0\0" if unicode else b"\0")
    data += b"\0" * (-(len(data) + 4) % 4)
    return struct.pack("<HH", len(data) + 4, 1 if unicode else 0) + data


blocks = [
    (0x1, 0x2, [entry("First message\r\n", False), entry("Second message\r\n", False)]),
    (0x40000100, 0x40000100, [entry("Unicode message %1\r\n", True)]),
]
table = struct.pack("<I", len(blocks))
offset = 4 + 12 * len(blocks)
body = b""
for low, high, entries in blocks:
    table += struct.pack("<III", low, high, offset + len(body))
    body += b"".join(entries)
(out / "filly.msg").write_bytes(table + body)
