"""Writes pictures.fodt, the source of tests/fixtures/external/doc/pictures.doc:
a paragraph with a small PNG inline (as a character) and a second PNG
anchored to the paragraph, so LibreOffice's Word 97 export stores one
picture in the Data stream (a run with sprmCPicLocation) and one in the
drawing group (DggInfo).

    python3 tests/data/doc/make_pictures.py pictures.fodt
    lo-convert.sh doc pictures.fodt <outdir>
"""

import base64
import struct
import sys
import zlib


def png(width, height, rgb):
    def chunk(kind, data):
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    rows = b"".join(b"\0" + bytes(rgb) * width for _ in range(height))
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows, 9))
            + chunk(b"IEND", b""))


def frame(name, anchor, rgb):
    data = base64.b64encode(png(8, 8, rgb)).decode()
    return (f'<draw:frame draw:name="{name}" text:anchor-type="{anchor}" svg:width="1cm" '
            f'svg:height="1cm"><draw:image><office:binary-data>{data}</office:binary-data>'
            f'</draw:image></draw:frame>')


doc = f"""<?xml version="1.0" encoding="UTF-8"?>
<office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0" xmlns:xlink="http://www.w3.org/1999/xlink" office:version="1.3" office:mimetype="application/vnd.oasis.opendocument.text">
 <office:meta>
  <dc:title>Pictures</dc:title>
  <meta:initial-creator>fillyfoal</meta:initial-creator>
  <dc:creator>fillyfoal</dc:creator>
  <meta:creation-date>2026-01-02T03:04:05</meta:creation-date>
  <dc:date>2026-01-02T03:04:05</dc:date>
 </office:meta>
 <office:body>
  <office:text>
   <text:p>Inline {frame("Inline", "as-char", (200, 30, 30))} picture.</text:p>
   <text:p>{frame("Anchored", "paragraph", (30, 30, 200))}Anchored picture.</text:p>
  </office:text>
 </office:body>
</office:document>
"""
with open(sys.argv[1], "w") as f:
    f.write(doc)
