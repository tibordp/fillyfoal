"""Writes long.fodt: a plain Writer document whose Word export is larger
than the 66 KiB probe window, so LibreOffice's directory (which it writes
in the last sectors of the file) lies outside the head window.

    python3 make_long.py long.fodt
    sh ../cfb/lo-convert.sh doc long.fodt <outdir>
"""

import sys

HEAD = """<?xml version="1.0" encoding="UTF-8"?>
<office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0" xmlns:dc="http://purl.org/dc/elements/1.1/" office:version="1.3" office:mimetype="application/vnd.oasis.opendocument.text">
 <office:meta>
  <dc:title>Fillyfoal long document</dc:title>
  <meta:initial-creator>fillyfoal</meta:initial-creator>
  <dc:creator>fillyfoal</dc:creator>
  <meta:creation-date>2026-01-02T03:04:05</meta:creation-date>
  <dc:date>2026-01-02T03:04:05</dc:date>
 </office:meta>
 <office:body>
  <office:text>
"""
TAIL = """  </office:text>
 </office:body>
</office:document>
"""
LINE = "Paragraph {n:04}: the quick brown fox jumps over the lazy dog, again and again."

with open(sys.argv[1], "w", encoding="utf-8") as f:
    f.write(HEAD)
    for n in range(400):
        f.write(f"   <text:p>{LINE.format(n=n)}</text:p>\n")
    f.write(TAIL)
