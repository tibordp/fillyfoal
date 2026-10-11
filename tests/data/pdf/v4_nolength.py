"""Writes tests/fixtures/synthetic/pdf/v4-nolength-{aes,rc4}.pdf: PDFs
encrypted by qpdf (through pikepdf) with the standard security handler,
V 4 / R 4 and an empty user password, whose top-level /Length was then
blanked out with spaces (offsets unchanged). ISO 32000-1 Table 20 gives
/Length only for V 2 and 3; with crypt filters the key length comes from
/CF/<filter>/Length (kept here, 16 bytes), or is 128 bits.

    uv run --with pikepdf==10.16.0 python tests/data/pdf/v4_nolength.py <outdir>
"""

import os
import re
import sys

import pikepdf

out = sys.argv[1]
for name, aes in (("aes", True), ("rc4", False)):
    pdf = pikepdf.new()
    pdf.add_blank_page()
    pdf.docinfo["/Title"] = "Fillyfoal V4 without Length"
    pdf.docinfo["/Producer"] = "fillyfoal"
    path = os.path.join(out, f"v4-nolength-{name}.pdf")
    pdf.save(
        path,
        encryption=pikepdf.Encryption(owner="fillyfoal", user="", R=4, aes=aes, metadata=aes),
        object_stream_mode=pikepdf.ObjectStreamMode.disable,
    )
    data = open(path, "rb").read()
    # The Encrypt dictionary's own /Length (the crypt filter's is inside /CF
    # << ... >>, so it is preceded by more nesting).
    start = data.index(b"/Filter /Standard")
    start = data.rindex(b"<<", 0, start)
    end = data.index(b"endobj", start)
    body = data[start:end]
    cf = body.index(b"/CF")
    cf_end = body.index(b">> >>", cf) + 5
    outside = body[:cf] + b"\0" * (cf_end - cf) + body[cf_end:]
    m = re.search(rb"/Length \d+", outside)
    assert m, body
    body = body[: m.start()] + b" " * (m.end() - m.start()) + body[m.end():]
    open(path, "wb").write(data[:start] + body + data[end:])
