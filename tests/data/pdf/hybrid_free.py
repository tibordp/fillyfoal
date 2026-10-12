"""Writes tests/fixtures/synthetic/pdf/hybrid-free.pdf: a hybrid-reference
file whose classic table marks object 3 free (65535 f) while the stream
named by the trailer's /XRefStm places it in an object stream. The stream's
entry must win within the section, so the page resolves.

    python3 tests/data/pdf/hybrid_free.py tests/fixtures/synthetic/pdf/hybrid-free.pdf
"""

import struct
import sys

out = bytearray(b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n")
offsets = {}


def obj(num, body):
    offsets[num] = len(out)
    out.extend(b"%d 0 obj\n" % num + body + b"\nendobj\n")


obj(1, b"<< /Type /Catalog /Pages 2 0 R >>")
obj(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
page = b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>"
header = b"3 0 "
data = header + page
obj(4, b"<< /Type /ObjStm /N 1 /First %d /Length %d >>\nstream\n" % (len(header), len(data))
    + data + b"\nendstream")
# The hybrid stream: object 3 is entry 0 of object stream 4.
row = bytes([2]) + struct.pack(">I", 4) + struct.pack(">H", 0)
xref_stream = len(out)
obj(5, b"<< /Type /XRef /Size 6 /W [1 4 2] /Index [3 1] /Length %d >>\nstream\n" % len(row)
    + row + b"\nendstream")
table = len(out)
out.extend(b"xref\n0 6\n0000000000 65535 f \n")
for num in (1, 2):
    out.extend(b"%010d 00000 n \n" % offsets[num])
out.extend(b"0000000000 65535 f \n")
for num in (4, 5):
    out.extend(b"%010d 00000 n \n" % offsets[num])
out.extend(b"trailer\n<< /Size 6 /Root 1 0 R /XRefStm %d >>\nstartxref\n%d\n%%%%EOF\n"
           % (xref_stream, table))
with open(sys.argv[1], "wb") as f:
    f.write(out)
