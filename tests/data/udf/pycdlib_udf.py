"""Writes an ISO 9660 + UDF bridge image with pycdlib (udf="2.60", the only value
pycdlib accepts; the descriptors it writes say UDF 1.02 and NSR02).

uv run --with pycdlib==1.21.0 python tests/data/udf/pycdlib_udf.py OUT.iso
"""

import io
import sys

import pycdlib

iso = pycdlib.PyCdlib()
iso.new(interchange_level=3, vol_ident="FILLY", udf="2.60")
iso.add_directory("/DOCS", udf_path="/docs")
files = [
    ("/HELLO.TXT;1", "/hello.txt", b"hello pycdlib UDF\n"),
    ("/DOCS/NOTE.TXT;1", "/docs/note.txt", b"nested file\n"),
    ("/LONG.TXT;1", "/long.txt", b"".join(b"line %03d of a longer text file\n" % i for i in range(120))),
]
for iso_path, udf_path, data in files:
    iso.add_fp(io.BytesIO(data), len(data), iso_path, udf_path=udf_path)
iso.add_symlink(udf_symlink_path="/link", udf_target="docs/note.txt")
iso.write(sys.argv[1])
iso.close()
