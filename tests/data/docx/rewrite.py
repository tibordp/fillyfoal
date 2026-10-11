"""Rewrites a ZIP package entry by entry with Python's zipfile into a seekable
file, so no entry has a data descriptor (general purpose bit 3) and the
sizes are in the local headers. Names, order, times and compression method
are kept; the deflate streams are recompressed by zlib.

    python3 -I rewrite.py IN OUT
"""

import sys
import zipfile

src, dst = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w") as zout:
    for info in zin.infolist():
        out = zipfile.ZipInfo(info.filename, info.date_time)
        out.compress_type = info.compress_type
        out.external_attr = info.external_attr
        zout.writestr(out, zin.read(info))
