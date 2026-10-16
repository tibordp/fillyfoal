"""Synthetic CDS archive of a version whose layout we do not know.

Takes the first 4 KiB of the real JDK 21 static archive prefix and sets its
version to 15 (a JDK between 17 and 21), so the dissector shows the generic
header and leaves the rest raw. Run from the repository root:

    uv run --with zstandard python tests/data/jvm-cds/make_synthetic.py
"""

import struct

import zstandard as zstd

src = "tests/fixtures/external/jvm-cds/jdk21-static-prefix.jsa.raw.zst"
dst = "tests/fixtures/synthetic/jvm-cds/version15-prefix.jsa"

data = bytearray(zstd.ZstdDecompressor().stream_reader(open(src, "rb")).read(4096))
struct.pack_into("<i", data, 8, 15)
open(dst, "wb").write(bytes(data))
