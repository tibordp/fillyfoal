"""Synthetic UBJSON fixture covering what py-ubjson never writes.

    python3 tests/data/ubjson/synthetic.py

Written from the UBJSON Draft 12 specification: strongly typed optimized
containers (`$` with `i`, `d`, `S`, `Z`, `T` and nested `[` elements, and a
typed object), no-op markers between values, `l` and `d` numbers and
counted containers holding end-marked ones.
"""

import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "..", "fixtures", "synthetic", "ubjson", "typed.ubj")


def length(n):
    return b"U" + bytes([n]) if n < 256 else b"l" + struct.pack(">i", n)


def key(k):
    b = k.encode()
    return length(len(b)) + b


def s(v):
    b = v.encode()
    return length(len(b)) + b  # without the 'S' marker inside typed containers


body = bytearray()
body += key("int8s") + b"[$i#U\x04" + bytes([1, 0xFF, 0x7F, 0x80])
body += key("floats") + b"[$d#U\x02" + struct.pack(">f", 0.5) + struct.pack(">f", -2.25)
body += key("strings") + b"[$S#U\x02" + s("alpha") + s("beta")
body += key("nulls") + b"[$Z#U\x05"
body += key("trues") + b"[$T#U\x03"
body += key("matrix") + b"[$[#U\x02" + b"$i#U\x02\x01\x02" + b"i\x03i\x04]"  # elements without their "[" marker
body += key("typed object") + b"{$l#U\x02" + key("a") + struct.pack(">i", 100000) + key("b") + struct.pack(">i", -1)
body += key("noops") + b"[NiNNi\x02N]"
body += key("int32") + b"l" + struct.pack(">i", -123456789)
body += key("float32") + b"d" + struct.pack(">f", 3.5)

doc = b"{#U\x0a" + bytes(body)
with open(OUT, "wb") as f:
    f.write(doc)
