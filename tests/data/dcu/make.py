#!/usr/bin/env python3
"""Generates the synthetic Delphi compiled unit fixtures.

No Delphi compiler is available, so these files are written from our own
reading of the format (see src/formats/executable/dcu.rs): they share any
misunderstanding the dissector has and only lock its behaviour in.

- d7.dcu: a Delphi 7 style unit. 18-byte header, unit flags (0x96), a
  source and a resource file (p, r), three used units with imported types
  (f) and values (g), each closed by c, then a few made-up bytes standing
  for the undecoded declarations, and the end tag a.
- xe.dcu: a header with a later CompilerVersion byte (22, XE) whose record
  layout is not decoded: everything after the 12 common header bytes is
  filler, then the end tag.

Usage: python3 make.py  (writes into tests/fixtures/synthetic/dcu/)
"""

import os
import struct

OUT = os.path.join(os.path.dirname(__file__), "..", "..", "fixtures", "synthetic", "dcu")


def dos(y, mo, d, h, mi, s):
    return ((y - 1980) << 25) | (mo << 21) | (d << 16) | (h << 11) | (mi << 5) | (s // 2)


def name(s):
    b = s.encode("latin-1")
    return bytes([len(b)]) + b


def u32(v):
    return struct.pack("<I", v)


def finish(magic, time, body):
    size = 12 + len(body)
    return u32(magic) + u32(size) + u32(time) + body


def d7():
    t = dos(2003, 5, 17, 10, 30, 0)
    body = u32(0x11223344) + b"\x00\x02"  # unknown header fields
    body += b"\x96" + b"\x00" + b"\x10"  # unit flags: packed 0, packed 8
    body += b"p" + name("Demo.pas") + u32(dos(2003, 5, 17, 10, 29, 58)) + b"\x00"
    body += b"r" + name("Demo.res") + u32(dos(2003, 5, 17, 10, 29, 56)) + b"\x02"
    body += b"d" + name("Widgets") + u32(0x11223344) + u32(0)
    body += b"f" + name("TWidget") + u32(0xCAFEF00D)
    body += b"g" + name(".TWidget") + u32(0x0BADBEEF)
    body += b"g" + name("TWidget.Paint") + u32(0x12345678)
    body += b"c"
    body += b"d" + name("Helpers") + u32(0x55667788) + u32(0)
    body += b"c"
    body += b"d" + name("System") + u32(0x99AABBCC) + u32(0)
    body += b"f" + name("Integer") + u32(0x01020304)
    body += b"g" + name("Halt") + u32(0)
    body += b"c"
    # Undecoded declarations (made-up bytes after an unknown tag).
    body += b"4" + name("Demo") + b"\x00\x10\x02" + b"c" + b"*" + name("TDemo") + b"\x00" * 8
    body += b"a"
    return finish(0x0F0000DF, t, body)


def xe():
    t = dos(2011, 2, 3, 4, 5, 6)
    body = bytes(range(0x30, 0x70)) + b"a"
    return finish(0x16000123, t, body)


def main():
    os.makedirs(OUT, exist_ok=True)
    for fname, data in (("d7.dcu", d7()), ("xe.dcu", xe())):
        with open(os.path.join(OUT, fname), "wb") as f:
            f.write(data)


if __name__ == "__main__":
    main()
