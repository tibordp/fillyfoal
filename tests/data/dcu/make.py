#!/usr/bin/env python3
"""Generates the synthetic Delphi compiled unit fixtures.

No Delphi compiler is available, so these files are written from our own
reading of the format (see crates/exec/src/formats/executable/dcu.rs): they share any
misunderstanding the dissector has and only lock its behaviour in.

- d7.dcu: a Delphi 7 style unit. 18-byte header, unit flags (0x96), a
  source and a resource file (p, r), three used units with imported types
  (f) and values (g), each closed by c; unit references (4), unit-level
  declarations (&, *, variables, a procedure with parameters and a local),
  a 0x9e record, a G and a class definition (F) with a field and a method;
  then made-up bytes standing for the undecoded rest, and the end tag a.
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
    # Declaration numbers so far: 1 the unit, 2-9 the records above (types:
    # 1 TWidget, 2 Integer). Packed values below are written as bytes: a
    # one-byte packed value n is n << 1.
    # Unit references (10-13), each with an empty list.
    body += b"4" + name("Demo") + b"\x80" + u32(0x0A0B0C0D) + b"\x02" + b"c"
    body += b"4" + name("Widgets") + b"\x00" + b"\x04" + b"c"
    body += b"4" + name("Helpers") + b"\x00" + b"\x0c" + b"c"
    body += b"4" + name("System") + b"\x00" + b"\x0e" + b"c"
    # Declarations: a symbol of local type 3 (14), the class name for local
    # type 4 (15), two variables (16, 17) and a procedure (18) with two
    # parameters and a local (19-21).
    body += b"&" + name(".TDemoForm") + b"\x80" + u32(0x11111111) + b"\x06" + b"\x00"
    body += b"*" + name("TDemoForm") + b"\x88" + u32(0x22222222) + b"\x08"
    body += b" " + name("DemoForm") + b"\xe6" + u32(0x33333333) + b"\x08" + b"\x76"
    body += b" " + name("Count") + b"\x66" + b"\x04" + b"\x00"
    body += b"(" + name("TDemoForm.Click") + b"\x80" + u32(0x44444444)
    body += b"\x00" + b"\x20" + b"\x08" + b"\x40"
    body += b"!" + name("Self") + b"\x16" + b"\x08" + b"\x06"
    body += b'"' + name("Value") + b"\x16" + b"\x04" + b"\x02"
    body += b" " + name("n") + b"\x66" + b"\x04" + b"\xf8"  # frame offset -4
    body += b"c"
    body += b"\x9e" + b"\xfe"
    # Type definitions: G referring to type 4, then the class (declaration
    # 15, parent type 1, symbol 14) with a field and a method (implemented
    # by declaration 18).
    body += b"G" + b"\x00\x08\x00" + b"\x08" + b"\x81\x10"
    body += b"F" + b"\x3c\x08" + b"\x1e" + b"\x02" + b"\x00" + b"\xa1\x0d" + b"\x1c"
    body += b"\x7a" + b"\xa9\xfe" + b"\xbc" + b"\x02" + b"\x00"
    body += b"," + name("Widget1") + b"\x14" + b"\x02" + b"\xe1\x0b"  # offset 760
    body += b"-" + name("Click") + b"\x14" + b"\xee" + b"\x24" + b"\x08"
    body += b"c"
    # Undecoded from here (a made-up range definition and filler).
    body += b"D" + b"\x00\x08\x00\x0a" + b"\x00" * 8
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
