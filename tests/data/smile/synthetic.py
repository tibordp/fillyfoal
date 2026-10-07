"""Synthetic Smile fixture covering tokens smile-js never writes.

    python3 tests/data/smile/synthetic.py

Written from the Smile format specification (no encoder involved), so it
lives in tests/fixtures/synthetic/smile/: float32, BigDecimal, raw binary
(header flag 4), small (33-64 byte) ASCII and Unicode strings, short
Unicode keys, long (0x34) keys, long (10-bit) shared name and value
back-references, an end-of-content marker and a second document whose
header resets the shared tables.
"""

import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "..", "fixtures", "synthetic", "smile", "tokens.sml")


def vint(v):
    """Smile VInt: 7-bit groups, the last byte marked (0x80) with 6 bits."""
    last = 0x80 | (v & 0x3F)
    v >>= 6
    out = [last]
    while v:
        out.append(v & 0x7F)
        v >>= 7
    return bytes(reversed(out))


def zigzag(v):
    return (v << 1) ^ (v >> 63)


def seven_bit(data):
    out = bytearray()
    for i in range(0, len(data) - len(data) % 7, 7):
        acc = int.from_bytes(data[i : i + 7], "big")
        out += bytes((acc >> (7 * k)) & 0x7F for k in reversed(range(8)))
    rem = data[len(data) - len(data) % 7 :]
    if rem:
        n = len(rem)
        acc = int.from_bytes(rem, "big")
        # n bytes of 7 bits, then the last n bits.
        head = acc >> n
        out += bytes((head >> (7 * k)) & 0x7F for k in reversed(range(n)))
        out.append(acc & ((1 << n) - 1))
    return bytes(out)


def key(name):
    b = name.encode()
    if name.isascii() and 1 <= len(b) <= 64:
        return bytes([0x80 | (len(b) - 1)]) + b
    if not name.isascii() and 2 <= len(b) <= 57:
        return bytes([0xC0 | (len(b) - 2)]) + b
    return b"\x34" + b + b"\xfc"


def text(s):
    b = s.encode()
    if s.isascii():
        if len(b) <= 32:
            return bytes([0x40 | (len(b) - 1)]) + b
        if len(b) <= 64:
            return bytes([0x60 | (len(b) - 33)]) + b
        return b"\xe0" + b + b"\xfc"
    if len(b) <= 33:
        return bytes([0x80 | (len(b) - 2)]) + b
    if len(b) <= 65:
        return bytes([0xA0 | (len(b) - 34)]) + b
    return b"\xe4" + b + b"\xfc"


doc = bytearray(b":)\n\x07")  # version 0; shared names, shared values, raw binary
doc += b"\xfa"
bits = struct.unpack(">I", struct.pack(">f", 1.5))[0]
doc += key("f32") + b"\x28" + bytes([(bits >> 28) & 0x0F, (bits >> 21) & 0x7F, (bits >> 14) & 0x7F, (bits >> 7) & 0x7F, bits & 0x7F])
# BigDecimal 1234.5678: scale 4, unscaled 12345678.
unscaled = (12345678).to_bytes(4, "big", signed=True)
doc += key("decimal") + b"\x2a" + vint(zigzag(4)) + vint(len(unscaled)) + seven_bit(unscaled)
doc += key("raw") + b"\xfd" + vint(5) + b"\x00\xfe\xff\xfc\x80"
doc += key("small ascii") + text("x" * 40)
doc += key("small unicode") + text("é" * 20)
doc += key("über") + text("short unicode key")
doc += key("k" * 70) + b"\x21"  # long ASCII name (0x34), not shared (> 64 bytes)
doc += key("negative big") + b"\x26" + vint(9) + seven_bit((-(2**70)).to_bytes(9, "big", signed=True))
# Fill the tables past the short-reference ranges (64 names, 31 values).
doc += key("many") + b"\xfa"
for i in range(70):
    doc += key(f"n{i}") + text(f"v{i}")
doc += b"\xfb"
# Long references: name #65 ("n63" is the 66th name: 10 above + many + 64),
# value #40.
names_before = ["f32", "decimal", "raw", "small ascii", "small unicode", "über", "negative big", "many"]
values_before = ["x" * 40, "é" * 20, "short unicode key"]
target_name = len(names_before) + 63  # n63
target_value = len(values_before) + 40  # v40
doc += bytes([0x30 | (target_name >> 8), target_name & 0xFF])
doc += bytes([0xEC | (target_value >> 8), target_value & 0xFF])
doc += bytes([0x40 | 1])  # short name reference #1: "decimal"
doc += bytes([0x01 + 2])  # short value reference #2: "short unicode key"
doc += b"\xfb\xff"
# A second document: new header, empty tables.
doc += b":)\n\x00" + b"\xf8" + text("second") + b"\xc2\xf9"

with open(OUT, "wb") as f:
    f.write(doc)
