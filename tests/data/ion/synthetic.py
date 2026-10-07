"""Synthetic binary Ion fixture covering what ion-python does not write.

    python3 tests/data/ion/synthetic.py

Written from the Ion 1.0 binary specification: NOP padding (top level and
inside a struct), a sorted struct (length nibble 1), a local symbol table
importing a shared table we do not have (its symbols show as `$N`) and
one appending to the current table, float32, big and negative integers,
timestamps of minute and year precision and with an unknown offset, typed
nulls, symbol zero, an annotated list, and a second version marker that
resets the symbol table.
"""

import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "..", "fixtures", "synthetic", "ion", "features.10n")

BVM = b"\xe0\x01\x00\xea"


def varuint(v):
    out = [0x80 | (v & 0x7F)]
    v >>= 7
    while v:
        out.append(v & 0x7F)
        v >>= 7
    return bytes(reversed(out))


def varint(v, negative=None):
    neg = v < 0 if negative is None else negative
    m = abs(v)
    groups = []
    while True:
        groups.append(m & 0x7F)
        m >>= 7
        if m == 0:
            break
    groups.reverse()
    if groups[0] & 0x40:
        groups.insert(0, 0)
    if neg:
        groups[0] |= 0x40
    groups[-1] |= 0x80
    return bytes(groups)


def value(t, body):
    n = len(body)
    if n < 14:
        return bytes([(t << 4) | n]) + body
    return bytes([(t << 4) | 14]) + varuint(n) + body


def uint(v):
    return v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big") if v else b""


def int_(v):
    return value(2 if v >= 0 else 3, uint(abs(v)))


def string(s):
    return value(8, s.encode())


def symbol(sid):
    return value(7, uint(sid))


def struct_(fields, sorted_=False):
    body = b"".join(varuint(sid) + v for sid, v in fields)
    if sorted_:
        return b"\xd1" + varuint(len(body)) + body
    return value(13, body)


def lst(items, t=11):
    return value(t, b"".join(items))


def annotate(sids, v):
    ann = b"".join(varuint(s) for s in sids)
    return value(14, varuint(len(ann)) + ann + v)


def timestamp(offset, *fields, negative_zero=False):
    body = varint(offset, negative=True if negative_zero else None) + b"".join(varuint(f) for f in fields)
    return value(6, body)


out = bytearray(BVM)
# Symbol table: import 5 symbols of a shared table we cannot resolve, then
# local symbols starting at $15.
lst1 = annotate(
    [3],
    struct_(
        [
            (6, lst([struct_([(4, string("com.example.shared")), (5, int_(1)), (8, int_(5))])])),
            (7, lst([string("alpha"), string("beta"), value(0, b""), int_(1)])),
        ]
    ),
)
out += lst1
out += b"\x02\x00\x00"  # three bytes of NOP padding
out += struct_(
    [
        (15, string("alpha field")),  # $15 alpha
        (11, string("an imported name")),  # $11, from the shared table
        (16, value(4, struct.pack(">f", 0.25))),
        (16, value(0, b"\x00")),  # NOP padding with a field name
        (15, int_(-(2**70))),
        (15, int_(-42)),
        (15, timestamp(-300, 2026, 10, 7, 9, 30)),  # minute precision, UTC-05:00
        (15, timestamp(0, 1999)),  # year precision
        (15, timestamp(0, 2026, 1, 1, 0, 0, 0, negative_zero=True)),  # unknown offset
        (15, b"\x0f"),  # null.null
        (15, b"\x1f"),  # null.bool
        (15, b"\xdf"),  # null.struct
        (15, symbol(0)),
        (15, value(5, b"")),  # decimal 0
        (15, value(5, varint(-2) + b"\x80")),  # decimal -0.00 (negative zero coefficient)
    ]
)
out += struct_([(4, string("sorted")), (5, int_(2))], sorted_=True)
# Append two more symbols to the current table ($18, $19; $17 is the gap left by the integer).
out += annotate([3], struct_([(6, symbol(3)), (7, lst([string("gamma"), string("delta")]))]))
out += annotate([18, 19], lst([symbol(15), symbol(18)], t=12))
out += lst([])
# A new version marker: back to the system symbols only.
out += BVM
out += symbol(15)

with open(OUT, "wb") as f:
    f.write(out)
