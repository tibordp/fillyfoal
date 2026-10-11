"""Writes tests/fixtures/synthetic/wasm/huge-data.wasm.raw.zst: a small
WebAssembly module whose data section (a 17 MiB segment of zeros, then a
short one) is larger than one 16 MiB read, so the dissector must walk it
without reading it whole. Three functions call each other by index, and a
`name` section names them, for the names in the instruction listing.

    python3 tests/data/wasm/huge-data.py   (needs the zstd command)
"""

import os
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "..", "fixtures", "synthetic", "wasm", "huge-data.wasm.raw.zst")


def leb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def vec(items):
    return leb(len(items)) + b"".join(items)


def name(s):
    return leb(len(s)) + s.encode()


def section(id_, body):
    return bytes([id_]) + leb(len(body)) + body


BIG = 17 << 20

types = vec([b"\x60\x00\x01\x7f"])  # () -> (i32)
functions = vec([b"\x00", b"\x00", b"\x00"])
memory = vec([b"\x00" + leb(BIG // 65536 + 2)])
exports = vec([name("memory") + b"\x02\x00", name("main") + b"\x00\x02"])
bodies = [
    b"\x00\x41\x2a\x0b",  # i32.const 42
    b"\x00\x10\x00\x41\x01\x6a\x0b",  # call 0, i32.const 1, i32.add
    b"\x01\x01\x7f\x10\x01\x10\x00\x6a\x0b",  # local i32; call 1, call 0, i32.add
]
code = vec([leb(len(b)) + b for b in bodies])
data = vec([
    b"\x00\x41\x00\x0b" + leb(BIG) + bytes(BIG),  # active at 0
    b"\x01" + name("after the zeros"),  # passive
])
names = name("name") + bytes([1]) + (lambda m: leb(len(m)) + m)(
    vec([leb(0) + name("answer"), leb(1) + name("plus_one"), leb(2) + name("main")])
)

module = (
    b"\0asm\x01\0\0\0"
    + section(1, types)
    + section(3, functions)
    + section(5, memory)
    + section(7, exports)
    + section(10, code)
    + section(11, data)
    + section(0, names)
)

raw = subprocess.run(
    ["zstd", "-19", "-q", "-c", "--no-check"], input=module, capture_output=True, check=True
).stdout
with open(OUT, "wb") as f:
    f.write(raw)
print(f"{OUT}: {len(module)} bytes, {len(raw)} stored")
