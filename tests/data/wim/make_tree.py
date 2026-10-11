#!/usr/bin/env python3
"""Writes the directory tree captured into the LZMS WIM test files.

Usage: python3 -I make_tree.py DIR

The content is deterministic and neutral:
- notes.txt: text lines (LZ matches, repeat offsets, literals);
- code.bin: x86-like machine code (E8 calls, RIP-relative LEA/MOV,
  FF 15 indirect calls to a few targets), so the LZMS x86 filter
  translates addresses;
- ramp.pcm: 16-bit samples rising by a varying step, which suits LZMS
  delta matches;
- copy.txt: a duplicate of notes.txt (one stream, two references);
- one.bin: a single byte; empty: no data.
Every file gets the same fixed modification time.
"""

import os
import struct
import sys


def lcg(seed):
    x = seed
    while True:
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        yield x >> 8


def notes():
    words = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf",
             "hotel", "india", "juliet", "kilo", "lima", "mike", "november"]
    r = lcg(7)
    lines = []
    for i in range(700):
        n = 3 + next(r) % 6
        lines.append(f"{i:05d} " + " ".join(words[next(r) % len(words)] for _ in range(n)))
    return ("\n".join(lines) + "\n").encode()


def code():
    r = lcg(99)
    out = bytearray()
    targets = [0x400, 0x1800, 0x2c40, 0x5000, 0x7a10]
    while len(out) < 20000:
        k = next(r) % 7
        pos = len(out)
        t = targets[next(r) % len(targets)]
        if k == 0:
            out += b"\xe8" + struct.pack("<i", t - (pos + 5))
        elif k == 1:
            out += b"\x48\x8d\x05" + struct.pack("<i", t - (pos + 7))
        elif k == 2:
            out += b"\x48\x8b\x0d" + struct.pack("<i", t - (pos + 7))
        elif k == 3:
            out += b"\xff\x15" + struct.pack("<i", t - (pos + 6))
        elif k == 4:
            out += b"\x55\x48\x89\xe5"
        elif k == 5:
            out += bytes([0x89, 0xc0 | next(r) % 64])
        else:
            out += b"\x5d\xc3"
    return bytes(out)


def ramp():
    out = bytearray()
    v = 0
    for i in range(8000):
        v = (v + 3 + (i // 700)) & 0xFFFF
        out += struct.pack("<H", v)
    return bytes(out)


def main():
    root = sys.argv[1]
    os.makedirs(os.path.join(root, "sub"), exist_ok=True)
    files = {
        "notes.txt": notes(),
        "sub/code.bin": code(),
        "sub/ramp.pcm": ramp(),
        "sub/copy.txt": notes(),
        "one.bin": b"!",
        "empty": b"",
    }
    for name, data in files.items():
        with open(os.path.join(root, name), "wb") as f:
            f.write(data)
    stamp = 1_600_000_000
    for name in list(files) + ["sub", "."]:
        os.utime(os.path.join(root, name), (stamp, stamp))


if __name__ == "__main__":
    main()
