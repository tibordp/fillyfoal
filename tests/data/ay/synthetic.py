"""Synthetic AY (ZXAYEMUL) fixture: test.ay with two songs.

    python3 tests/data/ay/synthetic.py

Written from the ZXAYEMUL format description as implemented by Game_Music_Emu
(Ay_Emu's header_t): byte file version at 8 and player version at 9, then
big-endian signed self-relative pointers to the special player (0x0A), the
author (0x0C) and the misc string (0x0E), the last and first song indices
(0x10, 0x11) and a pointer to the song structures (0x12). Each song
structure holds a name pointer and a data pointer; the song data holds the
channel map, length, fade, register values and pointers to the points
(stack, init, interrupt) and to the memory blocks.
"""

import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "..", "fixtures", "synthetic", "ay")


class Builder:
    def __init__(self):
        self.buf = bytearray()
        self.fixups = []  # (pointer offset, label)
        self.labels = {}

    def here(self, label):
        self.labels[label] = len(self.buf)

    def ptr(self, label):
        self.fixups.append((len(self.buf), label))
        self.buf += b"\0\0"

    def raw(self, data):
        self.buf += data

    def build(self):
        for at, label in self.fixups:
            delta = self.labels[label] - at
            struct.pack_into(">h", self.buf, at, delta)
        return bytes(self.buf)


def main():
    b = Builder()
    b.raw(b"ZXAYEMUL")
    b.raw(bytes([0, 3]))  # file version, player version
    b.raw(b"\0\0")  # no special player
    b.ptr("author")
    b.ptr("misc")
    b.raw(bytes([1, 0]))  # last song index, first song index
    b.ptr("songs")
    # Song structures.
    b.here("songs")
    for i in range(2):
        b.ptr(f"name{i}")
        b.ptr(f"data{i}")
    # Song data.
    for i in range(2):
        b.here(f"data{i}")
        b.raw(bytes([0, 1, 2, 3]))  # AY channel map A, B, C, noise
        b.raw(struct.pack(">HH", 3000, 100))  # length, fade (1/50 s)
        b.raw(bytes([0, 0]))  # HiReg, LoReg
        b.ptr(f"points{i}")
        b.ptr(f"blocks{i}")
        b.here(f"points{i}")
        b.raw(struct.pack(">HHH", 0xF000, 0x8000, 0x8003))  # stack, init, interrupt
        b.here(f"blocks{i}")
        b.raw(struct.pack(">HH", 0x8000, 4))
        b.ptr(f"code{i}")
        b.raw(b"\0\0")  # end of blocks
        b.here(f"code{i}")
        b.raw(bytes([0xC9, 0x00, 0x00, 0xC9]))  # ret; nop; nop; ret
    b.here("author")
    b.raw(b"Composer\0")
    b.here("misc")
    b.raw(b"fillyfoal\0")
    for i in range(2):
        b.here(f"name{i}")
        b.raw(f"Song {chr(ord('A') + i)}\0".encode())
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "test.ay"), "wb") as f:
        f.write(b.build())


if __name__ == "__main__":
    main()
