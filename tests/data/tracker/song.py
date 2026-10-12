#!/usr/bin/env python3
"""Writes song.mod, the seed module the tracker fixtures are converted from.

A four-channel ProTracker module ("M.K.") with two short looped samples
(a square and a saw wave), two patterns of notes with a few common effects
(arpeggio, slides, volume, speed) and the order list 0 1 0. The external
tracker fixtures are this module loaded into a real tracker (Schism Tracker,
MilkyTracker) and saved in that tracker's formats; see make-*.sh.

Usage: song.py OUT.mod
"""
import struct
import sys

PERIODS = [
    856, 808, 762, 720, 678, 640, 604, 570, 538, 508, 480, 453,  # C-1..B-1
    428, 404, 381, 360, 339, 320, 302, 285, 269, 254, 240, 226,  # C-2..B-2
    214, 202, 190, 180, 170, 160, 151, 143, 135, 127, 120, 113,  # C-3..B-3
]
NAMES = ["C-", "C#", "D-", "D#", "E-", "F-", "F#", "G-", "G#", "A-", "A#", "B-"]


def period(note):
    """'C-2' -> Amiga period."""
    octave = int(note[2])
    return PERIODS[(octave - 1) * 12 + NAMES.index(note[:2])]


def cell(note=None, sample=0, effect=0, param=0):
    p = period(note) if note else 0
    return bytes([
        (sample & 0xF0) | (p >> 8),
        p & 0xFF,
        ((sample & 0x0F) << 4) | effect,
        param,
    ])


def pattern(events):
    """events: {(row, channel): cell bytes}."""
    out = bytearray()
    for row in range(64):
        for ch in range(4):
            out += events.get((row, ch), bytes(4))
    return bytes(out)


def main():
    square = bytes([0x40] * 16 + [0xC0] * 16)
    saw = bytes(((i * 4) - 128) & 0xFF for i in range(64))
    samples = [("square", square, 64, 0), ("saw", saw, 48, 0)]

    header = bytearray(b"fillyfoal".ljust(20, b"\0"))
    for name, data, volume, finetune in samples:
        header += name.encode().ljust(22, b"\0")
        header += struct.pack(">HBBHH", len(data) // 2, finetune, volume, 0, len(data) // 2)
    for _ in range(31 - len(samples)):
        header += bytes(22) + struct.pack(">HBBHH", 0, 0, 0, 0, 1)
    orders = [0, 1, 0]
    header += bytes([len(orders), 127])
    header += bytes(orders + [0] * (128 - len(orders)))
    header += b"M.K."

    p0 = pattern({
        (0, 0): cell("C-2", 1, 0xF, 6),       # speed 6
        (0, 1): cell("E-2", 2),
        (4, 0): cell("G-2", 1, 0x0, 0x37),    # arpeggio
        (8, 2): cell("C-3", 2, 0xC, 0x20),    # volume 32
        (12, 1): cell("A-1", 2, 0x1, 0x04),   # slide up
        (16, 3): cell("D-2", 1, 0xA, 0x02),   # volume slide down
        (32, 0): cell("F-2", 1),
        (48, 2): cell(None, 0, 0x3, 0x10),    # tone portamento, no note
        (63, 3): cell("B-2", 2, 0xD, 0x00),   # pattern break
    })
    p1 = pattern({
        (0, 0): cell("A-2", 2, 0x4, 0x44),    # vibrato
        (2, 1): cell("C#2", 1),
        (6, 2): cell("D#3", 2, 0x9, 0x01),    # sample offset
        (10, 3): cell(None, 0, 0xE, 0x91),    # retrigger
        (20, 0): cell("G#1", 1, 0x2, 0x08),   # slide down
        (40, 1): cell("F#2", 2, 0xB, 0x00),   # position jump
    })

    body = b"".join(data for _, data, _, _ in samples)
    with open(sys.argv[1], "wb") as f:
        f.write(bytes(header) + p0 + p1 + body)


if __name__ == "__main__":
    main()
