"""Writes tests/fixtures/synthetic/dweep/pack.dwp: a Dweep Gold level pack
built from our reading of the format (the game cannot export packs, and its
own packs stay out of the repository).

    python tests/data/dweep/make_pack.py tests/fixtures/synthetic/dweep/pack.dwp

Two listed levels and a third stored beyond the level count, as the original
game's pack hides its "Super Secret Bonus Level". Inventories end like the
stock packs': one (9, 0) slot, then (0, 0).
"""

import struct
import sys

WIDTH, HEIGHT = 16, 10


def text(s, size):
    raw = s.encode("cp1252")
    assert len(raw) < size
    return raw + b"\0" * (size - len(raw))


def level(title, tip, cells, inventory):
    board = bytearray(WIDTH * HEIGHT)
    for (x, y), code in cells.items():
        board[y * WIDTH + x] = code
    slots = [(0, 0)] + list(inventory) + [(9, 0)]
    slots += [(0, 0)] * (10 - len(slots))
    inv = b"".join(struct.pack("<II", t, v) for t, v in slots)
    record = text(title, 40) + text(tip, 200) + bytes(board) + inv + bytes(8)
    assert len(record) == 488
    return record


walls = {(x, 0): 1 for x in range(WIDTH)}
levels = [
    level(
        "First Light",
        "Turn the laser with the wrench.",
        {**walls, (1, 4): 5, (14, 4): 4, (7, 4): 7, (7, 2): 3, (9, 6): 2},
        [(4, 1), (2, 0)],
    ),
    level(
        "Mirror, Mirror",
        "Mirrors turn a beam by a right angle.",
        {**walls, (0, 9): 5, (15, 9): 4, (3, 3): 10, (12, 3): 11, (5, 5): 22, (8, 8): 16},
        [(2, 1), (3, 2), (6, 0)],
    ),
    level(
        "Hidden Room",
        "Not listed: it lies beyond the level count.",
        {(0, 0): 5, (15, 9): 4, (7, 5): 30, (8, 5): 31, (9, 5): 32},
        [],
    ),
]

header = b"Dweep\0" + text("Synthetic Pack", 40) + struct.pack("<I", 2)
with open(sys.argv[1], "wb") as f:
    f.write(header + b"".join(levels))
