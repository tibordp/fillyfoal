"""Synthetic Half-Life (GoldSrc) BSP: goldsrc.bsp, version 30.

    python3 tests/data/bsp/synthetic.py

GoldSrc keeps Quake's BSP layout (version, then 15 offset/length lump
entries in Quake's order) with the version raised to 30. Only the entities
lump has content; the others are empty and point past the directory.
Written from the Quake BSP29 lump directory and the GoldSrc v30 notes.
"""

import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "..", "fixtures", "synthetic", "bsp")


def main():
    entities = (
        b'{\n"classname" "worldspawn"\n"wad" "\\\\half-life\\\\valve\\\\halflife.wad"\n}\n'
        b'{\n"classname" "info_player_start"\n"origin" "0 0 36"\n}\n\0'
    )
    directory = 4 + 15 * 8
    lumps = [(directory, len(entities))]
    end = directory + len(entities)
    lumps += [(end, 0)] * 14
    data = struct.pack("<I", 30)
    data += b"".join(struct.pack("<II", off, size) for off, size in lumps)
    data += entities
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "goldsrc.bsp"), "wb") as f:
        f.write(data)


if __name__ == "__main__":
    main()
