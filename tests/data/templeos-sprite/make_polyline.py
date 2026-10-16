#!/usr/bin/env python3
"""Writes polyline.spr: a TempleOS sprite (CSprite element list) with a
color, a three-point PolyLine and End, laid out as in Adam/Gr/SpriteNew.HC
(sprite_elem_base_sizes, SpriteElemSize). No sprite on the V5.03 ISO has a
PolyLine, so this one is made by hand.

    python3 make_polyline.py ../../fixtures/synthetic/templeos-sprite/polyline.spr
"""
import struct
import sys

SPT_END, SPT_COLOR, SPT_POLYLINE = 0, 1, 11
points = [(3, 4), (10, 20), (-5, 7)]
data = bytes([SPT_COLOR, 4])  # RED
data += struct.pack('<Bi', SPT_POLYLINE, len(points))
for x, y in points:
    data += struct.pack('<ii', x, y)
data += bytes([SPT_END])
open(sys.argv[1], 'wb').write(data)
