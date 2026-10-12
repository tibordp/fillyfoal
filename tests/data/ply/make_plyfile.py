"""PLY meshes written by plyfile (Darsh Ranjan, GPL-3.0).

    uv run --with plyfile==1.1.5 --with numpy==2.5.4 \
        python tests/data/ply/make_plyfile.py OUTDIR

Writes, in OUTDIR, the same cube three times: cube-ascii.ply,
cube-le.ply (binary_little_endian) and cube-be.ply (binary_big_endian).
Each has a vertex element (float x, y, z and uchar red, green, blue), a face
element with a list property (uchar count, int indices: four quads and four
triangles) and an edge element after it, so the edge records start only
after the variable-size faces.
"""

import sys

import numpy as np
from plyfile import PlyData, PlyElement

out = sys.argv[1]

vertex = np.array(
    [
        (0.0, 0.0, 0.0, 255, 0, 0),
        (1.0, 0.0, 0.0, 0, 255, 0),
        (1.0, 1.0, 0.0, 0, 0, 255),
        (0.0, 1.0, 0.0, 255, 255, 0),
        (0.0, 0.0, 1.0, 255, 0, 255),
        (1.0, 0.0, 1.0, 0, 255, 255),
        (1.0, 1.0, 1.0, 255, 255, 255),
        (0.0, 1.0, 1.0, 0, 0, 0),
    ],
    dtype=[
        ("x", "f4"),
        ("y", "f4"),
        ("z", "f4"),
        ("red", "u1"),
        ("green", "u1"),
        ("blue", "u1"),
    ],
)
faces = [
    [0, 3, 2, 1],
    [4, 5, 6, 7],
    [0, 1, 5, 4],
    [2, 3, 7, 6],
    [1, 2, 6],
    [1, 6, 5],
    [0, 4, 7],
    [0, 7, 3],
]
face = np.empty(len(faces), dtype=[("vertex_indices", "O")])
face["vertex_indices"] = [np.array(f, dtype="i4") for f in faces]
edge = np.array(
    [(0, 1), (1, 2), (2, 3), (3, 0)],
    dtype=[("vertex1", "i4"), ("vertex2", "i4")],
)

elements = [
    PlyElement.describe(vertex, "vertex"),
    PlyElement.describe(face, "face", val_types={"vertex_indices": "i4"}),
    PlyElement.describe(edge, "edge"),
]
for name, text, byte_order in [
    ("cube-ascii.ply", True, "="),
    ("cube-le.ply", False, "<"),
    ("cube-be.ply", False, ">"),
]:
    PlyData(
        elements, text=text, byte_order=byte_order, comments=["made by fillyfoal"]
    ).write(f"{out}/{name}")
