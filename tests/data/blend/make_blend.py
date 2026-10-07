"""Writes the synthetic Blender fixtures (no Blender install was available).

    python3 tests/data/blend/make_blend.py
    zstd -19 -q -f --no-progress tests/fixtures/synthetic/blend/scene.blend \
        -o tests/data/blend/scene.blend.zst
    gzip -9 -n -c tests/fixtures/synthetic/blend/scene.blend > tests/data/blend/scene.blend.gz

The layout (file header, block headers, the DNA1 "SDNA" catalogue) follows
Blender's file format as remembered, not a spec or a real file. The struct
definitions are cut-down versions of Blender's DNA (real files define about
a thousand structs); the field names follow Blender's where remembered, and
the SDNA written into each file describes exactly what the file contains, so
the files are self-consistent. They are synthetic fixtures: they show the
dissector agrees with this writer, not with Blender.

Three files:
- scene.blend: "BLENDER-v293" (64-bit pointers, little-endian, 2.93), with a
  render-info block, an 8x8 thumbnail, global settings, a scene, a world, a
  camera, a mesh (vertex array and material array), a material and two
  objects.
- legacy-ppc.blend: "BLENDER_V249" (32-bit pointers, big-endian, 2.49, as a
  PowerPC Mac wrote them), with 24-byte ID names.
- blender5.blend: "BLENDER17-01v0500", the Blender 5 header with 32-byte
  ("large") block headers and 258-byte ID names.
"""

import os
import struct

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..")
OUT = os.path.join(ROOT, "tests", "fixtures", "synthetic", "blend")

BASIC = [
    ("char", 1), ("uchar", 1), ("short", 2), ("ushort", 2), ("int", 4),
    ("long", 4), ("ulong", 4), ("float", 4), ("double", 8), ("int64_t", 8),
    ("uint64_t", 8), ("void", 0),
]


def structs(id_name_len, modern_glob):
    """(struct name, [(type, declarator)]) in dependency order."""
    glob = [
        ("char", "subvstr[4]"), ("short", "subversion"), ("short", "minversion"),
        ("short", "minsubversion"), ("char", "_pad[6]"), ("void", "*curscreen"),
        ("Scene", "*curscene"), ("int", "fileflags"), ("int", "globalf"),
    ]
    if modern_glob:
        glob += [("uint64_t", "build_commit_timestamp"), ("char", "build_hash[16]")]
    glob += [("char", "filename[64]")]
    return [
        ("Link", [("Link", "*next"), ("Link", "*prev")]),
        ("ListBase", [("void", "*first"), ("void", "*last")]),
        ("ID", [
            ("void", "*next"), ("void", "*prev"), ("ID", "*newid"), ("void", "*lib"),
            ("char", "name[%d]" % id_name_len), ("short", "flag"), ("short", "_pad0"),
            ("int", "tag"), ("int", "us"), ("int", "icon_id"), ("char", "_pad1[6]"),
        ]),
        ("FileGlobal", glob),
        ("RenderData", [
            ("int", "cfra"), ("int", "sfra"), ("int", "efra"), ("short", "xsch"),
            ("short", "ysch"), ("short", "size"), ("char", "_pad[6]"),
        ]),
        ("MVert", [("float", "co[3]"), ("short", "no[3]"), ("char", "flag"), ("char", "bweight")]),
        ("World", [("ID", "id"), ("float", "horr"), ("float", "horg"), ("float", "horb"), ("float", "exposure")]),
        ("Camera", [
            ("ID", "id"), ("char", "type"), ("char", "dtx"), ("short", "flag"), ("float", "lens"),
            ("float", "ortho_scale"), ("float", "clip_start"), ("float", "clip_end"),
        ]),
        ("Material", [
            ("ID", "id"), ("float", "r"), ("float", "g"), ("float", "b"), ("float", "a"),
            ("float", "specr"), ("float", "specg"), ("float", "specb"), ("float", "roughness"),
        ]),
        ("Mesh", [
            ("ID", "id"), ("MVert", "*mvert"), ("Material", "**mat"), ("int", "totvert"),
            ("int", "totedge"), ("int", "totpoly"), ("int", "totloop"), ("short", "totcol"),
            ("char", "_pad[6]"),
        ]),
        ("Object", [
            ("ID", "id"), ("Object", "*parent"), ("void", "*data"), ("Material", "**mat"),
            ("ListBase", "modifiers"), ("short", "type"), ("short", "totcol"), ("char", "_pad[4]"),
            ("float", "loc[3]"), ("float", "rot[3]"), ("float", "scale[3]"), ("float", "_pad1"),
            ("float", "obmat[4][4]"),
        ]),
        ("Scene", [
            ("ID", "id"), ("Object", "*camera"), ("World", "*world"), ("ListBase", "base"),
            ("RenderData", "r"),
        ]),
    ]


def declarator(name):
    pointer = name.startswith("*") or name.startswith("(")
    count = 1
    rest = name
    while "[" in rest:
        a = rest.index("[")
        b = rest.index("]", a)
        count *= int(rest[a + 1:b])
        rest = rest[b + 1:]
    base = name.lstrip("*(").split("[")[0].split(")")[0]
    return pointer, count, base


class Writer:
    def __init__(self, ptr, endian, id_name_len, modern_glob):
        self.ptr = ptr
        self.e = endian
        self.defs = structs(id_name_len, modern_glob)
        self.types = list(BASIC) + [(n, 0) for n, _ in self.defs]
        self.index = {n: i for i, (n, _) in enumerate(self.types)}
        self.names = []
        self.sizes = dict(BASIC)
        for name, fields in self.defs:
            size = 0
            for ty, decl in fields:
                pointer, count, _ = declarator(decl)
                size += (self.ptr if pointer else self.sizes[ty]) * count
                if decl not in self.names:
                    self.names.append(decl)
            self.sizes[name] = size
        self.types = [(n, self.sizes[n]) for n, _ in self.types]
        self.struct_index = {n: i for i, (n, _) in enumerate(self.defs)}

    def pack(self, fmt, *v):
        return struct.pack(self.e + fmt, *v)

    def pointer(self, v):
        return self.pack("Q" if self.ptr == 8 else "I", v)

    def scalar(self, ty, v):
        fmt = {"char": "b", "uchar": "B", "short": "h", "ushort": "H", "int": "i",
               "long": "i", "ulong": "I", "float": "f", "double": "d",
               "int64_t": "q", "uint64_t": "Q"}[ty]
        if ty == "char" and isinstance(v, int) and v > 127:
            v -= 256
        return self.pack(fmt, v)

    def encode(self, sname, values):
        out = b""
        for ty, decl in dict(self.defs)[sname]:
            pointer, count, base = declarator(decl)
            v = values.get(base)
            if pointer:
                vs = v if isinstance(v, list) else [v or 0]
                vs = (vs + [0] * count)[:count]
                out += b"".join(self.pointer(x) for x in vs)
            elif ty in self.struct_index:
                out += self.encode(ty, v or {})
            elif ty == "char" and count > 1:
                raw = (v or "").encode() if isinstance(v, str) else (v or b"")
                out += raw[:count].ljust(count, b"\0")
            else:
                vs = v if isinstance(v, list) else [v or 0]
                vs = (vs + [0] * count)[:count]
                out += b"".join(self.scalar(ty, x) for x in vs)
        assert len(out) == self.sizes[sname], (sname, len(out), self.sizes[sname])
        return out

    def sdna(self):
        def strings(xs):
            b = b"".join(x.encode() + b"\0" for x in xs)
            return b + b"\0" * (-len(b) % 4)

        out = b"SDNA" + b"NAME" + self.pack("i", len(self.names)) + strings(self.names)
        out += b"TYPE" + self.pack("i", len(self.types)) + strings([n for n, _ in self.types])
        tlen = b"".join(self.pack("h", l) for _, l in self.types)
        out += b"TLEN" + tlen + b"\0" * (-len(tlen) % 4)
        out += b"STRC" + self.pack("i", len(self.defs))
        for name, fields in self.defs:
            out += self.pack("hh", self.index[name], len(fields))
            for ty, decl in fields:
                out += self.pack("hh", self.index[ty], self.names.index(decl))
        return out


def write(path, header, w, blocks, large):
    out = header
    for code, sdna, old, nr, data in blocks:
        code = code.encode().ljust(4, b"\0")
        if large:
            out += code + w.pack("iQqq", sdna, old, len(data), nr)
        else:
            out += code + w.pack("i", len(data)) + w.pointer(old) + w.pack("ii", sdna, nr)
        out += data
    with open(path, "wb") as f:
        f.write(out)


def thumbnail(w, size):
    px = b""
    for y in range(size):
        for x in range(size):
            px += bytes([x * 255 // (size - 1), y * 255 // (size - 1), 128, 255])
    return w.pack("ii", size, size) + px


def scene_file(w, base, step, version_glob, scene_name_len, thumb, extra_object):
    """The blocks of a small scene: addresses are made-up heap addresses."""
    addr = iter(range(base, base + 64 * step, step))
    sc, wo, ca, me, mv, mm, ma, ob, om, ob2 = (next(addr) for _ in range(10))
    s = w.struct_index
    cube = [(-1, -1, -1), (1, -1, -1), (1, 1, -1), (-1, 1, -1),
            (-1, -1, 1), (1, -1, 1), (1, 1, 1), (-1, 1, 1)]
    verts = cube if extra_object else cube[:3]
    ident = [1.0, 0, 0, 0, 0, 1.0, 0, 0, 0, 0, 1.0, 0, 0, 0, 0, 1.0]
    blocks = [
        ("REND", 0, next(addr), 1,
         w.pack("ii", 1, 250) + b"Scene".ljust(scene_name_len, b"\0")),
    ]
    if thumb:
        blocks.append(("TEST", 0, next(addr), 1, thumbnail(w, thumb)))
    blocks.append(("GLOB", s["FileGlobal"], next(addr), 1, w.encode("FileGlobal", {
        "subvstr": version_glob[0], "subversion": version_glob[1], "minversion": 290,
        "minsubversion": 0, "curscreen": next(addr), "curscene": sc,
        "build_commit_timestamp": 1_700_000_000, "build_hash": "0123456789ab",
        "filename": "/tmp/scene.blend",
    })))
    blocks += [
        ("SC", s["Scene"], sc, 1, w.encode("Scene", {
            "id": {"name": "SCScene", "us": 1}, "camera": ob2 if extra_object else 0,
            "world": wo if extra_object else 0,
            "r": {"cfra": 1, "sfra": 1, "efra": 250, "xsch": 1920, "ysch": 1080, "size": 100},
        })),
    ]
    if extra_object:
        blocks += [
            ("WO", s["World"], wo, 1, w.encode("World", {
                "id": {"name": "WOWorld", "us": 1}, "horr": 0.05, "horg": 0.05, "horb": 0.05,
                "exposure": 1.0})),
            ("CA", s["Camera"], ca, 1, w.encode("Camera", {
                "id": {"name": "CACamera", "us": 1}, "lens": 50.0, "ortho_scale": 7.3,
                "clip_start": 0.1, "clip_end": 100.0})),
        ]
    blocks += [
        ("ME", s["Mesh"], me, 1, w.encode("Mesh", {
            "id": {"name": "MECube" if extra_object else "METriangle", "us": 1},
            "mvert": mv, "mat": mm, "totvert": len(verts), "totcol": 1,
            "totedge": 12 if extra_object else 3, "totpoly": 6 if extra_object else 1,
            "totloop": 24 if extra_object else 3,
        })),
        ("DATA", s["MVert"], mv, len(verts), b"".join(
            w.encode("MVert", {"co": list(map(float, v)), "no": [x * 18918 for x in v]})
            for v in verts)),
        # Pointer arrays are written raw (struct 0) by Blender.
        ("DATA", 0, mm, 1, w.pointer(ma)),
        ("MA", s["Material"], ma, 1, w.encode("Material", {
            "id": {"name": "MAMaterial", "us": 2}, "r": 0.8, "g": 0.2, "b": 0.1, "a": 1.0,
            "specr": 1.0, "specg": 1.0, "specb": 1.0, "roughness": 0.5})),
        ("OB", s["Object"], ob, 1, w.encode("Object", {
            "id": {"name": "OBCube" if extra_object else "OBTriangle", "us": 1},
            "data": me, "mat": om, "type": 1, "totcol": 1, "loc": [0.0, 0.0, 1.0],
            "scale": [1.0, 1.0, 1.0], "obmat": ident[:12] + [0.0, 0.0, 1.0, 1.0]})),
        ("DATA", 0, om, 1, w.pointer(0)),
    ]
    if extra_object:
        blocks.append(("OB", s["Object"], ob2, 1, w.encode("Object", {
            "id": {"name": "OBCamera", "us": 1}, "data": ca, "parent": ob, "type": 11,
            "loc": [7.4, -6.5, 5.3], "rot": [1.1, 0.0, 0.81],
            "scale": [1.0, 1.0, 1.0], "obmat": ident})))
    blocks += [("DNA1", 0, 0, 1, w.sdna()), ("ENDB", 0, 0, 0, b"")]
    return blocks


def main():
    os.makedirs(OUT, exist_ok=True)
    w = Writer(8, "<", 66, True)
    write(os.path.join(OUT, "scene.blend"), b"BLENDER-v293", w,
          scene_file(w, 0x7F3A_4C00_0000, 0x400, ("293", 5), 64, 8, True), False)

    w = Writer(4, ">", 24, False)
    write(os.path.join(OUT, "legacy-ppc.blend"), b"BLENDER_V249", w,
          scene_file(w, 0x0200_0000, 0x100, ("249", 2), 32, 0, False), False)

    w = Writer(8, "<", 258, True)
    write(os.path.join(OUT, "blender5.blend"), b"BLENDER17-01v0500", w,
          scene_file(w, 0x6000_0100_0000, 0x400, ("500", 31), 256, 4, False), True)


if __name__ == "__main__":
    main()
