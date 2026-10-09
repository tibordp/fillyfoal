"""A minimal Compound File Binary writer (version 3, 512-byte sectors) for
the synthetic fixtures: streams below 4096 bytes go to the mini stream,
directories are balanced red-black trees in CFB name order.

    tree = {"Stream": b"...", "Storage": {"Inner": b"..."}}
    write("out.cfb", tree, root_clsid=b"\\0" * 16)
"""

import struct

SECTOR = 512
MINI = 64
CUTOFF = 4096
FREESECT, ENDOFCHAIN, FATSECT = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD
NOSTREAM = 0xFFFFFFFF


def _key(name):
    return (len(name), name.upper())


class _Entry:
    def __init__(self, name, kind, data=None, children=None, clsid=b"\0" * 16):
        self.name, self.kind, self.data = name, kind, data
        self.children = children or []
        self.clsid = clsid
        self.left = self.right = self.child = NOSTREAM
        self.color = 1
        self.start, self.size = ENDOFCHAIN, 0
        self.id = None


def _build(name, tree, kind, clsid=b"\0" * 16):
    e = _Entry(name, kind, clsid=clsid)
    for k, v in tree.items():
        if isinstance(v, dict):
            e.children.append(_build(k, v, 1))
        else:
            c = _Entry(k, 2, data=v)
            e.children.append(c)
    return e


def _flatten(root):
    out = [root]
    def visit(e):
        for c in e.children:
            c.id = len(out)
            out.append(c)
        for c in e.children:
            if c.kind == 1:
                visit(c)
    root.id = 0
    visit(root)
    return out


def _tree(entries):
    """Balanced BST; nodes on the deepest, incomplete level are red."""
    entries = sorted(entries, key=lambda e: _key(e.name))
    depth = {}

    def build(lo, hi, d):
        if lo >= hi:
            return NOSTREAM
        mid = (lo + hi) // 2
        e = entries[mid]
        depth[e.id] = d
        e.left = build(lo, mid, d + 1)
        e.right = build(mid + 1, hi, d + 1)
        return e.id

    root = build(0, len(entries), 0)
    if entries:
        maxd = max(depth.values())
        full = (1 << (maxd + 1)) - 1 == len(entries)
        for e in entries:
            e.color = 0 if (depth[e.id] == maxd and not full and maxd > 0) else 1
    return root


def write(path, tree, root_clsid=b"\0" * 16):
    root = _build("Root Entry", tree, 5, clsid=root_clsid)
    entries = _flatten(root)
    for e in entries:
        if e.kind in (1, 5):
            e.child = _tree(e.children)
    root.color = 1

    # Mini stream.
    mini = bytearray()
    minifat = []
    for e in entries:
        if e.kind == 2 and 0 < len(e.data) < CUTOFF:
            n = (len(e.data) + MINI - 1) // MINI
            e.start = len(minifat)
            e.size = len(e.data)
            minifat += [len(minifat) + i + 1 for i in range(n - 1)] + [ENDOFCHAIN]
            mini += e.data + b"\0" * (n * MINI - len(e.data))
        elif e.kind == 2 and len(e.data) == 0:
            e.start, e.size = ENDOFCHAIN, 0

    sectors = []  # list of bytes objects
    fat = []

    def alloc(data):
        if not data:
            return ENDOFCHAIN
        n = (len(data) + SECTOR - 1) // SECTOR
        first = len(sectors)
        for i in range(n):
            chunk = data[i * SECTOR:(i + 1) * SECTOR]
            sectors.append(chunk + b"\0" * (SECTOR - len(chunk)))
            fat.append(first + i + 1 if i < n - 1 else ENDOFCHAIN)
        return first

    for e in entries:
        if e.kind == 2 and len(e.data) >= CUTOFF:
            e.size = len(e.data)
            e.start = alloc(e.data)
    root.start = alloc(bytes(mini)) if mini else ENDOFCHAIN
    root.size = len(mini)
    minifat_bytes = b"".join(struct.pack("<I", x) for x in minifat)
    if minifat_bytes:
        minifat_bytes += b"\xff" * ((-len(minifat_bytes)) % SECTOR)
    first_minifat = alloc(minifat_bytes) if minifat_bytes else ENDOFCHAIN
    n_minifat = len(minifat_bytes) // SECTOR

    dirdata = bytearray()
    for e in entries:
        name = e.name.encode("utf-16-le") + b"\0\0"
        dirdata += name + b"\0" * (64 - len(name))
        dirdata += struct.pack("<HBBIII", len(name), e.kind, e.color, e.left, e.right, e.child)
        dirdata += e.clsid + struct.pack("<IQQIQ", 0, 0, 0, e.start, e.size)
    while len(dirdata) % SECTOR:
        dirdata += b"\0" * 64 + struct.pack("<HBBIII", 0, 0, 0, NOSTREAM, NOSTREAM, NOSTREAM) + b"\0" * 16 + struct.pack("<IQQIQ", 0, 0, 0, 0, 0)
    first_dir = alloc(bytes(dirdata))

    # FAT sectors (fixed point: the FAT must also cover itself).
    n_fat = 1
    while (len(sectors) + n_fat) > n_fat * (SECTOR // 4):
        n_fat += 1
    fat_start = len(sectors)
    fat += [FATSECT] * n_fat
    for _ in range(n_fat):
        sectors.append(b"")
    fat += [FREESECT] * (n_fat * (SECTOR // 4) - len(fat))
    fat_bytes = b"".join(struct.pack("<I", x) for x in fat)
    for i in range(n_fat):
        sectors[fat_start + i] = fat_bytes[i * SECTOR:(i + 1) * SECTOR]
    assert n_fat <= 109

    header = bytearray(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 16)
    header += struct.pack("<HHHHH", 0x3E, 3, 0xFFFE, 9, 6) + b"\0" * 6
    header += struct.pack("<IIIIIIIII", 0, n_fat, first_dir, 0, CUTOFF, first_minifat, n_minifat, ENDOFCHAIN, 0)
    difat = [fat_start + i for i in range(n_fat)] + [FREESECT] * (109 - n_fat)
    header += b"".join(struct.pack("<I", x) for x in difat)
    assert len(header) == SECTOR
    with open(path, "wb") as f:
        f.write(header)
        for s in sectors:
            f.write(s)
