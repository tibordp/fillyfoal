"""Writes tests/fixtures/synthetic/unity-serialized/v9.assets: a Unity 4
era SerializedFile (version 9: header before the metadata, recursive type
trees, 32-bit path IDs). UnityPy's writer cannot produce old type trees, so
this is assembled here; the result is read back with UnityPy.

    uv run --with UnityPy==1.25.4 python tests/data/unity-serialized/make_v9.py
"""

import os
import struct

import UnityPy

OUT = os.path.join(os.path.dirname(__file__), "..", "..", "fixtures", "synthetic", "unity-serialized", "v9.assets")


def node(type_, name, size, index, is_array, version, meta, children=()):
    out = type_.encode() + b"\0" + name.encode() + b"\0"
    out += struct.pack("<iiiii", size, index, is_array, version, meta)
    out += struct.pack("<i", len(children))
    return out + b"".join(children)


class Counter:
    def __init__(self):
        self.n = 0

    def __call__(self):
        self.n += 1
        return self.n - 1


def string_node(name, idx):
    return node("string", name, -1, idx(), 0, 1, 0x8000, [
        node("Array", "Array", -1, idx(), 1, 1, 0x4001, [
            node("int", "size", 4, idx(), 0, 1, 0x1),
            node("char", "data", 1, idx(), 0, 1, 0x1),
        ]),
    ])


def text_asset_tree():
    idx = Counter()
    root_index = idx()
    return node("TextAsset", "Base", -1, root_index, 0, 1, 0x8000, [
        string_node("m_Name", idx),
        string_node("m_Script", idx),
        string_node("m_PathName", idx),
    ])


def vector_tree():
    """A made-up class (class ID 9999, not a Unity class) with a float, a bool and a
    vector of ints, to exercise more of the type-tree reader."""
    idx = Counter()
    root_index = idx()
    return node("Settings", "Base", -1, root_index, 0, 1, 0x8000, [
        string_node("m_Name", idx),
        node("float", "m_Scale", 4, idx(), 0, 1, 0),
        node("bool", "m_Enabled", 1, idx(), 0, 1, 0x4000),
        node("vector", "m_Values", -1, idx(), 0, 1, 0x8000, [
            node("Array", "Array", -1, idx(), 1, 1, 0x4000, [
                node("int", "size", 4, idx(), 0, 1, 0),
                node("SInt32", "data", 4, idx(), 0, 1, 0),
            ]),
        ]),
    ])


def aligned_string(s):
    b = s.encode()
    out = struct.pack("<i", len(b)) + b
    return out + b"\0" * ((-len(out)) % 4)


def main():
    version = 9
    meta = b"4.7.2f1\0" + struct.pack("<i", 5)  # StandaloneWindows
    trees = [(49, text_asset_tree()), (9999, vector_tree())]
    meta += struct.pack("<i", len(trees))
    for class_id, tree in trees:
        meta += struct.pack("<i", class_id) + tree
    meta += struct.pack("<i", 0)  # big IDs disabled

    objects = [
        (1, 49, aligned_string("notes") + aligned_string("Old-style serialized file.\n") + aligned_string("Assets/notes.txt")),
        (2, 9999, aligned_string("settings") + struct.pack("<f", 1.5) + b"\x01\0\0\0" + struct.pack("<iiii", 3, 10, -20, 30)),
    ]
    data = b""
    table = struct.pack("<i", len(objects))
    for path_id, class_id, body in objects:
        data += b"\0" * ((-len(data)) % 8)
        table += struct.pack("<iIIiHH", path_id, len(data), len(body), class_id, class_id, 0)
        data += body
    meta += table
    # externals: one, with GUID and type
    meta += struct.pack("<i", 1)
    meta += b"\0" + bytes(range(16)) + struct.pack("<i", 2) + b"Assets/other.unity\0"
    meta += b"\0"  # user information

    header = 20
    data_offset = (header + len(meta) + 15) // 16 * 16
    size = data_offset + len(data)
    out = struct.pack(">IIII", len(meta), size, version, data_offset) + b"\0\0\0\0" + meta
    out += b"\0" * (data_offset - len(out)) + data
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "wb") as f:
        f.write(out)

    env = UnityPy.load(out)
    for o in env.objects:
        print(o.path_id, o.class_id, o.read_typetree(check_read=True))


if __name__ == "__main__":
    main()
