"""Writes the Unity fixtures with UnityPy's own writers.

    uv run --with UnityPy==1.25.4 python tests/data/unityfs/make.py

UnityPy has no API to create a file from nothing, so each one starts from a
seed with empty tables (the few bytes below, written here), which UnityPy
parses. Types (from UnityPy's bundled type-tree database), objects (encoded
by UnityPy's type-tree writer), script types, externals and resource files
are then added through UnityPy's object model and the result is written by
`SerializedFile.save` / `BundleFile.save`. Every output is read back with
UnityPy before it is kept.
"""

import os
import struct
import sys

import UnityPy
from UnityPy.enums import ClassIDType
from UnityPy.files.ObjectReader import ObjectReader
from UnityPy.files.SerializedFile import (
    FileIdentifier,
    LocalSerializedObjectIdentifier,
    SerializedType,
)
from UnityPy.helpers.Tpk import get_typetree_node
from UnityPy.helpers.TypeTreeHelper import FUNCTION_WRITE_MAP

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "fixtures", "external"))


def seed_serialized(version, unity, platform=19):
    """An empty SerializedFile (all tables empty), padded past UnityPy's
    128-byte minimum."""
    meta = unity.encode() + b"\0" + struct.pack("<i", platform)
    if version >= 13:
        meta += b"\x01"  # type trees enabled
    meta += struct.pack("<i", 0)  # types
    if 7 <= version < 14:
        meta += struct.pack("<i", 0)  # big IDs
    meta += struct.pack("<i", 0)  # objects
    if version >= 11:
        meta += struct.pack("<i", 0)  # script types
    meta += struct.pack("<i", 0)  # externals
    if version >= 20:
        meta += struct.pack("<i", 0)  # ref types
    meta += b"\0"  # user information
    if version >= 22:
        head = 48
        data_offset = (head + len(meta) + 15) // 16 * 16
        size = max(data_offset, 160)
        out = struct.pack(">IIII", 0, 0, version, 0) + b"\0\0\0\0"
        out += struct.pack(">IQQQ", len(meta), size, data_offset, 0)
    else:
        head = 20
        data_offset = (head + len(meta) + 15) // 16 * 16
        size = max(data_offset, 160)
        out = struct.pack(">IIII", len(meta), size, version, data_offset) + b"\0\0\0\0"
    out += meta
    return out + b"\0" * (size - len(out))


def seed_unityfs(version, unity, cab, serialized):
    """An uncompressed UnityFS bundle holding one file."""
    info = b"\0" * 16
    info += struct.pack(">i", 1) + struct.pack(">IIH", len(serialized), len(serialized), 0x40)
    info += struct.pack(">i", 1) + struct.pack(">qqI", 0, len(serialized), 4) + cab.encode() + b"\0"
    head = b"UnityFS\0" + struct.pack(">I", version) + b"5.x.x\0" + unity.encode() + b"\0"
    rest = struct.pack(">IIIq", 0, 0, 0, 0)  # placeholder, rebuilt below
    head_len = len(head) + 20
    pad = (-head_len) % 16 if version >= 7 else 0
    total = head_len + pad + len(info) + len(serialized)
    rest = struct.pack(">qIII", total, len(info), len(info), 0x40)
    return head + rest + b"\0" * pad + info + serialized


def seed_unityraw(unity, cab, serialized):
    """An uncompressed version 3 UnityRaw bundle holding one file."""
    names = struct.pack(">i", 1) + cab.encode() + b"\0" + struct.pack(">II", 0, 0)
    pad = (-len(names)) % 4
    first = len(names) + pad
    names = struct.pack(">i", 1) + cab.encode() + b"\0" + struct.pack(">II", first, len(serialized))
    body = names + b"\0" * pad + serialized
    head = b"UnityRaw\0" + struct.pack(">I", 3) + b"3.x.x\0" + unity.encode() + b"\0"
    header_size = (len(head) + 32 + 3) // 4 * 4
    head += struct.pack(">IIIi", header_size + len(body), header_size, 1, 1)
    head += struct.pack(">II", len(body), len(body))
    head += struct.pack(">II", header_size + len(body), first)
    head += b"\0" * (header_size - len(head))
    return head + body


def default(node):
    """A zero value for every field of a type tree (UnityPy wants them all)."""
    if node.m_Type in FUNCTION_WRITE_MAP:
        return {"string": "", "TypelessData": b"", "bool": False, "float": 0.0, "double": 0.0}.get(node.m_Type, 0)
    if node.m_Type == "pair":
        return (default(node.m_Children[0]), default(node.m_Children[1]))
    if node.m_Children and node.m_Children[0].m_Type == "Array":
        return []
    return {c.m_Name: default(c) for c in node.m_Children}


class Builder:
    """Adds types and objects to a parsed (seed) SerializedFile."""

    def __init__(self, sf):
        self.sf = sf
        self.by_class = {}

    def type_index(self, class_id, script_index=-1, script_id=None):
        key = (class_id, script_index)
        if key in self.by_class:
            return self.by_class[key]
        sf = self.sf
        v = sf.header.version
        t = SerializedType.__new__(SerializedType)
        t.__attrs_init__(class_id)
        t.is_stripped_type = False if v >= 16 else None
        t.script_type_index = script_index
        t.script_id = script_id if (v >= 16 and class_id == 114) else None
        if v < 16 and class_id < 0:
            t.script_id = script_id
        t.old_type_hash = bytes(range(16)) if v >= 13 else None
        t.node = get_typetree_node(class_id, sf.version)
        # The database leaves out what only serialized trees carry: the
        # is-array flag and the (zero) reference type hash.
        for n in t.node.traverse():
            n.m_TypeFlags = 1 if n.m_Type == "Array" else 0
            n.m_RefTypeHash = 0
        t.type_dependencies = () if v >= 21 else None
        sf.types.append(t)
        index = len(sf.types) - 1 if v >= 16 else class_id
        self.by_class[key] = index
        return index

    def add(self, class_id, path_id, fields, script_index=-1, script_id=None):
        sf = self.sf
        type_id = self.type_index(class_id, script_index, script_id)
        typ = sf.types[type_id] if sf.header.version >= 16 else next(t for t in sf.types if t.class_id == class_id)
        obj = ObjectReader(
            sf, sf.reader, path_id, type_id, typ, class_id, ClassIDType(class_id), 0, 0,
            0 if sf.header.version < 11 else None,
            0 if sf.header.version in (15, 16) else None,
        )
        value = default(typ.node)
        value.update(fields)
        obj.save_typetree(value)
        sf.objects[path_id] = obj
        return obj

    def external(self, path, kind=0):
        e = FileIdentifier.__new__(FileIdentifier)
        e.temp_empty = ""
        e.guid = bytes(16) if kind == 0 else bytes.fromhex("0000000000000000f000000000000000")
        e.type = kind
        e.path = path
        self.sf.externals.append(e)

    def script(self, file_index, path_id):
        s = LocalSerializedObjectIdentifier.__new__(LocalSerializedObjectIdentifier)
        s.local_serialized_file_index = file_index
        s.local_identifier_in_file = path_id
        self.sf.script_types.append(s)


def pptr(path_id, file_id=0):
    return {"m_FileID": file_id, "m_PathID": path_id}


def load_one(data):
    env = UnityPy.load(data)
    return env


def write(path, data):
    path = os.path.join(ROOT, path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    print(path, len(data))


def check(data, expect):
    """Reads `data` back with UnityPy and compares object names."""
    env = UnityPy.load(data)
    names = sorted(
        (o.path_id, o.type.name, o.peek_name() or "")
        for o in env.objects
    )
    assert names == sorted(expect), (names, expect)


def fill_main(sf, cab, with_texture=True, with_script=True):
    b = Builder(sf)
    res = f"archive:/{cab}/{cab}.resS"
    objects = []
    container = [("assets/readme.txt", {"preloadIndex": 0, "preloadSize": 1, "asset": pptr(2)})]
    b.add(49, 2, {"m_Name": "readme", "m_Script": "Hello from fillyfoal.\nUnity TextAsset, written by UnityPy.\n"})
    objects.append((2, "TextAsset", "readme"))
    b.add(1, 4, {"m_Name": "Player", "m_Layer": 0, "m_IsActive": True, "m_Tag": 0})
    objects.append((4, "GameObject", "Player"))
    if with_texture:
        # A TextAsset holding a document long enough to be shown as a file.
        levels = ",\n".join(
            f'    {{"name": "level{i}", "width": {16 * i}, "height": {9 * i}, "enemies": {i * 3}}}'
            for i in range(1, 6)
        )
        b.add(49, 7, {"m_Name": "levels", "m_Script": "{\n  \"levels\": [\n" + levels + "\n  ]\n}\n"})
        objects.append((7, "TextAsset", "levels"))
        container.append(("assets/levels.json", {"preloadIndex": 0, "preloadSize": 1, "asset": pptr(7)}))
        b.add(28, 3, {
            "m_Name": "checker", "m_Width": 4, "m_Height": 4, "m_CompleteImageSize": 64,
            "m_TextureFormat": 4, "m_MipCount": 1, "m_IsReadable": True, "m_ImageCount": 1,
            "m_TextureDimension": 2,
            "m_StreamData": {"offset": 0, "size": 64, "path": res},
        })
        objects.append((3, "Texture2D", "checker"))
        container.append(("assets/checker.png", {"preloadIndex": 0, "preloadSize": 1, "asset": pptr(3)}))
    if with_script:
        b.script(0, 6)
        b.add(115, 6, {"m_Name": "Spinner", "m_ClassName": "Spinner", "m_Namespace": "Demo", "m_AssemblyName": "Assembly-CSharp.dll"})
        objects.append((6, "MonoScript", "Spinner"))
        b.add(114, 5, {"m_Name": "", "m_GameObject": pptr(4), "m_Enabled": 1, "m_Script": pptr(6)},
              script_index=0, script_id=bytes(range(16, 32)))
        objects.append((5, "MonoBehaviour", ""))
    b.add(142, 1, {
        "m_Name": "fixtures", "m_AssetBundleName": "fixtures",
        "m_PreloadTable": [pptr(2)] + ([pptr(3)] if with_texture else []),
        "m_Container": container,
        "m_MainAsset": {"preloadIndex": 0, "preloadSize": 0, "asset": pptr(0)},
        "m_RuntimeCompatibility": 1,
    })
    objects.append((1, "AssetBundle", "fixtures"))
    b.external("Library/unity default resources")
    return objects


def checker_pixels():
    out = b""
    for y in range(4):
        for x in range(4):
            out += b"\xff\xff\xff\xff" if (x + y) % 2 == 0 else b"\x20\x40\x80\xff"
    return out


def main():
    # 1. Unity 2022.3, UnityFS 8, SerializedFile 22, LZ4HC (blocks info at
    #    the end), a TextAsset, a Texture2D with pixels in a .resS file, a
    #    GameObject, a MonoBehaviour with its MonoScript, the AssetBundle.
    cab = "CAB-3f1d7c2a9b8e4d6f0a1b2c3d4e5f6071"
    unity = "2022.3.10f1"
    env = UnityPy.load(seed_unityfs(8, unity, cab, seed_serialized(22, unity)))
    bundle = env.file
    sf = bundle.files[cab]
    expect = fill_main(sf, cab)
    res = bundle.get_writeable_cab(f"{cab}.resS")
    res.write(checker_pixels())
    sf.mark_changed()
    data = bundle.save(packer="lz4hc")
    check(data, expect)
    write("unityfs/lz4hc.bundle", data)

    # 2. Unity 2018.4, UnityFS 6, SerializedFile 17, LZMA blocks info and data.
    cab = "CAB-0123456789abcdef0123456789abcdef"
    unity = "2018.4.36f1"
    env = UnityPy.load(seed_unityfs(6, unity, cab, seed_serialized(17, unity)))
    bundle = env.file
    sf = bundle.files[cab]
    expect = fill_main(sf, cab, with_texture=False, with_script=False)
    sf.mark_changed()
    data = bundle.save(packer="lzma")
    check(data, expect)
    write("unityfs/lzma.bundle", data)

    # 3. Unity 2020.3, UnityFS 7, SerializedFile 21, uncompressed.
    cab = "CAB-fedcba9876543210fedcba9876543210"
    unity = "2020.3.48f1"
    env = UnityPy.load(seed_unityfs(7, unity, cab, seed_serialized(21, unity)))
    bundle = env.file
    sf = bundle.files[cab]
    expect = fill_main(sf, cab, with_texture=False)
    sf.mark_changed()
    data = bundle.save(packer="none")
    check(data, expect)
    write("unityfs/plain.bundle", data)

    # 4. Unity 5.2, UnityRaw 3 and UnityWeb 3 (LZMA), SerializedFile 15.
    cab = "CAB-00112233445566778899aabbccddeeff"
    unity = "5.2.4f1"
    for sig, name in (("UnityRaw", "raw"), ("UnityWeb", "web")):
        env = UnityPy.load(seed_unityraw(unity, cab, seed_serialized(15, unity)))
        bundle = env.file
        bundle.signature = sig
        sf = bundle.files[cab]
        expect = fill_main(sf, cab, with_texture=False, with_script=False)
        sf.mark_changed()
        data = bundle.save()
        check(data, expect)
        write(f"unityfs/{name}.unity3d", data)

    # 5. A standalone serialized file (sharedassets), Unity 2019.4,
    #    SerializedFile 19.
    unity = "2019.4.40f1"
    env = UnityPy.load(seed_serialized(19, unity, platform=13))
    sf = env.file
    expect = fill_main(sf, "x", with_texture=False)
    expect = [e for e in expect if e[1] != "AssetBundle"]
    del sf.objects[1]
    data = sf.save()
    check(data, expect)
    write("unity-serialized/sharedassets0.assets", data)


if __name__ == "__main__":
    sys.exit(main())
