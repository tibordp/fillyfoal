"""Synthetic Unreal Engine paks with real indexes, for the versions and
codecs repak does not write:

- game.pak: version 3 (CompressionEncryption): a stored file and a file in
  two zlib blocks (absolute block offsets, method as a flag).
- v8a.pak: version 8 with four compression method names (the entry's method
  is a byte): a stored file, a file in two raw LZ4 blocks and a gzip file.
- v9.pak: version 9 (FrozenIndex, with the frozen-index byte clear): the
  same files, the method a u32.
- v11.pak: version 11 with five method names: the v10+ index (encoded
  entries and a full directory index), a file in two gzip blocks, an LZ4
  file and a stored one.

    uv run --with lz4 python3 tests/data/unreal-pak/synthetic.py

Written from FPakInfo::Serialize, FPakEntry::Serialize and
FPakFile::EncodePakEntry in UE4/UE5's IPlatformFilePak and repak's
`pak.rs`/`entry.rs` (the readers our dissector follows): from v7 the
encryption key GUID and from v4 the encrypted-index byte come before the
magic; then version, index offset and size, the SHA-1 of the index, the
frozen-index byte (v9 only) and, from v8, 32-byte compression method names.
Each file's data is preceded by its FPakEntry (with offset 0); from v5
block offsets count from the entry's offset.
"""

import gzip
import hashlib
import os
import struct
import zlib

import lz4.block

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "..", "fixtures", "synthetic", "unreal-pak")
BLOCK = 0x10000

INI = b"[/Script/EngineSettings.GeneralProjectSettings]\nProjectName=fillyfoal\n"
README = b"A synthetic pak for the fillyfoal tests.\n" * 3
LEVEL = b"0123456789abcdef" * 5120  # 80 KiB: two 64 KiB blocks


def fstring(s):
    b = s.encode() + b"\0"
    return struct.pack("<i", len(b)) + b


def compress(codec, data):
    if codec == "zlib":
        return zlib.compress(data, 9)
    if codec == "gzip":
        return gzip.compress(data, 9, mtime=0)
    if codec == "lz4":
        return lz4.block.compress(data, store_size=False)
    raise ValueError(codec)


class Pak:
    def __init__(self, version, methods):
        self.version = version
        self.methods = methods  # names (v8+), or None
        self.narrow = version == 8 and len(methods) == 4
        self.data = b""
        self.entries = []  # (path, entry fields)

    def method_id(self, codec):
        if codec is None:
            return 0
        if self.version < 8:
            return {"zlib": 1, "gzip": 2}[codec]
        names = [m.lower() for m in self.methods]
        return names.index(codec) + 1

    def entry(self, offset, stored, size, method, blocks, digest):
        e = struct.pack("<QQQ", offset, stored, size)
        e += struct.pack("<B" if self.narrow else "<I", method)
        if self.version == 1:
            e += struct.pack("<Q", 0)
        e += digest
        if self.version >= 3:
            if method:
                e += struct.pack("<I", len(blocks))
                for start, end in blocks:
                    e += struct.pack("<QQ", start, end)
            e += struct.pack("<BI", 0, BLOCK if method else 0)
        return e

    def add(self, path, content, codec=None):
        method = self.method_id(codec)
        parts = [content[i:i + BLOCK] for i in range(0, len(content), BLOCK)] or [b""]
        packed = [compress(codec, p) for p in parts] if codec else [content]
        stored = sum(len(p) for p in packed)
        offset = len(self.data)
        digest = hashlib.sha1(b"".join(packed)).digest()
        # The header's size is known before its block offsets are.
        dummy = [(0, 0)] * len(packed) if codec else []
        header_len = len(self.entry(0, 0, 0, method, dummy, digest))
        base = 0 if self.version >= 5 else offset
        blocks, at = [], header_len
        for p in packed:
            blocks.append((base + at, base + at + len(p)))
            at += len(p)
        if not codec:
            blocks = []
        self.data += self.entry(0, stored, len(content), method, blocks, digest)
        self.data += b"".join(packed)
        self.entries.append(
            dict(path=path, offset=offset, stored=stored, size=len(content),
                 method=method, blocks=blocks, digest=digest, packed=packed)
        )

    def index_v1(self):
        index = fstring("../../../") + struct.pack("<I", len(self.entries))
        for e in self.entries:
            index += fstring(e["path"])
            index += self.entry(e["offset"], e["stored"], e["size"], e["method"],
                                e["blocks"], e["digest"])
        return index

    def encoded(self, e):
        """FPakFile::EncodePakEntry."""
        count = len(e["blocks"])
        bits = (BLOCK >> 11) if e["method"] else 0
        bits |= count << 6
        bits |= e["method"] << 23
        small = lambda v: v <= 0xFFFFFFFF
        bits |= int(small(e["stored"])) << 29
        bits |= int(small(e["size"])) << 30
        bits |= int(small(e["offset"])) << 31
        out = struct.pack("<I", bits)
        for v, bit in ((e["offset"], 31), (e["size"], 30)):
            out += struct.pack("<I" if bits >> bit & 1 else "<Q", v)
        if e["method"]:
            out += struct.pack("<I" if bits >> 29 & 1 else "<Q", e["stored"])
        if count > 1:
            for p in e["packed"]:
                out += struct.pack("<I", len(p))
        return out

    def index_v10(self, index_offset):
        encoded, offsets = b"", []
        for e in self.entries:
            offsets.append(len(encoded))
            encoded += self.encoded(e)
        dirs = {}
        for e, off in zip(self.entries, offsets):
            d, _, name = e["path"].rpartition("/")
            dirs.setdefault(d + "/" if d else "/", []).append((name, off))
        directory = struct.pack("<I", len(dirs))
        for d in sorted(dirs):
            directory += fstring(d) + struct.pack("<I", len(dirs[d]))
            for name, off in dirs[d]:
                directory += fstring(name) + struct.pack("<i", off)
        head = fstring("../../../") + struct.pack("<I", len(self.entries))
        head += struct.pack("<Q", 0)  # path hash seed
        head += struct.pack("<I", 0)  # no path hash index
        size_without_dir = len(head) + 4 + 8 + 8 + 20 + 4 + len(encoded) + 4
        dir_offset = index_offset + size_without_dir
        head += struct.pack("<IQQ", 1, dir_offset, len(directory))
        head += hashlib.sha1(directory).digest()
        head += struct.pack("<I", len(encoded)) + encoded
        head += struct.pack("<I", 0)  # irregular entries
        assert len(head) == size_without_dir
        return head, directory

    def build(self, frozen_byte=False):
        offset = len(self.data)
        if self.version >= 10:
            index, extra = self.index_v10(offset)
        else:
            index, extra = self.index_v1(), b""
        info = b""
        if self.version >= 7:
            info += b"\x11" * 16  # encryption key GUID
        if self.version >= 4:
            info += b"\0"  # encrypted index
        info += struct.pack("<IIQQ", 0x5A6F12E1, self.version, offset, len(index))
        info += hashlib.sha1(index).digest()
        if frozen_byte:
            info += b"\0"
        for name in self.methods or []:
            info += name.encode().ljust(32, b"\0")
        return self.data + index + extra + info


def main():
    os.makedirs(OUT, exist_ok=True)
    files = {}

    p = Pak(3, None)
    p.add("Game/Config/DefaultGame.ini", INI)
    p.add("Game/Content/Maps/Level.txt", LEVEL, "zlib")
    files["game.pak"] = p.build()

    p = Pak(8, ["Zlib", "Gzip", "LZ4", ""])
    p.add("Game/Config/DefaultGame.ini", INI)
    p.add("Game/Content/Maps/Level.txt", LEVEL, "lz4")
    p.add("Game/Content/readme.txt", README, "gzip")
    files["v8a.pak"] = p.build()

    p = Pak(9, ["Zlib", "Gzip", "LZ4", "", ""])
    p.add("Game/Config/DefaultGame.ini", INI)
    p.add("Game/Content/Maps/Level.txt", LEVEL, "gzip")
    p.add("Game/Content/readme.txt", README, "lz4")
    files["v9.pak"] = p.build(frozen_byte=True)

    p = Pak(11, ["Zlib", "Gzip", "LZ4", "", ""])
    p.add("Game/Config/DefaultGame.ini", INI)
    p.add("Game/Content/Maps/Level.txt", LEVEL, "gzip")
    p.add("Game/Content/readme.txt", README, "lz4")
    files["v11.pak"] = p.build()

    for name, content in files.items():
        with open(os.path.join(OUT, name), "wb") as f:
            f.write(content)


if __name__ == "__main__":
    main()
