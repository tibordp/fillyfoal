"""Extracts the TempleOS document and graphics fixtures from the V5.03 ISO.

Usage: python3 extract.py TempleOS.ISO TOSZ OUTDIR

TempleOS.ISO is the official distribution image
(https://web.archive.org/web/2017id_/http://www.templeos.org/Downloads/TempleOS.ISO,
17,350,656 bytes, SHA-256 5d0fc944...ba26). TOSZ is Terry Davis's own
expander, built from Linux/TOSZ.CPP of the same release
(`c++ -w -o tosz TOSZ.CPP`). TempleOS is in the public domain.

The ISO wraps a RedSea file system whose boot record is at byte 0xB000;
block numbers in its directory entries are absolute 512-byte blocks,
offset by the drive's first block (88). Files are stored `.Z` compressed;
TOSZ expands them to the bytes TempleOS reads. The AutoComplete files are
cut to their first records (ACDefs is 26 MB expanded) and given back their
end marker; the compiler map to its first 12 links and their bins.
"""

import hashlib
import os
import struct
import subprocess
import sys
import tempfile

ISO_SHA256 = "5d0fc944e5d89c155c0fc17c148646715bc1db6fa5750c0b913772cfec19ba26"
BOOT = 0xB000

FILES = {
    "/Doc/FileLowLevel.DD.Z": "doldoc/FileLowLevel.DD",
    "/Doc/Once.DD.Z": "doldoc/Once.DD",
    "/Compiler/Compiler.MAP.Z": "doldoc/Compiler.MAP",
    "/Demo/Graphics/SpriteText.HC.Z": "holyc/SpriteText.HC",
    "/Demo/Graphics/SpritePlot3D.HC.Z": "holyc/SpritePlot3D.HC",
    "/Adam/AMouse.HC.Z": "holyc/AMouse.HC",
    "/Apps/GrModels/Load.HC.Z": "holyc/Load.HC",
    "/Demo/Games/Stadium/StadiumBG.GR.Z": "templeos-gr/StadiumBG.GR",
    "/Adam/AutoComplete/ACWords.DATA.Z": "templeos-ac-words/ACWords.DATA",
    "/Adam/AutoComplete/ACDefs.DATA.Z": "templeos-ac-defs/ACDefs.DATA",
}
WORDS_KEPT = 40
ENTRIES_KEPT = 11
MAP_LINES = 12


def walk(iso):
    drv_off, _sects, root = struct.unpack_from("<qqq", iso, BOOT + 8)
    files = {}

    def directory(block, size, path):
        off = (block - drv_off) * 512 + BOOT
        for i in range(1, size // 64):  # entry 0 is the directory itself
            e = iso[off + i * 64 : off + i * 64 + 64]
            name = e[2:40].split(b"\0")[0].decode("latin-1")
            if not name:
                break
            attr = struct.unpack_from("<H", e)[0]
            cluster, length = struct.unpack_from("<qq", e, 40)
            if name == "..":
                continue
            if attr & 0x10:
                directory(cluster, length, f"{path}/{name}")
            else:
                start = (cluster - drv_off) * 512 + BOOT
                files[f"{path}/{name}"] = iso[start : start + length]

    directory(root, 1 << 20, "")
    return files


def cut_words(data):
    pos = 0
    for _ in range(WORDS_KEPT):
        assert data[pos] == 1
        pos = data.index(b"\0", pos + 1) + 3
    return data[:pos] + b"\0"


def cut_defs(data):
    pos, words = 0, 0
    while True:
        if data[pos] == 1:
            if words == ENTRIES_KEPT:
                return data[:pos] + b"\0"
            words += 1
        pos = data.index(b"\0", pos + 1) + 1


def cut_map(data):
    """The first MAP_LINES links and the bins they refer to."""
    nul = data.index(b"\0")
    lines = data[:nul].split(b"\n")[:MAP_LINES]
    text = b"\n".join(lines) + b"\n"
    refs = {int(l.rsplit(b",BI=", 1)[1][:-1]) for l in lines if b",BI=" in l}
    out, pos = [text, b"\0"], nul + 1
    while pos + 16 <= len(data):
        num, _flags, size = struct.unpack_from("<III", data, pos)
        if num in refs:
            out.append(data[pos : pos + 16 + size])
        pos += 16 + size
    assert len(out) == len(refs) + 2
    return b"".join(out)


def main():
    iso_path, tosz, out = sys.argv[1:4]
    iso = open(iso_path, "rb").read()
    assert hashlib.sha256(iso).hexdigest() == ISO_SHA256, "not the V5.03 ISO"
    files = walk(iso)
    with tempfile.TemporaryDirectory() as tmp:
        for src, dst in FILES.items():
            z = os.path.join(tmp, "in.Z")
            raw = os.path.join(tmp, "in")
            open(z, "wb").write(files[src])
            # TOSZ writes NAME.Z expanded to NAME (and deletes NAME.Z).
            subprocess.run([tosz, z], check=True, stdout=subprocess.DEVNULL)
            data = open(raw, "rb").read()
            if dst.startswith("templeos-ac-words/"):
                data = cut_words(data)
            elif dst.endswith(".MAP"):
                data = cut_map(data)
            elif dst.startswith("templeos-ac-defs/"):
                data = cut_defs(data)
            target = os.path.join(out, dst)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            open(target, "wb").write(data)
            print(f"{dst}: {len(data)} bytes, sha256 {hashlib.sha256(data).hexdigest()}")


if __name__ == "__main__":
    main()
