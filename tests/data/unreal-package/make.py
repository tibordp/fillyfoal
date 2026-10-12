#!/usr/bin/env python3
"""Writes the synthetic Unreal package fixtures in tests/fixtures/synthetic/unreal-package/.

There is no open writer for Unreal packages, so these are laid out by hand
in the order UModel (UnPackage3.cpp, FPackageFileSummary::Serialize3) and
UAssetAPI (UAsset.ReadHeader/WriteHeader, Import, Export map entries) read
them:

- udk.upk: UE3 (file version 868, UDK), with the FolderName FString that
  UE3 stores between the header size and the package flags from v269.
- ue4.uasset: UE 4.27 editor package (legacy version -7, UE4 522).
- ue5.uasset: UE 5.1-style cooked package (legacy -8, UE4 522, UE5 1012).
- unversioned.uasset: cooked with -unversioned (all versions 0).

Usage: make.py OUTDIR
"""
import struct
import sys
import uuid
from pathlib import Path

TAG = 0x9E2A83C1


def i32(v):
    return struct.pack("<i", v)


def u32(v):
    return struct.pack("<I", v)


def i64(v):
    return struct.pack("<q", v)


def fstring(s):
    if s is None:
        return i32(0)
    b = s.encode("latin-1") + b"\0"
    return i32(len(b)) + b


def guid(n):
    return uuid.UUID(int=n).bytes_le


# ---------------------------------------------------------------------------
# UE3


def ue3_package():
    version = 868
    names = ["None", "Core", "Package", "Class", "TestPackage", "Texture2D", "Crate"]
    name_table = b"".join(fstring(n) + struct.pack("<Q", 0x0007001000000000) for n in names)

    def summary(name_off, export_off, import_off, depends_off, header):
        out = u32(TAG) + u32(version)
        out += i32(header)  # TotalHeaderSize (v249+)
        out += fstring("None")  # FolderName / PackageGroup (v269+)
        out += u32(0x00000001)  # PackageFlags: AllowDownload
        out += i32(len(names)) + i32(name_off)
        out += i32(1) + i32(export_off)
        out += i32(2) + i32(import_off)
        out += i32(depends_off)  # v415+
        out += i32(0) + i32(0) + i32(0)  # import/export guids (v623+)
        out += i32(0)  # thumbnail table offset (v584+)
        out += guid(0x0123456789ABCDEF0011223344556677)
        out += i32(1) + i32(1) + i32(len(names)) + i32(0)  # one generation (v322+: net objects)
        out += i32(12791)  # engine version (v245+)
        out += i32(136)  # cooker version (v277+)
        out += u32(0) + i32(0)  # compression flags, compressed chunks (v334+)
        out += u32(0)  # U3unk60 (v482+)
        return out

    size = len(summary(0, 0, 0, 0, 0))
    name_off = size
    import_off = name_off + len(name_table)
    # FObjectImport in UE3: ClassPackage, ClassName (FNames), PackageIndex, ObjectName.
    imports = (
        i32(1) + i32(0) + i32(2) + i32(0) + i32(0) + i32(4) + i32(0)  # Core.Package TestPackage
        + i32(1) + i32(0) + i32(3) + i32(0) + i32(-1) + i32(5) + i32(0)  # Core.Class Texture2D
    )
    export_off = import_off + len(imports)
    exports = b"\0" * 68
    depends_off = export_off + len(exports)
    depends = i32(0)
    header = depends_off + len(depends)
    out = summary(name_off, export_off, import_off, depends_off, header)
    assert len(out) == size
    return out + name_table + imports + exports + depends


# ---------------------------------------------------------------------------
# UE4/5

NAMES = [
    "/Game/Props/Crate",
    "/Script/CoreUObject",
    "/Script/Engine",
    "Class",
    "Crate",
    "Default__StaticMesh",
    "None",
    "Package",
    "StaticMesh",
]
N = {n: i for i, n in enumerate(NAMES)}


def name_entry(s):
    # FString and the two 16-bit hashes (VER_UE4_NAME_HASHES_SERIALIZED, 504).
    return fstring(s) + struct.pack("<HH", 0x1234, 0x5678)


def fname(s, number=0):
    return i32(N[s]) + i32(number)


def engine_version(major, minor, patch, changelist, branch):
    return struct.pack("<HHHI", major, minor, patch, changelist) + fstring(branch)


def ue4_summary(legacy, ue4, ue5, flags, t, unversioned=False):
    """FPackageFileSummary, as UAssetAPI's ReadHeader reads it. `t` holds the
    table offsets (filled in on a second pass)."""
    editor = not flags & 0x80000000
    out = u32(TAG) + i32(legacy)
    if legacy != -4:
        out += i32(0 if unversioned else 864)
    out += i32(ue4)
    if legacy <= -8:
        out += i32(ue5)
    out += i32(0)  # licensee
    # Custom versions (optimized format from legacy -6: GUID + version).
    customs = [] if unversioned else [(0x29E575DDE0A346279D10D276232CDCEA, 17), (0xE4B068EDF49442E9A231DA0B2E46BB41, 40)]
    out += i32(len(customs)) + b"".join(guid(g) + i32(v) for g, v in customs)
    out += i32(t["header"])
    out += fstring("None" if not unversioned else "/Game/Props/Crate")
    out += u32(flags)
    out += i32(len(NAMES)) + i32(t["names"])
    if unversioned:
        return out
    if ue5 >= 1008:
        out += i32(0) + i32(0)  # soft object paths
    if editor and ue4 >= 516:
        out += fstring("0123456789ABCDEF0123456789ABCDEF")  # localization ID
    if ue4 >= 459:
        out += i32(0) + i32(0)  # gatherable text data
    out += i32(t["nexports"]) + i32(t["exports"])
    out += i32(t["nimports"]) + i32(t["imports"])
    out += i32(t["depends"])
    if ue4 >= 384:
        out += i32(0) + i32(0)  # soft package references
    if ue4 >= 510:
        out += i32(0)  # searchable names
    out += i32(0)  # thumbnail table
    out += guid(0x8E1D2F3A4B5C6D7E8F90A1B2C3D4E5F6)  # package GUID (before UE5 1016)
    if editor and ue4 >= 518:
        out += guid(0x11111111222233334444555555555555)  # persistent GUID
    out += i32(1) + i32(t["nexports"]) + i32(len(NAMES))  # one generation
    out += engine_version(4 if ue5 == 0 else 5, 27 if ue5 == 0 else 1, 2, 18319896, "++UE4+Release-4.27" if ue5 == 0 else "++UE5+Release-5.1")
    out += engine_version(4 if ue5 == 0 else 5, 27 if ue5 == 0 else 1, 0, 18319896, "++UE4+Release-4.27" if ue5 == 0 else "++UE5+Release-5.1")
    out += u32(0) + i32(0)  # compression flags, compressed chunks
    out += u32(0x0BADF00D)  # package source
    out += i32(0)  # additional packages to cook
    if legacy > -7:
        out += i32(0)  # texture allocations
    out += i32(t["registry"])  # asset registry data offset
    out += i64(t["bulk"])  # bulk data start
    out += i32(0)  # world tile info
    out += i32(0)  # chunk IDs
    out += i32(t["preload"]) + i32(t["preload_off"])
    if ue5 >= 1001:
        out += i32(len(NAMES))
    if ue5 >= 1002:
        out += i64(-1)
    if ue5 >= 1009:
        out += i32(-1)
    return out


def imports(ue4, ue5, editor):
    rows = [
        # class package, class name, outer, object name, package name
        ("/Script/CoreUObject", "Package", 0, "/Script/Engine", "None"),
        ("/Script/CoreUObject", "Class", -1, "StaticMesh", "None"),
        ("/Script/Engine", "StaticMesh", -1, "Default__StaticMesh", "None"),
    ]
    out = b""
    for package, cls, outer, obj, pkg in rows:
        out += fname(package) + fname(cls) + i32(outer) + fname(obj)
        if ue4 >= 520 and editor:
            out += fname(pkg)
        if ue5 >= 1003:
            out += i32(0)
    return out, len(rows)


def export(ue4, ue5, flags, size, offset):
    out = i32(-2)  # class: import 1 (StaticMesh)
    out += i32(0)  # super
    if ue4 >= 508:
        out += i32(-3)  # template: Default__StaticMesh
    out += i32(0)  # outer
    out += fname("Crate")
    out += u32(0x00000009)  # RF_Public | RF_Transactional
    out += i64(size) + i64(offset) if ue4 >= 511 else i32(size) + i32(offset)
    out += i32(0) + i32(0) + i32(0)  # forced export, not for client, not for server
    if ue5 < 1005:
        out += guid(0)
    if ue5 >= 1006:
        out += i32(0)
    out += u32(0)  # package flags
    if ue4 >= 365:
        out += i32(0)
    if ue4 >= 485:
        out += i32(1)  # is asset
    if ue5 >= 1003:
        out += i32(0)
    if ue4 >= 507:
        out += i32(-1) + i32(0) + i32(0) + i32(0) + i32(0)
    if not flags & 0x2000 and ue5 >= 1010:
        out += i64(0) + i64(size)
    return out


def ue4_package(legacy, ue4, ue5, flags, unversioned=False):
    editor = not flags & 0x80000000
    payload = b"\x00\x00\x00\x00" + b"CRATEDATA" * 4 + b"\xc1\x83\x2a\x9e"  # property stream stand-in
    t = dict(header=0, names=0, nexports=1, exports=0, nimports=0, imports=0, depends=0,
             registry=0, bulk=0, preload=0, preload_off=0)
    for _ in range(2):
        out = ue4_summary(legacy, ue4, ue5, flags, t, unversioned)
        t["names"] = len(out)
        out += b"".join(name_entry(n) for n in NAMES)
        if unversioned:
            t["header"] = len(out)
            continue
        imp, n = imports(ue4, ue5, editor)
        t["imports"], t["nimports"] = len(out), n
        out += imp
        t["exports"] = len(out)
        out += export(ue4, ue5, flags, len(payload), t["header"])
        t["depends"] = len(out)
        out += i32(0)  # depends map: one empty array per export
        t["registry"] = len(out)
        out += i32(0)  # asset registry: no objects
        t["preload_off"] = len(out)
        t["header"] = len(out)
        t["bulk"] = len(out) + len(payload)
    body = payload + u32(TAG)  # every package file ends with the tag
    return out + body


def main():
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    (out / "udk.upk").write_bytes(ue3_package())
    (out / "ue4.uasset").write_bytes(ue4_package(-7, 522, 0, 0))
    (out / "ue5.uasset").write_bytes(ue4_package(-8, 522, 1012, 0x80000200))
    (out / "unversioned.uasset").write_bytes(ue4_package(-8, 0, 0, 0x80002200, unversioned=True))


if __name__ == "__main__":
    main()
