"""Synthetic .NET serialization fixtures, written from memory of the formats.

No .NET SDK was available, so these files come from our own understanding of
ResourceWriter (.resources), MS-NRBF (BinaryFormatter) and ECMA-335 (a tiny
managed DLL carrying manifest resources). They are regression fixtures, not
conformance evidence.

    python3 tests/data/dotnet-resources/make.py

writes
    tests/fixtures/synthetic/dotnet-resources/{Strings,Mixed,Legacy}.resources
    tests/fixtures/synthetic/nrbf/object.nrbf
    tests/fixtures/synthetic/pe/managed.dll
"""

import os
import struct
import zlib

ROOT = os.path.join(os.path.dirname(__file__), "..", "..", "fixtures", "synthetic")


def out(rel, data):
    path = os.path.join(ROOT, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def enc7(n):
    n &= 0xFFFFFFFF
    b = bytearray()
    while n >= 0x80:
        b.append((n & 0x7F) | 0x80)
        n >>= 7
    b.append(n)
    return bytes(b)


def bwstr(s):
    """BinaryWriter.Write(string): 7-bit byte count, UTF-8."""
    raw = s.encode("utf-8")
    return enc7(len(raw)) + raw


def png(w=2, h=2, rgb=(0x20, 0x80, 0xE0)):
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))

    raw = b"".join(b"\0" + bytes(rgb) * w for _ in range(h))
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


# ---------------------------------------------------------------------------
# MS-NRBF


def lps(s):
    return bwstr(s)


def nrbf_header(root=1):
    return b"\x00" + struct.pack("<iiii", root, -1, 1, 0)


def nrbf_point():
    """A System.Drawing.Point(3, 4), as BinaryFormatter writes it."""
    lib = "System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"
    return (
        nrbf_header(1)
        + b"\x0c" + struct.pack("<i", 2) + lps(lib)
        + b"\x05" + struct.pack("<i", 1) + lps("System.Drawing.Point")
        + struct.pack("<i", 2) + lps("x") + lps("y")
        + b"\x00\x00" + b"\x08\x08"
        + struct.pack("<i", 2)
        + struct.pack("<ii", 3, 4)
        + b"\x0b"
    )


def nrbf_rich():
    """A made-up class graph exercising most record types."""
    lib = "Filly.Model, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null"
    d = nrbf_header(1)
    d += b"\x0c" + struct.pack("<i", 2) + lps(lib)
    # Filly.Model.Pony: Name (String), Age (Int32), Born (DateTime), Mane
    # (Class Filly.Model.Colour), Tags (StringArray), Scores (PrimitiveArray
    # Double), Icon (PrimitiveArray Byte), Friend (Object), Parent (Class).
    members = ["Name", "Age", "Born", "Mane", "Tags", "Scores", "Icon", "Friend", "Parent"]
    d += b"\x05" + struct.pack("<i", 1) + lps("Filly.Model.Pony") + struct.pack("<i", len(members))
    d += b"".join(lps(m) for m in members)
    d += bytes([1, 0, 0, 4, 6, 7, 7, 2, 4])
    d += b"\x08"  # Age: Int32
    d += b"\x0d"  # Born: DateTime
    d += lps("Filly.Model.Colour") + struct.pack("<i", 2)  # Mane
    d += b"\x06"  # Scores: Double[]
    d += b"\x02"  # Icon: Byte[]
    d += lps("Filly.Model.Pony") + struct.pack("<i", 2)  # Parent
    d += struct.pack("<i", 2)  # library
    # values
    d += b"\x06" + struct.pack("<i", 3) + lps("Filly")  # Name
    d += struct.pack("<i", 7)  # Age
    ticks = 637_134_336_000_000_000  # 2020-01-01T00:00:00Z
    d += struct.pack("<q", ticks | (1 << 62))  # Born, UTC
    # Mane: Filly.Model.Colour { R, G, B : Byte }
    d += b"\x05" + struct.pack("<i", 4) + lps("Filly.Model.Colour") + struct.pack("<i", 3)
    d += lps("R") + lps("G") + lps("B") + b"\x00\x00\x00" + b"\x02\x02\x02" + struct.pack("<i", 2)
    d += bytes([0xFF, 0x80, 0x00])
    d += b"\x09" + struct.pack("<i", 5)  # Tags -> #5
    d += b"\x09" + struct.pack("<i", 6)  # Scores -> #6
    d += b"\x09" + struct.pack("<i", 7)  # Icon -> #7
    d += b"\x08\x12" + lps("a boxed string")  # Friend: MemberPrimitiveTyped String
    # Parent: a second Pony reusing the metadata (ClassWithId)
    d += b"\x01" + struct.pack("<ii", 8, 1)
    d += b"\x06" + struct.pack("<i", 9) + lps("Mother")
    d += struct.pack("<i", 12)
    d += struct.pack("<q", 630_822_816_000_000_000)  # 2000-01-01, unspecified
    d += b"\x09" + struct.pack("<i", 4)  # same mane
    d += b"\x0a"  # Tags null
    d += b"\x0a"  # Scores null
    d += b"\x0a"  # Icon null
    d += b"\x0a"  # Friend null
    d += b"\x0a"  # Parent null
    # deferred objects
    d += b"\x11" + struct.pack("<ii", 5, 4)
    d += b"\x06" + struct.pack("<i", 10) + lps("small")
    d += b"\x06" + struct.pack("<i", 11) + lps("pink")
    d += b"\x0d\x02"  # two nulls
    d += b"\x0f" + struct.pack("<ii", 6, 3) + b"\x06" + struct.pack("<ddd", 1.5, 2.25, -3.0)
    icon = png()
    d += b"\x0f" + struct.pack("<ii", 7, len(icon)) + b"\x02" + icon
    # A rectangular Int32[2,2] (BinaryArray), unreferenced.
    d += b"\x07" + struct.pack("<i", 12) + b"\x02" + struct.pack("<iii", 2, 2, 2) + b"\x00\x08"
    d += struct.pack("<iiii", 1, 2, 3, 4)
    # An untyped system class: System.Collections.DictionaryEntry-like.
    d += b"\x02" + struct.pack("<i", 13) + lps("System.Collections.DictionaryEntry")
    d += struct.pack("<i", 2) + lps("key") + lps("value")
    d += b"\x06" + struct.pack("<i", 14) + lps("k")
    d += b"\x08\x08" + struct.pack("<i", 42)
    d += b"\x0b"
    return d


# ---------------------------------------------------------------------------
# .resources


def name_hash(name):
    h = 5381
    for i in range(0, len(name.encode("utf-16-le")), 2):
        c = struct.unpack_from("<H", name.encode("utf-16-le"), i)[0]
        h = (((h << 5) + h) ^ c) & 0xFFFFFFFF
    return h


def signed(h):
    return h - (1 << 32) if h & 0x80000000 else h


READER = "System.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
SET = "System.Resources.RuntimeResourceSet"


def resources(items, version=2, types=()):
    """items: list of (name, encoded value bytes including the type code)."""
    hdr = bwstr(READER) + bwstr(SET)
    out_ = struct.pack("<III", 0xBEEFCACE, 1, len(hdr)) + hdr
    out_ += struct.pack("<iii", version, len(items), len(types))
    for t in types:
        out_ += bwstr(t)
    i = 0
    while len(out_) & 7:
        out_ += b"PAD"[i % 3 : i % 3 + 1]
        i += 1
    items = sorted(items, key=lambda kv: kv[0])  # ordinal for ASCII names
    names = b""
    data = b""
    entries = []
    for name, value in items:
        entries.append((signed(name_hash(name)), len(names)))
        raw = name.encode("utf-16-le")
        names += enc7(len(raw)) + raw + struct.pack("<i", len(data))
        data += value
    entries.sort()
    out_ += b"".join(struct.pack("<i", h) for h, _ in entries)
    out_ += b"".join(struct.pack("<i", p) for _, p in entries)
    data_offset = len(out_) + 4 + len(names)
    out_ += struct.pack("<i", data_offset) + names + data
    return out_


def v_string(s):
    return enc7(1) + bwstr(s)


def mixed():
    from datetime import datetime, timezone

    epoch = datetime(1, 1, 1, tzinfo=timezone.utc)
    dt = datetime(2024, 2, 29, 12, 30, 15, tzinfo=timezone.utc)
    ticks = (dt - epoch) // __import__("datetime").timedelta(microseconds=1) * 10
    icon = png(3, 1, (0xF0, 0x40, 0x80))
    items = [
        ("Greeting", v_string("Hello, filly!")),
        ("Unicode", v_string("Žrebe – ポニー")),
        ("Flag", enc7(2) + b"\x01"),
        ("Letter", enc7(3) + struct.pack("<H", 0x263A)),
        ("Byte", enc7(4) + b"\xfe"),
        ("SByte", enc7(5) + struct.pack("<b", -2)),
        ("Short", enc7(6) + struct.pack("<h", -300)),
        ("UShort", enc7(7) + struct.pack("<H", 60000)),
        ("Int", enc7(8) + struct.pack("<i", -123456)),
        ("UInt", enc7(9) + struct.pack("<I", 4000000000)),
        ("Long", enc7(10) + struct.pack("<q", -(1 << 40))),
        ("ULong", enc7(11) + struct.pack("<Q", 1 << 63)),
        ("Single", enc7(12) + struct.pack("<f", 1.5)),
        ("Double", enc7(13) + struct.pack("<d", 3.141592653589793)),
        ("Price", enc7(14) + struct.pack("<IIII", 1999, 0, 0, 2 << 16)),
        ("When", enc7(15) + struct.pack("<q", ticks | (1 << 62))),
        ("Duration", enc7(16) + struct.pack("<q", 93_784_500_0000)),
        ("Nothing", enc7(0)),
        ("Icon", enc7(0x20) + struct.pack("<i", len(icon)) + icon),
        ("Blob", enc7(0x21) + struct.pack("<i", 5) + b"hello"),
        ("Origin", enc7(0x40) + nrbf_point()),
    ]
    types = ["System.Drawing.Point, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"]
    return resources(items, 2, types)


def legacy():
    """Version 1: values start with an index into the type table."""
    types = [
        "System.String, mscorlib, Version=1.0.5000.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Int32, mscorlib, Version=1.0.5000.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
    ]
    items = [
        ("Title", enc7(0) + bwstr("Legacy")),
        ("Count", enc7(1) + struct.pack("<i", 5)),
        ("Missing", enc7(0xFFFFFFFF)),
    ]
    return resources(items, 1, types)


# ---------------------------------------------------------------------------
# A minimal managed DLL with two manifest resources


def managed_dll(res_blobs):
    text_rva, file_align, sect_align = 0x2000, 0x200, 0x2000
    # Section contents, laid out from the start of .text.
    body = bytearray(8)  # import address table placeholder (unused)
    clr_at = len(body)
    body += bytes(72)
    # resources
    while len(body) % 8:
        body.append(0)
    res_at = len(body)
    resb = bytearray()
    offsets = []
    for name, blob in res_blobs:
        offsets.append(len(resb))
        resb += struct.pack("<I", len(blob)) + blob
        while len(resb) % 8:
            resb.append(0)
    body += resb
    # metadata
    while len(body) % 4:
        body.append(0)
    md_at = len(body)
    strings = bytearray(b"\0")

    def s(x):
        i = len(strings)
        strings.extend(x.encode() + b"\0")
        return i

    mod_name = s("managed.dll")
    asm_name = s("managed")
    obj = s("Object")
    sysns = s("System")
    modty = s("<Module>")
    mscorlib = s("mscorlib")
    res_names = [s(n) for n, _ in res_blobs]
    while len(strings) % 4:
        strings.append(0)
    guids = bytes(range(16))
    blob = b"\0\0\0\0"
    # tables: Module 0x00, TypeRef 0x01, TypeDef 0x02, Assembly 0x20,
    # AssemblyRef 0x23, ManifestResource 0x28
    present = [0x00, 0x01, 0x02, 0x20, 0x23, 0x28]
    valid = sum(1 << t for t in present)
    rows = {0x00: 1, 0x01: 1, 0x02: 1, 0x20: 1, 0x23: 1, 0x28: len(res_blobs)}
    t = struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, valid, 0)
    t += b"".join(struct.pack("<I", rows[i]) for i in present)
    t += struct.pack("<HHHHH", 0, mod_name, 1, 0, 0)  # Module
    t += struct.pack("<HHH", (1 << 2) | 2, obj, sysns)  # TypeRef: AssemblyRef 1
    t += struct.pack("<IHHHHH", 0, modty, 0, 0, 1, 1)  # TypeDef <Module>
    t += struct.pack("<IHHHHIHHH", 0x8004, 1, 0, 0, 0, 0, 0, asm_name, 0)  # Assembly
    t += struct.pack("<HHHHIHHHH", 4, 0, 0, 0, 0, 0, mscorlib, 0, 0)  # AssemblyRef
    for off, n in zip(offsets, res_names):
        t += struct.pack("<IIHH", off, 1, n, 0)  # ManifestResource, public
    while len(t) % 4:
        t += b"\0"
    version = b"v4.0.30319\0\0"
    streams = [(b"#~", t), (b"#Strings", bytes(strings)), (b"#GUID", guids), (b"#Blob", blob)]
    hdr_len = 16 + len(version) + 4
    for name, _ in streams:
        hdr_len += 8 + ((len(name) + 1 + 3) & ~3)
    md = struct.pack("<IHHII", 0x424A5342, 1, 1, 0, len(version)) + version + struct.pack("<HH", 0, len(streams))
    off = hdr_len
    for name, data in streams:
        n = name + b"\0"
        n += b"\0" * ((4 - len(n) % 4) % 4)
        md += struct.pack("<II", off, len(data)) + n
        off += len(data)
    for _, data in streams:
        md += data
    body += md
    # CLR header
    clr = struct.pack(
        "<IHHIIIIII",
        72, 2, 5, text_rva + md_at, len(md), 1, 0, text_rva + res_at, len(resb),
    ) + bytes(72 - 32)
    assert len(clr) == 72
    body[clr_at : clr_at + 72] = clr
    raw_size = (len(body) + file_align - 1) // file_align * file_align
    # headers
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    dos += bytes(0x80 - 64)
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, 0x2102)
    opt = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIII",
        0x10B, 8, 0, raw_size, 0, 0, 0, text_rva, text_rva,
        0x10000000, sect_align, file_align, 4, 0, 0, 0, 4, 0, 0,
        text_rva + sect_align, 0x200, 0, 3, 0x8540, 0x100000, 0x1000, 0x100000, 0x1000, 0,
    ) + struct.pack("<I", 16)
    dirs = [(0, 0)] * 16
    dirs[14] = (text_rva + clr_at, 72)
    opt += b"".join(struct.pack("<II", a, b) for a, b in dirs)
    sect = struct.pack(
        "<8sIIIIIIHHI", b".text", len(body), text_rva, raw_size, 0x200, 0, 0, 0, 0, 0x60000020
    )
    headers = bytes(dos) + b"PE\0\0" + coff + opt + sect
    headers += bytes(0x200 - len(headers))
    return headers + bytes(body) + bytes(raw_size - len(body))


def main():
    strings = resources(
        [
            ("AppName", v_string("Filly")),
            ("Greeting", v_string("Hello, world")),
            ("Farewell", v_string("Goodbye")),
        ]
    )
    out("dotnet-resources/Strings.resources", strings)
    out("dotnet-resources/Mixed.resources", mixed())
    out("dotnet-resources/Legacy.resources", legacy())
    out("nrbf/object.nrbf", nrbf_rich())
    out(
        "pe/managed.dll",
        managed_dll([("Filly.Strings.resources", strings), ("Filly.logo.png", png(2, 2))]),
    )


if __name__ == "__main__":
    main()
