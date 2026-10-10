"""Writes a small differencing VHDX ([MS-VHDX]; synthetic: QEMU does not
create or open differencing VHDX files): file type identifier, two headers,
two region tables, a metadata region with a parent locator, a BAT with a
fully present, a partially present, an absent and a zero block plus the
sector bitmap entry of the first chunk, the sector bitmap block and the
payload blocks.

usage: python3 vhdx-diff.py <out.vhdx>
"""

import struct
import sys
import uuid

KIB = 1024
MIB = 1024 * KIB
BLOCK = MIB
DISK = 4 * MIB
LOGICAL = 512
CHUNK_RATIO = (1 << 23) * LOGICAL // BLOCK


def crc32c(data):
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
        table.append(c)
    crc = 0xFFFFFFFF
    for b in data:
        crc = table[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def guid(text):
    return uuid.UUID(text).bytes_le


def with_crc(buf):
    buf = bytearray(buf)
    struct.pack_into("<I", buf, 4, 0)
    struct.pack_into("<I", buf, 4, crc32c(buf))
    return bytes(buf)


def header(seq):
    h = b"head" + b"\0" * 4 + struct.pack(
        "<Q16s16s16sHHIQ",
        seq,
        guid("11111111-1111-4111-8111-111111111111"),
        guid("22222222-2222-4222-8222-222222222222"),
        b"\0" * 16,
        0,
        1,
        MIB,
        MIB,
    )
    return with_crc(h.ljust(4 * KIB, b"\0"))


def region_table():
    t = b"regi" + b"\0" * 4 + struct.pack("<II", 2, 0)
    t += guid("2dc27766-f623-4200-9d64-115e9bfd4a08") + struct.pack("<QII", 3 * MIB, MIB, 1)
    t += guid("8b7ca206-4790-4b9a-b8fe-575f050f886e") + struct.pack("<QII", 2 * MIB, MIB, 1)
    return with_crc(t.ljust(64 * KIB, b"\0"))


def parent_locator():
    pairs = [
        ("parent_linkage", "{33333333-3333-4333-8333-333333333333}"),
        ("relative_path", "..\\parent.vhdx"),
        ("absolute_win32_path", "C:\\vms\\parent.vhdx"),
    ]
    head = guid("b04aefb7-d19e-4a81-b789-25b8e9445913") + struct.pack("<HH", 0, len(pairs))
    at = len(head) + 12 * len(pairs)
    entries = b""
    strings = b""
    for k, v in pairs:
        kb, vb = k.encode("utf-16-le"), v.encode("utf-16-le")
        entries += struct.pack("<IIHH", at, at + len(kb), len(kb), len(vb))
        strings += kb + vb
        at += len(kb) + len(vb)
    return head + entries + strings


def metadata():
    items = [
        ("caa16737-fa36-4d43-b3b6-33f0aa44e76b", struct.pack("<II", BLOCK, 2), 4),
        ("2fa54224-cd1b-4876-b211-5dbed83bf4b8", struct.pack("<Q", DISK), 6),
        ("beca12ab-b2e6-4523-93ef-c309e000c746", guid("44444444-4444-4444-8444-444444444444"), 6),
        ("8141bf1d-a96f-4709-ba47-f233a8faab5f", struct.pack("<I", LOGICAL), 6),
        ("cda348c7-445d-4471-9cc9-e9885251c556", struct.pack("<I", 4096), 6),
        ("a8d35f2d-b30b-454d-abf7-d3d84834ab0c", parent_locator(), 4),
    ]
    table = b"metadata" + struct.pack("<HH", 0, len(items)) + b"\0" * 20
    values = b""
    at = 64 * KIB
    for g, v, flags in items:
        table += guid(g) + struct.pack("<IIII", at + len(values), len(v), flags, 0)
        values += v.ljust((len(v) + 7) // 8 * 8, b"\0")
    return table.ljust(64 * KIB, b"\0") + values


def main():
    out = bytearray(7 * MIB)
    ident = b"vhdxfile" + "fillyfoal vhdx-diff.py".encode("utf-16-le")
    out[0:len(ident)] = ident
    out[64 * KIB:68 * KIB] = header(1)
    out[128 * KIB:132 * KIB] = header(2)
    out[192 * KIB:256 * KIB] = region_table()
    out[256 * KIB:320 * KIB] = region_table()
    md = metadata()
    out[2 * MIB:2 * MIB + len(md)] = md
    # BAT: payload blocks 0-3, then the sector bitmap entry of chunk 0.
    bat = {0: (4 << 20) | 6, 1: (5 << 20) | 7, 2: 0, 3: 2, CHUNK_RATIO: (6 << 20) | 6}
    for i, e in bat.items():
        struct.pack_into("<Q", out, 3 * MIB + 8 * i, e)
    # Block 0: fully present.
    for s in range(BLOCK // LOGICAL):
        out[4 * MIB + s * LOGICAL:4 * MIB + (s + 1) * LOGICAL] = bytes([s & 0xFF]) * LOGICAL
    # Block 1: sectors 0-7 present (bitmap bits for sectors 2048-2055).
    out[5 * MIB:5 * MIB + 8 * LOGICAL] = b"\xb1" * (8 * LOGICAL)
    sectors_per_block = BLOCK // LOGICAL
    out[6 * MIB + sectors_per_block // 8] = 0xFF
    open(sys.argv[1], "wb").write(out)


main()
