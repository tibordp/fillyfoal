"""Writes synthetic UDF images for partition map types no available tool
produces: a UDF 2.50 metadata partition (Blu-ray style), a UDF 1.50
sparable partition with one relocated packet, and a UDF 2.00 virtual
partition with a virtual allocation table.

Layouts are from memory of ECMA-167 / OSTA UDF; these fixtures only lock in
behaviour and do not show conformance.

python3 -I tests/data/udf/synth.py OUTDIR   (writes *.udf.gz)
"""

import gzip
import os
import struct
import sys

BS = 2048
PART = 272  # first block of the physical partition


def crc16(data):
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else crc << 1
            crc &= 0xFFFF
    return crc


def tag(ident, loc, body, version=3):
    head = struct.pack("<HHBBHHHI", ident, version, 0, 0, 1, crc16(body), len(body), loc)
    s = sum(head[i] for i in range(16) if i != 4) & 0xFF
    return head[:4] + bytes([s]) + head[5:] + body


def dstr(s, n):
    b = b"\x08" + s.encode("latin-1") if s else b""
    return b.ljust(n - 1, b"\0") + bytes([len(b)])


def regid(ident, suffix=b""):
    return b"\0" + ident.ljust(23, b"\0") + suffix.ljust(8, b"\0")


def udf_regid(ident, rev):
    return regid(ident, struct.pack("<HB", rev, 0))


IMPL = regid(b"*fillyfoal synth", b"\x04\x05")  # UNIX / Linux
CHARSPEC = b"\0" + b"OSTA Compressed Unicode".ljust(63, b"\0")


def ts(minute=0):
    # Local time UTC+01:00 (type 1, offset 60 minutes): 2024-05-06 07:08:09.
    return struct.pack("<HhBBBBBBBB", 0x1000 | 60, 2024, 5, 6, 7, 8 + minute, 9, 0, 0, 0)


def long_ad(length, lbn, part, kind=0):
    return struct.pack("<IIH6x", length | kind << 30, lbn, part)


def short_ad(length, lbn, kind=0):
    return struct.pack("<II", length | kind << 30, lbn)


class Image:
    def __init__(self, blocks):
        self.data = bytearray(blocks * BS)

    def put(self, block, data):
        assert len(data) <= BS * max(1, (len(data) + BS - 1) // BS)
        self.data[block * BS : block * BS + len(data)] = data

    def save(self, path):
        with open(path, "wb") as f:
            with gzip.GzipFile(fileobj=f, mode="wb", compresslevel=9, mtime=0, filename="") as g:
                g.write(bytes(self.data))


def vrs(img, nsr):
    for i, ident in enumerate([b"BEA01", nsr, b"TEA01"]):
        img.put(16 + i, b"\0" + ident + b"\x01")


def pvd(loc, label):
    body = struct.pack("<II", 0, 0) + dstr(label, 32) + struct.pack("<HHHHII", 1, 1, 2, 3, 1, 1)
    body += dstr("0123456789ABCDEF" + label, 128) + CHARSPEC + CHARSPEC + bytes(16)
    body += regid(b"") + ts() + IMPL + bytes(64) + struct.pack("<IH", 0, 0) + bytes(22)
    return tag(1, loc, body)


def iuvd(loc, label):
    lvinfo = CHARSPEC + dstr(label, 128) + dstr("fillyfoal", 36) + dstr("synthetic", 36)
    lvinfo += dstr("", 36) + IMPL + bytes(128)
    return tag(4, loc, struct.pack("<I", 1) + udf_regid(b"*UDF LV Info", 0x0150) + lvinfo)


def pd(loc, start, length, nsr=b"+NSR03", access=1):
    body = struct.pack("<IHH", 2, 1, 0) + regid(nsr) + bytes(128)
    body += struct.pack("<III", access, start, length) + IMPL + bytes(128) + bytes(156)
    return tag(5, loc, body)


def lvd(loc, label, rev, fsd, maps, nmaps):
    body = struct.pack("<I", 3) + CHARSPEC + dstr(label, 128) + struct.pack("<I", BS)
    body += udf_regid(b"*OSTA UDF Compliant", rev) + fsd.ljust(16, b"\0")
    body += struct.pack("<II", len(maps), nmaps) + IMPL + bytes(128)
    body += struct.pack("<II", 2 * BS, 64) + maps
    return tag(6, loc, body)


def usd(loc):
    return tag(7, loc, struct.pack("<II", 4, 0))


def td(loc):
    return tag(8, loc, bytes(496))


def lvid(loc, files, dirs, part_len, rev):
    iu = IMPL + struct.pack("<IIHHH", files, dirs, rev, rev, rev)
    body = ts() + struct.pack("<I", 1) + bytes(8) + struct.pack("<Q", 32) + bytes(24)
    body += struct.pack("<II", 1, len(iu)) + struct.pack("<II", 0, part_len) + iu
    return tag(9, loc, body)


def avdp():
    return tag(2, 256, struct.pack("<IIII", 6 * BS, 32, 6 * BS, 48) + bytes(480))


def volume(img, label, rev, nsr, part_len, maps, nmaps, fsd, files, dirs):
    vrs(img, nsr)
    for base in (32, 48):
        img.put(base, pvd(base, label))
        img.put(base + 1, iuvd(base + 1, label))
        img.put(base + 2, pd(base + 2, PART, part_len, b"+" + nsr))
        img.put(base + 3, lvd(base + 3, label, rev, fsd, maps, nmaps))
        img.put(base + 4, usd(base + 4))
        img.put(base + 5, td(base + 5))
    img.put(64, lvid(64, files, dirs, part_len, rev))
    img.put(65, td(65))
    img.put(256, avdp())


def fe(loc, ftype, size, ads, ad_type, efe=True, perms=0x1884, eas=b"", stream=None, uid=0, gid=0):
    """A (extended) file entry; ad_type 0 short, 1 long, 3 embedded."""
    icbtag = struct.pack("<IHHHBB6sH", 0, 4, 0, 1, 0, ftype, bytes(6), ad_type)
    links = 2 if ftype == 4 else 1
    body = icbtag + struct.pack("<IIIHBBI", uid, gid, perms, links, 0, 0, 0)
    blocks = 0 if ad_type == 3 else (size + BS - 1) // BS
    if efe:
        body += struct.pack("<QQQ", size, size, blocks) + ts() + ts(1) + ts(2) + ts(3)
        body += struct.pack("<II", 1, 0) + bytes(16) + (stream or bytes(16))
    else:
        body += struct.pack("<QQ", size, blocks) + ts() + ts(1) + ts(3) + struct.pack("<I", 1)
        body += bytes(16)
    body += IMPL + struct.pack("<QII", loc + 16, len(eas), len(ads)) + eas + ads
    return tag(266 if efe else 261, loc, body)


def fid(loc, name, icb, chars=0):
    ident = b"\x08" + name.encode("latin-1") if name else b""
    body = struct.pack("<HBB", 1, chars, len(ident)) + icb + struct.pack("<H", 0) + ident
    pad = (-(16 + len(body))) % 4
    return tag(257, loc, body + bytes(pad))


def fsd(loc, label, root, rev, stream=None):
    body = ts() + struct.pack("<HHIIII", 3, 3, 1, 1, 0, 0) + CHARSPEC + dstr(label, 128)
    body += CHARSPEC + dstr(label + " files", 32) + dstr("", 32) + dstr("", 32) + root
    body += udf_regid(b"*OSTA UDF Compliant", rev) + bytes(16) + (stream or bytes(16)) + bytes(32)
    return tag(256, loc, body)


def path_components(*names):
    out = b""
    for n in names:
        if n == "..":
            out += struct.pack("<BBH", 3, 0, 0)
        else:
            ident = b"\x08" + n.encode()
            out += struct.pack("<BBH", 5, len(ident), 0) + ident
    return out


def file_times_ea(loc):
    """An extended attribute header plus a file times EA (creation time)."""
    ea = struct.pack("<IB3xIII", 5, 1, 12 + 8 + 12, 12, 1) + ts(4)
    end = 24 + len(ea)
    return tag(262, loc, struct.pack("<II", end, end)) + ea


def metadata_250(path):
    """UDF 2.50: physical partition 0 plus a metadata partition on it."""
    img = Image(PART + 64)
    meta_at, mirror_at, data_at = 8, 24, 40  # partition-relative blocks
    meta = bytearray(16 * BS)

    def mput(lbn, data):
        meta[lbn * BS : lbn * BS + len(data)] = data

    m = lambda lbn: long_ad(BS, lbn, 1)
    root_dir = fid(2, "", m(1), 0x0A)
    root_dir += fid(2, "hello.txt", m(3)) + fid(2, "sub", m(4), 0x02)
    root_dir += fid(2, "frag.bin", m(6)) + fid(2, "chain.txt", m(7)) + fid(2, "link", m(10))
    root_dir += fid(2, "gone.txt", m(3), 0x04)
    mput(0, fsd(0, "FILLYMETA", long_ad(BS, 1, 1), 0x0250))
    mput(1, fe(1, 4, len(root_dir), short_ad(len(root_dir), 2), 0, perms=0x7CA5))
    mput(2, root_dir)
    hello = b"hello from a metadata partition\n"
    mput(3, fe(3, 5, len(hello), long_ad(len(hello), data_at, 0), 1, eas=file_times_ea(3),
               stream=long_ad(BS, 11, 1), uid=1000, gid=1000))
    sub = fid(4, "", m(1), 0x0A) + fid(4, "note.txt", m(5))
    mput(4, fe(4, 4, len(sub), sub, 3, perms=0x7CA5))
    note = b"embedded in its file entry\n"
    mput(5, fe(5, 5, len(note), note, 3))
    # frag.bin: two recorded extents around an unrecorded one (a hole).
    frag = long_ad(BS, data_at + 1, 0) + long_ad(BS, 0, 0, 1) + long_ad(100, data_at + 3, 0)
    mput(6, fe(6, 5, 2 * BS + 100, frag, 1))
    # chain.txt: allocation descriptors continue in an allocation extent
    # descriptor (block 8 of the metadata partition).
    chain1 = b"first extent, "
    chain2 = b"second extent via an AED\n"
    ads = long_ad(len(chain1), data_at + 4, 0) + long_ad(BS, 8, 1, 3)
    mput(7, fe(7, 5, len(chain1) + len(chain2), ads, 1))
    aed_ads = long_ad(len(chain2), data_at + 5, 0)
    mput(8, tag(258, 8, struct.pack("<II", 0, len(aed_ads)) + aed_ads))
    target = path_components("sub", "note.txt")
    mput(10, fe(10, 12, len(target), target, 3, perms=0x7FFF))
    # Named stream directory of hello.txt, with one stream.
    streams = fid(11, "", m(3), 0x0A) + fid(11, "comment", m(12))
    mput(11, fe(11, 13, len(streams), streams, 3, perms=0x7CA5))
    comment = b"a named stream\n"
    mput(12, fe(12, 5, len(comment), comment, 3))

    img.put(PART + meta_at, bytes(meta))
    img.put(PART + mirror_at, bytes(meta))
    img.put(PART + 0, fe(0, 250, len(meta), short_ad(len(meta), meta_at), 0))
    img.put(PART + 1, fe(1, 251, len(meta), short_ad(len(meta), mirror_at), 0))
    img.put(PART + data_at, hello)
    img.put(PART + data_at + 1, b"A" * BS)
    img.put(PART + data_at + 3, b"C" * 100)
    img.put(PART + data_at + 4, chain1)
    img.put(PART + data_at + 5, chain2)
    maps = struct.pack("<BBHH", 1, 6, 1, 0)
    maps += struct.pack("<BBH", 2, 64, 0) + udf_regid(b"*UDF Metadata Partition", 0x0250)
    maps += struct.pack("<HHIIIIHB5x", 1, 0, 0, 1, 0xFFFFFFFF, 16, 1, 0)
    volume(img, "FILLYMETA", 0x0250, b"NSR03", 64, maps, 2, long_ad(BS, 0, 1), 6, 3)
    img.save(path)


def sparable_150(path):
    """UDF 1.50 sparable partition; the packet at partition block 32 moved."""
    part_len = 96
    img = Image(640)
    spare_at = 600
    p = lambda lbn: long_ad(BS, lbn, 0)
    root_dir = fid(2, "", p(1), 0x0A) + fid(2, "hello.txt", p(3)) + fid(2, "cross.bin", p(5))
    img.put(PART + 0, fsd(0, "FILLYSPARE", p(1), 0x0150))
    img.put(PART + 1, fe(1, 4, len(root_dir), short_ad(len(root_dir), 2), 0, efe=False, perms=0x7CA5))
    img.put(PART + 2, root_dir)
    hello = b"hello from a sparable partition\n"
    img.put(PART + 3, fe(3, 5, len(hello), short_ad(len(hello), 4), 0, efe=False))
    img.put(PART + 4, hello)
    # cross.bin: partition blocks 30-33; 32 and 33 are in the spared packet.
    img.put(PART + 5, fe(5, 5, 4 * BS, short_ad(4 * BS, 30), 0, efe=False))
    for i, c in enumerate(b"0123"):
        img.put(PART + 30 + i, bytes([c]) * BS)
    img.put(PART + 32, b"STALE" * 400)
    img.put(spare_at, b"2" * BS)
    img.put(spare_at + 1, b"3" * BS)
    table = udf_regid(b"*UDF Sparing Table", 0x0150) + struct.pack("<HHI", 2, 0, 1)
    table += struct.pack("<II", 32, spare_at) + struct.pack("<II", 0xFFFFFFFF, spare_at + 32)
    img.put(200, tag(0, 200, table, version=2))
    maps = struct.pack("<BBH", 2, 64, 0) + udf_regid(b"*UDF Sparable Partition", 0x0150)
    maps += struct.pack("<HHHBBII", 1, 0, 32, 1, 0, BS, 200) + bytes(12)
    volume(img, "FILLYSPARE", 0x0150, b"NSR02", part_len, maps, 1, p(0), 2, 1)
    img.save(path)


def virtual_200(path):
    """UDF 2.00 virtual partition: blocks translated through the VAT."""
    blocks = PART + 20
    img = Image(blocks)
    v = lambda lbn: long_ad(BS, lbn, 1)
    # virtual block -> partition-relative physical block
    vat = [5, 7, 9, 11]
    root_dir = fid(2, "", v(1), 0x0A) + fid(2, "hello.txt", v(3))
    img.put(PART + 5, fsd(0, "FILLYVAT", v(1), 0x0200))
    img.put(PART + 7, fe(1, 4, len(root_dir), short_ad(len(root_dir), 2), 0, perms=0x7CA5))
    img.put(PART + 9, root_dir)
    hello = b"hello through a virtual allocation table\n"
    img.put(PART + 11, fe(3, 5, len(hello), long_ad(len(hello), 12, 0), 1))
    img.put(PART + 12, hello)
    head = struct.pack("<HH", 152, 0) + dstr("FILLYVAT", 128)
    head += struct.pack("<IIIHHHH", 0xFFFFFFFF, 1, 1, 0x0200, 0x0200, 0x0200, 0)
    body = head + b"".join(struct.pack("<I", x) for x in vat)
    last = blocks - 1 - PART
    img.put(PART + last, fe(last, 248, len(body), body, 3))
    maps = struct.pack("<BBHH", 1, 6, 1, 0)
    maps += struct.pack("<BBH", 2, 64, 0) + udf_regid(b"*UDF Virtual Partition", 0x0200)
    maps += struct.pack("<HH", 1, 0) + bytes(24)
    volume(img, "FILLYVAT", 0x0200, b"NSR02", blocks - PART, maps, 2, v(0), 1, 1)
    img.save(path)


out = sys.argv[1]
os.makedirs(out, exist_ok=True)
metadata_250(os.path.join(out, "metadata-250.udf.gz"))
sparable_150(os.path.join(out, "sparable-150.udf.gz"))
virtual_200(os.path.join(out, "virtual-200.udf.gz"))
