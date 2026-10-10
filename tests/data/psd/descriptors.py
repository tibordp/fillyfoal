"""Synthetic fixtures for Photoshop descriptors and the metadata formats
that carry them or ride along:

- psd/descriptors.psd: a 1x1 RGB PSD with a layer comps resource (1065), an
  IPTC resource and global tagged blocks lfx2, SoCo and Patt (one pattern).
- photoshop-irb/resources.8bim, iptc-iim/datasets.iptc, dib/palette.dib,
  jumbf/c2pa.jumbf: the formats with no signature, on their own.
- png/profiles.png: ImageMagick raw 8bim and iptc profiles and a caBX chunk.
- cfb/thumbnail.cfb: a compound file with only a SummaryInformation stream
  whose thumbnail is a VT_CF CF_DIB.
- tiff/photoshop-data.tif: ImageSourceData (tag 37724) holding a SoCo
  block after Photoshop's signature.

    python3 tests/data/psd/descriptors.py

Written from the Adobe Photoshop File Formats Specification, [MS-OLEPS],
[MS-CFB], ISO 19566-5 and IPTC-IIM 4.2, from memory.
"""

import os
import struct
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "..", "fixtures", "synthetic")

be32 = lambda v: struct.pack(">I", v)
be16 = lambda v: struct.pack(">H", v)


def ustr(s):
    units = (s + "\0").encode("utf-16-be")
    return be32(len(units) // 2) + units


def key(k):
    b = k.encode()
    return be32(0) + b if len(b) == 4 else be32(len(b)) + b


def desc(cls, items, name=""):
    body = ustr(name) + key(cls) + be32(len(items))
    for k, v in items:
        body += key(k) + v
    return body


doub = lambda f: b"doub" + struct.pack(">d", f)
untf = lambda u, f: b"UntF" + u.encode() + struct.pack(">d", f)
text = lambda s: b"TEXT" + ustr(s)
boolean = lambda v: b"bool" + bytes([1 if v else 0])
objc = lambda cls, items: b"Objc" + desc(cls, items)
vlls = lambda vals: b"VlLs" + be32(len(vals)) + b"".join(vals)
long_ = lambda v: b"long" + struct.pack(">i", v)


def resource(rid, data):
    pad = b"\0" if len(data) % 2 else b""
    return b"8BIM" + be16(rid) + b"\0\0" + be32(len(data)) + data + pad


def block(k, data):
    while len(data) % 4:
        data += b"\0"
    return b"8BIM" + k.encode() + be32(len(data)) + data


def pattern():
    channel = be32(8) + be32(0) * 2 + be32(1) * 2 + be16(8) + b"\0" + b"\x80"
    vm_body = be32(0) + be32(0) + be32(1) + be32(1) + be32(3)
    for _ in range(3):
        vm_body += be32(1) + be32(len(channel)) + channel
    vm_body += be32(0) + be32(0)
    p = be32(1) + be32(3) + be16(1) + be16(1) + ustr("Dot") + b"\x03abc"
    p += be32(3) + be32(len(vm_body)) + vm_body
    return p


iptc = (b"\x1c\x01\x5a" + be16(3) + b"\x1b%G"
        + b"\x1c\x02\x00" + be16(2) + be16(4)
        + b"\x1c\x02\x05" + be16(7) + b"Fixture"
        + b"\x1c\x02\x19" + be16(6) + b"sample")

comps = be32(16) + desc("null", [("list", vlls([objc("Comp", [("Nm  ", text("Comp 1")), ("compID", long_(7))])]))])
resolution = be32(72 << 16) + be16(1) + be16(1) + be32(72 << 16) + be16(1) + be16(1)
irb = resource(1005, resolution) + resource(1028, iptc) + resource(1065, comps)

soco = be32(16) + desc("null", [("Clr ", objc("RGBC", [("Rd  ", doub(255.0)), ("Grn ", doub(0.0)), ("Bl  ", doub(0.0))]))])
lfx2 = be32(0) + be32(16) + desc("null", [("Scl ", untf("#Prc", 100.0)), ("masterFXSwitch", boolean(True))])
pat = pattern()
patt = be32(len(pat)) + pat
while len(patt) % 4:
    patt += b"\0"
blocks = block("lfx2", lfx2) + block("SoCo", soco) + block("Patt", patt)
layer_and_mask = be32(0) + be32(0) + blocks

psd = b"8BPS" + be16(1) + b"\0" * 6 + be16(3) + be32(1) + be32(1) + be16(8) + be16(3)
psd += be32(0)
psd += be32(len(irb)) + irb
psd += be32(len(layer_and_mask)) + layer_and_mask
psd += be16(0) + b"\x10\x20\x30"

# A 2x2 8-bit DIB with a two-entry palette.
dib = struct.pack("<IiiHHIIiiII", 40, 2, 2, 1, 8, 0, 8, 2835, 2835, 2, 0)
dib += bytes([0, 0, 0, 0, 255, 255, 255, 0])
dib += bytes([0, 1, 0, 0, 1, 0, 0, 0])

# A JUMBF superbox: a C2PA-typed description and a JSON content box.
c2pa = bytes.fromhex("6332706100110010800000aa00389b71")
jumd_body = c2pa + b"\x03" + b"c2pa\0"
jumd = be32(8 + len(jumd_body)) + b"jumd" + jumd_body
json = b'{"a":1}'
jbox = be32(8 + len(json)) + b"json" + json
jumbf = be32(8 + len(jumd) + len(jbox)) + b"jumb" + jumd + jbox


def chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


def raw_profile(kind, data):
    h = data.hex()
    lines = "\n".join(h[i:i + 72] for i in range(0, len(h), 72))
    return f"Raw profile type {kind}".encode() + b"\0" + f"\n{kind}\n{len(data):8d}\n{lines}\n".encode()


png = b"\x89PNG\r\n\x1a\n"
png += chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0))
png += chunk(b"tEXt", raw_profile("8bim", irb))
png += chunk(b"tEXt", raw_profile("iptc", iptc))
png += chunk(b"caBX", jumbf)
png += chunk(b"IDAT", zlib.compress(b"\x00\x80"))
png += chunk(b"IEND", b"")

# Property set stream: SummaryInformation with a code page, a title and a
# CF_DIB thumbnail.
le16 = lambda v: struct.pack("<H", v)
le32 = lambda v: struct.pack("<I", v)
fmtid = bytes.fromhex("e0859ff2f94f6810ab9108002b27b3d9")
values = []
values.append((1, le16(0x0002) + le16(0) + le16(1252) + le16(0)))
title = b"Thumb\0"
title_value = le16(0x001e) + le16(0) + le32(len(title)) + title
while len(title_value) % 4:
    title_value += b"\0"
values.append((2, title_value))
cf = struct.pack("<i", -1) + le32(8) + dib
thumb = le16(0x0047) + le16(0) + le32(len(cf)) + cf
while len(thumb) % 4:
    thumb += b"\0"
values.append((17, thumb))
table_len = 8 + 8 * len(values)
offsets, body, at = [], b"", table_len
for pid, v in values:
    offsets.append((pid, at))
    body += v
    at += len(v)
pset = le32(at) + le32(len(values)) + b"".join(le32(p) + le32(o) for p, o in offsets) + body
stream = le16(0xfffe) + le16(0) + le32(0x00020006) + b"\0" * 16 + le32(1) + fmtid + le32(48) + pset
stream = stream.ljust(4096, b"\0")

FREE, END, FATSECT, NOSTREAM = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFF
header = bytes.fromhex("d0cf11e0a1b11ae1") + b"\0" * 16 + le16(0x3e) + le16(3) + le16(0xfffe)
header += le16(9) + le16(6) + b"\0" * 6 + le32(0) + le32(1) + le32(1) + le32(0) + le32(4096)
header += le32(END) + le32(0) + le32(END) + le32(0) + le32(0) + le32(FREE) * 108
fat = [FATSECT, END] + list(range(3, 10)) + [END]
fat += [FREE] * (128 - len(fat))
fat_sector = b"".join(le32(v) for v in fat)


def entry(name, kind, child, start, size):
    n = (name + "\0").encode("utf-16-le") if name else b""
    e = n.ljust(64, b"\0") + le16(len(n)) + bytes([kind, 1])
    e += le32(NOSTREAM) + le32(NOSTREAM) + le32(child) + b"\0" * 16 + le32(0) + b"\0" * 16
    e += le32(start) + le32(size) + le32(0)
    return e


empty = b"\0" * 64 + le16(0) + bytes([0, 0]) + le32(NOSTREAM) * 3 + b"\0" * 36 + le32(0) * 3
directory = entry("Root Entry", 5, 1, END, 0) + entry("\x05SummaryInformation", 2, NOSTREAM, 2, 4096) + empty + empty
cfb = header + fat_sector + directory + stream


# Reuse the SoCo tagged block from the PSD fixture.
at = psd.index(b"8BIMSoCo")
length = struct.unpack(">I", psd[at + 8:at + 12])[0]
soco = psd[at:at + 12 + length]
source = b"Adobe Photoshop Document Data Block\0" + soco

le16 = lambda v: struct.pack("<H", v)
le32 = lambda v: struct.pack("<I", v)
pixel_at = 8
data_at = pixel_at + 1
data_at += data_at % 2
entries = [
    (256, 3, 1, 1),  # ImageWidth
    (257, 3, 1, 1),  # ImageLength
    (258, 3, 1, 8),  # BitsPerSample
    (259, 3, 1, 1),  # Compression
    (262, 3, 1, 1),  # PhotometricInterpretation
    (273, 4, 1, pixel_at),  # StripOffsets
    (277, 3, 1, 1),  # SamplesPerPixel
    (278, 3, 1, 1),  # RowsPerStrip
    (279, 4, 1, 1),  # StripByteCounts
    (37724, 7, len(source), data_at),  # ImageSourceData
]
ifd_at = data_at + len(source)
ifd_at += ifd_at % 2
tiff = b"II*\0" + le32(ifd_at) + b"\x80"
tiff = tiff.ljust(data_at, b"\0") + source
tiff = tiff.ljust(ifd_at, b"\0")
tiff += le16(len(entries))
for tag, kind, count, value in entries:
    if kind == 3:
        field = le16(value) + b"\0\0"
    else:
        field = le32(value)
    tiff += le16(tag) + le16(kind) + le32(count) + field
tiff += le32(0)

files = {
    "psd/descriptors.psd": psd,
    "photoshop-irb/resources.8bim": irb,
    "iptc-iim/datasets.iptc": iptc,
    "dib/palette.dib": dib,
    "jumbf/c2pa.jumbf": jumbf,
    "png/profiles.png": png,
    "cfb/thumbnail.cfb": cfb,
    "tiff/photoshop-data.tif": tiff,
}
out = sys.argv[1] if len(sys.argv) > 1 else OUT
for name, data in files.items():
    path = os.path.join(out, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
