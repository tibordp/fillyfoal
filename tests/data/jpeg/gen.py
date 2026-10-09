"""Builds the synthetic JPEG fixtures in tests/fixtures/synthetic/jpeg/.

    uv run --with pillow python tests/data/jpeg/gen.py tests/fixtures/synthetic/jpeg

The image data in `app-segments.jpg`, `motion-photo.jpg` and
`photoshop-split.jpg` is real Pillow (libjpeg)
output; the application segments around it, the appended data and
the whole of `hierarchical.jpg` and `dnl.jpg` are assembled here from the
specifications as remembered (JFIF 1.02, Adobe XMP part 3, Exif 2.3 FPXR,
the StereoGraphics JPS note, Photoshop image resources and IPTC-IIM 4.2,
ISO 19566-5 JUMBF with C2PA-style content types, ITU T.81 hierarchical mode
and DNL). The entropy-coded data in the last two is filler, not decodable.
The MP4 in `motion-photo.jpg` is written by FFmpeg (one 16×16 frame).
"""

import hashlib
import io
import os
import struct
import subprocess
import sys
import tempfile

from PIL import Image


def seg(marker, payload):
    return struct.pack(">BBH", 0xFF, marker, len(payload) + 2) + payload


def pillow_jpeg(size, quality, color=(200, 80, 40), subsampling=2):
    im = Image.new("RGB", size, color)
    for x in range(size[0]):
        im.putpixel((x, x % size[1]), (20, 220, 90))
    out = io.BytesIO()
    im.save(out, "JPEG", quality=quality, subsampling=subsampling)
    return out.getvalue()


def strip_app0(jpeg):
    """Pillow's output without its JFIF segment: SOI + the rest."""
    assert jpeg[2:4] == b"\xff\xe0"
    n = struct.unpack(">H", jpeg[4:6])[0]
    return jpeg[:2], jpeg[4 + n:]


def jfif(thumb_w=0, thumb_h=0, pixels=b""):
    return seg(0xE0, b"JFIF\0" + bytes([1, 2, 1]) + struct.pack(">HH", 72, 72) + bytes([thumb_w, thumb_h]) + pixels)


def irb(rid, data, name=b""):
    pascal = bytes([len(name)]) + name
    if len(pascal) % 2:
        pascal += b"\0"
    body = b"8BIM" + struct.pack(">H", rid) + pascal + struct.pack(">I", len(data)) + data
    return body + (b"\0" if len(data) % 2 else b"")


def iptc(record, dataset, value):
    return b"\x1c" + bytes([record, dataset]) + struct.pack(">H", len(value)) + value


def box(kind, payload):
    return struct.pack(">I", len(payload) + 8) + kind + payload


def iso_uuid(cc):
    return cc + bytes.fromhex("00110010800000aa00389b71")


def jumd(cc, label):
    return box(b"jumd", iso_uuid(cc) + b"\x03" + label + b"\0")


def app_segments():
    soi, rest = strip_app0(pillow_jpeg((16, 16), 60))
    thumb = pillow_jpeg((8, 8), 50, subsampling=0)
    out = bytearray(soi)
    # JFIF with a 2×1 RGB thumbnail; JFXX JPEG and RGB thumbnails.
    out += jfif(2, 1, bytes([255, 0, 0, 0, 0, 255]))
    out += seg(0xE0, b"JFXX\0\x10" + thumb)
    out += seg(0xE0, b"JFXX\0\x13" + bytes([1, 1, 9, 8, 7]))
    # XMP with an extended part in two portions.
    ext = (b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
           b'<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:description>'
           + b"filly " * 20 + b"</dc:description></rdf:Description></rdf:RDF></x:xmpmeta>")
    guid = hashlib.md5(ext).hexdigest().upper().encode()
    xmp = (b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
           b'<rdf:Description rdf:about="" xmlns:xmpNote="http://ns.adobe.com/xmp/note/" xmpNote:HasExtendedXMP="'
           + guid + b'"/></rdf:RDF></x:xmpmeta>')
    out += seg(0xE1, b"http://ns.adobe.com/xap/1.0/\0" + xmp)
    half = len(ext) // 2
    for offset, part in ((half, ext[half:]), (0, ext[:half])):
        out += seg(0xE1, b"http://ns.adobe.com/xmp/extension/\0" + guid + struct.pack(">II", len(ext), offset) + part)
    # FlashPix-ready contents list: one storage, one stream.
    name1 = "Root".encode("utf-16-le") + b"\0\0"
    name2 = "Audio".encode("utf-16-le") + b"\0\0"
    fpxr = b"FPXR\0" + bytes([0, 1]) + struct.pack(">H", 2)
    fpxr += struct.pack(">I", 0xFFFFFFFF) + b"\0" + name1 + bytes(range(16))
    fpxr += struct.pack(">I", 1234) + b"\0" + name2
    out += seg(0xE2, fpxr)
    out += seg(0xE2, b"urn:iso:std:iso:ts:21496:-1\0" + struct.pack(">HH", 0, 0))
    # JPS: stereoscopic, side-by-side, half width; a comment.
    out += seg(0xE3, b"_JPSJPS_" + struct.pack(">HI", 4, 0x00020201) + struct.pack(">H", 5) + b"filly")
    # JUMBF in two packets of box instance 1.
    claim = box(b"jumb", jumd(b"c2cl", b"c2pa.claim") + box(b"json", b'{"claim_generator":"fillyfoal"}'))
    cbor = box(b"jumb", jumd(b"cbor", b"c2pa.hash.data") + box(b"cbor", bytes.fromhex("a1646e616d656566696c6c79")))
    manifest = box(b"jumb", jumd(b"c2ma", b"urn:uuid:00000000-0000-4000-8000-000000000000") + claim + cbor)
    store = box(b"jumb", jumd(b"c2pa", b"c2pa") + manifest)
    cut = len(store) // 2
    out += seg(0xEB, b"JP" + struct.pack(">HI", 1, 1) + store[:cut])
    out += seg(0xEB, b"JP" + struct.pack(">HI", 1, 2) + store[:8] + store[cut:])
    # Ducky: quality and a comment.
    note = "filly".encode("utf-16-be")
    out += seg(0xEC, b"Ducky" + struct.pack(">HHI", 1, 4, 60) + struct.pack(">HHI", 2, 4 + len(note), len(note) // 2) + note + b"\0\0")
    # Photoshop resources with IPTC.
    record = (iptc(1, 90, b"\x1b%G") + iptc(2, 0, b"\x00\x04") + iptc(2, 5, b"Filly") + iptc(2, 25, b"foal")
              + iptc(2, 25, b"horse") + iptc(2, 105, "Café headline".encode()) + iptc(2, 116, b"(c) nobody"))
    out += seg(0xED, b"Photoshop 3.0\0" + irb(1028, record) + irb(1005, struct.pack(">IHHIHH", 72 << 16, 1, 1, 72 << 16, 1, 1)))
    out += seg(0xEE, b"Adobe" + struct.pack(">HHHB", 100, 0, 0, 1))
    out += seg(0xFE, "café, a comment".encode())
    # Fill bytes and three stray bytes before the tables.
    out += b"\xab\xcd\xef"
    out += b"\xff\xff" + rest
    return bytes(out)


def photoshop_split():
    """Image resources split over two APP13 segments in the middle of the
    IPTC record (as Photoshop does when they exceed one segment), then a
    third segment that stands alone."""
    soi, rest = strip_app0(pillow_jpeg((8, 8), 50))
    record = (iptc(1, 90, b"\x1b%G") + iptc(2, 0, b"\x00\x04") + iptc(2, 25, b"foal")
              + iptc(2, 55, b"20240501") + iptc(2, 60, b"120000+0200") + iptc(2, 120, "Grazing — a caption".encode()))
    resources = irb(1005, struct.pack(">IHHIHH", 72 << 16, 1, 1, 72 << 16, 1, 1)) + irb(1028, record) + irb(1049, struct.pack(">I", 1))
    cut = 40
    out = bytearray(soi) + jfif()
    out += seg(0xED, b"Photoshop 3.0\0" + resources[:cut])
    out += seg(0xED, b"Photoshop 3.0\0" + resources[cut:])
    out += seg(0xED, b"Photoshop 3.0\0" + irb(1011, b"\x01\x00\x00\x00\x00\x00\x00\x00\x02", b"flags"))
    return bytes(out + rest)


def mp4():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "clip.mp4")
        subprocess.run(["ffmpeg", "-v", "error", "-y", "-f", "lavfi", "-i", "color=c=red:s=16x16:r=1",
                        "-frames:v", "1", "-c:v", "mjpeg", "-q:v", "20", "-fflags", "+bitexact",
                        "-flags:v", "+bitexact", "-movflags", "+faststart", path], check=True)
        return open(path, "rb").read()


def motion_photo():
    primary = pillow_jpeg((16, 16), 70)
    soi, rest = strip_app0(primary)
    xmp = (b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
           b'<rdf:Description rdf:about="" xmlns:GCamera="http://ns.google.com/photos/1.0/camera/" GCamera:MotionPhoto="1"/>'
           b'</rdf:RDF></x:xmpmeta>')
    out = soi + jfif() + seg(0xE1, b"http://ns.adobe.com/xap/1.0/\0" + xmp) + rest
    out += pillow_jpeg((8, 8), 50, color=(128, 128, 128))
    out += b"MotionPhoto_Data"
    out += mp4()
    out += b"\0" * 4 + b"SEFH" + struct.pack("<II", 107, 0) + struct.pack("<I", 12) + b"SEFT"
    return out


def tables():
    """Annex K luminance tables at quality 50, for one component."""
    lum = [16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55, 14, 13, 16, 24, 40, 57, 69, 56,
           14, 17, 22, 29, 51, 87, 80, 62, 18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113,
           92, 49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99]
    zigzag = [0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27,
              20, 13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51,
              58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63]
    dqt = seg(0xDB, b"\x00" + bytes(lum[z] for z in zigzag))
    dc = bytes([0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0]) + bytes(range(12))
    dht = seg(0xC4, b"\x00" + dc)
    return dqt + dht


def frame(marker, w, h, precision=8):
    return seg(marker, struct.pack(">BHHB", precision, h, w, 1) + bytes([1, 0x11, 0]))


def scan(ss=1, se=0, pt=0):
    return seg(0xDA, bytes([1, 1, 0x00, ss, se, pt]))


FILLER = bytes([0x12, 0x34, 0xFF, 0x00, 0x56, 0x78, 0x9A])


def hierarchical():
    out = b"\xff\xd8" + tables()
    out += seg(0xDE, struct.pack(">BHHB", 8, 16, 16, 1) + bytes([1, 0x11, 0]))
    out += frame(0xC3, 8, 8) + scan(1) + FILLER
    out += seg(0xDF, b"\x11")
    out += frame(0xC7, 16, 16) + scan(1) + FILLER
    return out + b"\xff\xd9"


def dnl():
    out = b"\xff\xd8" + tables()
    out += seg(0xDD, struct.pack(">H", 1))
    out += frame(0xC1, 8, 0) + scan(0, 63) + FILLER
    out += b"\xff\xd0" + FILLER
    out += seg(0xDC, struct.pack(">H", 8))
    return out + b"\xff\xd9"


def main():
    dest = sys.argv[1]
    os.makedirs(dest, exist_ok=True)
    for name, data in (("app-segments.jpg", app_segments()), ("motion-photo.jpg", motion_photo()),
                       ("hierarchical.jpg", hierarchical()), ("dnl.jpg", dnl()),
                       ("photoshop-split.jpg", photoshop_split())):
        with open(os.path.join(dest, name), "wb") as f:
            f.write(data)
        print(name, len(data))


main()
