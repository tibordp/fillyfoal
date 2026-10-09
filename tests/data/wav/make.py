"""Writes the synthetic WAVE fixtures in tests/fixtures/synthetic/wav/.

    python3 tests/data/wav/make.py

- bw64-adm.wav: a BW64 file whose data and axml chunks have their sizes in
  the ds64 table (32-bit sizes 0xffffffff), with an ADM chna chunk.
- extras.wav: the less common WAVE chunks (cart, acid, PEAK, DISP, plst,
  smpl with sampler-specific data, inst, iXML, LIST INFO and adtl with a
  labelled-text and an embedded file), laid out as their specifications say.
"""

import math
import pathlib
import struct

OUT = pathlib.Path(__file__).resolve().parents[2] / "fixtures/synthetic/wav"


def chunk(cid, body):
    data = cid + struct.pack("<I", len(body)) + body
    return data + (b"\0" if len(body) % 2 else b"")


def tone(frames, channels, rate=8000):
    out = bytearray()
    for i in range(frames):
        v = int(8000 * math.sin(2 * math.pi * 440 * i / rate))
        out += struct.pack("<h", v) * channels
    return bytes(out)


def fmt_pcm(channels, rate, bits):
    align = channels * bits // 8
    return chunk(b"fmt ", struct.pack("<HHIIHH", 1, channels, rate, rate * align, align, bits))


def bw64():
    samples = tone(160, 2)
    axml = (b'<?xml version="1.0" encoding="UTF-8"?>\n<ebuCoreMain><coreMetadata>'
            b'<format><audioFormatExtended version="ITU-R_BS.2076-2">'
            b'<audioTrackUID UID="ATU_00000001"/><audioTrackUID UID="ATU_00000002"/>'
            b'</audioFormatExtended></format></coreMetadata></ebuCoreMain>\n')
    chna_entries = b""
    for i, (track, pack) in enumerate([(b"AT_00010001_01", b"AP_00010002"), (b"AT_00010002_01", b"AP_00010002")]):
        chna_entries += struct.pack("<H", i + 1) + b"ATU_%08d" % (i + 1) + track + pack + b"\0"
    chna = chunk(b"chna", struct.pack("<HH", 2, 2) + chna_entries)
    fmt = fmt_pcm(2, 8000, 16)
    big_axml = b"axml" + struct.pack("<I", 0xFFFFFFFF) + axml + (b"\0" if len(axml) % 2 else b"")
    big_data = b"data" + struct.pack("<I", 0xFFFFFFFF) + samples
    ds64_body_len = 28 + 12
    riff_size = 4 + (8 + ds64_body_len) + len(fmt) + len(chna) + len(big_axml) + len(big_data)
    ds64 = chunk(b"ds64", struct.pack("<QQQI", riff_size, len(samples), 160, 1) + b"axml" + struct.pack("<Q", len(axml)))
    return b"BW64" + struct.pack("<I", 0xFFFFFFFF) + b"WAVE" + ds64 + fmt + chna + big_axml + big_data


def fixed(text, n):
    return text.encode("latin-1").ljust(n, b"\0")


def extras():
    samples = tone(200, 1)
    cart = (fixed("0101", 4) + fixed("Station ID", 64) + fixed("fillyfoal", 64)
            + fixed("CUT-0042", 64) + fixed("CLIENT", 64) + fixed("JINGLE", 64)
            + fixed("", 64) + fixed("fade", 64)
            + fixed("2026-10-09", 10) + fixed("06:00:00", 8) + fixed("2026-12-31", 10) + fixed("23:59:59", 8)
            + fixed("fillyfoal", 64) + fixed("1.0", 64) + fixed("", 64)
            + struct.pack("<i", 32768)
            + b"SEC1" + struct.pack("<I", 8000) + b"EOD " + struct.pack("<I", 150) + b"\0" * 48
            + b"\0" * 276 + fixed("https://example.invalid/cut/42", 1024)
            + b"<tag>text</tag>\r\n")
    acid = struct.pack("<IHHfIHHf", 0x2, 60, 0x8000, 0.0, 4, 4, 4, 120.0)
    peak = struct.pack("<II", 1, 1760000000) + struct.pack("<fI", 0.25, 17)
    disp = struct.pack("<I", 1) + b"A test tone\0"
    plst = struct.pack("<I", 2) + struct.pack("<III", 1, 100, 2) + struct.pack("<III", 2, 100, 1)
    smpl = struct.pack("<9I", 0x01000041, 0x6A, 125000, 69, 0x80000000, 25, 0x01020304, 1, 4)
    smpl += struct.pack("<6I", 1, 1, 0, 199, 0, 3) + b"ROLD"
    inst = struct.pack("<BbbBBBB", 69, -10, 3, 21, 108, 1, 127)
    cue = struct.pack("<I", 2) + struct.pack("<II4sIII", 1, 0, b"data", 0, 0, 0) + struct.pack("<II4sIII", 2, 100, b"data", 0, 0, 100)
    ixml = b"<?xml version=\"1.0\"?><BWFXML><PROJECT>fillyfoal</PROJECT></BWFXML>"
    info = b"INFO" + chunk(b"IENC", b"fillyfoal\0") + chunk(b"ICRD", b"2026-10-09\0") + chunk(b"IMED", b"File\0")
    adtl = (b"adtl" + chunk(b"labl", struct.pack("<I", 1) + b"Start\0")
            + chunk(b"ltxt", struct.pack("<II4sHHHH", 2, 100, b"rgn ", 44, 9, 1, 1252) + b"Second half\0")
            + chunk(b"file", struct.pack("<I4s", 2, b"TEXT") + b"notes for cue 2\n"))
    body = (b"WAVE" + fmt_pcm(1, 8000, 16) + chunk(b"cart", cart) + chunk(b"acid", acid)
            + chunk(b"PEAK", peak) + chunk(b"DISP", disp) + chunk(b"cue ", cue) + chunk(b"plst", plst)
            + chunk(b"smpl", smpl) + chunk(b"inst", inst) + chunk(b"iXML", ixml)
            + chunk(b"LIST", info) + chunk(b"LIST", adtl) + chunk(b"data", samples))
    return b"RIFF" + struct.pack("<I", len(body)) + body


OUT.mkdir(parents=True, exist_ok=True)
for name, data in [("bw64-adm.wav", bw64()), ("extras.wav", extras())]:
    (OUT / name).write_bytes(data)
    print(name, len(data))
