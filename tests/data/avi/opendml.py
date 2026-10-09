"""A small OpenDML (AVI 2.0) file: two RIFF chunks (`AVI ` and `AVIX`),
super indexes (`indx`) in the stream headers pointing at standard indexes
(`ix00`, `ix01`) in each `movi` list, an `odml`/`dmlh` header, a legacy
`idx1`, a `vprp` video properties chunk, stream names and a
WAVEFORMATEXTENSIBLE audio format. FFmpeg only writes these past 1 GiB.

    python3 tests/data/avi/opendml.py

The video frames are the MJPEG frames FFmpeg wrote into
`tests/fixtures/external/avi/mjpeg-pcm.avi`; the audio is a synthetic
16-bit tone. Writes `tests/fixtures/synthetic/avi/opendml.avi`.
"""

import math
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
OUT = os.path.join(ROOT, "fixtures", "synthetic", "avi", "opendml.avi")
SRC = os.path.join(ROOT, "fixtures", "external", "avi", "mjpeg-pcm.avi")

RATE = 8000
FPS = 5


def chunk(cid, data):
    pad = b"\0" if len(data) & 1 else b""
    return cid + struct.pack("<I", len(data)) + data + pad


def lst(kind, *children):
    body = kind + b"".join(children)
    return b"LIST" + struct.pack("<I", len(body)) + body


def mjpeg_frames():
    data = open(SRC, "rb").read()
    out = []
    pos = data.find(b"movi") + 4
    while pos + 8 <= len(data):
        cid, size = data[pos : pos + 4], struct.unpack("<I", data[pos + 4 : pos + 8])[0]
        if cid == b"idx1":
            break
        if cid == b"00dc":
            out.append(data[pos + 8 : pos + 8 + size])
        pos += 8 + size + (size & 1)
    return out


def tone(n, start):
    return b"".join(
        struct.pack("<h", int(8000 * math.sin(2 * math.pi * 440 * (start + i) / RATE)))
        for i in range(n)
    )


def main():
    frames = mjpeg_frames()
    video = [frames[0], frames[1], frames[0]]
    per_frame = RATE // FPS
    audio = [tone(per_frame, i * per_frame) for i in range(3)]
    riffs = [[0, 1], [2]]

    def build(super_entries, idx1_offsets):
        w, h = 16, 16
        avih = struct.pack(
            "<IIIIIIIIII16x",
            1000000 // FPS,
            60000,
            0,
            0x10 | 0x100 | 0x800,
            len(riffs[0]),
            0,
            2,
            0x10000,
            w,
            h,
        )
        strh_v = struct.pack(
            "<4s4sIHHIIIIIIIIhhhh",
            b"vids", b"MJPG", 0, 0, 0, 0, 1, FPS, 0, len(video), 4096, 0xFFFFFFFF, 0, 0, 0, w, h
        )
        strf_v = struct.pack("<IiiHH4sIiiII", 40, w, h, 1, 24, b"MJPG", w * h * 3, 0, 0, 0, 0)
        strh_a = struct.pack(
            "<4s4sIHHIIIIIIIIhhhh",
            b"auds", b"\0\0\0\0", 0, 0, 0x0809, 0, 2, 2 * RATE, 0, len(audio) * per_frame, 4096, 0xFFFFFFFF, 2, 0, 0, 0, 0
        )
        guid = struct.pack("<IHH8s", 1, 0, 0x10, bytes([0x80, 0, 0, 0xAA, 0, 0x38, 0x9B, 0x71]))
        strf_a = struct.pack("<HHIIHHHHI", 0xFFFE, 1, RATE, 2 * RATE, 2, 16, 22, 16, 0x4) + guid

        def indx(cid, entries):
            head = struct.pack("<HBBI4s12x", 4, 0, 0, len(entries), cid)
            body = b"".join(struct.pack("<QII", *e) for e in entries)
            return chunk(b"indx", head + body)

        vprp = struct.pack("<9I", 0, 1, 50, 864, 625, (4 << 16) | 3, w, h, 1) + struct.pack(
            "<8I", h, w, h, w, 0, 0, 0, 23
        )
        hdrl = lst(
            b"hdrl",
            chunk(b"avih", avih),
            lst(
                b"strl",
                chunk(b"strh", strh_v),
                chunk(b"strf", strf_v),
                indx(b"00dc", super_entries[0]),
                chunk(b"strn", b"Test pattern\0"),
                chunk(b"vprp", vprp),
            ),
            lst(
                b"strl",
                chunk(b"strh", strh_a),
                chunk(b"strf", strf_a),
                indx(b"01wb", super_entries[1]),
                chunk(b"strn", b"Tone\0"),
            ),
            lst(b"odml", chunk(b"dmlh", struct.pack("<I", len(video)) + bytes(244))),
        )
        info = lst(b"INFO", chunk(b"INAM", b"OpenDML test\0"), chunk(b"ISFT", b"opendml.py\0"))
        head = b"RIFF" + b"\0\0\0\0" + b"AVI " + hdrl + info + chunk(b"JUNK", bytes(64))

        out = bytearray()
        new_super = [[], []]
        idx1 = []
        for r, frame_ids in enumerate(riffs):
            base = len(head) if r == 0 else len(out)
            if r == 0:
                out += head
            else:
                out += b"RIFFxxxxAVIX"
            movi_start = len(out)
            out += b"LISTxxxxmovi"
            ix = [[], []]
            for i in frame_ids:
                for s, (cid, data) in enumerate([(b"00dc", video[i]), (b"01wb", audio[i])]):
                    at = len(out)
                    out += chunk(cid, data)
                    flags = 0x10
                    ix[s].append((at + 8, len(data)))
                    if r == 0:
                        idx1.append((cid, flags, at - (movi_start + 8), len(data)))
            for s, cid in enumerate([b"00dc", b"01wb"]):
                at = len(out)
                base_off = movi_start
                entries = b"".join(struct.pack("<II", o - base_off, n) for o, n in ix[s])
                body = struct.pack("<HBBI4sQI", 2, 0, 1, len(ix[s]), cid, base_off, 0) + entries
                out += chunk(b"ix" + cid[:2], body)
                duration = len(ix[s]) if s == 0 else len(ix[s]) * per_frame
                new_super[s].append((at, 8 + len(body), duration))
            struct.pack_into("<I", out, movi_start + 4, len(out) - movi_start - 8)
            if r == 0:
                body = b"".join(struct.pack("<4sIII", *e) for e in idx1)
                out += chunk(b"idx1", body)
            riff_start = 0 if r == 0 else base
            struct.pack_into("<I", out, riff_start + 4, len(out) - riff_start - 8)
        return bytes(out), new_super

    supers = [[(0, 0, 0)] * 2, [(0, 0, 0)] * 2]
    for _ in range(3):
        data, supers = build(supers, None)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "wb") as f:
        f.write(data)


if __name__ == "__main__":
    main()
