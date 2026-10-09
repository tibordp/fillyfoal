"""A hand-assembled Matroska file covering structures FFmpeg's muxer does
not write: block lacing (Xiph, EBML and fixed-size), BlockGroups with
durations, references and additions, unknown-size Segment and Cluster
elements, header stripping, VfW/ACM codec structures, HDR colour and
mastering metadata, projection, nested chapters and tags, CRC-32 elements.

    python3 tests/data/mkv/laced.py

The video frames are the MJPEG frames FFmpeg wrote into
`tests/fixtures/external/avi/mjpeg-pcm.avi`; the audio frames are
synthetic. Writes `tests/fixtures/synthetic/mkv/laced.mkv`.
"""

import os
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
OUT = os.path.join(ROOT, "fixtures", "synthetic", "mkv", "laced.mkv")
AVI = os.path.join(ROOT, "fixtures", "external", "avi", "mjpeg-pcm.avi")


def vsize(n, width=None):
    """An EBML data size."""
    if width is None:
        width = 1
        while n >= (1 << (7 * width)) - 1:
            width += 1
    return ((1 << (7 * width)) | n).to_bytes(width, "big")


UNKNOWN = b"\x01\xff\xff\xff\xff\xff\xff\xff"


def el(id_, data, size=None):
    head = id_.to_bytes((id_.bit_length() + 7) // 8, "big")
    return head + (size if size is not None else vsize(len(data))) + data


def master(id_, *children, crc=False, unknown=False):
    body = b"".join(children)
    if crc:
        body = el(0xBF, struct.pack("<I", zlib.crc32(body))) + body
    return el(id_, body, UNKNOWN if unknown else None)


def uint(id_, v):
    n = max(1, (v.bit_length() + 7) // 8)
    return el(id_, v.to_bytes(n, "big"))


def sint(id_, v):
    for n in range(1, 9):
        if -(1 << (8 * n - 1)) <= v < (1 << (8 * n - 1)):
            return el(id_, v.to_bytes(n, "big", signed=True))
    raise ValueError(v)


def f32(id_, v):
    return el(id_, struct.pack(">f", v))


def f64(id_, v):
    return el(id_, struct.pack(">d", v))


def s(id_, text):
    return el(id_, text.encode())


def mjpeg_frames():
    data = open(AVI, "rb").read()
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


def block(track, tc, flags, frames, lacing=None):
    head = vsize(track) + struct.pack(">hB", tc, flags)
    if lacing is None:
        return head + frames[0]
    n = len(frames)
    head += bytes([n - 1])
    if lacing == "xiph":
        for f in frames[:-1]:
            size = len(f)
            head += b"\xff" * (size // 255) + bytes([size % 255])
    elif lacing == "ebml":
        head += vsize(len(frames[0]))
        for prev, f in zip(frames, frames[1:-1]):
            delta = len(f) - len(prev)
            width = 1
            while not -(1 << (7 * width - 1)) + 1 <= delta <= (1 << (7 * width - 1)) - 1:
                width += 1
            head += vsize(delta + (1 << (7 * width - 1)) - 1, width)
    return head + b"".join(frames)


def bitmapinfo(w, h, fourcc):
    return struct.pack("<IiiHH4sIiiII", 40, w, h, 1, 24, fourcc, w * h * 3, 0, 0, 0, 0)


def waveformatextensible(rate, channels, bits):
    align = channels * bits // 8
    guid = struct.pack("<IHH8s", 1, 0, 0x10, bytes([0x80, 0, 0, 0xAA, 0, 0x38, 0x9B, 0x71]))
    return struct.pack("<HHIIHHHHI", 0xFFFE, channels, rate, rate * align, align, bits, 22, bits, 0x4) + guid


def pcm(n, seed):
    return bytes((seed * 37 + i * 11) & 0xFF for i in range(n))


def main():
    jpegs = mjpeg_frames()
    assert len(jpegs) >= 2 and all(j.startswith(b"\xff\xd8") for j in jpegs)

    ebml = master(
        0x1A45DFA3,
        uint(0x4286, 1),
        uint(0x42F7, 1),
        uint(0x42F2, 4),
        uint(0x42F3, 8),
        s(0x4282, "matroska"),
        uint(0x4287, 4),
        uint(0x4285, 2),
    )

    info = master(
        0x1549A966,
        uint(0x2AD7B1, 1000000),
        f32(0x4489, 400.0),
        sint(0x4461, 812_345_678_000_000_000),
        el(0x73A4, bytes(range(16))),
        s(0x7BA9, "Lacing test"),
        s(0x4D80, "laced.py"),
        s(0x5741, "laced.py"),
        crc=True,
    )

    video = master(
        0xAE,
        uint(0xD7, 1),
        uint(0x73C5, 0x1111),
        uint(0x83, 1),
        uint(0x88, 1),
        uint(0x55AA, 0),
        s(0x86, "V_MS/VFW/FOURCC"),
        el(0x63A2, bitmapinfo(16, 16, b"MJPG")),
        uint(0x23E383, 200_000_000),
        s(0x22B59D, "en-GB"),
        master(
            0xE0,
            uint(0xB0, 16),
            uint(0xBA, 16),
            uint(0x54B0, 32),
            uint(0x54BA, 16),
            uint(0x9A, 2),
            uint(0x53B8, 0),
            master(
                0x55B0,
                uint(0x55B1, 9),
                uint(0x55B2, 10),
                uint(0x55B3, 1),
                uint(0x55B4, 1),
                uint(0x55B7, 1),
                uint(0x55B8, 2),
                uint(0x55B9, 1),
                uint(0x55BA, 16),
                uint(0x55BB, 9),
                uint(0x55BC, 1000),
                uint(0x55BD, 400),
                master(
                    0x55D0,
                    f64(0x55D1, 0.708),
                    f64(0x55D2, 0.292),
                    f64(0x55D3, 0.170),
                    f64(0x55D4, 0.797),
                    f64(0x55D5, 0.131),
                    f64(0x55D6, 0.046),
                    f64(0x55D7, 0.3127),
                    f64(0x55D8, 0.3290),
                    f64(0x55D9, 1000.0),
                    f64(0x55DA, 0.005),
                ),
            ),
            master(
                0x7670,
                uint(0x7671, 1),
                el(0x7672, bytes(4) + struct.pack(">IIII", 0, 0, 0, 0)),
                f32(0x7673, 0.0),
                f32(0x7674, 0.0),
                f32(0x7675, 90.0),
            ),
        ),
        master(
            0x6D80,
            master(
                0x6240,
                uint(0x5031, 0),
                uint(0x5032, 1),
                uint(0x5033, 0),
                master(0x5034, uint(0x4254, 3), el(0x4255, b"\xff\xd8")),
            ),
        ),
    )

    pcm_track = master(
        0xAE,
        uint(0xD7, 2),
        uint(0x73C5, 0x2222),
        uint(0x83, 2),
        s(0x86, "A_PCM/INT/LIT"),
        s(0x22B59C, "eng"),
        s(0x536E, "Xiph-laced PCM"),
        uint(0x9C, 1),
        master(0xE1, f64(0xB5, 8000.0), uint(0x9F, 1), uint(0x6264, 16)),
    )

    acm_track = master(
        0xAE,
        uint(0xD7, 3),
        uint(0x73C5, 0x3333),
        uint(0x83, 2),
        s(0x86, "A_MS/ACM"),
        el(0x63A2, waveformatextensible(8000, 1, 16)),
        s(0x536E, "EBML-laced PCM"),
        master(0xE1, f64(0xB5, 8000.0), uint(0x9F, 1), uint(0x6264, 16)),
    )

    # AAC LC, 48 kHz, stereo, with the backward-compatible SBR signal.
    asc = bytes([0x11, 0x90, 0x56, 0xE5, 0x00])
    aac_track = master(
        0xAE,
        uint(0xD7, 4),
        uint(0x73C5, 0x4444),
        uint(0x83, 2),
        s(0x86, "A_AAC"),
        el(0x63A2, asc),
        uint(0x56AA, 0),
        s(0x536E, "Fixed-laced AAC"),
        master(0xE1, f64(0xB5, 48000.0), uint(0x9F, 2)),
    )

    text_track = master(
        0xAE,
        uint(0xD7, 5),
        uint(0x73C5, 0x5555),
        uint(0x83, 0x11),
        s(0x86, "S_TEXT/UTF8"),
        s(0x22B59C, "ger"),
        uint(0x55AB, 1),
        uint(0x55AE, 1),
        uint(0x88, 0),
        master(0x41E4, uint(0x41F0, 1), s(0x41A4, "notes"), uint(0x41E7, 0)),
        uint(0x55EE, 1),
    )

    # AV1 and VP9 configuration records (no frames).
    av1_track = master(
        0xAE,
        uint(0xD7, 6),
        uint(0x73C5, 0x6666),
        uint(0x83, 1),
        s(0x86, "V_AV1"),
        el(0x63A2, bytes([0x81, 0x08, 0x0C, 0x00]) + bytes([0x0A, 0x0A, 0x00, 0x00, 0x00, 0x24, 0xC4, 0xFF, 0xDF, 0x00, 0x68, 0x02])),
        master(0xE0, uint(0xB0, 64), uint(0xBA, 64)),
    )
    vp9_track = master(
        0xAE,
        uint(0xD7, 7),
        uint(0x73C5, 0x7777),
        uint(0x83, 1),
        s(0x86, "V_VP9"),
        el(0x63A2, bytes([1, 1, 2, 2, 1, 21, 3, 1, 10, 4, 1, 1])),
        master(0xE0, uint(0xB0, 64), uint(0xBA, 64)),
    )

    tracks = master(0x1654AE6B, video, pcm_track, acm_track, aac_track, text_track, av1_track, vp9_track, crc=True)

    xiph = [pcm(300, 1), pcm(40, 2), pcm(255, 3), pcm(17, 4)]
    ebml_frames = [pcm(100, 5), pcm(98, 6), pcm(130, 7), pcm(64, 8)]
    fixed = [pcm(24, 9), pcm(24, 10), pcm(24, 11)]

    cluster1 = master(
        0x1F43B675,
        uint(0xE7, 0),
        el(0xA3, block(1, 0, 0x80, [jpegs[0][2:]])),
        el(0xA3, block(2, 0, 0x82, xiph, "xiph")),
        el(0xA3, block(3, 0, 0x86, ebml_frames, "ebml")),
        el(0xA3, block(4, 0, 0x84, fixed, "fixed")),
        master(
            0xA0,
            el(0xA1, block(5, 10, 0x00, ["Hallo Welt".encode()])),
            uint(0x9B, 150),
            master(0x75A1, master(0xA6, uint(0xEE, 1), el(0xA5, b"note"))),
        ),
        unknown=True,
    )
    cluster1_pos = None  # filled in below

    cluster2_body = [
        uint(0xE7, 200),
        uint(0xAB, len(cluster1)),
        el(0xA3, block(1, 0, 0x08 | 0x01, [jpegs[1][2:]])),
        master(
            0xA0,
            el(0xA1, block(2, 5, 0x00, [pcm(80, 12)])),
            sint(0xFB, -200),
            uint(0xFA, 0),
            sint(0x75A2, -1000000),
        ),
    ]
    cluster2 = master(0x1F43B675, *cluster2_body, crc=True)

    chapters = master(
        0x1043A770,
        master(
            0x45B9,
            uint(0x45BC, 0xABCD),
            uint(0x45DB, 1),
            uint(0x45DD, 0),
            master(0x4520, s(0x4521, "Main edition"), s(0x45E4, "en")),
            master(
                0xB6,
                uint(0x73C4, 1),
                uint(0x91, 0),
                uint(0x92, 200_000_000),
                master(0x80, s(0x85, "Part one"), s(0x437C, "eng"), s(0x437E, "gb")),
                master(
                    0xB6,
                    uint(0x73C4, 2),
                    uint(0x91, 100_000_000),
                    uint(0x98, 1),
                    uint(0x4598, 1),
                    master(0x80, s(0x85, "Nested"), s(0x437D, "en")),
                ),
            ),
            master(
                0xB6,
                uint(0x73C4, 3),
                s(0x5654, "chapter-3"),
                uint(0x91, 200_000_000),
                uint(0x92, 400_000_000),
                uint(0x4588, 2),
                master(0x8F, uint(0x89, 0x1111)),
                master(0x80, s(0x85, "Part two")),
            ),
        ),
    )

    tags = master(
        0x1254C367,
        master(
            0x7373,
            master(0x63C0, uint(0x68CA, 50), s(0x63CA, "MOVIE")),
            master(
                0x67C8,
                s(0x45A3, "ARTIST"),
                s(0x447A, "eng"),
                uint(0x4484, 1),
                s(0x4487, "fillyfoal"),
                master(0x67C8, s(0x45A3, "SORT_WITH"), s(0x4487, "Fillyfoal")),
            ),
            master(0x67C8, s(0x45A3, "BINARY"), el(0x4485, bytes(range(8)))),
        ),
        master(
            0x7373,
            master(0x63C0, uint(0x68CA, 30), uint(0x63C5, 0x2222)),
            master(0x67C8, s(0x45A3, "TITLE"), s(0x4487, "Tone")),
        ),
    )

    attachments = master(
        0x1941A469,
        master(
            0x61A7,
            s(0x467E, "Release notes"),
            s(0x466E, "notes.txt"),
            s(0x4660, "text/plain"),
            el(0x465C, b"Hand-made Matroska test file.\n"),
            uint(0x46AE, 0xBEEF),
        ),
    )

    void = el(0xEC, bytes(20))

    # Segment layout: SeekHead, Void, Info, Tracks, Chapters, Tags,
    # Attachments, Cluster (unknown size), Cluster, Cues.
    def build(seek_positions):
        seekhead = master(
            0x114D9B74,
            *[
                master(0x4DBB, el(0x53AB, id_.to_bytes(4, "big")), uint(0x53AC, pos))
                for id_, pos in seek_positions
            ],
            crc=True,
        )
        parts = [seekhead, void, info, tracks, chapters, tags, attachments]
        offsets = {}
        at = 0
        for p in parts:
            offsets[int.from_bytes(p[:4], "big")] = at
            at += len(p)
        c1 = at
        c2 = c1 + len(cluster1)
        cues_at = c2 + len(cluster2)
        cues = master(
            0x1C53BB6B,
            master(
                0xBB,
                uint(0xB3, 0),
                master(0xB7, uint(0xF7, 1), uint(0xF1, c1), uint(0xF0, 4), uint(0xB2, 200)),
                master(0xB7, uint(0xF7, 2), uint(0xF1, c1), uint(0x5378, 2)),
            ),
            master(
                0xBB,
                uint(0xB3, 200),
                master(0xB7, uint(0xF7, 1), uint(0xF1, c2), master(0xDB, uint(0x96, 0))),
            ),
        )
        body = b"".join(parts) + cluster1 + cluster2 + cues
        return body, offsets, cues_at

    ids = [0x1549A966, 0x1654AE6B, 0x1043A770, 0x1254C367, 0x1941A469, 0x1C53BB6B]
    positions = [(i, 0) for i in ids]
    for _ in range(4):
        body, offsets, cues_at = build(positions)
        offsets[0x1C53BB6B] = cues_at
        positions = [(i, offsets[i]) for i in ids]
    body, _, _ = build(positions)

    segment = el(0x18538067, body, UNKNOWN)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "wb") as f:
        f.write(ebml + segment)


if __name__ == "__main__":
    main()
