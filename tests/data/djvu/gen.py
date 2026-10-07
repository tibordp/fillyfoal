"""Builds the synthetic DjVu fixtures in tests/fixtures/synthetic/djvu/.

    uv run --with pillow python tests/data/djvu/gen.py tests/fixtures/synthetic/djvu

The containers, directories, text layers, annotations and bookmarks follow
the layouts of DjVuLibre (IFFByteStream, DjVmDir, DjVmNav, DjVuText,
DjVuInfo) as remembered, not checked against DjVuLibre output: no DjVuLibre
tools were available (`brew install djvulibre` would provide c44, cjb2,
djvm and djvused for real fixtures). BZZ streams come from `bzz.py`. The
image chunks (Sjbz, Smmr, BG44, Djbz) carry plausible headers and filler,
not real JB2/MMR/IW44 data; the BGjp background is a real JPEG written by
Pillow.
"""

import io
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bzz  # noqa: E402


def u16(v):
    return struct.pack(">H", v)


def u24(v):
    return struct.pack(">I", v)[1:]


def chunk(cid, body):
    return cid + struct.pack(">I", len(body)) + body


def form(kind, chunks):
    """A FORM chunk; each child starts at an even offset (FORMs start even)."""
    body = kind
    for c in chunks:
        if len(body) % 2:
            body += b"\0"
        body += c
    return chunk(b"FORM", body)


def info(w, h, dpi=300, gamma=22, rotation=1, version=(24, 0)):
    # Width and height big-endian, minor/major version, dpi little-endian.
    return chunk(
        b"INFO",
        u16(w) + u16(h) + bytes(version) + struct.pack("<H", dpi) + bytes([gamma, rotation]),
    )


# --- hidden text -----------------------------------------------------------

PAGE, COLUMN, REGION, PARAGRAPH, LINE, WORD, CHARACTER = range(1, 8)


class Zone:
    def __init__(self, kind, rect, start, length, children=()):
        self.kind = kind
        self.rect = rect  # (xmin, ymin, xmax, ymax), y up from the bottom
        self.start = start
        self.length = length
        self.children = list(children)


def encode_zone(z, parent=None, prev=None):
    xmin, ymin, xmax, ymax = z.rect
    w, h = xmax - xmin, ymax - ymin
    x, y, start = xmin, ymin, z.start
    if prev is not None:
        if z.kind in (PAGE, PARAGRAPH, LINE):
            x = xmin - prev.rect[0]
            y = prev.rect[1] - (ymin + h)
        else:
            x = xmin - prev.rect[2]
            y = ymin - prev.rect[1]
        start -= prev.start + prev.length
    elif parent is not None:
        x = xmin - parent.rect[0]
        y = parent.rect[3] - (ymin + h)
        start -= parent.start
    out = bytes([z.kind])
    for v in (x, y, w, h, start):
        out += u16(v + 0x8000)
    out += u24(z.length) + u24(len(z.children))
    p = None
    for c in z.children:
        out += encode_zone(c, z, p)
        p = c
    return out


def text_layer(text, root):
    raw = text.encode("utf-8")
    return u24(len(raw)) + raw + bytes([1]) + encode_zone(root)


def words_zones(text, words, base):
    """Word zones for `words` [(word, rect)], located in `text` from `base`."""
    out = []
    at = base
    raw = text.encode("utf-8")
    for word, rect in words:
        i = raw.index(word.encode("utf-8"), at)
        out.append(Zone(WORD, rect, i, len(word.encode("utf-8"))))
        at = i + len(word.encode("utf-8"))
    return out


def page_text():
    text = "Hello DjVu world\nSecond line\n"
    raw = text.encode()
    l1 = Zone(
        LINE,
        (10, 30, 90, 40),
        0,
        raw.index(b"\n") + 1,
        words_zones(
            text,
            [("Hello", (10, 30, 30, 40)), ("DjVu", (34, 30, 52, 40)), ("world", (56, 30, 90, 40))],
            0,
        ),
    )
    s2 = raw.index(b"Second")
    l2 = Zone(
        LINE,
        (10, 15, 60, 25),
        s2,
        len(raw) - s2,
        words_zones(text, [("Second", (10, 15, 38, 25)), ("line", (42, 15, 60, 25))], s2),
    )
    para = Zone(PARAGRAPH, (10, 15, 90, 40), 0, len(raw), [l1, l2])
    region = Zone(REGION, (10, 15, 90, 40), 0, len(raw), [para])
    column = Zone(COLUMN, (10, 15, 90, 40), 0, len(raw), [region])
    page = Zone(PAGE, (0, 0, 100, 50), 0, len(raw), [column])
    return text_layer(text, page)


def simple_text(text, w, h):
    raw = text.encode()
    line = Zone(LINE, (5, 5, w - 5, h - 5), 0, len(raw))
    return text_layer(text, Zone(PAGE, (0, 0, w, h), 0, len(raw), [line]))


ANNOTATIONS = (
    b"(background #ffffff)\n(zoom page)\n(mode color)\n"
    b'(metadata (Author "Fillyfoal") (Title "Sample page"))\n'
    b'(maparea "https://example.com/" "Example link" (rect 10 30 40 10) (xor))\n'
)


def jpeg():
    from PIL import Image

    img = Image.new("RGB", (16, 8))
    for x in range(16):
        for y in range(8):
            img.putpixel((x, y), (x * 16, y * 32, 128))
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=50)
    return buf.getvalue()


def iw44(width, height, color=True):
    # serial 0, 1 slice, major (bit 7: grayscale), minor, width, height,
    # chroma delay; then filler for the wavelet data.
    major = 1 if color else 0x81
    return bytes([0, 1, major, 2]) + u16(width) + u16(height) + bytes([0x80]) + bytes(range(8))


def single_page():
    return b"AT&T" + form(
        b"DJVU",
        [
            info(100, 50),
            chunk(b"Sjbz", bytes(range(1, 10))),
            chunk(b"BG44", iw44(34, 17)),
            chunk(b"BGjp", jpeg()),
            chunk(b"TXTz", bzz.encode(page_text())),
            chunk(b"ANTz", bzz.encode(ANNOTATIONS)),
        ],
    )


# --- multi-page ------------------------------------------------------------

INCLUDE, PAGE_FILE, THUMBNAILS, SHARED_ANNO = 0, 1, 2, 3
HAS_NAME, HAS_TITLE = 0x80, 0x40


def dirm(entries, offsets=None):
    """entries: [(id, type, name, title, size)]; offsets for a bundled file."""
    head = bytes([(0x80 if offsets is not None else 0) | 1]) + u16(len(entries))
    if offsets is not None:
        head += b"".join(struct.pack(">I", o) for o in offsets)
    rest = b"".join(u24(e[4]) for e in entries)
    flags = []
    for fid, kind, name, title, _ in entries:
        flags.append(kind | (HAS_NAME if name else 0) | (HAS_TITLE if title else 0))
    rest += bytes(flags)
    for fid, kind, name, title, _ in entries:
        rest += fid.encode() + b"\0"
        if name:
            rest += name.encode() + b"\0"
        if title:
            rest += title.encode() + b"\0"
    return chunk(b"DIRM", head + bzz.encode(rest))


def navm(bookmarks):
    """bookmarks: [(title, url, children)]"""
    flat = []

    def walk(items):
        for title, url, children in items:
            t, u = title.encode(), url.encode()
            flat.append(bytes([len(children)]) + u24(len(t)) + t + u24(len(u)) + u)
            walk(children)

    walk(bookmarks)
    return chunk(b"NAVM", bzz.encode(u16(len(flat)) + b"".join(flat)))


def bundled():
    shared = form(
        b"DJVI",
        [chunk(b"Djbz", bytes(range(2, 12))), chunk(b"ANTz", bzz.encode(b"(mode bw)\n"))],
    )
    p1 = form(
        b"DJVU",
        [
            info(64, 32, dpi=150),
            chunk(b"INCL", b"dict0001.iff"),
            chunk(b"Sjbz", bytes(range(3, 14))),
            chunk(b"FGbz", bytes([0]) + u16(2) + bytes([0, 0, 0, 0x20, 0x40, 0xC0])),
            chunk(b"TXTz", bzz.encode(simple_text("Cover page", 64, 32))),
        ],
    )
    p2 = form(
        b"DJVU",
        [
            info(32, 64, dpi=150, rotation=6),
            chunk(b"INCL", b"dict0001.iff"),
            chunk(b"Smmr", b"MMR\0" + u16(32) + u16(64) + bytes(range(6))),
            chunk(b"TXTa", simple_text("Second page", 32, 64)),
            chunk(b"ANTa", b'(metadata (Subject "Page two"))\n'),
        ],
    )
    files = [
        ("dict0001.iff", INCLUDE, None, None, shared),
        ("p0001.djvu", PAGE_FILE, None, "Cover", p1),
        ("p0002.djvu", PAGE_FILE, "page-two.djvu", None, p2),
    ]
    entries = [(f, k, n, t, len(c)) for f, k, n, t, c in files]
    nav = navm(
        [("Chapter 1", "#1", [("Section 1.1", "#p0001.djvu", [])]), ("Chapter 2", "#2", [])]
    )
    for _ in range(2):
        offsets = []
        pos = 16  # AT&T, FORM header, "DJVM"
        d = dirm(entries, [0] * len(files) if not offsets else offsets)
        pos += len(d)
        pos += pos % 2
        pos += len(nav)
        for *_, c in files:
            pos += pos % 2
            offsets.append(pos)
            pos += len(c)
        d = dirm(entries, offsets)
    return b"AT&T" + form(b"DJVM", [d, nav] + [c for *_, c in files])


def indirect():
    entries = [
        ("p0001.djvu", PAGE_FILE, None, "Front", 1234),
        ("p0002.djvu", PAGE_FILE, None, None, 2345),
    ]
    return b"AT&T" + form(b"DJVM", [dirm(entries)])


def main(out):
    os.makedirs(out, exist_ok=True)
    for name, data in (
        ("page.djvu", single_page()),
        ("bundled.djvu", bundled()),
        ("indirect.djvu", indirect()),
    ):
        with open(os.path.join(out, name), "wb") as f:
            f.write(data)
        print(name, len(data))


if __name__ == "__main__":
    main(sys.argv[1])
