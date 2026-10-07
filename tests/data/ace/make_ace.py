"""Writes the synthetic ACE fixtures and checks them with acefile.

ACE archives can only be created by WinAce (Windows); no producer runs
here. This script is an ACE 1.0/2.0 *encoder* written for the tests: an
LZ77 matcher with Huffman blocks, the ACE 2.0 mode switches (EXE, DELTA,
SOUND, PIC), solid streams and compressed comments. Tree codes are
assigned with acefile's own tree builder, and the SOUND and PIC segments are
produced by driving acefile's decoder classes with a recording bit source
(choosing residuals and symbols as they are asked for). Every archive is
then decompressed by acefile (an independent reimplementation of unace),
and its CRC-32 is filled in from acefile's output, which must equal the
input for the LZ77-based modes.

    uv run --with acefile==0.6.14 python -I tests/data/ace/make_ace.py OUTDIR
"""

import os
import struct
import sys
import zlib

import acefile

LZ = acefile.LZ77
TYPECODE = LZ.TYPECODE  # 283
NUMMAIN = LZ.NUMMAINCODES  # 284
NUMLEN = LZ.NUMLENCODES  # 255


def ace_crc32(b):
    return zlib.crc32(b) ^ 0xFFFFFFFF


def ace_crc16(b):
    return ace_crc32(b) & 0xFFFF


# ---------------------------------------------------------------------------
# Bits


class BitWriter:
    """MSB-first bits packed into little-endian 32-bit words."""

    def __init__(self):
        self.bits = []

    def write(self, value, n):
        for i in reversed(range(n)):
            self.bits.append((value >> i) & 1)

    def getvalue(self):
        bits = self.bits + [0] * (-len(self.bits) % 32)
        out = bytearray()
        for w in range(0, len(bits), 32):
            v = 0
            for b in bits[w : w + 32]:
                v = v << 1 | b
            out += struct.pack("<I", v)
        return bytes(out)


# ---------------------------------------------------------------------------
# Huffman


def huffman_lengths(freqs, limit):
    """Code lengths (0 = unused) at most `limit` bits; at least two used."""
    freqs = list(freqs)
    used = [i for i, f in enumerate(freqs) if f > 0]
    while len(used) < 2:
        for i in range(len(freqs)):
            if freqs[i] == 0:
                freqs[i] = 1
                used.append(i)
                break
    while True:
        import heapq

        heap = [(freqs[i], i, (i,)) for i in used]
        heapq.heapify(heap)
        depth = {i: 0 for i in used}
        n = len(freqs)
        while len(heap) > 1:
            f1, _, s1 = heapq.heappop(heap)
            f2, _, s2 = heapq.heappop(heap)
            for s in s1 + s2:
                depth[s] += 1
            n += 1
            heapq.heappush(heap, (f1 + f2, n, s1 + s2))
        if max(depth.values()) <= limit:
            out = [0] * len(freqs)
            for i, d in depth.items():
                out[i] = d
            return out
        for i in used:
            freqs[i] = (freqs[i] + 1) // 2 or 1


class Code:
    """A code as unace assigns it: symbol -> (bits, width)."""

    def __init__(self, widths, max_width):
        self.widths = list(widths)
        tree = acefile.Huffman._make_tree(list(widths), max_width)
        self.max = max_width
        self.codes = {}
        for i, s in enumerate(tree.codes):
            if s not in self.codes:
                w = tree.widths[s]
                self.codes[s] = (i >> (max_width - w), w)

    def write(self, bw, sym):
        bits, width = self.codes[sym]
        bw.write(bits, width)


def write_tree(bw, widths, max_width):
    """Writes `widths` the way Huffman.read_tree reads them; returns the
    code. Trailing unused symbols are not sent."""
    num = len(widths)
    while num > 1 and widths[num - 1] == 0:
        num -= 1
    widths = list(widths[:num])
    nz = [w for w in widths if w]
    lower = min(nz) - 1
    v = [w - lower if w else 0 for w in widths]
    upper = max(v) + 1
    assert upper <= 15 and lower <= 15
    s = [v[0]] + [(v[i] - v[i - 1]) % upper for i in range(1, num)]
    # Tokens: symbols < upper, or a run of 4..19 zeros (symbol `upper`).
    tokens = []
    i = 0
    while i < num:
        if s[i] == 0:
            j = i
            while j < num and s[j] == 0 and j - i < 19:
                j += 1
            if j - i >= 4:
                tokens.append((upper, j - i - 4))
                i = j
                continue
        tokens.append((s[i], None))
        i += 1
    freq = [0] * (upper + 1)
    for t, _ in tokens:
        freq[t] += 1
    ww = huffman_lengths(freq, 7)
    wcode = Code(ww, 7)
    bw.write(num - 1, 9)
    bw.write(lower, 4)
    bw.write(upper, 4)
    for w in ww:
        bw.write(w, 3)
    for t, extra in tokens:
        wcode.write(bw, t)
        if extra is not None:
            bw.write(extra, 4)
    # The decoder's view of the widths (padded back to full size).
    return Code(widths, max_width)


# ---------------------------------------------------------------------------
# LZ77 symbols


class Lz77Encoder:
    """Greedy LZ77 over the dictionary the decoder keeps."""

    def __init__(self, dictionary):
        self.dict = dictionary  # bytearray shared with the stream
        self.hist = [0, 0, 0, 0]
        self.heads = {}

    def _index(self, upto):
        for p in range(getattr(self, "_indexed", 0), upto):
            if p + 3 <= len(self.dict):
                key = bytes(self.dict[p : p + 3])
                self.heads.setdefault(key, []).append(p)
        self._indexed = max(getattr(self, "_indexed", 0), upto)

    def encode(self, data, events, matches=True):
        """Appends main/len symbol events for `data` (which the decoder will
        append to its dictionary)."""
        start = len(self.dict)
        self.dict += data
        pos = start
        end = len(self.dict)
        while pos < end:
            best = (0, 0)
            if matches and pos + 3 <= end:
                self._index(pos)
                key = bytes(self.dict[pos : pos + 3])
                for cand in reversed(self.heads.get(key, [])[-64:]):
                    dist = pos - cand
                    if dist > (1 << 22):
                        break
                    n = 0
                    while pos + n < end and n < 256 and self.dict[cand + n] == self.dict[pos + n]:
                        n += 1
                    if n > best[0]:
                        best = (n, dist)
            n, dist = best
            d = dist - 1
            minlen = 2 if d <= 255 else 3 if d <= 8191 else 4
            if n >= max(minlen, 3):
                if d in self.hist:
                    offset = 3 - self.hist.index(d)
                    base = 3 if offset > 1 else 2
                    if n - base > 254:
                        n = 254 + base
                    events.append(("main", 256 + offset))
                    events.append(("len", n - base))
                    self.hist.remove(d)
                    self.hist.append(d)
                else:
                    if n - minlen > 254:
                        n = 254 + minlen
                    bits = d.bit_length()
                    events.append(("main", 260 + bits))
                    if bits >= 2:
                        events.append(("raw", d - (1 << (bits - 1)), bits - 1))
                    events.append(("len", n - minlen))
                    self.hist.pop(0)
                    self.hist.append(d)
                pos += n
            else:
                events.append(("main", self.dict[pos]))
                pos += 1

    def mode(self, events, mode, *args):
        events.append(("main", TYPECODE))
        events.append(("raw", mode, 8))
        if mode == 1:
            events.append(("raw", args[0], 8))
            events.append(("raw", args[1], 17))
        elif mode == 2:
            events.append(("raw", args[0], 8))


def serialize(events, block=32767):
    """Writes events: LZ77 main/len symbols in Huffman blocks of at most
    `block` main symbols; SOUND symbols (with their own blocks); raw bits."""
    bw = BitWriter()
    mains = [i for i, e in enumerate(events) if e[0] == "main"]
    # Block boundaries by index of main event.
    blocks = {}
    for b in range(0, len(mains), block):
        idx = mains[b : b + block]
        mfreq = [0] * NUMMAIN
        lfreq = [0] * NUMLEN
        first, last = idx[0], idx[-1]
        for e in events[first : last + 1]:
            if e[0] == "main":
                mfreq[e[1]] += 1
            elif e[0] == "len":
                lfreq[e[1]] += 1
        # Length symbols after the last main of the block belong to it too.
        k = last + 1
        while k < len(events) and events[k][0] in ("len", "raw"):
            if events[k][0] == "len":
                lfreq[events[k][1]] += 1
            k += 1
        blocks[first] = (mfreq, lfreq, len(idx))
    main = lens = None
    sound = None
    for i, e in enumerate(events):
        if e[0] == "main":
            if i in blocks:
                mfreq, lfreq, count = blocks[i]
                main = write_tree(bw, huffman_lengths(mfreq, LZ.MAXCODEWIDTH), LZ.MAXCODEWIDTH)
                lens = write_tree(bw, huffman_lengths(lfreq, LZ.MAXCODEWIDTH), LZ.MAXCODEWIDTH)
                bw.write(count, 15)
            main.write(bw, e[1])
        elif e[0] == "len":
            lens.write(bw, e[1])
        elif e[0] == "raw":
            bw.write(e[1], e[2])
        elif e[0] == "bits":
            for b in e[1]:
                bw.write(b, 1)
        elif e[0] == "sound_trees":
            _, models, symbols = e
            freq = [0] * acefile.Sound.NUMCODES
            for s in symbols:
                freq[s] += 1
            widths = huffman_lengths(freq, acefile.Sound.MAXCODEWIDTH)
            for _ in range(models):
                sound = write_tree(bw, widths, acefile.Sound.MAXCODEWIDTH)
            bw.write(len(symbols), 15)
        elif e[0] == "sound":
            sound.write(bw, e[1])
        else:
            raise ValueError(e)
    return bw.getvalue()


# ---------------------------------------------------------------------------
# SOUND and PIC segments, by driving acefile's decoders


class Chooser:
    def __init__(self, seed):
        self.x = seed

    def next(self, n):
        self.x = (self.x * 1103515245 + 12345) & 0x7FFFFFFF
        return (self.x >> 8) % n


def sound_segment(mode, samples, seed):
    """Events for a SOUND segment of `samples` bytes (a multiple of 4)
    ending with a switch back to LZ77, and acefile's decoded bytes."""
    rng = Chooser(seed)
    snd = acefile.Sound()
    snd.reinit(mode)
    symbols = []
    calls = [0]

    class Reader:
        def read_symbol(self, bs, model):
            calls[0] += 1
            if calls[0] < samples // 3 and rng.next(16) == 0:
                s = rng.next(4)  # a short run of zero residuals
            else:
                # Residual magnitudes skewed small.
                s = 32 + min(rng.next(24), rng.next(24))
            symbols.append(s)
            return s

    for ch in snd._Sound__channels:
        ch._Channel__symreader = Reader()
    out, nm = snd.read(None, samples)
    assert nm is None and len(out) == samples
    chans = snd._Sound__channels
    use = acefile.Sound.USECHANNELS[mode - 3][0]
    assert chans[use]._Channel__get_state != 2
    symbols.append(acefile.Sound.TYPECODE)
    models = 3 * acefile.Sound.NUMCHANNELS[mode - 3]
    events = [("sound_trees", models, symbols)]
    events += [("sound", s) for s in symbols]
    events.append(("raw", 0, 8))  # back to LZ77
    return events, bytes(out)


def golomb_bits(value, r, signed):
    if signed:
        value = 2 * value if value >= 0 else -2 * value - 1
    bits = [(value >> i) & 1 for i in reversed(range(r))] if r else []
    bits += [1] * (value >> r) + [0]
    return bits


def pic_segment(width, planes, rows, seed):
    """Events for a PIC segment (width x rows, `planes` interleaved
    planes) ending with a switch back to LZ77, and acefile's output."""
    rng = Chooser(seed)
    bits = []

    class Source:
        def read_bits(self, n):
            assert n == 2
            v = rng.next(3)
            bits.extend((v >> i) & 1 for i in reversed(range(n)))
            return v

        def read_golomb_rice(self, r, signed=False):
            if signed:
                v = rng.next(9) - 4
            else:
                v = self.fixed.pop(0)
            bits.extend(golomb_bits(v, r, signed))
            return v

    src = Source()
    src.fixed = [width, planes]
    pic = acefile.Pic()
    # reinit reads the width with 12 and the planes with 2 remainder bits.
    pic.reinit(src)
    out = []
    for _ in range(rows):
        bits.append(1)
        out += pic._row(src)
    bits.append(0)
    events = [("bits", bits), ("raw", 0, 8)]
    return events, bytes(out)


# ---------------------------------------------------------------------------
# Archives


def main_header(flags, comment=None, version=20):
    body = struct.pack("<BH", 0, flags) + b"**ACE**"
    body += struct.pack("<BBBBL", version, version, 2, 0, 0x58221880)
    body += b"\0" * 8
    if comment is not None:
        body += struct.pack("<H", len(comment)) + comment
    return struct.pack("<HH", ace_crc16(body), len(body)) + body


def file_header(name, packed, size, crc, comp, flags=0, comment=None):
    flags |= 0x0001
    if comment is not None:
        flags |= 0x0002
    body = struct.pack("<BHLL", 1, flags, len(packed), size)
    body += struct.pack("<LLLBBHHH", 0x58221880, 0x20, crc, comp, 3 if comp else 0, 0x000A, 0, len(name))
    body += name
    if comment is not None:
        body += struct.pack("<H", len(comment)) + comment
    return struct.pack("<HH", ace_crc16(body), len(body)) + body + packed


def encode_comment(text):
    """A comment: its length, a tree, and literal symbols only."""
    events = []
    freq = [0] * NUMMAIN
    for b in text:
        freq[b] += 1
    bw = BitWriter()
    bw.write(len(text), 15)
    code = write_tree(bw, huffman_lengths(freq, LZ.MAXCODEWIDTH), LZ.MAXCODEWIDTH)
    for b in text:
        code.write(bw, b)
    return bw.getvalue()


def text_sample():
    words = (
        b"the quick brown fox jumps over the lazy dog while the archiver "
        b"packs every byte it can find into ever smaller blocks of bits "
    )
    out = bytearray()
    for i in range(14):
        out += words[i % 7 * 9 :] + words[: i % 7 * 9] + b"\r\n"
    return bytes(out)


def binary_sample(n, seed):
    rng = Chooser(seed)
    out = bytearray()
    while len(out) < n:
        if rng.next(3) == 0 and len(out) > 8:
            start = rng.next(len(out))
            out += out[start : start + 3 + rng.next(20)]
        else:
            out.append(rng.next(256) if rng.next(4) else 0)
    return bytes(out[:n])


def exe_sample(at):
    """x86-looking bytes with CALL/JMP opcodes, none in the last 8 bytes."""
    rng = Chooser(7)
    out = bytearray()
    while len(out) < 600:
        r = rng.next(6)
        if r == 0:
            out += bytes([0xE8]) + struct.pack("<l", 0x100 - len(out))
        elif r == 1:
            out += bytes([0xE9]) + struct.pack("<h", -0x40)
        else:
            out += bytes([0x55, 0x89, 0xE5, 0x83, 0xEC, rng.next(4) * 4][: 1 + rng.next(6)])
    out = out[:600]
    out += b"\x90" * 8
    return bytes(out)


def exe_forward(data, at, exe_mode):
    """The encoder side of the EXE filter (the same scan as the decoder)."""
    b = bytearray(data)
    i = 0
    while i + 4 < len(b):
        if b[i] == 0xE8 and exe_mode:
            v = (struct.unpack_from("<L", b, i + 1)[0] + at + i) & 0xFFFFFFFF
            struct.pack_into("<L", b, i + 1, v)
            i += 5
        elif b[i] in (0xE8, 0xE9):
            v = (struct.unpack_from("<H", b, i + 1)[0] + at + i) & 0xFFFF
            struct.pack_into("<H", b, i + 1, v)
            i += 3
        else:
            i += 1
    return bytes(b)


def delta_forward(data, dist, last):
    n = len(data)
    ps = n // dist
    assert ps * dist == n
    delta = [0] * n
    k = 0
    for pos in range(ps):
        plane = 0
        while plane < n:
            delta[plane + pos] = data[k]
            k += 1
            plane += ps
    raw = bytearray()
    for d in delta:
        raw.append((d - last) & 0xFF)
        last = d
    return bytes(raw), last


def acefile_members(path):
    with acefile.open(path) as f:
        return [(m.filename, f.read(m)) for m in f.getmembers()]


def blocked_stream(segments, seed):
    """An ACE 2.0 stream from (kind, data/params) segments; returns the
    packed bytes and the expected output (None where acefile decides)."""
    dictionary = bytearray()
    enc = Lz77Encoder(dictionary)
    events = []
    expected = bytearray()
    last_delta = 0
    mode = 0
    for kind, arg in segments:
        if kind == "lz":
            if mode != 0:
                enc.mode(events, 0)
                mode = 0
            enc.encode(arg, events)
            expected += arg
        elif kind == "exe":
            data, exe_mode = arg
            enc.mode(events, 2, exe_mode)
            mode = 2
            enc.encode(exe_forward(data, len(expected), exe_mode), events)
            expected += data
        elif kind == "delta":
            data, dist = arg
            enc.mode(events, 1, dist, len(data))
            mode = 1
            raw, last_delta = delta_forward(data, dist, last_delta)
            enc.encode(raw, events)
            expected += data
        elif kind == "sound":
            m, samples = arg
            enc.mode(events, m)
            ev, out = sound_segment(m, samples, seed)
            events += ev
            dictionary += out
            expected += out
            mode = 0
        elif kind == "pic":
            width, planes, rows = arg
            enc.mode(events, 7)
            ev, out = pic_segment(width, planes, rows, seed)
            events += ev
            dictionary += out
            expected += out
            mode = 0
    return serialize(events), bytes(expected)


def lz77_stream(data, dictionary=None):
    enc = Lz77Encoder(dictionary if dictionary is not None else bytearray())
    events = []
    enc.encode(data, events)
    return serialize(events)


def write(path, blob, expected):
    with open(path, "wb") as f:
        f.write(blob)
    got = acefile_members(path)
    assert [n for n, _ in got] == [n for n, _ in expected], got
    for (name, data), (_, want) in zip(got, expected):
        assert data == want, name
    print(path, len(blob), "bytes,", len(got), "members verified by acefile")


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    text = text_sample()
    binary = binary_sample(700, 3)

    # ACE 1.0 LZ77 (method 1), with an archive comment.
    comment = encode_comment(b"Made by the fillyfoal test generator.")
    members = [(b"README.TXT", text), (b"DATA\\BLOB.BIN", binary)]
    blob = main_header(0x0002, comment, version=10)
    for name, data in members:
        packed = lz77_stream(data)
        blob += file_header(name, packed, len(data), ace_crc32(data), 1)
    write(os.path.join(outdir, "lz77.ace"), blob, [(n.decode().replace("\\", "/"), d) for n, d in members])

    # ACE 2.0 blocked (method 2): one member per mode, and one mixing them.
    exe = exe_sample(0)
    planes = binary_sample(512, 11)
    cases = [
        (b"EXE16.BIN", [("lz", b"MZ" + b"\0" * 30), ("exe", (exe, 0)), ("lz", b"tail")]),
        (b"EXE32.BIN", [("exe", (exe, 1)), ("lz", b"tail")]),
        (b"DELTA.BIN", [("lz", b"RIFF"), ("delta", (planes, 4)), ("lz", b"end of delta")]),
        (b"SOUND8.WAV", [("lz", b"RIFF....WAVEfmt "), ("sound", (3, 400)), ("lz", b"done")]),
        (b"SOUND16.WAV", [("sound", (4, 256)), ("lz", b"done")]),
        (b"PICTURE.BMP", [("lz", b"BM header"), ("pic", (24, 3, 6)), ("lz", b"done")]),
        (b"MIXED.BIN", [("lz", text[:200]), ("delta", (planes[:64], 2)), ("lz", text[100:300])]),
    ]
    blob = main_header(0x0100)
    expected = []
    for name, segs in cases:
        packed, data = blocked_stream(segs, len(name))
        blob += file_header(name, packed, len(data), ace_crc32(data), 2)
        expected.append((name.decode(), data))
    write(os.path.join(outdir, "blocked.ace"), blob, expected)

    # Solid: later files refer back into earlier ones.
    files = [(b"ONE.TXT", text), (b"TWO.TXT", text[50:] + text[:50]), (b"THREE.BIN", binary)]
    dictionary = bytearray()
    blob = main_header(0x8100)
    for i, (name, data) in enumerate(files):
        enc = Lz77Encoder(dictionary)
        enc.hist = [0, 0, 0, 0]
        events = []
        enc.encode(data, events)
        packed = serialize(events)
        blob += file_header(name, packed, len(data), ace_crc32(data), 2, 0x8000 if i else 0)
    write(os.path.join(outdir, "solid.ace"), blob, [(n.decode(), d) for n, d in files])


if __name__ == "__main__":
    main(sys.argv[1])
