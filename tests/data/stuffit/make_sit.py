"""Writes the synthetic StuffIt fixtures.

No StuffIt producer (or independent decoder) runs here: StuffIt itself is
a classic Mac OS / Windows application, and The Unarchiver's `unar` is not
installed. So this script carries its own encoders for the fork methods,
written from the same (unverified) understanding of the formats as
`crates/codec/src/codec/stuffit.rs`: RLE90 (1), Huffman (3), LZAH (5, Okumura's
LZHUF), the dynamic variant of method 13, and Arsenic (15). Method 2
(LZW) comes from the system's `compress -b 14` with its 3-byte header
removed, a real implementation of that algorithm.

    python3 -I tests/data/stuffit/make_sit.py OUTDIR
"""

import heapq
import os
import struct
import subprocess
import sys
import zlib


def crc16(data):
    """CRC-16/ARC."""
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


class MsbWriter:
    def __init__(self):
        self.bits = []

    def write(self, value, n):
        for i in reversed(range(n)):
            self.bits.append((value >> i) & 1)

    def getvalue(self):
        bits = self.bits + [0] * (-len(self.bits) % 8)
        return bytes(
            int("".join(map(str, bits[i : i + 8])), 2) for i in range(0, len(bits), 8)
        )


class LsbWriter:
    def __init__(self):
        self.bits = []

    def write(self, value, n):
        for i in range(n):
            self.bits.append((value >> i) & 1)

    def write_msb(self, value, n):
        """A Huffman code: its most significant bit first."""
        for i in reversed(range(n)):
            self.bits.append((value >> i) & 1)

    def getvalue(self):
        bits = self.bits + [0] * (-len(self.bits) % 8)
        return bytes(
            sum(bits[i + k] << k for k in range(8)) for i in range(0, len(bits), 8)
        )


def huffman_lengths(freqs, limit):
    freqs = list(freqs)
    used = [i for i, f in enumerate(freqs) if f > 0]
    while len(used) < 2:
        i = freqs.index(0)
        freqs[i] = 1
        used.append(i)
    while True:
        heap = [(freqs[i], i, (i,)) for i in used]
        heapq.heapify(heap)
        depth = dict.fromkeys(used, 0)
        n = len(freqs)
        while len(heap) > 1:
            f1, _, a = heapq.heappop(heap)
            f2, _, b = heapq.heappop(heap)
            for s in a + b:
                depth[s] += 1
            n += 1
            heapq.heappush(heap, (f1 + f2, n, a + b))
        if max(depth.values()) <= limit:
            out = [0] * len(freqs)
            for i, d in depth.items():
                out[i] = d
            return out
        for i in used:
            freqs[i] = (freqs[i] + 1) // 2 or 1


def canonical(lengths):
    """Canonical codes, shortest first, all-zeros first (as deflate)."""
    codes = {}
    code = 0
    for length in range(1, 33):
        for s, l in enumerate(lengths):
            if l == length:
                codes[s] = (code, length)
                code += 1
        code <<= 1
    return codes


# ---------------------------------------------------------------------------
# 1: RLE90


def rle90(data):
    out = bytearray()
    i = 0
    while i < len(data):
        b = data[i]
        n = 1
        while i + n < len(data) and data[i + n] == b and n < 255:
            n += 1
        out += b"\x90\x00" if b == 0x90 else bytes([b])
        if n >= 3:
            out += bytes([0x90, n])
            i += n
        else:
            i += 1
    return bytes(out)


# ---------------------------------------------------------------------------
# 2: LZW (compress)


def lzw(data):
    z = subprocess.run(["compress", "-b", "14", "-c"], input=data, capture_output=True).stdout
    assert z[:3] == b"\x1f\x9d\x8e", z[:3]
    return z[3:]


# ---------------------------------------------------------------------------
# 3: Huffman


def huffman(data):
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    heap = [(f, i, i) for i, f in enumerate(freq) if f]
    heapq.heapify(heap)
    n = 256
    while len(heap) > 1:
        f1, _, a = heapq.heappop(heap)
        f2, _, b = heapq.heappop(heap)
        n += 1
        heapq.heappush(heap, (f1 + f2, n, (a, b)))
    tree = heap[0][2]
    bw = MsbWriter()
    codes = {}

    def walk(node, prefix):
        if isinstance(node, int):
            bw.write(1, 1)
            bw.write(node, 8)
            codes[node] = prefix
        else:
            bw.write(0, 1)
            walk(node[0], prefix + "0")
            walk(node[1], prefix + "1")

    walk(tree, "")
    for b in data:
        for c in codes[b]:
            bw.write(int(c), 1)
    return bw.getvalue()


# ---------------------------------------------------------------------------
# 5: LZAH (LZHUF)

N, F, THRESHOLD = 4096, 60, 2
N_CHAR = 256 - THRESHOLD + F
T = N_CHAR * 2 - 1
R = T - 1
MAX_FREQ = 0x8000


class AdaptiveHuffman:
    def __init__(self):
        self.freq = [0] * (T + 1)
        self.prnt = [0] * (T + N_CHAR)
        self.son = [0] * T
        for i in range(N_CHAR):
            self.freq[i] = 1
            self.son[i] = i + T
            self.prnt[i + T] = i
        i, j = 0, N_CHAR
        while j <= R:
            self.freq[j] = self.freq[i] + self.freq[i + 1]
            self.son[j] = i
            self.prnt[i] = self.prnt[i + 1] = j
            i += 2
            j += 1
        self.freq[T] = 0xFFFF
        self.prnt[R] = 0

    def reconst(self):
        freq, son, prnt = self.freq, self.son, self.prnt
        j = 0
        for i in range(T):
            if son[i] >= T:
                freq[j] = (freq[i] + 1) // 2
                son[j] = son[i]
                j += 1
        i, j = 0, N_CHAR
        while j < T:
            f = freq[j] = freq[i] + freq[i + 1]
            k = j - 1
            while f < freq[k]:
                k -= 1
            k += 1
            freq[k + 1 : j + 1] = freq[k:j]
            freq[k] = f
            son[k + 1 : j + 1] = son[k:j]
            son[k] = i
            i += 2
            j += 1
        for i in range(T):
            k = son[i]
            prnt[k] = i
            if k < T:
                prnt[k + 1] = i

    def update(self, c):
        freq, son, prnt = self.freq, self.son, self.prnt
        if freq[R] == MAX_FREQ:
            self.reconst()
        c = prnt[c + T]
        while True:
            freq[c] += 1
            k = freq[c]
            l = c + 1
            if k > freq[l]:
                while k > freq[l + 1]:
                    l += 1
                freq[c] = freq[l]
                freq[l] = k
                i = son[c]
                prnt[i] = l
                if i < T:
                    prnt[i + 1] = l
                j = son[l]
                son[l] = i
                prnt[j] = c
                if j < T:
                    prnt[j + 1] = c
                son[c] = j
                c = l
            c = prnt[c]
            if c == 0:
                break

    def encode(self, bw, c):
        # From the leaf's node up to the root; each node is its parent's
        # first or second son.
        bits = []
        k = self.prnt[c + T]
        while k != R:
            p = self.prnt[k]
            bits.append(k - self.son[p])
            k = p
        for b in reversed(bits):
            bw.write(b, 1)
        self.update(c)


# Upper six position bits: (code, length) as lzhuf's p_code / p_len.
P_CODES = []
for count, length, step in ((1, 3, 0x20), (3, 4, 0x10), (8, 5, 8), (12, 6, 4), (24, 7, 2), (16, 8, 1)):
    for _ in range(count):
        P_CODES.append((length, step))
_at = 0
P_TABLE = []
for length, step in P_CODES:
    P_TABLE.append((_at >> (8 - length), length))
    _at += step


def lzah(data):
    bw = MsbWriter()
    tree = AdaptiveHuffman()
    i = 0
    while i < len(data):
        best = (0, 0)
        for dist in range(1, min(i, 4095) + 1):
            n = 0
            while i + n < len(data) and n < F and data[i - dist + n] == data[i + n]:
                n += 1
            if n > best[0]:
                best = (n, dist)
        n, dist = best
        if n > THRESHOLD:
            tree.encode(bw, n + 255 - THRESHOLD)
            pos = dist - 1
            code, length = P_TABLE[pos >> 6]
            bw.write(code, length)
            bw.write(pos & 0x3F, 6)
            i += n
        else:
            tree.encode(bw, data[i])
            i += 1
    return bw.getvalue()


# ---------------------------------------------------------------------------
# 13

META = [
    (0x5D8, 11), (0x058, 8), (0x040, 8), (0x0C0, 8), (0x000, 8), (0x078, 7), (0x02B, 6),
    (0x014, 5), (0x00C, 5), (0x01C, 5), (0x01B, 5), (0x00B, 6), (0x010, 5), (0x020, 6),
    (0x038, 7), (0x018, 7), (0x0D8, 9), (0xBD8, 12), (0x180, 10), (0x680, 11), (0x380, 11),
    (0xF80, 12), (0x780, 12), (0x480, 11), (0x080, 11), (0x280, 11), (0x3D8, 12), (0xFD8, 12),
    (0x7D8, 12), (0x9D8, 12), (0x1D8, 12), (0x004, 5), (0x001, 2), (0x002, 2), (0x007, 3),
    (0x003, 4), (0x008, 5),
]


def write_lengths(bw, lengths):
    """Code lengths through the meta-code: values, +-1 steps and repeats."""

    def meta(sym):
        code, length = META[sym]
        bw.write(code, length)

    cur = 0
    i = 0
    n = len(lengths)
    while i < n:
        target = lengths[i] if lengths[i] else -1
        # The symbol setting the length assigns one entry.
        if target == cur + 1 and cur > 0:
            meta(32)
        elif target == cur - 1 and cur > 1:
            meta(33)
        elif target == -1:
            meta(31)
        else:
            meta(target - 1)
        cur = target
        i += 1
        run = 0
        while i + run < n and (lengths[i + run] or -1) == cur:
            run += 1
        while run > 0:
            if run >= 11:
                k = min(run, 74)
                meta(36)
                bw.write(k - 11, 6)
            elif run >= 3:
                k = min(run, 9)
                meta(35)
                bw.write(k - 3, 3)
            else:
                k = run
                meta(34)
                bw.write(k - 1, 1)
            run -= k
            i += k


def sit13(data, shared=False):
    # LZSS symbols.
    syms = []  # (code index 0/1, symbol, extra) or ("off", bitlength, extra bits, n)
    heads = {}
    i = 0
    after_match = False
    while i < len(data):
        best = (0, 0)
        key = data[i : i + 3]
        if len(key) == 3:
            for cand in reversed(heads.get(key, [])[-32:]):
                dist = i - cand
                if dist > 65536:
                    break
                n = 0
                while i + n < len(data) and n < 2000 and data[cand + n] == data[i + n]:
                    n += 1
                if n > best[0]:
                    best = (n, dist)
        for p in range(i, i + max(best[0], 1)):
            heads.setdefault(data[p : p + 3], []).append(p)
        n, dist = best
        which = 1 if after_match and not shared else 0
        if n >= 3:
            if n <= 64:
                syms.append((which, 0x100 + n - 3, None))
            elif n <= 65 + 1023:
                syms.append((which, 0x13E, (n - 65, 10)))
            else:
                syms.append((which, 0x13F, (n - 65, 15)))
            b = (dist - 1).bit_length()
            extra = (dist - 1 - (1 << (b - 1)), b - 1) if b >= 2 else None
            syms.append((2, b, extra))
            i += n
            after_match = True
        else:
            syms.append((which, data[i], None))
            i += 1
            after_match = False
    syms.append((1 if after_match and not shared else 0, 0x140, None))
    freqs = [[0] * 321, [0] * 321, [0] * 17]
    for w, s, _ in syms:
        freqs[w][s] += 1
    if shared:
        lens = [huffman_lengths(freqs[0], 15)]
    else:
        lens = [huffman_lengths(freqs[0], 15), huffman_lengths(freqs[1], 15)]
    offlens = huffman_lengths(freqs[2], 15)
    bw = LsbWriter()
    for l in lens:
        write_lengths(bw, l)
    write_lengths(bw, offlens)
    codes = [canonical(l) for l in lens] + [canonical(offlens)]
    if shared:
        codes = [codes[0], codes[0], codes[1]]
    for w, s, extra in syms:
        c, l = codes[w][s]
        bw.write_msb(c, l)
        if extra:
            bw.write(extra[0], extra[1])
    return bytes([0x08 * shared | 7]) + bw.getvalue()


# ---------------------------------------------------------------------------
# 15: Arsenic

NUM_BITS = 26
ONE = 1 << (NUM_BITS - 1)
HALF = 1 << (NUM_BITS - 2)


class Model:
    def __init__(self, first, last, inc, limit):
        self.syms = list(range(first, last + 1))
        self.inc = inc
        self.limit = limit
        self.reset()

    def reset(self):
        self.freq = [self.inc] * len(self.syms)
        self.total = self.inc * len(self.syms)

    def increase(self, n):
        self.freq[n] += self.inc
        self.total += self.inc
        if self.total > self.limit:
            self.freq = [(f + 1) >> 1 for f in self.freq]
            self.total = sum(self.freq)


class ArithEncoder:
    def __init__(self):
        self.low = 0
        self.range = ONE
        self.shifts = 0

    def encode(self, model, symbol):
        n = model.syms.index(symbol)
        cum = sum(model.freq[:n])
        size = model.freq[n]
        r = self.range // model.total
        incr = r * cum
        self.low += incr
        if cum + size == model.total:
            self.range -= incr
        else:
            self.range = size * r
        while self.range <= HALF:
            self.range <<= 1
            self.low <<= 1
            self.shifts += 1
        model.increase(n)

    def bits(self, model, value, n):
        for i in range(n):
            self.encode(model, (value >> i) & 1)

    def getvalue(self):
        total = NUM_BITS + self.shifts
        bw = MsbWriter()
        bw.write(self.low, total)
        bw.write(0, 32)
        return bw.getvalue()


def arsenic_rle(data):
    out = bytearray()
    i = 0
    while i < len(data):
        b = data[i]
        n = 1
        while i + n < len(data) and data[i + n] == b:
            n += 1
        i += n
        while n >= 4:
            c = min(n - 4, 255)
            out += bytes([b] * 4 + [c])
            n -= 4 + c
        out += bytes([b] * n)
    return bytes(out)


def arsenic(data, block_bits=9):
    enc = ArithEncoder()
    initial = Model(0, 1, 1, 256)
    selector = Model(0, 10, 8, 1024)
    mtf_models = [Model(2, 3, 8, 1024), Model(4, 7, 4, 1024), Model(8, 15, 4, 1024),
                  Model(16, 31, 4, 1024), Model(32, 63, 2, 1024), Model(64, 127, 2, 1024),
                  Model(128, 255, 1, 1024)]
    enc.bits(initial, ord("A"), 8)
    enc.bits(initial, ord("s"), 8)
    enc.bits(initial, block_bits - 9, 4)
    block_size = 1 << block_bits
    # Split the input so each block's RLE form fits.
    chunks = []
    i = 0
    while i < len(data):
        n = len(data) - i
        while len(arsenic_rle(data[i : i + n])) > block_size:
            n = n * 3 // 4
        chunks.append(data[i : i + n])
        i += n
    enc.encode(initial, 0 if chunks else 1)
    for k, chunk in enumerate(chunks):
        block = arsenic_rle(chunk)
        n = len(block)
        rots = sorted(range(n), key=lambda j: block[j:] + block[:j])
        last = bytes(block[(j - 1) % n] for j in rots)
        primary = rots.index(0)
        enc.encode(initial, 0)  # not randomized
        enc.bits(initial, primary, block_bits)
        mtf = list(range(256))
        zeros = 0

        def flush_zeros(z):
            while z > 0:
                if z & 1:
                    enc.encode(selector, 0)
                    z = (z - 1) >> 1
                else:
                    enc.encode(selector, 1)
                    z = (z - 2) >> 1

        for b in last:
            idx = mtf.index(b)
            mtf.pop(idx)
            mtf.insert(0, b)
            if idx == 0:
                zeros += 1
                continue
            flush_zeros(zeros)
            zeros = 0
            if idx == 1:
                enc.encode(selector, 2)
            else:
                sel = idx.bit_length() + 1  # 2..3 -> 3, 4..7 -> 4, ...
                enc.encode(selector, sel)
                enc.encode(mtf_models[sel - 3], idx)
        flush_zeros(zeros)
        enc.encode(selector, 10)
        selector.reset()
        for m in mtf_models:
            m.reset()
        if k == len(chunks) - 1:
            enc.encode(initial, 1)
            enc.bits(initial, zlib.crc32(data), 32)
        else:
            enc.encode(initial, 0)
    return enc.getvalue()


# ---------------------------------------------------------------------------
# Containers

ENCODERS = {0: lambda d: d, 1: rle90, 2: lzw, 3: huffman, 5: lzah, 13: sit13, 15: arsenic}

MAC_TIME = 0xE1B92DA0


def classic_entry(name, rsrc, data, rsrc_method, data_method, ftype=b"TEXT", creator=b"ttxt"):
    rp = ENCODERS[rsrc_method](rsrc) if rsrc else b""
    dp = ENCODERS[data_method](data) if data else b""
    h = bytes([rsrc_method, data_method, len(name)]) + name.ljust(63, b"\0")
    h += ftype + creator + struct.pack(">H", 0x0100)
    h += struct.pack(">LL", MAC_TIME, MAC_TIME)
    h += struct.pack(">LLLL", len(rsrc), len(data), len(rp), len(dp))
    h += struct.pack(">HH", crc16(rsrc), crc16(data)) + b"\0" * 6
    h += struct.pack(">H", crc16(h))
    assert len(h) == 112
    return h + rp + dp


def classic_folder(name, start):
    m = 32 if start else 33
    h = bytes([m, m, len(name)]) + name.ljust(63, b"\0")
    h += b"\0" * 8 + struct.pack(">H", 0) + struct.pack(">LL", MAC_TIME, MAC_TIME)
    h += b"\0" * 16 + b"\0" * 4 + b"\0" * 6
    h += struct.pack(">H", crc16(h))
    assert len(h) == 112
    return h


def classic_archive(entries, files):
    body = b"".join(entries)
    total = 22 + len(body)
    head = b"SIT!" + struct.pack(">HL", files, total) + b"rLau" + bytes([2]) + b"\0" * 7
    return head + body


BANNER = b"StuffIt (c)1997-2002 Aladdin Systems, Inc., http://www.aladdinsys.com/StuffIt/\r\n"


def sit5_entry(at, name, parent, data=b"", rsrc=None, method=15, rmethod=15, directory=None):
    """One entry at offset `at`; returns its bytes. `directory` is the
    number of entries in a directory."""
    flags = 0x40 if directory is not None else 0
    dp = ENCODERS[method](data) if directory is None else b""
    first = struct.pack(">LBBHBB", 0xA5A5A5A5, 1, 0, 0, 0, flags)
    first += struct.pack(">LL", MAC_TIME, MAC_TIME)
    first += struct.pack(">LLL", 0, 0, parent)
    first += struct.pack(">HH", len(name), 0)
    if directory is None:
        first += struct.pack(">LLHH", len(data), len(dp), crc16(data) if method != 15 else 0, 0)
        first += bytes([method, 0])
    else:
        first += struct.pack(">LLHH", 0, 0, 0, 0)
        first += struct.pack(">H", directory)
    first += name
    first = first[:6] + struct.pack(">H", len(first)) + first[8:]
    crc = crc16(first)
    first = first[:32] + struct.pack(">H", crc) + first[34:]
    second = struct.pack(">HH", 1 if rsrc is not None else 0, 0)
    second += b"TEXT" + b"ttxt" + struct.pack(">H", 0x0100) + b"\0" * 22
    rp = b""
    if rsrc is not None:
        rp = ENCODERS[rmethod](rsrc)
        second += struct.pack(">LLHH", len(rsrc), len(rp), crc16(rsrc) if rmethod != 15 else 0, 0)
        second += bytes([rmethod, 0])
    return first + second + rp + dp


def sit5_archive(build):
    """`build(at)` returns the entries' bytes given where they start."""
    head_len = 100
    entries, roots = build(head_len)
    total = head_len + len(entries)
    head = BANNER + b"\x1a\x00" + bytes([5, 0]) + struct.pack(">LLHL", total, head_len, roots, head_len)
    head += b"\0" * (head_len - len(head))
    return head + entries


def resource_fork():
    """A minimal resource fork: one 'STR ' resource."""
    data = struct.pack(">L", 5) + b"Hello"
    tlist = struct.pack(">H", 0) + b"STR " + struct.pack(">HH", 0, 10)
    refs = struct.pack(">hhB", 128, -1, 0) + b"\0\0\0" + b"\0\0\0\0"
    map_body = b"\0" * 22 + struct.pack(">HH", 28, 28 + len(tlist) + len(refs)) + tlist + refs
    data_off = 256
    map_off = data_off + len(data)
    header = struct.pack(">LLLL", data_off, map_off, len(data), len(map_body))
    head = header + b"\0" * (data_off - 16)
    map_body = header + map_body[16:]
    return head + data + map_body


def sample_text():
    lines = []
    for i in range(24):
        lines.append(b"Line %02d: StuffIt packs Macintosh files with both forks.\r" % i)
    return b"".join(lines) + b"\x90\x90\x90 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r"


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    text = sample_text()
    rsrc = resource_fork()
    entries = [
        classic_entry(b"ReadMe (stored)", b"", text, 0, 0),
        classic_entry(b"ReadMe (RLE90)", rsrc, text, 0, 1),
        classic_entry(b"ReadMe (LZW)", b"", text, 0, 2),
        classic_entry(b"ReadMe (Huffman)", b"", text, 0, 3),
        classic_folder(b"Docs", True),
        classic_entry(b"ReadMe (LZAH)", b"", text, 0, 5),
        classic_entry(b"ReadMe (13)", rsrc, text, 13, 13),
        classic_folder(b"Docs", False),
        classic_entry(b"ReadMe (Arsenic)", b"", text, 0, 15),
    ]
    blob = classic_archive(entries, 7)
    with open(os.path.join(outdir, "methods.sit"), "wb") as f:
        f.write(blob)
    print("methods.sit", len(blob))

    def build(at):
        out = b""
        # A folder with two files, then a file at the root.
        folder_at = at
        out += sit5_entry(at, b"Folder", 0, directory=2)
        out += sit5_entry(at + len(out), b"hello.txt", folder_at, text, method=15)
        out += sit5_entry(at + len(out), b"Icon\r", folder_at, b"", rsrc=rsrc, method=0, rmethod=13)
        out += sit5_entry(at + len(out), b"notes.txt", 0, text[:300] * 3, method=13)
        return out, 2

    blob = sit5_archive(build)
    with open(os.path.join(outdir, "arsenic.sit"), "wb") as f:
        f.write(blob)
    print("arsenic.sit", len(blob))


if __name__ == "__main__":
    main(sys.argv[1])
