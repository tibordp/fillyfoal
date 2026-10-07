#!/usr/bin/env python3
"""Generates the LHA, ARJ, ZOO, SZDD, KWAJ and PSARC test fixtures.

No LHA, ARJ, ZOO, COMPRESS.EXE or PSARC writer is installed on the
development machine (`lha`, `jlha`, `arj`, `zoo` are absent), so the
compressed streams come from the small encoders below, written from memory
of the reference decoders (LHa for UNIX, Okumura's lzhuf.c, unarj, zoo's
lzd.c, libmspack), and the containers are assembled here. With --check,
every archive an independent decoder can read is extracted and compared
with the input:

- 7-Zip (`7zz x`): LHA -lh0- and -lh4- to -lh7- (it does not do -lh1-,
  -lzs- or -lz5-), ARJ methods 1 to 4, SZDD;
- libarchive (`bsdtar -x`): LHA -lh5- to -lh7-;
- lhafile (`uv run --with lhafile`): LHA -lh5- to -lh7-.

-lh1-, -lzs-, -lz5-, ZOO (LZW and -lh5-), KWAJ and PSARC have no
independent decoder here: they are only checked against our own decoder
(the stored CRCs, computed here from the input, must match). KWAJ's MSZIP
blocks and PSARC's zlib/LZMA blocks come from Python's zlib and lzma.

Usage: python3 make.py [--check]
"""

import hashlib
import heapq
import lzma
import os
import struct
import subprocess
import sys
import tempfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "..", "..", "fixtures", "synthetic")

# ---------------------------------------------------------------- inputs


def text(n, seed=1):
    words = (
        "the quick brown fox jumps over lazy dogs while old archivers "
        "squeeze bytes into tiny floppy disks and bulletin boards"
    ).split()
    out = []
    x = seed
    i = 0
    while sum(len(w) + 1 for w in out) < n:
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        out.append(words[(x >> 16) % len(words)])
        i += 1
        if i % 12 == 0:
            out.append(f"{i}\r\n")
    return " ".join(out).encode()[:n]


def binary(n, seed=7):
    x = seed
    out = bytearray()
    for i in range(n):
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        r = (x >> 16) & 0xFF
        out.append(r if r < 160 else (i & 0x0F))
    return bytes(out)


def crc16(data):
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


# ---------------------------------------------------------------- bits


class MsbWriter:
    def __init__(self):
        self.bits = []

    def put(self, n, v):
        for i in range(n - 1, -1, -1):
            self.bits.append((v >> i) & 1)

    def code(self, code):
        self.bits.extend(code)

    def bytes(self):
        out = bytearray()
        bits = self.bits + [0] * (-len(self.bits) % 8)
        for i in range(0, len(bits), 8):
            v = 0
            for b in bits[i : i + 8]:
                v = v << 1 | b
            out.append(v)
        return bytes(out)


# ---------------------------------------------------------------- LZ77


def matches(data, window, min_len, max_len):
    """Greedy LZ77 parse with hash chains: (literal byte) or (length,
    distance) tuples."""
    heads = {}
    prev = {}
    i = 0
    out = []
    n = len(data)

    def insert(j):
        if j + 3 <= n:
            key = data[j : j + 3]
            prev[j] = heads.get(key)
            heads[key] = j

    while i < n:
        best_len, best_dist = 0, 0
        if i + 3 <= n:
            cand = heads.get(data[i : i + 3])
            tries = 0
            while cand is not None and i - cand <= window and tries < 64:
                length = 0
                while length < max_len and i + length < n and data[cand + length] == data[i + length]:
                    length += 1
                if length > best_len:
                    best_len, best_dist = length, i - cand
                cand = prev.get(cand)
                tries += 1
        if best_len >= min_len:
            out.append((best_len, best_dist))
            for j in range(i, i + best_len):
                insert(j)
            i += best_len
        else:
            out.append(data[i])
            insert(i)
            i += 1
    return out


# ---------------------------------------------------------------- Huffman


def huffman_lengths(freqs, max_len):
    """Huffman code lengths (<= max_len); symbols with zero frequency get
    none. At least two symbols must be used."""
    scale = 0
    while True:
        fs = [((f >> scale) | 1) if f else 0 for f in freqs]
        heap = [(f, i, [i]) for i, f in enumerate(fs) if f]
        heapq.heapify(heap)
        lengths = [0] * len(freqs)
        tie = len(freqs)
        while len(heap) > 1:
            f1, _, s1 = heapq.heappop(heap)
            f2, _, s2 = heapq.heappop(heap)
            for s in s1 + s2:
                lengths[s] += 1
            heapq.heappush(heap, (f1 + f2, tie, s1 + s2))
            tie += 1
        if max(lengths) <= max_len:
            return lengths
        scale += 1


def canonical(lengths):
    """Codes (bit lists) assigned shortest first, then in symbol order."""
    codes = [None] * len(lengths)
    code = 0
    for length in range(1, 33):
        for s, l in enumerate(lengths):
            if l == length:
                codes[s] = [(code >> (length - 1 - k)) & 1 for k in range(length)]
                code += 1
        code <<= 1
    return codes


# ---------------------------------------------------------------- static Huffman (-lh4- .. -lh7-, ARJ 1-3)

NC = 510
NT = 19


def write_pt_len(w, lengths, nbit, special):
    n = len(lengths)
    while n > 0 and lengths[n - 1] == 0:
        n -= 1
    w.put(nbit, n)
    i = 0
    while i < n:
        k = lengths[i]
        i += 1
        if k <= 6:
            w.put(3, k)
        else:
            w.put(k - 3, (1 << (k - 3)) - 2)
        if i == special:
            while i < 6 and lengths[i] == 0:
                i += 1
            w.put(2, (i - 3) & 3)


def c_len_symbols(c_lengths):
    """The T-table symbols (and extra bits) coding the literal/length
    lengths."""
    n = len(c_lengths)
    while n > 0 and c_lengths[n - 1] == 0:
        n -= 1
    out = []
    i = 0
    while i < n:
        k = c_lengths[i]
        i += 1
        if k == 0:
            count = 1
            while i < n and c_lengths[i] == 0:
                i += 1
                count += 1
            if count <= 2:
                out += [(0, 0, 0)] * count
            elif count <= 18:
                out.append((1, 4, count - 3))
            elif count == 19:
                out.append((0, 0, 0))
                out.append((1, 4, 15))
            else:
                out.append((2, 9, count - 20))
        else:
            out.append((k + 2, 0, 0))
    return n, out


def lh_static(data, window, np_, pbit, block_tokens=1500):
    tokens = matches(data, window - 256, 3, 256)
    w = MsbWriter()
    for b in range(0, len(tokens), block_tokens):
        block = tokens[b : b + block_tokens]
        cf = [0] * NC
        pf = [0] * np_
        for t in block:
            if isinstance(t, int):
                cf[t] += 1
            else:
                cf[t[0] + 253] += 1
                pf[(t[1] - 1).bit_length()] += 1
        w.put(16, len(block))
        # Literal/length table.
        single_c = sum(1 for f in cf if f) == 1
        if single_c:
            c_lengths = [0] * NC
            c_codes = {cf.index(max(cf)): []}
            w.put(5, 0)
            w.put(5, 0)
            w.put(9, 0)
            w.put(9, cf.index(max(cf)))
        else:
            c_lengths = huffman_lengths(cf, 16)
            c_codes = canonical(c_lengths)
            n, tsyms = c_len_symbols(c_lengths)
            tf = [0] * NT
            for s, _, _ in tsyms:
                tf[s] += 1
            if sum(1 for f in tf if f) == 1:
                w.put(5, 0)
                w.put(5, tf.index(max(tf)))
                t_codes = {tf.index(max(tf)): []}
            else:
                t_lengths = huffman_lengths(tf, 16)
                t_codes = canonical(t_lengths)
                write_pt_len(w, t_lengths, 5, 3)
            w.put(9, n)
            for s, nb, v in tsyms:
                w.code(t_codes[s])
                w.put(nb, v)
        # Position table.
        if sum(1 for f in pf if f) <= 1:
            p_codes = {max(range(np_), key=lambda i: pf[i]): []}
            w.put(pbit, 0)
            w.put(pbit, max(range(np_), key=lambda i: pf[i]))
        else:
            p_lengths = huffman_lengths(pf, 16)
            p_codes = canonical(p_lengths)
            write_pt_len(w, p_lengths, pbit, -1)
        for t in block:
            if isinstance(t, int):
                w.code(c_codes[t])
            else:
                length, dist = t
                w.code(c_codes[length + 253])
                p = dist - 1
                pc = p.bit_length()
                w.code(p_codes[pc])
                if pc > 1:
                    w.put(pc - 1, p - (1 << (pc - 1)))
    return w.bytes()


def lh(data, dict_bits):
    np_ = max(dict_bits, 13) + 1
    return lh_static(data, 1 << dict_bits, np_, 4 if np_ <= 14 else 5)


def arj_static(data):
    return lh_static(data, 26624, 17, 5)


# ---------------------------------------------------------------- -lh1- (LZHUF)

N_CHAR = 256 - 3 + 60
T = N_CHAR * 2 - 1
R = T - 1
MAX_FREQ = 0x8000


class Adaptive:
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
        i = 0
        for j in range(N_CHAR, T):
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
        for i in range(T):
            k = son[i]
            if k >= T:
                prnt[k] = i
            else:
                prnt[k] = prnt[k + 1] = i

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

    def encode(self, w, c):
        bits = []
        k = self.prnt[c + T]
        while True:
            bits.append(k & 1)
            k = self.prnt[k]
            if k == R:
                break
        w.code(bits[::-1])
        self.update(c)


LH1_P_LENGTHS = [3] * 1 + [4] * 3 + [5] * 8 + [6] * 12 + [7] * 24 + [8] * 16


def lh1(data):
    tokens = matches(data, 4096 - 60, 3, 60)
    w = MsbWriter()
    tree = Adaptive()
    p_codes = canonical(LH1_P_LENGTHS)
    for t in tokens:
        if isinstance(t, int):
            tree.encode(w, t)
        else:
            length, dist = t
            tree.encode(w, length + 253)
            p = dist - 1
            w.code(p_codes[p >> 6])
            w.put(6, p & 0x3F)
    return w.bytes()


# ---------------------------------------------------------------- ring LZSS (-lzs-, -lz5-, SZDD)


def ring_items(data, size, start, max_len):
    """Tokens with absolute ring positions: the ring index of output byte
    x is (start + x) mod size."""
    out = []
    pos = 0
    for t in matches(data, size - max_len, 3, max_len):
        if isinstance(t, int):
            out.append(t)
            pos += 1
        else:
            length, dist = t
            out.append((length, (start + pos - dist) % size))
            pos += length
    return out


def flag_lzss(data, start, max_len):
    """SZDD / -lz5-: a flag byte (LSB first, 1 = literal) per 8 items.
    COMPRESS.EXE's matches are at most 16 bytes long (7-Zip rejects longer
    ones), LArc's 18."""
    items = ring_items(data, 4096, start, max_len)
    out = bytearray()
    for g in range(0, len(items), 8):
        group = items[g : g + 8]
        flags = 0
        body = bytearray()
        for k, t in enumerate(group):
            if isinstance(t, int):
                flags |= 1 << k
                body.append(t)
            else:
                length, p = t
                body.append(p & 0xFF)
                body.append(((p >> 4) & 0xF0) | (length - 3))
        out.append(flags)
        out += body
    return bytes(out)


def szdd_lzss(data):
    return flag_lzss(data, 4096 - 16, 16)


def lz5(data):
    return flag_lzss(data, 4096 - 18, 18)


def lzs(data):
    w = MsbWriter()
    for t in ring_items(data, 2048, 2048 - 17, 17):
        if isinstance(t, int):
            w.put(1, 1)
            w.put(8, t)
        else:
            length, p = t
            w.put(1, 0)
            w.put(11, p)
            w.put(4, length - 2)
    return w.bytes()


# ---------------------------------------------------------------- ARJ method 4


def arj_number(w, v, start, stop):
    width = start
    plus = 0
    while width < stop and v >= plus + (1 << width):
        plus += 1 << width
        width += 1
    w.put(width - start, (1 << (width - start)) - 1)
    if width < stop:
        w.put(1, 0)
    w.put(width, v - plus)


def arj_fastest(data):
    w = MsbWriter()
    for t in matches(data, 15872, 3, 256):
        if isinstance(t, int):
            w.put(1, 0)
            w.put(8, t)
        else:
            length, dist = t
            arj_number(w, length - 2, 0, 7)
            arj_number(w, dist - 1, 9, 13)
    return w.bytes()


# ---------------------------------------------------------------- ZOO LZW


def zoo_lzw(data):
    """LZW as zoo's lzd.c reads it: 9- to 13-bit codes, LSB first; 256
    clears, 257 ends. The decoder adds a table entry for every code but the
    first after a clear, and widens codes once the next free code reaches
    2^bits; the encoder mirrors that."""
    out_bits = []

    def emit(code, bits):
        for i in range(bits):
            out_bits.append((code >> i) & 1)

    state = {}

    def reset():
        state["dict"] = {bytes([i]): i for i in range(256)}
        state["free"] = 258
        state["bits"] = 9
        state["first"] = True

    def put(code):
        emit(code, state["bits"])
        if state["first"]:
            state["first"] = False
            return
        state["free"] += 1
        if state["free"] >= (1 << state["bits"]) and state["bits"] < 13:
            state["bits"] += 1

    reset()
    emit(256, 9)
    w = b""
    for b in data:
        wc = w + bytes([b])
        if wc in state["dict"]:
            w = wc
            continue
        put(state["dict"][w])
        # The entry the decoder adds when it reads the next code.
        if len(state["dict"]) - 256 + 258 < 8192:
            state["dict"][wc] = len(state["dict"]) - 256 + 258
        else:
            emit(256, state["bits"])
            reset()
        w = bytes([b])
    if w:
        put(state["dict"][w])
    emit(257, state["bits"])
    out_bits += [0] * (-len(out_bits) % 8)
    out = bytearray()
    for i in range(0, len(out_bits), 8):
        out.append(sum(bit << k for k, bit in enumerate(out_bits[i : i + 8])))
    return bytes(out)


# ---------------------------------------------------------------- containers

DOS_TIME = 0x58221880  # 2024-01-02 03:04:00


def lha_level0(method, name, data, packed):
    name = name.encode()
    body = (
        method.encode()
        + struct.pack("<IIIBBB", len(packed), len(data), DOS_TIME, 0x20, 0, len(name))
        + name
        + struct.pack("<H", crc16(data))
    )
    return bytes([len(body), sum(body) & 0xFF]) + body + packed


LHA_METHODS = [
    ("-lh0-", lambda d: d),
    ("-lh1-", lh1),
    ("-lh4-", lambda d: lh(d, 12)),
    ("-lh5-", lambda d: lh(d, 13)),
    ("-lh6-", lambda d: lh(d, 15)),
    ("-lh7-", lambda d: lh(d, 16)),
    ("-lzs-", lzs),
    ("-lz5-", lz5),
]


def lha_inputs():
    return {
        "-lh0-": b"stored member\r\n",
        "-lh1-": text(3000, 11),
        "-lh4-": text(2500, 12) + binary(500),
        "-lh5-": text(3000, 13),
        "-lh6-": binary(1500, 3) + text(1500, 14),
        "-lh7-": binary(256, 4) + text(20000, 15) + binary(256, 4),
        "-lzs-": text(1500, 16),
        "-lz5-": text(1500, 17),
    }


def make_lha():
    inputs = lha_inputs()
    out = bytearray()
    files = {}
    for method, enc in LHA_METHODS:
        name = method.strip("-") + (".bin" if method in ("-lh4-", "-lh6-") else ".txt")
        data = inputs[method]
        out += lha_level0(method, name, data, enc(data))
        files[name] = data
    out.append(0)
    return bytes(out), files


def arj_header(file_type, method, name, comment, data=b"", packed=b"", main=False):
    first = struct.pack(
        "<BBBBBBBBIIIIHHBB",
        30,
        11,
        1,
        0,  # MS-DOS
        0,
        method,
        file_type,
        0,
        DOS_TIME,
        len(packed),
        len(data),
        0 if main else zlib.crc32(data),
        0,
        0 if main else 0x20,
        0,
        0,
    )
    basic = first + name.encode() + b"\0" + comment.encode() + b"\0"
    return (
        b"\x60\xea"
        + struct.pack("<H", len(basic))
        + basic
        + struct.pack("<I", zlib.crc32(basic))
        + b"\0\0"
        + packed
    )


def arj_inputs():
    return {
        0: b"stored member\r\n",
        1: text(3000, 21),
        2: binary(800, 5) + text(1200, 22),
        3: text(2000, 23),
        4: text(3000, 24),
    }


def make_arj():
    inputs = arj_inputs()
    out = bytearray(arj_header(2, 0, "METHODS.ARJ", "methods 0 to 4", main=True))
    files = {}
    for method, data in inputs.items():
        name = f"METHOD{method}.{'BIN' if method == 2 else 'TXT'}"
        if method == 0:
            packed = data
        elif method == 4:
            packed = arj_fastest(data)
        else:
            packed = arj_static(data)
        out += arj_header(0, method, name, "", data, packed)
        files[name] = data
    out += b"\x60\xea\0\0"
    return bytes(out), files


def make_zoo():
    inputs = {
        "stored.txt": (0, b"stored member\r\n"),
        "lzw.txt": (1, text(9000, 31)),
        "lzh.txt": (2, text(3000, 32)),
    }
    head = b"ZOO 2.10 Archive.\x1a".ljust(20, b"\0")
    out = bytearray(head + struct.pack("<IIiBBBIHB", 0xFDC4A7DC, 42, -42, 2, 0, 1, 0, 0, 0))
    entries = []
    pos = 42
    blobs = []
    for name, (method, data) in inputs.items():
        packed = {0: lambda d: d, 1: zoo_lzw, 2: lambda d: lh(d, 13)}[method](data)
        entries.append((name, method, data, packed))
    # Entry, data, entry, data, ..., end entry.
    for name, method, data, packed in entries:
        entry_at = pos
        data_at = entry_at + 51
        next_at = data_at + len(packed)
        fname = name.encode().ljust(13, b"\0")
        entry = struct.pack(
            "<IBBIIHHHIIBBBBIH",
            0xFDC4A7DC,
            1,
            method,
            next_at,
            data_at,
            DOS_TIME >> 16,
            DOS_TIME & 0xFFFF,
            crc16(data),
            len(data),
            len(packed),
            2 if method == 2 else 1,
            0,
            0,
            0,
            0,
            0,
        ) + fname
        assert len(entry) == 51
        blobs.append(entry + packed)
        pos = next_at
    end = struct.pack("<IBBII", 0xFDC4A7DC, 1, 0, 0, 0).ljust(51, b"\0")
    return bytes(out) + b"".join(blobs) + end, {n: d for n, (_, d) in inputs.items()}


def make_szdd():
    data = text(3000, 41)
    return b"SZDD\x88\xf0\x27\x33A" + b"t" + struct.pack("<I", len(data)) + szdd_lzss(data), data


def kwaj_mszip(data):
    out = bytearray()
    dictionary = b""
    for at in range(0, len(data), 32768):
        block = data[at : at + 32768]
        c = zlib.compressobj(9, zlib.DEFLATED, -15, zdict=dictionary) if dictionary else zlib.compressobj(9, zlib.DEFLATED, -15)
        raw = c.compress(block) + c.flush()
        out += struct.pack("<H", len(raw) + 2) + b"CK" + raw
        dictionary = (dictionary + block)[-32768:]
    return bytes(out)


def make_kwaj(method):
    data = text(3000, 51) if method == 2 else text(40000, 52)
    packed = szdd_lzss(data) if method == 2 else kwaj_mszip(data)
    # Flags: uncompressed length (1), file name (8), extension (0x10).
    name = b"README\0TXT\0"
    header_len = 14 + 4 + len(name)
    head = b"KWAJ\x88\xf0\x27\xd1" + struct.pack("<HHH", method, header_len, 0x19)
    return head + struct.pack("<I", len(data)) + name + packed, data


def make_psarc(compression, block_size=4096):
    files = {
        "/docs/readme.txt": text(9000, 61),
        "/data/noise.bin": binary(4096, 9)[:4096] + bytes(range(256)) * 2,
        "/data/tail.txt": b"short text member\n",
    }
    names = list(files)
    manifest = "\n".join(names).encode()
    contents = [manifest] + [files[n] for n in names]
    sizes_table = []
    data = bytearray()
    entries = []
    for i, content in enumerate(contents):
        first_block = len(sizes_table)
        offset = len(data)
        for at in range(0, max(len(content), 1), block_size):
            block = content[at : at + block_size]
            if compression == b"zlib":
                packed = zlib.compress(block, 9)
            else:
                c = lzma.LZMACompressor(lzma.FORMAT_ALONE, preset=6)
                packed = c.compress(block) + c.flush()
            if len(packed) >= len(block):
                packed = block
                sizes_table.append(0 if len(block) == block_size else len(block))
            else:
                sizes_table.append(len(packed))
            data += packed
        digest = b"\0" * 16 if i == 0 else hashlib.md5(names[i - 1].encode()).digest()
        entries.append((digest, first_block, len(content), offset))
    toc_len = 32 + 30 * len(entries) + 2 * len(sizes_table)
    toc = bytearray()
    for digest, first_block, size, offset in entries:
        toc += digest + struct.pack(">I", first_block) + size.to_bytes(5, "big") + (offset + toc_len).to_bytes(5, "big")
    toc += b"".join(struct.pack(">H", s) for s in sizes_table)
    header = b"PSAR" + struct.pack(">HH", 1, 4) + compression + struct.pack(">IIIII", toc_len, 30, len(entries), block_size, 2)
    return header + bytes(toc) + bytes(data), files


# ---------------------------------------------------------------- checks


def check_7zz(path, files):
    with tempfile.TemporaryDirectory() as d:
        r = subprocess.run(["7zz", "x", "-y", f"-o{d}", path], capture_output=True, text=True)
        ok = True
        for name, data in files.items():
            p = os.path.join(d, name)
            got = open(p, "rb").read() if os.path.exists(p) else None
            status = "ok" if got == data else "MISMATCH"
            ok &= got == data
            print(f"  7zz {os.path.basename(path)}:{name}: {status}")
        if not ok:
            print(r.stdout, r.stderr)
        return ok


def check_bsdtar(path, files):
    with tempfile.TemporaryDirectory() as d:
        subprocess.run(["bsdtar", "-x", "-C", d, "-f", path], capture_output=True)
        for name, data in files.items():
            p = os.path.join(d, name)
            got = open(p, "rb").read() if os.path.exists(p) else None
            print(f"  bsdtar {name}: {'ok' if got == data else 'MISMATCH'}")


def check_lhafile(files):
    """lhafile refuses archives with methods it lacks: check a copy with
    only -lh5- to -lh7-."""
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "t.lzh")
        out = bytearray()
        for name, data in files.items():
            enc = {"lh5": 13, "lh6": 15, "lh7": 16}[name[:3]]
            out += lha_level0(f"-{name[:3]}-", name, data, lh(data, enc))
        out.append(0)
        open(path, "wb").write(out)
        return lhafile_read(path, list(files))


def lhafile_read(path, names):
    script = (
        "import sys, lhafile\n"
        "f = lhafile.Lhafile(sys.argv[1])\n"
        "for n in sys.argv[2:]:\n"
        "    sys.stdout.buffer.write(f.read(n).hex().encode() + b'\\n')\n"
    )
    r = subprocess.run(
        ["uv", "run", "--quiet", "--with", "lhafile", "python", "-I", "-c", script, path, *names],
        capture_output=True,
    )
    return [bytes.fromhex(line) for line in r.stdout.decode().split()]


def write(fmt, name, data):
    d = os.path.join(FIXTURES, fmt)
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, name)
    with open(path, "wb") as f:
        f.write(data)
    print(f"{fmt}/{name}: {len(data)} bytes")
    return path


def main():
    check = "--check" in sys.argv
    lha_data, lha_files = make_lha()
    lha_path = write("lha", "methods.lzh", lha_data)
    arj_data, arj_files = make_arj()
    arj_path = write("arj", "methods.arj", arj_data)
    zoo_data, _ = make_zoo()
    write("zoo", "methods.zoo", zoo_data)
    szdd_data, szdd_plain = make_szdd()
    szdd_path = write("szdd", "lzss.tx_", szdd_data)
    write("kwaj", "lzss.tx_", make_kwaj(2)[0])
    write("kwaj", "mszip.tx_", make_kwaj(4)[0])
    write("psarc", "zlib.psarc", make_psarc(b"zlib")[0])
    write("psarc", "lzma.psarc", make_psarc(b"lzma")[0])
    if not check:
        return
    ok = True
    sevenzip = {n: d for n, d in lha_files.items() if not n.startswith(("lh1", "lzs", "lz5"))}
    ok &= check_7zz(lha_path, sevenzip)
    ok &= check_7zz(arj_path, arj_files)
    with tempfile.TemporaryDirectory() as d:
        # 7-Zip names an SZDD member after the archive.
        p = os.path.join(d, "lzss.tx_")
        open(p, "wb").write(szdd_data)
        r = subprocess.run(["7zz", "x", "-y", f"-o{d}/out", p], capture_output=True, text=True)
        outs = os.listdir(os.path.join(d, "out")) if os.path.isdir(os.path.join(d, "out")) else []
        got = open(os.path.join(d, "out", outs[0]), "rb").read() if outs else None
        print(f"  7zz lzss.tx_ ({outs}): {'ok' if got == szdd_plain else 'MISMATCH'}")
        ok &= got == szdd_plain
    libarchive = {n: d for n, d in lha_files.items() if n.startswith(("lh5", "lh6", "lh7"))}
    check_bsdtar(lha_path, libarchive)
    got = check_lhafile(libarchive)
    for (n, d), g in zip(libarchive.items(), got):
        print(f"  lhafile {n}: {'ok' if g == d else 'MISMATCH'}")
    if len(got) != len(libarchive):
        print("  lhafile: failed")
    print("all 7-Zip checks passed" if ok else "7-Zip CHECKS FAILED")


if __name__ == "__main__":
    main()
