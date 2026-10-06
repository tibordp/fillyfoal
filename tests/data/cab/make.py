#!/usr/bin/env python3
"""Generates the cabinet and CHM test files in this directory.

No CAB/CHM writer is installed on the development machine, so:
- MSZIP data comes from zlib (a real DEFLATE encoder) with the previous
  block as the preset dictionary, as MSZIP requires;
- LZX and Quantum data come from the small encoders below, written from
  libmspack's decoder description. Every generated file is cross-checked
  by extracting it with 7-Zip (`7zz x`), an independent decoder, and
  comparing the result with the input (run with --check).

Usage: python3 make.py [--check]
"""

import os
import struct
import subprocess
import sys
import tempfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))


def lzma_text():
    return "".join(f"line {i}: the quick brown fox {i * 7919 % 1000}\n" for i in range(2000)).encode()


def lzma_code():
    x = 12345
    out = bytearray()
    for _ in range(40000):
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        r = (x >> 16) & 0xFF
        out.append(0xE8 if r < 40 else r)
    return bytes(out)


# ---------------------------------------------------------------- Huffman


def huffman_lengths(freqs, max_len):
    """Code lengths (<= max_len) for the given frequencies; at least two
    symbols get codes so the code is complete."""
    freqs = list(freqs)
    used = [i for i, f in enumerate(freqs) if f > 0]
    while len(used) < 2:
        for i in range(len(freqs)):
            if freqs[i] == 0:
                freqs[i] = 1
                used.append(i)
                break
    scale = 0
    while True:
        fs = [((f >> scale) | 1) if f else 0 for f in freqs]
        nodes = [(f, [i]) for i, f in enumerate(fs) if f]
        lengths = [0] * len(freqs)
        import heapq

        heap = [(f, n, syms) for n, (f, syms) in enumerate(nodes)]
        heapq.heapify(heap)
        counter = len(heap)
        while len(heap) > 1:
            f1, _, s1 = heapq.heappop(heap)
            f2, _, s2 = heapq.heappop(heap)
            for s in s1 + s2:
                lengths[s] += 1
            heapq.heappush(heap, (f1 + f2, counter, s1 + s2))
            counter += 1
        if max(lengths) <= max_len:
            return lengths
        scale += 1


def canonical_codes(lengths):
    max_len = max(lengths) if lengths else 0
    bl_count = [0] * (max_len + 2)
    for l in lengths:
        if l:
            bl_count[l] += 1
    code = 0
    next_code = [0] * (max_len + 2)
    for bits in range(1, max_len + 1):
        code = (code + bl_count[bits - 1]) << 1
        next_code[bits] = code
    codes = [0] * len(lengths)
    for i, l in enumerate(lengths):
        if l:
            codes[i] = next_code[l]
            next_code[l] += 1
    return codes


# ---------------------------------------------------------------- LZX


class LzxBits:
    """16-bit little-endian words, filled MSB first."""

    def __init__(self):
        self.out = bytearray()
        self.cur = 0
        self.n = 0

    def write(self, value, n):
        for i in range(n - 1, -1, -1):
            self.cur = (self.cur << 1) | ((value >> i) & 1)
            self.n += 1
            if self.n == 16:
                self.out += struct.pack("<H", self.cur)
                self.cur = 0
                self.n = 0

    def align(self):
        if self.n:
            self.write(0, 16 - self.n)

    def raw(self, data):
        assert self.n == 0
        self.out += data


def lzx_slot_tables():
    extra = [0] * 51
    base = [0] * 51
    j = 0
    for i in range(0, 50, 2):
        extra[i] = extra[i + 1] = j
        if i != 0 and j < 17:
            j += 1
    b = 0
    for i in range(51):
        base[i] = b
        b += 1 << extra[i]
    return extra, base


LZX_EXTRA, LZX_BASE = lzx_slot_tables()
LZX_SLOTS = {15: 30, 16: 32, 17: 34, 18: 36, 19: 38, 20: 42, 21: 50}


def lzx_slot(formatted):
    s = 0
    while s + 1 < 51 and LZX_BASE[s + 1] <= formatted:
        s += 1
    return s


def e8_encode(data, filesize, frame=32768, restart=0):
    """The compressor side of E8 call translation (relative to absolute)."""
    data = bytearray(data)
    for start in range(0, len(data), frame):
        end = min(start + frame, len(data))
        if end - start <= 10:
            continue
        i = start
        while i < end - 10:
            if data[i] != 0xE8:
                i += 1
                continue
            cur = i - (start // restart * restart if restart else 0)
            rel = struct.unpack_from("<i", data, i + 1)[0]
            if -cur <= rel < filesize:
                ab = rel + cur if rel < filesize - cur else rel - filesize
                struct.pack_into("<i", data, i + 1, ab)
            i += 5
    return bytes(data)


def lz_parse(data, start, end, lo, reps, max_off, min_len=2, max_len=257):
    """`reps`: the repeated offsets (updated as LZX does), or None."""
    """Greedy LZ77 tokens for data[start:end], matches reaching no further
    back than `lo`. Tokens: ('lit', byte) or ('match', length, offset)."""
    tokens = []
    head = {}
    # Seed the hash with the history.
    for p in range(max(lo, start - max_off), start):
        if p + 3 <= len(data):
            head.setdefault(data[p : p + 3], []).append(p)
    i = start
    while i < end:
        best_len, best_off = 0, 0
        limit = min(max_len, end - i)
        # Repeated offsets first.
        for r in reps or []:
            if r <= i - lo and r <= max_off:
                l = 0
                while l < limit and data[i + l] == data[i + l - r]:
                    l += 1
                if l > best_len:
                    best_len, best_off = l, r
        key = data[i : i + 3]
        cands = head.get(key, [])
        for p in reversed(cands[-24:]):
            off = i - p
            if off > max_off or p < lo:
                break
            l = 0
            while l < limit and data[i + l] == data[p + l]:
                l += 1
            if l > best_len + 1:
                best_len, best_off = l, off
        is_rep = reps is not None and best_off in reps
        if best_len >= max(min_len, 3) or (best_len >= min_len and is_rep):
            tokens.append(("match", best_len, best_off))
            if is_rep:
                k = reps.index(best_off)
                reps[0], reps[k] = reps[k], reps[0]
            elif reps is not None:
                reps[:] = [best_off, reps[0], reps[1]]
            for p in range(i, i + best_len):
                if p + 3 <= len(data):
                    head.setdefault(data[p : p + 3], []).append(p)
            i += best_len
        else:
            tokens.append(("lit", data[i]))
            if i + 3 <= len(data):
                head.setdefault(key, []).append(i)
            i += 1
    return tokens


class LzxEncoder:
    def __init__(self, window_bits, e8_size=None, reset_frames=0, wim=False):
        self.window_bits = window_bits
        self.main_n = 256 + 8 * LZX_SLOTS[window_bits]
        self.e8_size = e8_size
        self.reset_frames = reset_frames
        self.wim = wim

    def encode(self, data, blocks):
        """`blocks`: list of (type, size) covering data; type 1 verbatim,
        2 aligned, 3 uncompressed. Returns (stream bytes, byte offsets of
        frame ends in the stream)."""
        assert sum(s for _, s in blocks) == len(data)
        if self.e8_size and not self.wim:
            src = e8_encode(data, self.e8_size, restart=32768 * self.reset_frames)
        elif self.wim:
            src = e8_encode(data, self.e8_size)
        else:
            src = data
        bw = LzxBits()
        frame_ends = []
        window = 1 << self.window_bits
        main_prev = [0] * self.main_n
        len_prev = [0] * 249
        reps = [1, 1, 1]
        pos = 0
        reset_at = 0
        frame = 0

        def start_frame_header():
            nonlocal main_prev, len_prev, reps, reset_at
            if self.wim:
                return
            main_prev = [0] * self.main_n
            len_prev = [0] * 249
            reps = [1, 1, 1]
            reset_at = pos
            if self.e8_size:
                bw.write(1, 1)
                bw.write(self.e8_size >> 16, 16)
                bw.write(self.e8_size & 0xFFFF, 16)
            else:
                bw.write(0, 1)

        start_frame_header()
        for btype, bsize in blocks:
            bstart, bend = pos, pos + bsize
            # Segments: the block cut at frame boundaries.
            segs = []
            p = bstart
            while p < bend:
                fe = (p // 32768 + 1) * 32768
                segs.append((p, min(bend, fe)))
                p = min(bend, fe)
            if btype == 3:
                bw.write(3, 3)
                self._size(bw, bsize)
                bw.write(0, 16 - bw.n if bw.n else 16)
                bw.raw(struct.pack("<III", *reps))
                for a, b in segs:
                    bw.raw(src[a:b])
                    pos = b
                    if pos % 32768 == 0 or pos == len(data):
                        frame_ends.append(len(bw.out))
                        frame += 1
                        if pos < len(data) and self.reset_frames and frame % self.reset_frames == 0:
                            assert pos == bend
                            start_frame_header()
                if bsize & 1:
                    assert pos % 32768 != 0
                    bw.raw(b"\0")
                continue
            reps_before = list(reps)
            seg_tokens = []
            for a, b in segs:
                seg_tokens.append(lz_parse(src, a, b, reset_at, reps, window - 3))
            # Symbol statistics.
            main_f = [0] * self.main_n
            len_f = [0] * 249
            al_f = [0] * 8
            # Main elements, with the repeat state as the decoder sees it.
            elements = []
            rr = list(reps_before)
            for toks in seg_tokens:
                el = []
                for t in toks:
                    if t[0] == "lit":
                        main_f[t[1]] += 1
                        el.append(("lit", t[1]))
                        continue
                    _, length, off = t
                    if off == rr[0]:
                        slot, extra_val = 0, None
                    elif off == rr[1]:
                        slot, extra_val = 1, None
                        rr[0], rr[1] = rr[1], rr[0]
                    elif off == rr[2]:
                        slot, extra_val = 2, None
                        rr[0], rr[2] = rr[2], rr[0]
                    else:
                        formatted = off + 2
                        slot = lzx_slot(formatted)
                        extra_val = formatted - LZX_BASE[slot]
                        rr[:] = [off, rr[0], rr[1]]
                    lh = min(length - 2, 7)
                    sym = 256 + slot * 8 + lh
                    main_f[sym] += 1
                    if lh == 7:
                        len_f[length - 9] += 1
                    if btype == 2 and extra_val is not None and LZX_EXTRA[slot] >= 3:
                        al_f[extra_val & 7] += 1
                    el.append(("match", sym, length, slot, extra_val))
                elements.append(el)
            assert rr == reps
            main_len = huffman_lengths(main_f, 16)
            len_len = huffman_lengths(len_f, 16)
            al_len = huffman_lengths([f + 1 for f in al_f], 7)
            main_c = canonical_codes(main_len)
            len_c = canonical_codes(len_len)
            al_c = canonical_codes(al_len)
            bw.write(btype, 3)
            self._size(bw, bsize)
            if btype == 2:
                for l in al_len:
                    bw.write(l, 3)
            self._lengths(bw, main_prev, main_len, 0, 256)
            self._lengths(bw, main_prev, main_len, 256, self.main_n)
            self._lengths(bw, len_prev, len_len, 0, 249)
            main_prev = main_len
            len_prev = len_len
            for (a, b), el in zip(segs, elements):
                for t in el:
                    if t[0] == "lit":
                        bw.write(main_c[t[1]], main_len[t[1]])
                        continue
                    _, sym, length, slot, extra_val = t
                    bw.write(main_c[sym], main_len[sym])
                    if length - 2 >= 7:
                        bw.write(len_c[length - 9], len_len[length - 9])
                    if extra_val is None:
                        continue
                    nbits = LZX_EXTRA[slot]
                    if btype == 2 and nbits >= 3:
                        bw.write(extra_val >> 3, nbits - 3)
                        bw.write(al_c[extra_val & 7], al_len[extra_val & 7])
                    else:
                        bw.write(extra_val, nbits)
                pos = b
                if pos % 32768 == 0 or pos == len(data):
                    bw.align()
                    frame_ends.append(len(bw.out))
                    frame += 1
                    if pos < len(data) and self.reset_frames and frame % self.reset_frames == 0:
                        assert pos == bend, "blocks must end at resets"
                        start_frame_header()
        bw.align()
        return bytes(bw.out), frame_ends

    def _size(self, bw, size):
        if self.wim:
            if size == 32768:
                bw.write(1, 1)
            else:
                bw.write(0, 1)
                bw.write(size, 16)
        else:
            bw.write(size >> 8, 16)
            bw.write(size & 0xFF, 8)

    def _lengths(self, bw, prev, new, first, last):
        syms = []  # (pretree symbol, extra bits value, extra bit count)
        x = first
        while x < last:
            if new[x] == 0:
                run = 1
                while x + run < last and new[x + run] == 0 and run < 51:
                    run += 1
                if run >= 20:
                    syms.append((18, run - 20, 5))
                    x += run
                    continue
                if run >= 4:
                    syms.append((17, run - 4, 4))
                    x += run
                    continue
            run = 1
            while x + run < last and new[x + run] == new[x] and run < 5:
                run += 1
            if run >= 4 and new[x] != 0:
                d = (prev[x] - new[x]) % 17
                syms.append((19, run - 4, 1, d))
                x += run
                continue
            syms.append(((prev[x] - new[x]) % 17, 0, 0))
            x += 1
        freqs = [0] * 20
        for s in syms:
            freqs[s[0]] += 1
            if s[0] == 19:
                freqs[s[3]] += 1
        pre_len = huffman_lengths(freqs, 15)
        pre_c = canonical_codes(pre_len)
        for l in pre_len:
            bw.write(l, 4)
        for s in syms:
            bw.write(pre_c[s[0]], pre_len[s[0]])
            if s[0] == 19:
                bw.write(s[1], 1)
                bw.write(pre_c[s[3]], pre_len[s[3]])
            elif s[2]:
                bw.write(s[1], s[2])


# ---------------------------------------------------------------- Quantum

Q_POS_BASE = [0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536, 2048,
              3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072, 196608, 262144,
              393216, 524288, 786432, 1048576, 1572864]
Q_EXTRA = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14,
           14, 15, 15, 16, 16, 17, 17, 18, 18, 19, 19]
Q_LEN_BASE = [0, 1, 2, 3, 4, 5, 6, 8, 10, 12, 14, 18, 22, 26, 30, 38, 46, 54, 62, 78, 94, 110, 126, 158, 190, 222, 254]
Q_LEN_EXTRA = [0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0]


class QModel:
    def __init__(self, start, n):
        self.shifts = 4
        self.n = n
        self.syms = [start + i for i in range(n + 1)]
        self.cum = [n - i for i in range(n + 1)]

    def bump(self, index):
        for i in range(index + 1):
            self.cum[i] += 8
        if self.cum[0] > 3800:
            self.update()

    def update(self):
        n = self.n
        self.shifts -= 1
        if self.shifts:
            for i in range(n - 1, -1, -1):
                self.cum[i] >>= 1
                if self.cum[i] <= self.cum[i + 1]:
                    self.cum[i] = self.cum[i + 1] + 1
            return
        self.shifts = 50
        for i in range(n):
            self.cum[i] = (self.cum[i] - self.cum[i + 1] + 1) >> 1
        for i in range(n - 1):
            for j in range(i + 1, n):
                if self.cum[i] < self.cum[j]:
                    self.cum[i], self.cum[j] = self.cum[j], self.cum[i]
                    self.syms[i], self.syms[j] = self.syms[j], self.syms[i]
        for i in range(n - 1, -1, -1):
            self.cum[i] += self.cum[i + 1]


def q_slot(d):
    s = 0
    while s + 1 < 42 and Q_POS_BASE[s + 1] <= d:
        s += 1
    return s


class QuantumEncoder:
    def __init__(self, window_bits):
        self.window_bits = window_bits
        slots = window_bits * 2
        self.selector = QModel(0, 7)
        self.lit = [QModel(0, 64), QModel(64, 64), QModel(128, 64), QModel(192, 64)]
        self.pos3 = QModel(0, min(slots, 24))
        self.pos4 = QModel(0, min(slots, 36))
        self.pos = QModel(0, slots)
        self.len = QModel(0, 27)

    def frame(self, data, start, end):
        """Encodes data[start:end] as one frame (one CAB block)."""
        L, H = 0, 0xFFFF
        pending = 0
        code = []
        events = []  # 'shift' or (value, nbits)

        def put(bit):
            nonlocal pending
            code.append(bit)
            code.extend([1 - bit] * pending)
            pending = 0

        def sym(model, value):
            nonlocal L, H, pending
            index = model.syms.index(value)
            assert index < model.n
            total = model.cum[0]
            rng = H - L + 1
            H = L + (model.cum[index] * rng) // total - 1
            L = L + (model.cum[index + 1] * rng) // total
            model.bump(index)
            while True:
                if (L & 0x8000) == (H & 0x8000):
                    put(L >> 15)
                elif (L & 0x4000) and not (H & 0x4000):
                    pending += 1
                    L &= 0x3FFF
                    H |= 0x4000
                else:
                    break
                L = (L << 1) & 0xFFFF
                H = ((H << 1) | 1) & 0xFFFF
                events.append("shift")

        window = 1 << self.window_bits
        tokens = lz_parse(data, start, end, 0, None, window - 1, min_len=3, max_len=259)
        p = start
        for t in tokens:
            if t[0] == "match" and t[1] == 3 and q_slot(t[2] - 1) >= self.pos3.n:
                lits = [("lit", b) for b in data[p : p + 3]]
            else:
                lits = [t] if t[0] == "lit" else []
            for lt in lits:
                b = lt[1]
                sym(self.selector, b >> 6)
                sym(self.lit[b >> 6], b)
                p += 1
            if lits:
                continue
            _, length, off = t
            p += length
            d = off - 1
            slot = q_slot(d)
            if length == 3 and slot < self.pos3.n:
                sym(self.selector, 4)
                sym(self.pos3, slot)
            elif length == 4 and slot < self.pos4.n:
                sym(self.selector, 5)
                sym(self.pos4, slot)
            elif length >= 5:
                sym(self.selector, 6)
                ls = 0
                while ls + 1 < 27 and Q_LEN_BASE[ls + 1] <= length - 5:
                    ls += 1
                sym(self.len, ls)
                events.append((length - 5 - Q_LEN_BASE[ls], Q_LEN_EXTRA[ls]))
                sym(self.pos, slot)
            else:
                raise AssertionError("unencodable match")
            events.append((d - Q_POS_BASE[slot], Q_EXTRA[slot]))
        # Flush.
        pending += 1
        put(0 if L < 0x4000 else 1)
        shifts = sum(1 for e in events if e == "shift")
        need = 16 + shifts
        assert len(code) <= need, (len(code), need)
        code += [0] * (need - len(code))
        bits = code[:16]
        k = 16
        for e in events:
            if e == "shift":
                bits.append(code[k])
                k += 1
            else:
                v, n = e
                bits += [(v >> i) & 1 for i in range(n - 1, -1, -1)]
        # Two zero bits, then padding to a byte: 7-Zip reads these two bits
        # and requires the block to end right after them.
        bits += [0, 0]
        bits += [0] * (-len(bits) % 8)
        out = bytearray()
        for i in range(0, len(bits), 8):
            v = 0
            for b in bits[i : i + 8]:
                v = (v << 1) | b
            out.append(v)
        assert 0xFF not in out[-1:], "trailing 0xFF would confuse the trailer scan"
        return bytes(out)


def quantum_tokens_ok(data):
    return True


# ---------------------------------------------------------------- CAB


def cab_checksum(data, seed=0):
    csum = seed
    n = len(data) // 4
    for i in range(n):
        csum ^= struct.unpack_from("<I", data, i * 4)[0]
    ul = 0
    rest = data[n * 4 :]
    if len(rest) == 3:
        ul |= rest[0] << 16 | rest[1] << 8 | rest[2]
    elif len(rest) == 2:
        ul |= rest[0] << 8 | rest[1]
    elif len(rest) == 1:
        ul |= rest[0]
    return csum ^ ul


def write_cab(path, folders, files):
    """folders: list of (typeCompress, [(packed bytes, unpacked size)]);
    files: list of (name, folder index, offset in folder, size)."""
    header_len = 36
    folders_len = 8 * len(folders)
    files_at = header_len + folders_len
    file_entries = b""
    for name, fi, off, size in files:
        file_entries += struct.pack("<IIHHHH", size, off, fi, 0x5822, 0x6000, 0x20) + name.encode() + b"\0"
    data_at = files_at + len(file_entries)
    folder_entries = b""
    data = b""
    for kind, blocks in folders:
        folder_entries += struct.pack("<IHH", data_at + len(data), len(blocks), kind)
        for packed, unpacked in blocks:
            fixed = struct.pack("<HH", len(packed), unpacked)
            csum = cab_checksum(fixed, cab_checksum(packed))
            data += struct.pack("<I", csum) + fixed + packed
    total = data_at + len(data)
    header = b"MSCF" + struct.pack("<IIIIIBBHHHHH", 0, total, 0, files_at, 0, 3, 1, len(folders), len(files), 0, 0x1234, 0)
    blob = header + folder_entries + file_entries + data
    assert len(blob) == total
    with open(path, "wb") as f:
        f.write(blob)


def frames(data):
    return [data[i : i + 32768] for i in range(0, len(data), 32768)]


def mszip_blocks(data):
    out = []
    prev = b""
    for chunk in frames(data):
        c = zlib.compressobj(9, zlib.DEFLATED, -15, zdict=prev) if prev else zlib.compressobj(9, zlib.DEFLATED, -15)
        out.append((b"CK" + c.compress(chunk) + c.flush(), len(chunk)))
        prev = (prev + chunk)[-32768:]
    return out


def lzx_blocks(data, window_bits, e8, blocks):
    enc = LzxEncoder(window_bits, e8_size=e8)
    stream, ends = enc.encode(data, blocks)
    out = []
    start = 0
    for (chunk, end) in zip(frames(data), ends):
        out.append((stream[start:end], len(chunk)))
        start = end
    assert start == len(stream)
    return out


def quantum_blocks(data, window_bits):
    enc = QuantumEncoder(window_bits)
    out = []
    for i in range(0, len(data), 32768):
        end = min(i + 32768, len(data))
        out.append((enc.frame(data, i, end), end - i))
    return out


# ---------------------------------------------------------------- CHM


def encint(n):
    out = [n & 0x7F]
    n >>= 7
    while n:
        out.append(0x80 | (n & 0x7F))
        n >>= 7
    return bytes(reversed(out))


def write_chm(path, files, window_bits=16, reset_frames=2, e8=None):
    """files: list of (name, data) stored in the LZX section."""
    content = b""
    entries = []  # name, section, offset, length
    for name, data in files:
        entries.append((name, 1, len(content), len(data)))
        content += data
    length = len(content)
    # The stream covers whole frames (7-Zip decodes 32 KiB per frame); the
    # reset table and SpanInfo give the real length.
    content += b"\0" * (-len(content) % 32768)
    # LZX stream: verbatim blocks ending at every reset boundary, plus an
    # aligned and an uncompressed block.
    interval = 32768 * reset_frames
    p = 0
    kinds = [1, 2, 3]
    k = 0
    blocks = []
    while p < len(content):
        end = min(p + interval, len(content))
        first = min(end - p, 20000)
        blocks.append((kinds[k % 3], first))
        if end - p > first:
            blocks.append((1, end - p - first))
        k += 1
        p = end
    enc = LzxEncoder(window_bits, e8_size=e8, reset_frames=reset_frames)
    stream, ends = enc.encode(content, blocks)
    nframes = len(ends)
    # One entry per frame (32 KiB of output); resets happen at every
    # `reset_frames`-th.
    reset_offsets = [0] + ends[:-1]
    control = struct.pack("<I4sIIIII", 6, b"LZXC", 2, reset_frames, (1 << window_bits) // 32768, 2, 0)
    reset = struct.pack("<IIIIQQQ", 2, len(reset_offsets), 8, 0x28, length, len(stream), 32768)
    reset += b"".join(struct.pack("<Q", o) for o in reset_offsets)

    def utf16_names(names):
        body = struct.pack("<H", len(names))
        for n in names:
            body += struct.pack("<H", len(n)) + n.encode("utf-16-le") + b"\0\0"
        return struct.pack("<H", (len(body) + 2) // 2) + body

    namelist = utf16_names(["Uncompressed", "MSCompressed"])
    guid_list = struct.pack("<IHH", 0x7FC28940, 0x9D31, 0x11D0) + bytes.fromhex("9b2700a0c91e9c7c")
    base = "::DataSpace/Storage/MSCompressed/"
    sec0 = [
        ("::DataSpace/NameList", namelist),
        (base + "ControlData", control),
        (base + "Content", stream),
        (base + "SpanInfo", struct.pack("<Q", length)),
        (base + "Transform/List", guid_list),
        (base + "Transform/{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}/InstanceData/ResetTable", reset),
    ]
    sec0_data = b""
    for name, data in sec0:
        entries.append((name, 0, len(sec0_data), len(data)))
        sec0_data += data
    entries.append(("/", 0, 0, 0))
    # Directory entries are sorted case-insensitively.
    entries.sort(key=lambda e: e[0].lower())
    chunk_size = 4096
    listing = b""
    for name, sec, off, length in entries:
        nb = name.encode()
        listing += encint(len(nb)) + nb + encint(sec) + encint(off) + encint(length)
    assert len(listing) + 20 <= chunk_size - 2, "one listing chunk only"
    free = chunk_size - 20 - len(listing)
    pmgl = b"PMGL" + struct.pack("<IIii", free, 0, -1, -1) + listing
    pmgl += b"\0" * (chunk_size - len(pmgl) - 2) + struct.pack("<H", len(entries))
    itsp = b"ITSP" + struct.pack("<IIIIIIiIIiII", 1, 0x54, 10, chunk_size, 2, 1, -1, 0, 0, -1, 1, 0x409)
    itsp += bytes.fromhex("6a92025d2e21d0119df900a0c922e6ec") + struct.pack("<I", 0x54) + b"\xff" * 12
    assert len(itsp) == 0x54
    directory = itsp + pmgl
    header_len = 0x60
    hs0_at = header_len
    dir_at = hs0_at + 0x18
    content_at = dir_at + len(directory)
    total = content_at + len(sec0_data)
    itsf = b"ITSF" + struct.pack("<IIIII", 3, header_len, 1, 0x12345678, 0x409)
    itsf += bytes.fromhex("10fd017caa7bd0119e0c00a0c922e6ec") + bytes.fromhex("11fd017caa7bd0119e0c00a0c922e6ec")
    itsf += struct.pack("<QQQQ", hs0_at, 0x18, dir_at, len(directory))
    assert len(itsf) == 0x58
    itsf += struct.pack("<Q", content_at)
    hs0 = struct.pack("<IIQII", 0x1FE, 0, total, 0, 0)
    blob = itsf + hs0 + directory + sec0_data
    assert len(blob) == total
    with open(path, "wb") as f:
        f.write(blob)


# ---------------------------------------------------------------- main


def build():
    text = lzma_text()
    code = lzma_code()
    small = b"hello cabinet " * 40
    built = {}

    # MSZIP: two files, text across three blocks.
    data = text + small
    write_cab(os.path.join(HERE, "mszip.cab"), [(1, mszip_blocks(data))],
              [("text.txt", 0, 0, len(text)), ("small.txt", 0, len(text), len(small))])
    built["mszip.cab"] = {"text.txt": text, "small.txt": small}

    # LZX, window 2^16, E8 translation, verbatim/aligned/uncompressed blocks.
    data = code + text[:40000]
    blocks = [(1, 30000), (2, 20001), (3, 7001), (2, 12000), (1, len(data) - 69002)]
    write_cab(os.path.join(HERE, "lzx16.cab"), [(3 | 16 << 8, lzx_blocks(data, 16, 12000000, blocks))],
              [("code.bin", 0, 0, len(code)), ("text.txt", 0, len(code), 40000)])
    built["lzx16.cab"] = {"code.bin": code, "text.txt": text[:40000]}

    # LZX, window 2^21, no translation; two folders, the second stored.
    data = text
    write_cab(os.path.join(HERE, "lzx21.cab"),
              [(3 | 21 << 8, lzx_blocks(data, 21, None, [(2, len(data))])), (0, [(small, len(small))])],
              [("text.txt", 0, 0, len(text)), ("small.txt", 1, 0, len(small))])
    built["lzx21.cab"] = {"text.txt": text, "small.txt": small}

    # Quantum, window 2^16.
    data = text + code[:20000]
    write_cab(os.path.join(HERE, "quantum.cab"), [(2 | 4 << 4 | 16 << 8, quantum_blocks(data, 16))],
              [("text.txt", 0, 0, len(text)), ("code.bin", 0, len(text), 20000)])
    built["quantum.cab"] = {"text.txt": text, "code.bin": code[:20000]}

    # CHM: LZX section with resets every two frames.
    files = [("/text.txt", text), ("/code.bin", code[:30000]), ("/small.html", b"<html>" + small + b"</html>")]
    write_chm(os.path.join(HERE, "lzx.chm"), files, e8=12000000)
    built["lzx.chm"] = {n.lstrip("/"): d for n, d in files}

    # A WIM-style LZX chunk (no 7-Zip check: raw chunks aren't a container).
    chunk = (code[:6000] + text)[:32768]
    enc = LzxEncoder(15, e8_size=12000000, wim=True)
    stream, _ = enc.encode(chunk, [(1, 32768)])
    with open(os.path.join(HERE, "wim-chunk.lzx"), "wb") as f:
        f.write(stream)

    # Small fixtures for the snapshot and robustness tests: one folder per
    # method, and a CHM with an LZX section.
    readme = b"Compressed cabinet fixture.\r\n" * 12
    words = b"MSZIP, Quantum and LZX folders. " * 20
    calls = bytes([0xE8, 0x10, 0x00, 0x00, 0x00, 0x90]) * 40 + words[:200]
    name = "../../fixtures/cab/compressed.cab"
    write_cab(os.path.join(HERE, name),
              [(1, mszip_blocks(readme)), (3 | 15 << 8, lzx_blocks(calls, 15, 1000, [(2, len(calls))])),
               (2 | 3 << 4 | 10 << 8, quantum_blocks(words, 10))],
              [("README.TXT", 0, 0, len(readme)), ("calls.bin", 1, 0, len(calls)), ("words.txt", 2, 0, len(words))])
    built[name] = {"README.TXT": readme, "calls.bin": calls, "words.txt": words}
    name = "../../fixtures/chm/lzx.chm"
    pages = [("/index.html", b"<html><body>" + b"Index page. " * 8 + b"</body></html>"),
             ("/about.html", b"<html><body>" + b"About this help file. " * 6 + b"</body></html>")]
    write_chm(os.path.join(HERE, name), pages, window_bits=15, reset_frames=1)
    built[name] = {n.lstrip("/"): d for n, d in pages}
    return built


def check(built):
    ok = True
    for name, expected in built.items():
        with tempfile.TemporaryDirectory() as d:
            r = subprocess.run(["7zz", "x", "-y", f"-o{d}", os.path.join(HERE, name)], capture_output=True, text=True)
            if r.returncode != 0:
                print(name, "7zz failed:", r.stdout[-600:], r.stderr[-600:])
                ok = False
                continue
            for fname, data in expected.items():
                got = open(os.path.join(d, fname), "rb").read()
                status = "ok" if got == data else "MISMATCH"
                ok &= got == data
                print(f"{name}/{fname}: {status} ({len(got)} bytes)")
    return ok


if __name__ == "__main__":
    built = build()
    if "--check" in sys.argv:
        sys.exit(0 if check(built) else 1)
