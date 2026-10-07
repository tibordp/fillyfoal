"""A small RAR compressor (test encoder) for the RAR 2.9 (`Unpack29`) and
RAR 5.0 (`Unpack5`) LZ schemes, and writers for the RAR 4 and RAR 5
containers around them.

No RAR compressor is available (the `rar` tool is proprietary and not
installed), so the fixtures are written by this encoder and checked with
7-Zip (`7zz t` / `7zz x`), whose decoder is independent of ours. The
encoder deliberately exercises the stream features: literals, matches of
every distance class, repeated distances, "repeat last match", RAR 3 short
distances and low-distance repeats, table reuse and deltas, several blocks,
filters (RAR 5), solid groups, and PPMd blocks (RAR 3, re-encoded from a
symbol trace: see `ppmd_trace` in the tests).
"""

import heapq
import struct
import zlib

# Stream features the encoder may use (switches for narrowing down
# disagreements with other decoders).
FEATURES = {"lowrep": True, "short": True, "last": True, "rep": True, "keep_old": True}


class BitWriter:
    def __init__(self):
        self.out = bytearray()
        self.acc = 0
        self.n = 0

    def bits(self, value, count):
        for i in range(count - 1, -1, -1):
            self.acc = (self.acc << 1) | ((value >> i) & 1)
            self.n += 1
            if self.n == 8:
                self.out.append(self.acc)
                self.acc = 0
                self.n = 0

    def align(self):
        if self.n:
            self.bits(0, 8 - self.n)

    def bitpos(self):
        return len(self.out) * 8 + self.n

    def getvalue(self):
        w = BitWriter()
        w.out = bytearray(self.out)
        w.acc, w.n = self.acc, self.n
        w.align()
        return bytes(w.out)


# ---------------------------------------------------------------------------
# Huffman codes (canonical, MSB first, as unrar's MakeDecodeTables)


def code_lengths(freqs, limit=15):
    """Huffman code lengths (at most `limit`) for `freqs`; at least two
    symbols get codes so every code has at least one bit."""
    freqs = list(freqs)
    used = [i for i, f in enumerate(freqs) if f > 0]
    if len(used) == 0:
        return [0] * len(freqs)
    if len(used) == 1:
        other = 0 if used[0] != 0 else 1
        freqs[other] = 1
    while True:
        heap = [(f, i, (i,)) for i, f in enumerate(freqs) if f > 0]
        heapq.heapify(heap)
        depth = [0] * len(freqs)
        tick = len(freqs)
        while len(heap) > 1:
            f1, _, s1 = heapq.heappop(heap)
            f2, _, s2 = heapq.heappop(heap)
            for s in s1 + s2:
                depth[s] += 1
            heapq.heappush(heap, (f1 + f2, tick, s1 + s2))
            tick += 1
        if max(depth) <= limit:
            return depth
        freqs = [(f + 1) // 2 if f > 0 else 0 for f in freqs]


def canonical(lengths):
    """Code values for `lengths`, ordered by (length, symbol)."""
    codes = [0] * len(lengths)
    code = 0
    for bits in range(1, 16):
        for sym, l in enumerate(lengths):
            if l == bits:
                codes[sym] = code
                code += 1
        code <<= 1
    return codes


class Huff:
    def __init__(self, lengths):
        self.lengths = lengths
        self.codes = canonical(lengths)

    def put(self, w, sym):
        l = self.lengths[sym]
        assert l > 0, f"symbol {sym} has no code"
        w.bits(self.codes[sym], l)


def write_bit_lengths(w, lengths):
    """The 20 pre-code lengths, 4 bits each (15 escaped as 15, 0), with a
    run of zeros coded as 15, n when possible."""
    i = 0
    while i < len(lengths):
        l = lengths[i]
        if l == 0:
            run = 0
            while i + run < len(lengths) and lengths[i + run] == 0:
                run += 1
            if run >= 3:
                run = min(run, 17)
                w.bits(15, 4)
                w.bits(run - 2, 4)
                i += run
                continue
        if l == 15:
            w.bits(15, 4)
            w.bits(0, 4)
        else:
            w.bits(l, 4)
        i += 1


def table_symbols(table, old=None):
    """Pre-code symbols (with extra bits) coding `table`: 0-15 literal (as
    a delta against `old` for RAR 3), 16/17 repeat the previous length,
    18/19 runs of zeros."""
    out = []
    i = 0
    n = len(table)
    while i < n:
        l = table[i]
        run = 1
        while i + run < n and table[i + run] == l:
            run += 1
        if l == 0 and run >= 3:
            run = min(run, 138)
            if run <= 10:
                out.append((18, run - 3, 3))
            else:
                out.append((19, run - 11, 7))
            i += run
            continue
        if i > 0 and table[i - 1] == l and run >= 3:
            run = min(run, 138)
            if run <= 10:
                out.append((16, run - 3, 3))
            else:
                out.append((17, run - 11, 7))
            i += run
            continue
        base = old[i] if old is not None else 0
        out.append(((l - base) & 15, 0, 0))
        i += 1
    return out


def write_tables(w, table, old=None):
    syms = table_symbols(table, old)
    freqs = [0] * 20
    for s, _, _ in syms:
        freqs[s] += 1
    bl = code_lengths(freqs)
    write_bit_lengths(w, bl)
    bc = Huff(bl)
    for s, extra, nbits in syms:
        bc.put(w, s)
        if nbits:
            w.bits(extra, nbits)


# ---------------------------------------------------------------------------
# LZ77 parsing


class Matcher:
    """Greedy hash-chain matching over a growing history (kept across the
    files of a solid group)."""

    def __init__(self, min_len=3, max_len=255, window=1 << 22, chain=48):
        self.hist = bytearray()
        self.heads = {}
        self.prev = {}
        self.min_len = min_len
        self.max_len = max_len
        self.window = window
        self.chain = chain

    def _insert(self, pos):
        if pos + 3 <= len(self.hist):
            key = bytes(self.hist[pos : pos + 3])
            self.prev[pos] = self.heads.get(key)
            self.heads[key] = pos

    def find(self, pos, end, accept=None):
        """The longest match at `pos` (in `hist`, data up to `end`) as
        (length, distance), or None; `accept(length, distance)` may veto
        candidates."""
        if pos + 3 > end:
            return None
        key = bytes(self.hist[pos : pos + 3])
        cand = self.heads.get(key)
        best = None
        tries = 0
        while cand is not None and tries < self.chain:
            dist = pos - cand
            if dist > self.window:
                break
            l = 0
            limit = min(self.max_len, end - pos)
            while l < limit and self.hist[cand + l] == self.hist[pos + l]:
                l += 1
            if l >= self.min_len and (best is None or l > best[0]):
                if accept is None or accept(l, dist):
                    best = (l, dist)
            cand = self.prev.get(cand)
            tries += 1
        return best

    def feed(self, data):
        """Appends `data` and returns its start in `hist`."""
        start = len(self.hist)
        self.hist += data
        return start

    def advance(self, start, n):
        for p in range(start, start + n):
            self._insert(p)


# ---------------------------------------------------------------------------
# RAR 5 streams


def slot5_length(length):
    """(slot, extra bits, extra value) for a RAR 5 length (>= 2)."""
    v = length - 2
    if v < 8:
        return v, 0, 0
    for slot in range(8, 44):
        lbits = slot // 4 - 1
        base = (4 | (slot & 3)) << lbits
        if base <= v < base + (1 << lbits):
            return slot, lbits, v - base
    raise ValueError(length)


def slot5_dist(dist):
    v = dist - 1
    if v < 4:
        return v, 0, 0
    dbits = v.bit_length() - 2
    b = (v >> dbits) & 1
    return 2 * (dbits + 1) + b, dbits, v & ((1 << dbits) - 1)


def adjust5(dist):
    return (dist > 0x100) + (dist > 0x2000) + (dist > 0x40000)


class Rar5Encoder:
    """Turns tokens into RAR 5 blocks. Tokens: ('lit', b), ('match', len,
    dist), ('rep', k, len), ('last',), ('filter', start, len, type,
    channels)."""

    def __init__(self, extra_dist=False):
        self.dc = 80 if extra_dist else 64
        self.tables = None

    def symbols(self, tokens):
        """(main, dist, lowdist, replen) symbol lists with extra bits."""
        out = []
        for t in tokens:
            if t[0] == "lit":
                out.append(("ld", t[1], []))
            elif t[0] == "match":
                _, length, dist = t
                ls, lb, lv = slot5_length(length - adjust5(dist))
                ds, db, dv = slot5_dist(dist)
                extra = [("bits", lv, lb)]
                dsyms = [("dd", ds)]
                if db >= 4:
                    if db > 4:
                        dsyms.append(("bits", dv >> 4, db - 4))
                    dsyms.append(("ldd", dv & 15))
                elif db > 0:
                    dsyms.append(("bits", dv, db))
                out.append(("ld", 262 + ls, extra + dsyms))
            elif t[0] == "rep":
                _, k, length = t
                ls, lb, lv = slot5_length(length)
                out.append(("ld", 258 + k, [("rd", ls), ("bits", lv, lb)]))
            elif t[0] == "last":
                out.append(("ld", 257, []))
            elif t[0] == "filter":
                _, start, length, ftype, channels = t
                out.append(("ld", 256, [("filter", start, length, ftype, channels)]))
        return out

    def block(self, w, tokens, last, new_tables=True):
        syms = self.symbols(tokens)
        if not new_tables and self.tables is not None:
            # Reuse only if the old tables code every symbol.
            for kind, s, extra in syms:
                if self.tables[kind].lengths[s] == 0 or any(
                    e[0] in self.tables and self.tables[e[0]].lengths[e[1]] == 0 for e in extra
                ):
                    new_tables = True
                    break
        if new_tables or self.tables is None:
            freqs = {"ld": [0] * 306, "dd": [0] * self.dc, "ldd": [0] * 16, "rd": [0] * 44}
            for kind, s, extra in syms:
                freqs[kind][s] += 1
                for e in extra:
                    if e[0] in freqs:
                        freqs[e[0]][e[1]] += 1
            self.tables = {k: Huff(code_lengths(v)) for k, v in freqs.items()}
            tables = True
        else:
            tables = False
        body = BitWriter()
        if tables:
            table = (
                self.tables["ld"].lengths
                + self.tables["dd"].lengths
                + self.tables["ldd"].lengths
                + self.tables["rd"].lengths
            )
            write_tables(body, table)
        for kind, s, extra in syms:
            self.tables[kind].put(body, s)
            for e in extra:
                if e[0] == "bits":
                    if e[2]:
                        body.bits(e[1], e[2])
                elif e[0] == "filter":
                    _, start, length, ftype, channels = e
                    for v in (start, length):
                        n = max(1, (v.bit_length() + 7) // 8)
                        body.bits(n - 1, 2)
                        for i in range(n):
                            body.bits((v >> (8 * i)) & 0xFF, 8)
                    body.bits(ftype, 3)
                    if ftype == 0:
                        body.bits(channels - 1, 5)
                else:
                    self.tables[e[0]].put(body, e[1])
        nbits = body.bitpos()
        data = body.getvalue()
        size = len(data)
        bit_size = nbits - (size - 1) * 8 if size else 8
        count = 1 if size < 0x100 else 2 if size < 0x10000 else 3
        flags = (count - 1) << 3 | (bit_size - 1) | (0x40 if last else 0) | (0x80 if tables else 0)
        check = (0x5A ^ flags ^ size ^ (size >> 8) ^ (size >> 16)) & 0xFF
        w.align()
        w.bits(flags, 8)
        w.bits(check, 8)
        for i in range(count):
            w.bits((size >> (8 * i)) & 0xFF, 8)
        for b in data:
            w.bits(b, 8)
        # The decoder counts the block's bits exactly; the padding of the
        # last byte belongs to it.


class LzState:
    """The repeated-distance state both encoder and decoder keep."""

    def __init__(self):
        self.old = [0, 0, 0, 0]
        self.last_len = 0

    def insert(self, dist):
        self.old = [dist] + self.old[:3]


def tokens5(m, start, end, state, rng, file_start, filters=()):
    """Greedy tokens for hist[start:end] (RAR 5), using every symbol kind.
    `filters` lists (offset in file, length, type, channels) to declare:
    the first at the start of the file, the others when (or shortly
    before) their block starts."""
    toks = []
    pos = start
    pending = sorted(filters)
    if pending:
        off, length, ftype, ch = pending.pop(0)
        toks.append(("filter", file_start + off - pos, length, ftype, ch))
    while pos < end:
        if pending:
            at = file_start + pending[0][0]
            if at - pos <= 0 or (at - pos < 64 and rng.random() < 0.2):
                off, length, ftype, ch = pending.pop(0)
                toks.append(("filter", at - pos, length, ftype, ch))
        cap = end
        if pending:
            cap = min(end, file_start + pending[0][0])
        found = m.find(pos, cap, lambda l, d: l - adjust5(d) >= 2) if cap > pos else None
        if found:
            length, dist = found
            if dist == state.old[0] and length == state.last_len:
                toks.append(("last",))
            elif dist in state.old:
                k = state.old.index(dist)
                toks.append(("rep", k, length))
                state.old.pop(k)
                state.old.insert(0, dist)
                state.last_len = length
            else:
                toks.append(("match", length, dist))
                state.insert(dist)
                state.last_len = length
            m.advance(pos, length)
            pos += length
        else:
            toks.append(("lit", m.hist[pos]))
            m.advance(pos, 1)
            pos += 1
    return toks


def compress5(files, solid, rng, block_tokens=3000, filters=None, extra_dist=False):
    """Packed streams for RAR 5 `files` (bytes, as transformed for their
    filters); one solid group if `solid`."""
    filters = filters or {}
    out = []
    m = Matcher(min_len=3, max_len=4000)
    enc = Rar5Encoder(extra_dist)
    state = LzState()
    for i, data in enumerate(files):
        if not solid:
            m = Matcher(min_len=3, max_len=4000)
            enc = Rar5Encoder(extra_dist)
            state = LzState()
        start = m.feed(data)
        toks = tokens5(m, start, start + len(data), state, rng, start, filters.get(i, ()))
        w = BitWriter()
        chunks = [toks[j : j + block_tokens] for j in range(0, len(toks), block_tokens)] or [[]]
        for j, chunk in enumerate(chunks):
            reuse = j % 2 == 1 and enc.tables is not None
            enc.block(w, chunk, last=j == len(chunks) - 1, new_tables=not reuse)
        out.append(w.getvalue())
    return out


# ---------------------------------------------------------------------------
# RAR 3 streams

LDECODE = [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224]
LBITS = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5]
SDDECODE = [0, 4, 8, 16, 32, 64, 128, 192]
SDBITS = [2, 2, 3, 4, 5, 6, 6, 6]


def dist_tables():
    counts = [4, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 14, 0, 12]
    base, bits = [], []
    d = 0
    for i, c in enumerate(counts):
        for _ in range(c):
            base.append(d)
            bits.append(i)
            d += 1 << i
    return base, bits


DDECODE, DBITS = dist_tables()


def slot3(value, table, bits):
    for s in range(len(table)):
        if table[s] <= value < table[s] + (1 << bits[s]):
            return s, bits[s], value - table[s]
    raise ValueError(value)


def adjust3(dist):
    return (dist >= 0x2000) + (dist >= 0x40000)


class Rar3State(LzState):
    def __init__(self):
        super().__init__()
        self.defs = []
        self.prev_low = 0
        self.low_rep = 0


def tokens3(m, start, end, st, rng, block_tokens, tables_at_start, filters=()):
    """Greedy RAR 3 tokens: ('lit', b), ('match', len, dist), ('rep', k,
    len), ('last',), ('short', dist). A table is read every `block_tokens`
    tokens (and at the start if `tables_at_start`), which resets the
    low-distance repeat state."""
    toks = []
    pos = start
    if tables_at_start:
        st.prev_low = 0
        st.low_rep = 0
    for off, length, kind, regs in sorted(filters):
        toks.append(vm_token(st.defs, kind, off, length, regs))
    while pos < end:
        if toks and len(toks) % block_tokens == 0:
            st.prev_low = 0
            st.low_rep = 0

        def accept(length, dist):
            if dist in st.old and FEATURES["rep"]:
                return length >= 2
            if length - adjust3(dist) < 3:
                return False
            ds, db, dv = slot3(dist - 1, DDECODE, DBITS)
            # While low distances repeat, long distances must share them.
            if st.low_rep > 0 and ds > 9 and (dv & 15) != st.prev_low:
                return False
            return True

        found = m.find(pos, end, accept)
        if found and found[1] in st.old and FEATURES["rep"]:
            length, dist = found
            if dist == st.old[0] and length == st.last_len and FEATURES["last"]:
                toks.append(("last",))
            else:
                k = st.old.index(dist)
                length = min(length, 255)
                toks.append(("rep", k, length))
                st.old.pop(k)
                st.old.insert(0, dist)
                st.last_len = length
        elif found:
            length, dist = found
            ds, db, dv = slot3(dist - 1, DDECODE, DBITS)
            low = None
            if ds > 9:
                if st.low_rep > 0:
                    st.low_rep -= 1
                elif FEATURES["lowrep"] and (dv & 15) == st.prev_low and rng.random() < 0.5:
                    low = 16
                    st.low_rep = 15
                else:
                    low = dv & 15
                    st.prev_low = low
            toks.append(("match", length, dist, low))
            st.insert(dist)
            st.last_len = length
        else:
            short = None
            if pos + 2 <= end:
                for d in range(1, min(257, pos + 1)):
                    if m.hist[pos - d : pos - d + 2] == m.hist[pos : pos + 2] and d not in st.old:
                        short = d
                        break
            if FEATURES["short"] and short is not None and rng.random() < 0.3:
                toks.append(("short", short))
                st.insert(short)
                st.last_len = 2
                m.advance(pos, 2)
                pos += 2
                continue
            toks.append(("lit", m.hist[pos]))
            m.advance(pos, 1)
            pos += 1
            continue
        m.advance(pos, length)
        pos += length
    return toks


class Rar3Encoder:
    def __init__(self):
        self.old = [0] * 404
        self.tables = None

    def symbols(self, tokens):
        out = []
        for t in tokens:
            if t[0] == "lit":
                out.append(("ld", t[1], []))
            elif t[0] == "match":
                _, length, dist, low = t
                ls = length - adjust3(dist) - 3
                li = max(i for i in range(28) if LDECODE[i] <= ls)
                extra = [("bits", ls - LDECODE[li], LBITS[li])]
                ds, db, dv = slot3(dist - 1, DDECODE, DBITS)
                extra.append(("dd", ds))
                if db > 0:
                    if ds > 9:
                        if db > 4:
                            extra.append(("bits", dv >> 4, db - 4))
                        if low is not None:
                            extra.append(("ldd", low))
                    else:
                        extra.append(("bits", dv, db))
                out.append(("ld", 271 + li, extra))
            elif t[0] == "rep":
                _, k, length = t
                ls = length - 2
                li = max(i for i in range(28) if LDECODE[i] <= ls)
                out.append(("ld", 259 + k, [("rd", li), ("bits", ls - LDECODE[li], LBITS[li])]))
            elif t[0] == "last":
                out.append(("ld", 258, []))
            elif t[0] == "short":
                v = t[1] - 1
                k = max(i for i in range(8) if SDDECODE[i] <= v)
                out.append(("ld", 263 + k, [("bits", v - SDDECODE[k], SDBITS[k])]))
            elif t[0] == "eob":
                out.append(("ld", 256, []))
            elif t[0] == "vm":
                out.append(("ld", 257, [("vm", t[1], t[2])]))
        return out

    def write_tables(self, w, tokens, keep_old):
        syms = self.symbols(tokens + [("eob",)])
        freqs = {"ld": [0] * 299, "dd": [0] * 60, "ldd": [0] * 17, "rd": [0] * 28}
        for kind, s, extra in syms:
            freqs[kind][s] += 1
            for e in extra:
                if e[0] in freqs:
                    freqs[e[0]][e[1]] += 1
        self.tables = {k: Huff(code_lengths(v)) for k, v in freqs.items()}
        table = (
            self.tables["ld"].lengths
            + self.tables["dd"].lengths
            + self.tables["ldd"].lengths
            + self.tables["rd"].lengths
        )
        w.align()
        w.bits(0, 1)  # LZ, not PPMd
        w.bits(1 if keep_old else 0, 1)
        if not keep_old:
            self.old = [0] * 404
        write_tables(w, table, self.old)
        self.old = list(table)

    def write_tokens(self, w, tokens):
        for kind, s, extra in self.symbols(tokens):
            self.tables[kind].put(w, s)
            for e in extra:
                if e[0] == "bits":
                    if e[2]:
                        w.bits(e[1], e[2])
                elif e[0] == "vm":
                    _, first, record = e
                    n = len(record)
                    if n <= 6:
                        w.bits(first | (n - 1), 8)
                    elif n < 7 + 256:
                        w.bits(first | 6, 8)
                        w.bits(n - 7, 8)
                    else:
                        w.bits(first | 7, 8)
                        w.bits(n, 16)
                    for b in record:
                        w.bits(b, 8)
                else:
                    self.tables[e[0]].put(w, e[1])


# RarVM filters. Decoders recognise the standard filter programs by their
# length and CRC32 (and unrar by a XOR check byte), not by running them. The
# real programs are not available here, so the byte code is forged to those
# lengths and checksums: right for every checksum-based decoder (unrar 5+,
# 7-Zip, libarchive, ours), meaningless to a real RarVM.
STANDARD = {"e8": (53, 0xAD576887), "e8e9": (57, 0x3CD7E57E), "itanium": (120, 0x3769893F),
            "delta": (29, 0x0E06077D), "rgb": (149, 0x1C2C5DC8), "audio": (216, 0xBC85E701)}


def forge_code(length, crc, seed=0):
    """`length` bytes with CRC32 `crc` whose first byte is the XOR of the
    others: free bits in bytes 1-5 solved over GF(2)."""
    import random as _r

    rnd = _r.Random(seed)
    base = bytearray(rnd.randrange(256) for _ in range(length))
    free = [(i, b) for i in range(1, 6) for b in range(8)]

    def residual(buf):
        x = 0
        for v in buf[1:]:
            x ^= v
        return zlib.crc32(bytes(buf)) | ((x ^ buf[0]) << 32)

    for i in range(1, 6):
        base[i] = 0
    r0 = residual(base)
    cols = []
    for i, b in free:
        t = bytearray(base)
        t[i] ^= 1 << b
        cols.append(residual(t) ^ r0)
    target = r0 ^ crc  # want residual == crc (and xor part 0)
    # Gaussian elimination: find a subset of cols XORing to target.
    rows = [(c, 1 << k) for k, c in enumerate(cols)]
    basis = []
    for c, m in rows:
        for bc, bm in basis:
            if c ^ bc < c:
                c ^= bc
                m ^= bm
        if c:
            basis.append((c, m))
            basis.sort(reverse=True)
    t, m = target, 0
    for bc, bm in basis:
        if t ^ bc < t:
            t ^= bc
            m ^= bm
    assert t == 0, "no solution"
    for k, (i, b) in enumerate(free):
        if m >> k & 1:
            base[i] ^= 1 << b
    assert zlib.crc32(bytes(base)) == crc
    return bytes(base)


def read_data_bits(w, v):
    """RarVM `ReadData` encoding."""
    v &= 0xFFFFFFFF
    if v < 16:
        w.bits(0, 2)
        w.bits(v, 4)
    elif v < 256:
        w.bits(1, 2)
        w.bits(v, 8)
    elif v < 0x10000:
        w.bits(2, 2)
        w.bits(v, 16)
    else:
        w.bits(3, 2)
        w.bits(v, 32)


def vm_token(defs, kind, start, length, regs):
    """A filter declaration: ('vm', first byte, record). `defs` lists the
    filter kinds declared so far in the stream."""
    w = BitWriter()
    first = 0x80 | 0x20
    if kind in defs:
        read_data_bits(w, defs.index(kind) + 1)
        new = False
    else:
        read_data_bits(w, len(defs) + 1)
        defs.append(kind)
        new = True
    read_data_bits(w, start)
    read_data_bits(w, length)
    if regs:
        first |= 0x10
        mask = 0
        for r in regs:
            mask |= 1 << r
        w.bits(mask, 7)
        for r in sorted(regs):
            read_data_bits(w, regs[r])
    if new:
        code = forge_code(*STANDARD[kind])
        read_data_bits(w, len(code))
        for b in code:
            w.bits(b, 8)
    return ("vm", first, w.getvalue())


def compress3(files, solid, rng, block_tokens=2500, filters=None):
    """Packed RAR 3 LZ streams for `files`. In a solid group, every other
    file starts without tables (the previous one ends with "new table"
    clear), reusing the tables of the file before, which are then built to
    cover both."""
    # Plan: which files start with tables, then tokens (the low-distance
    # repeat state resets wherever a table is read).
    reads = [(not solid) or i == 0 or i % 2 == 0 for i in range(len(files))]
    chunked = []
    m = st = None
    for i, data in enumerate(files):
        if not solid or i == 0:
            m = Matcher(min_len=2, max_len=255)
            st = Rar3State()
        start = m.feed(data)
        toks = tokens3(m, start, start + len(data), st, rng, block_tokens, reads[i], (filters or {}).get(i, ()))
        chunked.append([toks[j : j + block_tokens] for j in range(0, len(toks), block_tokens)] or [[]])
    out = []
    enc = None
    for i, chunks in enumerate(chunked):
        if not solid or i == 0:
            enc = Rar3Encoder()
        w = BitWriter()
        for j, chunk in enumerate(chunks):
            cover = chunk
            # The last chunk's tables also serve the next file if it reads
            # none.
            if j == len(chunks) - 1 and i + 1 < len(chunked) and not reads[i + 1]:
                cover = chunk + chunked[i + 1][0]
            keep = FEATURES["keep_old"] and (i + j) % 2 == 1
            if j == 0:
                if reads[i]:
                    enc.write_tables(w, cover, keep_old=keep)
            else:
                # End of block, new tables follow.
                enc.tables["ld"].put(w, 256)
                w.bits(1, 1)
                enc.write_tables(w, cover, keep_old=keep)
            if len(chunks) == 1 and j == 0 and not reads[i]:
                pass
            enc.write_tokens(w, chunk)
        # End of file, with "new table" for the next file if it reads one.
        enc.tables["ld"].put(w, 256)
        w.bits(0, 1)
        w.bits(1 if i + 1 < len(chunked) and reads[i + 1] else 0, 1)
        out.append(w.getvalue())
    return out


# ---------------------------------------------------------------------------
# Containers


def rar4(entries, solid=False):
    """A RAR 4 archive. `entries`: (name, packed, data, method, dict_bits,
    file_solid, unp_ver)."""
    out = bytearray(b"Rar!\x1a\x07\x00")

    def block(kind, flags, body, add=b""):
        head = struct.pack("<BHH", kind, flags, 7 + len(body)) + body
        crc = zlib.crc32(head) & 0xFFFF
        return struct.pack("<H", crc) + head + add

    out += block(0x73, 0x0008 if solid else 0, struct.pack("<HI", 0, 0))
    for name, packed, data, method, dict_bits, fsolid, ver in entries:
        nb = name.encode()
        flags = 0x8000 | (dict_bits << 5) | (0x10 if fsolid else 0)
        body = struct.pack(
            "<IIBIIBBHI",
            len(packed),
            len(data),
            3,
            zlib.crc32(data),
            0x5A6B_4C21,
            ver,
            method,
            len(nb),
            0x81A4,
        )
        out += block(0x74, flags, body + nb, packed)
    out += block(0x7B, 0x4000, b"")
    return bytes(out)


def vint(v):
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def rar5(entries, solid=False):
    """A RAR 5 archive. `entries`: (name, packed, data, method, dict_n,
    file_solid, version)."""
    out = bytearray(b"Rar!\x1a\x07\x01\x00")

    def header(body, data=b""):
        size = vint(len(body))
        crc = zlib.crc32(size + body)
        return struct.pack("<I", crc) + size + body + data

    out += header(vint(1) + vint(0) + vint(0x04 if solid else 0))
    for name, packed, data, method, dict_n, fsolid, version in entries:
        nb = name.encode()
        info = version | (0x40 if fsolid else 0) | (method << 7) | (dict_n << 10)
        body = (
            vint(2)
            + vint(0x02)
            + vint(len(packed))
            + vint(0x04 | 0x02)
            + vint(len(data))
            + vint(0o100644)
            + struct.pack("<I", 1_700_000_000)
            + struct.pack("<I", zlib.crc32(data))
            + vint(info)
            + vint(1)
            + vint(len(nb))
            + nb
        )
        out += header(body, packed)
    out += header(vint(5) + vint(0) + vint(0))
    return bytes(out)


# ---------------------------------------------------------------------------
# Forward filter transforms (the decoders apply the inverses)


def e8_encode(data, file_offset, e9, rar5):
    """x86 CALL/JMP relative -> absolute, as the RAR E8/E8E9 filters undo."""
    data = bytearray(data)
    size = 0x1000000
    cur = 0
    while cur + 4 < len(data):
        b = data[cur]
        cur += 1
        if b == 0xE8 or (e9 and b == 0xE9):
            off = (cur + file_offset) & 0xFFFFFFFF
            if rar5:
                off %= size
            r = int.from_bytes(data[cur : cur + 4], "little", signed=True)
            if -off <= r < size - off:
                a = r + off
            elif size - off <= r < size:
                a = r - size
            else:
                a = r
            data[cur : cur + 4] = (a & 0xFFFFFFFF).to_bytes(4, "little")
            cur += 4
    return bytes(data)


def delta_encode(data, channels):
    out = bytearray()
    for ch in range(channels):
        prev = 0
        for i in range(ch, len(data), channels):
            out.append((prev - data[i]) & 0xFF)
            prev = data[i]
    return bytes(out)


def arm_encode(data, file_offset):
    data = bytearray(data)
    cur = 0
    while cur + 3 < len(data):
        if data[cur + 3] == 0xEB:
            v = data[cur] | data[cur + 1] << 8 | data[cur + 2] << 16
            v = (v + (file_offset + cur) // 4) & 0xFFFFFF
            data[cur : cur + 3] = v.to_bytes(3, "little")
        cur += 4
    return bytes(data)


def rgb_encode(data, width, pos_r):
    """Inverse of the RAR 3 RGB filter (`width` bytes per row)."""
    n = len(data)
    d = bytearray(data)
    i = pos_r
    while i < n - 2:
        g = data[i + 1]
        d[i] = (data[i] - g) & 0xFF
        d[i + 2] = (data[i + 2] - g) & 0xFF
        i += 3
    src = bytearray()
    for ch in range(3):
        prev = 0
        for i in range(ch, n, 3):
            if i >= width + 3:
                up = d[i - width]
                ul = d[i - width - 3]
                p = (prev + up - ul) & 0xFFFFFFFF
                sp = lambda v: v - (1 << 32) if v & 0x80000000 else v
                pa = abs(sp((p - prev) & 0xFFFFFFFF))
                pb = abs(sp((p - up) & 0xFFFFFFFF))
                pc = abs(sp((p - ul) & 0xFFFFFFFF))
                pred = prev if pa <= pb and pa <= pc else up if pb <= pc else ul
            else:
                pred = prev
            src.append((pred - d[i]) & 0xFF)
            prev = d[i]
    return bytes(src)


def audio_encode(data, channels):
    """Inverse of the RAR 3 AUDIO filter."""
    n = len(data)
    src = bytearray()
    s8 = lambda v: (v & 0xFF) - 256 if v & 0x80 else v & 0xFF
    for ch in range(channels):
        prev_byte = 0
        prev_delta = 0
        dif = [0] * 7
        d1 = d2 = 0
        k1 = k2 = k3 = 0
        count = 0
        for i in range(ch, n, channels):
            d3 = d2
            d2 = prev_delta - d1
            d1 = prev_delta
            pred = (8 * prev_byte + k1 * d1 + k2 * d2 + k3 * d3) & 0xFFFFFFFF
            pred = (pred >> 3) & 0xFF
            cur = (pred - data[i]) & 0xFF
            src.append(cur)
            out = (pred - cur) & 0xFFFFFFFF
            prev_delta = s8(out - prev_byte)
            prev_byte = out
            d = s8(cur) * 8
            for j, t in enumerate((d, d - d1, d + d1, d - d2, d + d2, d - d3, d + d3)):
                dif[j] += abs(t)
            if count & 0x1F == 0:
                mn, which = dif[0], 0
                dif[0] = 0
                for j in range(1, 7):
                    if dif[j] < mn:
                        mn, which = dif[j], j
                    dif[j] = 0
                if which == 1 and k1 >= -16:
                    k1 -= 1
                elif which == 2 and k1 < 16:
                    k1 += 1
                elif which == 3 and k2 >= -16:
                    k2 -= 1
                elif which == 4 and k2 < 16:
                    k2 += 1
                elif which == 5 and k3 >= -16:
                    k3 -= 1
                elif which == 6 and k3 < 16:
                    k3 += 1
            count += 1
    return bytes(src)
