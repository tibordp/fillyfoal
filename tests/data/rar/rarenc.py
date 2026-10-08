"""A small RAR compressor for tests: RAR 2.9/3.x and RAR 5.0 LZ streams,
and the RAR 4 and RAR 5 containers around them.

No RAR compressor is available (RARLAB's `rar` is proprietary), so the
fixtures are written by this encoder. It produces what libarchive's RAR
readers decode (`archive_read_support_format_rar.c`: `parse_codes`,
`expand`, `read_filter`, `parse_filter`, `execute_filter_*`;
`archive_read_support_format_rar5.c`: `parse_block_header`,
`parse_tables`, `do_uncompress_block`, `parse_filter`, `run_*_filter`), and
`make.py` checks the archives with libarchive's `bsdtar`. Container
headers follow RARLAB's RAR 5.0 technote and libarchive's `read_header`.

The encoder deliberately exercises the stream features: literals,
matches of every distance class, repeated distances, "repeat the last
match", RAR 3 two-byte short matches and low-offset repeats, table reuse
and delta-coded tables, several blocks, filters, solid groups. (PPMd
blocks are built in `make.py`.)

This file replaces an earlier version of the encoder, written from memory
of the RAR format, whose comments named unRAR functions (`Unpack29`,
`Unpack5`, `MakeDecodeTables`, RarVM `ReadData`) and borrowed unRAR's
identifiers for its tables. It was rewritten against libarchive's readers
by an AI model (Claude), keeping the earlier encoder's choices of what to
emit so that the stream it writes is unchanged byte for byte (the fixtures
regenerate identically); the model looked at neither unRAR's source nor
the earlier RAR decoder while doing so.
"""

import heapq
import struct
import zlib

# Stream features the RAR 3 encoder may use (switches for narrowing down
# disagreements between decoders).
FEATURES = {"lowrep": True, "short": True, "last": True, "rep": True, "keep_old": True}


class BitWriter:
    """Most significant bit first, as libarchive's bit readers take them."""

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
        """The bytes written, the last one padded with zero bits."""
        w = BitWriter()
        w.out = bytearray(self.out)
        w.acc, w.n = self.acc, self.n
        w.align()
        return bytes(w.out)


# ---------------------------------------------------------------------------
# Prefix codes


def code_lengths(freqs, limit=15):
    """Huffman code lengths (at most `limit`) for `freqs`. At least two
    symbols get a code, so that the code is complete (libarchive rejects
    reading an unassigned code)."""
    freqs = list(freqs)
    used = [i for i, f in enumerate(freqs) if f > 0]
    if not used:
        return [0] * len(freqs)
    if len(used) == 1:
        freqs[1 if used[0] == 0 else 0] = 1
    while True:
        heap = [(f, i, (i,)) for i, f in enumerate(freqs) if f > 0]
        heapq.heapify(heap)
        depth = [0] * len(freqs)
        order = len(freqs)
        while len(heap) > 1:
            fa, _, a = heapq.heappop(heap)
            fb, _, b = heapq.heappop(heap)
            for s in a + b:
                depth[s] += 1
            heapq.heappush(heap, (fa + fb, order, a + b))
            order += 1
        if max(depth) <= limit:
            return depth
        # Too deep: flatten the distribution and retry.
        freqs = [(f + 1) // 2 if f > 0 else 0 for f in freqs]


class Code:
    """A canonical code: codes handed out in order of (length, symbol), as
    libarchive's `create_code` and `create_decode_tables` assign them."""

    def __init__(self, lengths):
        self.lengths = lengths
        self.codes = [0] * len(lengths)
        next_code = 0
        for length in range(1, 16):
            for sym, l in enumerate(lengths):
                if l == length:
                    self.codes[sym] = next_code
                    next_code += 1
            next_code <<= 1

    def put(self, w, sym):
        assert self.lengths[sym] > 0, f"symbol {sym} has no code"
        w.bits(self.codes[sym], self.lengths[sym])


def put_precode_lengths(w, lengths):
    """The 20 pre-code lengths, 4 bits each; 15 is an escape: 15, 0 is a
    length of 15 and 15, n a run of n + 2 zeros (used for 3+ zeros)."""
    i = 0
    while i < len(lengths):
        if lengths[i] == 0:
            run = 0
            while i + run < len(lengths) and lengths[i + run] == 0:
                run += 1
            if run >= 3:
                run = min(run, 17)
                w.bits(15, 4)
                w.bits(run - 2, 4)
                i += run
                continue
        if lengths[i] == 15:
            w.bits(15, 4)
            w.bits(0, 4)
        else:
            w.bits(lengths[i], 4)
        i += 1


def length_table_symbols(lengths, previous=None):
    """The pre-code symbols, as (symbol, extra value, extra bits), for a
    table of code lengths: 0-15 a length (RAR 3: the difference to
    `previous` modulo 16), 16/17 repeat the length before 3-10 / 11-138
    times, 18/19 as many zeros."""
    out = []
    i = 0
    n = len(lengths)
    while i < n:
        value = lengths[i]
        run = 1
        while i + run < n and lengths[i + run] == value:
            run += 1
        if value == 0 and run >= 3:
            run = min(run, 138)
            out.append((18, run - 3, 3) if run <= 10 else (19, run - 11, 7))
            i += run
            continue
        if i > 0 and lengths[i - 1] == value and run >= 3:
            run = min(run, 138)
            out.append((16, run - 3, 3) if run <= 10 else (17, run - 11, 7))
            i += run
            continue
        base = previous[i] if previous is not None else 0
        out.append(((value - base) & 15, 0, 0))
        i += 1
    return out


def put_length_table(w, lengths, previous=None):
    syms = length_table_symbols(lengths, previous)
    freqs = [0] * 20
    for s, _, _ in syms:
        freqs[s] += 1
    pre_lengths = code_lengths(freqs)
    put_precode_lengths(w, pre_lengths)
    pre = Code(pre_lengths)
    for s, value, nbits in syms:
        pre.put(w, s)
        if nbits:
            w.bits(value, nbits)


# ---------------------------------------------------------------------------
# LZ77 match finding


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
        """The longest match at `pos` within hist[:end] as (length,
        distance), or None; `accept(length, distance)` may veto one."""
        if pos + 3 > end:
            return None
        cand = self.heads.get(bytes(self.hist[pos : pos + 3]))
        best = None
        tries = 0
        while cand is not None and tries < self.chain:
            dist = pos - cand
            if dist > self.window:
                break
            n = 0
            limit = min(self.max_len, end - pos)
            while n < limit and self.hist[cand + n] == self.hist[pos + n]:
                n += 1
            if n >= self.min_len and (best is None or n > best[0]):
                if accept is None or accept(n, dist):
                    best = (n, dist)
            cand = self.prev.get(cand)
            tries += 1
        return best

    def feed(self, data):
        """Appends `data`; returns where it starts in `hist`."""
        start = len(self.hist)
        self.hist += data
        return start

    def advance(self, start, n):
        for p in range(start, start + n):
            self._insert(p)


class Distances:
    """The four most recent distances and the last length, which encoder
    and decoder both keep (`oldoffset`/`lastlength` in libarchive's RAR 3
    reader, `dist_cache`/`last_len` in its RAR 5 reader)."""

    def __init__(self):
        self.old = [0, 0, 0, 0]
        self.last_len = 0

    def push(self, dist):
        self.old = [dist] + self.old[:3]

    def touch(self, idx):
        dist = self.old.pop(idx)
        self.old.insert(0, dist)


# ---------------------------------------------------------------------------
# RAR 5 (libarchive's archive_read_support_format_rar5.c)

RAR5_MAIN, RAR5_DIST, RAR5_LOW, RAR5_REP = 306, 64, 16, 44


def rar5_length_slot(length):
    """(slot, extra bits, extra value) for a length, inverting
    `decode_code_length`: slots 0-7 are 2-9, slot s >= 8 is
    2 + ((4 | s & 3) << (s / 4 - 1)) plus that many extra bits."""
    v = length - 2
    if v < 8:
        return v, 0, 0
    for slot in range(8, RAR5_REP):
        nbits = slot // 4 - 1
        base = (4 | (slot & 3)) << nbits
        if base <= v < base + (1 << nbits):
            return slot, nbits, v - base
    raise ValueError(length)


def rar5_dist_slot(dist):
    """(slot, extra bits, extra value) for a distance, inverting
    `do_uncompress_block`: slots 0-3 are 1-4, slot s >= 4 is
    1 + ((2 | s & 1) << (s / 2 - 1)) plus that many extra bits."""
    v = dist - 1
    if v < 4:
        return v, 0, 0
    nbits = v.bit_length() - 2
    return 2 * (nbits + 1) + ((v >> nbits) & 1), nbits, v & ((1 << nbits) - 1)


def rar5_length_bonus(dist):
    """What the decoder adds to the length of a match at `dist`."""
    return (dist > 0x100) + (dist > 0x2000) + (dist > 0x40000)


def put_filter_number(w, v):
    """A RAR 5 filter parameter: 2 bits of byte count - 1, then the bytes,
    least significant first (`parse_filter_data`)."""
    n = max(1, (v.bit_length() + 7) // 8)
    w.bits(n - 1, 2)
    for i in range(n):
        w.bits((v >> (8 * i)) & 0xFF, 8)


class Rar5Encoder:
    """Writes tokens as RAR 5 blocks. Tokens: ('lit', byte), ('match',
    length, dist), ('rep', index, length), ('last',), ('filter', start,
    length, type, channels)."""

    def __init__(self):
        self.codes = None

    def symbols(self, tokens):
        """Per token: (alphabet, symbol, [extras]); an extra is another
        (alphabet, symbol), ('bits', value, count) or a filter."""
        out = []
        for t in tokens:
            kind = t[0]
            if kind == "lit":
                out.append(("main", t[1], []))
            elif kind == "match":
                _, length, dist = t
                ls, lb, lv = rar5_length_slot(length - rar5_length_bonus(dist))
                ds, db, dv = rar5_dist_slot(dist)
                extras = [("bits", lv, lb), ("dist", ds)]
                if db >= 4:
                    # High bits as such, the low four through their code.
                    if db > 4:
                        extras.append(("bits", dv >> 4, db - 4))
                    extras.append(("low", dv & 15))
                elif db > 0:
                    extras.append(("bits", dv, db))
                out.append(("main", 262 + ls, extras))
            elif kind == "rep":
                _, idx, length = t
                ls, lb, lv = rar5_length_slot(length)
                out.append(("main", 258 + idx, [("rep", ls), ("bits", lv, lb)]))
            elif kind == "last":
                out.append(("main", 257, []))
            elif kind == "filter":
                out.append(("main", 256, [t]))
        return out

    def block(self, w, tokens, last, new_tables=True):
        syms = self.symbols(tokens)
        if not new_tables and self.codes is not None:
            # Reuse the codes only if they cover every symbol.
            for alphabet, s, extras in syms:
                if self.codes[alphabet].lengths[s] == 0 or any(
                    e[0] in self.codes and self.codes[e[0]].lengths[e[1]] == 0 for e in extras
                ):
                    new_tables = True
                    break
        tables = new_tables or self.codes is None
        if tables:
            freqs = {"main": [0] * RAR5_MAIN, "dist": [0] * RAR5_DIST, "low": [0] * RAR5_LOW, "rep": [0] * RAR5_REP}
            for alphabet, s, extras in syms:
                freqs[alphabet][s] += 1
                for e in extras:
                    if e[0] in freqs:
                        freqs[e[0]][e[1]] += 1
            self.codes = {k: Code(code_lengths(v)) for k, v in freqs.items()}
        body = BitWriter()
        if tables:
            put_length_table(
                body,
                self.codes["main"].lengths
                + self.codes["dist"].lengths
                + self.codes["low"].lengths
                + self.codes["rep"].lengths,
            )
        for alphabet, s, extras in syms:
            self.codes[alphabet].put(body, s)
            for e in extras:
                if e[0] == "bits":
                    if e[2]:
                        body.bits(e[1], e[2])
                elif e[0] == "filter":
                    _, start, length, ftype, channels = e
                    put_filter_number(body, start)
                    put_filter_number(body, length)
                    body.bits(ftype, 3)
                    if ftype == 0:
                        body.bits(channels - 1, 5)
                else:
                    self.codes[e[0]].put(body, e[1])
        # Block header (`parse_block_header`): flags = table present (0x80),
        # last block (0x40), size bytes - 1 (bits 3-5), bits used in the
        # last byte - 1 (bits 0-2); a check byte; the size, little-endian.
        nbits = body.bitpos()
        data = body.getvalue()
        size = len(data)
        last_bits = nbits - (size - 1) * 8 if size else 8
        size_bytes = 1 if size < 0x100 else 2 if size < 0x10000 else 3
        flags = (size_bytes - 1) << 3 | (last_bits - 1) | (0x40 if last else 0) | (0x80 if tables else 0)
        check = (0x5A ^ flags ^ size ^ (size >> 8) ^ (size >> 16)) & 0xFF
        w.align()
        w.bits(flags, 8)
        w.bits(check, 8)
        for i in range(size_bytes):
            w.bits((size >> (8 * i)) & 0xFF, 8)
        for b in data:
            w.bits(b, 8)


def rar5_tokens(m, start, end, dists, rng, file_start, filters=()):
    """Greedy tokens for hist[start:end]. `filters` lists (offset in the
    file, length, type, channels): the first is declared at the start of
    the file, the others when (or shortly before) their block starts."""
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
        # Matches stop at the next filter's block start.
        cap = min(end, file_start + pending[0][0]) if pending else end
        found = m.find(pos, cap, lambda n, d: n - rar5_length_bonus(d) >= 2) if cap > pos else None
        if found:
            length, dist = found
            if dist == dists.old[0] and length == dists.last_len:
                toks.append(("last",))
            elif dist in dists.old:
                idx = dists.old.index(dist)
                toks.append(("rep", idx, length))
                dists.touch(idx)
                dists.last_len = length
            else:
                toks.append(("match", length, dist))
                dists.push(dist)
                dists.last_len = length
            m.advance(pos, length)
            pos += length
        else:
            toks.append(("lit", m.hist[pos]))
            m.advance(pos, 1)
            pos += 1
    return toks


def compress5(files, solid, rng, block_tokens=3000, filters=None):
    """Packed RAR 5 streams for `files` (bytes, already transformed for
    their filters); one solid group if `solid`. Every other block reuses
    the tables of the block before when they cover it."""
    filters = filters or {}
    out = []
    m = Matcher(min_len=3, max_len=4000)
    enc = Rar5Encoder()
    dists = Distances()
    for i, data in enumerate(files):
        if not solid:
            m = Matcher(min_len=3, max_len=4000)
            enc = Rar5Encoder()
            dists = Distances()
        start = m.feed(data)
        toks = rar5_tokens(m, start, start + len(data), dists, rng, start, filters.get(i, ()))
        w = BitWriter()
        blocks = [toks[j : j + block_tokens] for j in range(0, len(toks), block_tokens)] or [[]]
        for j, block in enumerate(blocks):
            reuse = j % 2 == 1 and enc.codes is not None
            enc.block(w, block, last=j == len(blocks) - 1, new_tables=not reuse)
        out.append(w.getvalue())
    return out


# ---------------------------------------------------------------------------
# RAR 2.9/3.x (libarchive's archive_read_support_format_rar.c)

RAR3_MAIN, RAR3_OFFSET, RAR3_LOWOFFSET, RAR3_LENGTH = 299, 60, 17, 28

# The tables of libarchive's `expand`.
LENGTH_BASES = [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224]
LENGTH_BITS = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5]
OFFSET_BITS = [0, 0, 0, 0] + [b for b in range(1, 16) for _ in (0, 1)] + [16] * 14 + [18] * 12
OFFSET_BASES = [sum(1 << b for b in OFFSET_BITS[:i]) for i in range(len(OFFSET_BITS))]
SHORT_BASES = [0, 4, 8, 16, 32, 64, 128, 192]
SHORT_BITS = [2, 2, 3, 4, 5, 6, 6, 6]


def slot_of(value, bases, bits):
    """(slot, extra bits, extra value) for `value` in a base/bits table."""
    for s, (base, n) in enumerate(zip(bases, bits)):
        if base <= value < base + (1 << n):
            return s, n, value - base
    raise ValueError(value)


def rar3_length_bonus(dist):
    """What `expand` adds to the length of a match at `dist`."""
    return (dist >= 0x2000) + (dist >= 0x40000)


class Rar3Distances(Distances):
    """Adds the low-offset repeat state of `expand` (`lastlowoffset`,
    `numlowoffsetrepeats`), which `parse_codes` clears with every table."""

    def __init__(self):
        super().__init__()
        self.programs = []
        self.last_low = 0
        self.low_repeats = 0

    def new_table(self):
        self.last_low = 0
        self.low_repeats = 0


def rar3_tokens(m, start, end, st, rng, block_tokens, tables_at_start, filters=()):
    """Greedy tokens: ('lit', b), ('match', length, dist, low symbol or
    None), ('rep', index, length), ('last',), ('short', dist), ('vm', ...).
    Tables are read every `block_tokens` tokens (and at the start if
    `tables_at_start`)."""
    toks = []
    pos = start
    if tables_at_start:
        st.new_table()
    for off, length, kind, regs in sorted(filters):
        toks.append(filter_token(st.programs, kind, off, length, regs))
    while pos < end:
        if toks and len(toks) % block_tokens == 0:
            st.new_table()

        def accept(length, dist):
            if dist in st.old and FEATURES["rep"]:
                return length >= 2
            if length - rar3_length_bonus(dist) < 3:
                return False
            slot, _, extra = slot_of(dist - 1, OFFSET_BASES, OFFSET_BITS)
            # While the low offset repeats, far matches must share it.
            if st.low_repeats > 0 and slot > 9 and (extra & 15) != st.last_low:
                return False
            return True

        found = m.find(pos, end, accept)
        if found and found[1] in st.old and FEATURES["rep"]:
            length, dist = found
            if dist == st.old[0] and length == st.last_len and FEATURES["last"]:
                toks.append(("last",))
            else:
                idx = st.old.index(dist)
                length = min(length, 255)
                toks.append(("rep", idx, length))
                st.touch(idx)
                st.last_len = length
        elif found:
            length, dist = found
            slot, _, extra = slot_of(dist - 1, OFFSET_BASES, OFFSET_BITS)
            low = None
            if slot > 9:
                if st.low_repeats > 0:
                    st.low_repeats -= 1
                elif FEATURES["lowrep"] and (extra & 15) == st.last_low and rng.random() < 0.5:
                    low = 16
                    st.low_repeats = 15
                else:
                    low = extra & 15
                    st.last_low = low
            toks.append(("match", length, dist, low))
            st.push(dist)
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
                st.push(short)
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
        self.lengths = [0] * (RAR3_MAIN + RAR3_OFFSET + RAR3_LOWOFFSET + RAR3_LENGTH)
        self.codes = None

    def symbols(self, tokens):
        out = []
        for t in tokens:
            kind = t[0]
            if kind == "lit":
                out.append(("main", t[1], []))
            elif kind == "match":
                _, length, dist, low = t
                ls, lb, lv = slot_of(length - rar3_length_bonus(dist) - 3, LENGTH_BASES, LENGTH_BITS)
                os_, ob, ov = slot_of(dist - 1, OFFSET_BASES, OFFSET_BITS)
                extras = [("bits", lv, lb), ("offset", os_)]
                if ob > 0:
                    if os_ > 9:
                        # High bits as such; the low four through their
                        # code, unless they repeat.
                        if ob > 4:
                            extras.append(("bits", ov >> 4, ob - 4))
                        if low is not None:
                            extras.append(("lowoffset", low))
                    else:
                        extras.append(("bits", ov, ob))
                out.append(("main", 271 + ls, extras))
            elif kind == "rep":
                _, idx, length = t
                ls, lb, lv = slot_of(length - 2, LENGTH_BASES, LENGTH_BITS)
                out.append(("main", 259 + idx, [("length", ls), ("bits", lv, lb)]))
            elif kind == "last":
                out.append(("main", 258, []))
            elif kind == "short":
                k, kb, kv = slot_of(t[1] - 1, SHORT_BASES, SHORT_BITS)
                out.append(("main", 263 + k, [("bits", kv, kb)]))
            elif kind == "end":
                out.append(("main", 256, []))
            elif kind == "vm":
                out.append(("main", 257, [t]))
        return out

    def put_tables(self, w, tokens, keep_old):
        """A table read (`parse_codes`): byte-aligned; 0 (not PPMd); 1 to
        add the lengths to the previous ones, 0 to start from zeros; the
        length table."""
        syms = self.symbols(tokens + [("end",)])
        freqs = {
            "main": [0] * RAR3_MAIN,
            "offset": [0] * RAR3_OFFSET,
            "lowoffset": [0] * RAR3_LOWOFFSET,
            "length": [0] * RAR3_LENGTH,
        }
        for alphabet, s, extras in syms:
            freqs[alphabet][s] += 1
            for e in extras:
                if e[0] in freqs:
                    freqs[e[0]][e[1]] += 1
        self.codes = {k: Code(code_lengths(v)) for k, v in freqs.items()}
        lengths = (
            self.codes["main"].lengths
            + self.codes["offset"].lengths
            + self.codes["lowoffset"].lengths
            + self.codes["length"].lengths
        )
        w.align()
        w.bits(0, 1)
        w.bits(1 if keep_old else 0, 1)
        if not keep_old:
            self.lengths = [0] * len(lengths)
        put_length_table(w, lengths, self.lengths)
        self.lengths = list(lengths)

    def put_tokens(self, w, tokens):
        for alphabet, s, extras in self.symbols(tokens):
            self.codes[alphabet].put(w, s)
            for e in extras:
                if e[0] == "bits":
                    if e[2]:
                        w.bits(e[1], e[2])
                elif e[0] == "vm":
                    put_filter_record(w, e[1], e[2])
                else:
                    self.codes[e[0]].put(w, e[1])


# RarVM filters. libarchive (`compile_program`, `execute_filter`) checks
# that a program's first byte is the XOR of the others and then knows the
# standard programs by length and CRC32; it does not run them. The real
# programs are not available here, so the byte code is forged to those
# lengths and checksums: valid for checksum-based decoders, meaningless to
# a real RarVM.
STANDARD = {
    # As libarchive's `execute_filter` checks the fingerprints (CRC32 |
    # length << 32): delta, e8, e8 with e9, rgb, audio.
    "delta": (29, 0x0E06077D),
    "e8": (53, 0xAD576887),
    "e8e9": (57, 0x3CD7E57E),
    "rgb": (149, 0x1C2C5DC8),
    "audio": (216, 0xBC85E701),
}


def forge_program(length, crc, seed=0):
    """`length` pseudo-random bytes with CRC32 `crc` and the first byte the
    XOR of the rest: 40 free bits (bytes 1-5) solved over GF(2)."""
    import random as _random

    rnd = _random.Random(seed)
    code = bytearray(rnd.randrange(256) for _ in range(length))
    free = [(i, b) for i in range(1, 6) for b in range(8)]

    def syndrome(buf):
        # CRC32 in the low 32 bits, the XOR check in the next 8.
        x = 0
        for v in buf[1:]:
            x ^= v
        return zlib.crc32(bytes(buf)) | ((x ^ buf[0]) << 32)

    for i in range(1, 6):
        code[i] = 0
    s0 = syndrome(code)
    effects = []
    for i, b in free:
        t = bytearray(code)
        t[i] ^= 1 << b
        effects.append(syndrome(t) ^ s0)
    # Find free bits whose effects XOR to the needed change.
    basis = []
    for k, e in enumerate(effects):
        mask = 1 << k
        for be, bm in basis:
            if e ^ be < e:
                e ^= be
                mask ^= bm
        if e:
            basis.append((e, mask))
            basis.sort(reverse=True)
    want, chosen = s0 ^ crc, 0
    for be, bm in basis:
        if want ^ be < want:
            want ^= be
            chosen ^= bm
    assert want == 0, "no solution"
    for k, (i, b) in enumerate(free):
        if chosen >> k & 1:
            code[i] ^= 1 << b
    assert zlib.crc32(bytes(code)) == crc
    return bytes(code)


def put_vm_number(w, v):
    """A RarVM number as `membr_next_rarvm_number` reads it: 2 bits
    selecting 4, 8, 16 or 32 more bits (the 8-bit form only for 16-255)."""
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


def filter_token(programs, kind, start, length, regs):
    """A filter declaration ('vm', flags, record) for `parse_filter`: flags
    0x80 (program number follows) | 0x20 (block length follows), 0x10 if
    registers follow. The program number is 1 + its index, the index one
    past the end declaring a new program (whose byte code then follows).
    `programs` lists the kinds declared so far in the stream."""
    w = BitWriter()
    flags = 0x80 | 0x20
    new = kind not in programs
    if new:
        programs.append(kind)
    put_vm_number(w, programs.index(kind) + 1)
    put_vm_number(w, start)
    put_vm_number(w, length)
    if regs:
        flags |= 0x10
        mask = 0
        for r in regs:
            mask |= 1 << r
        w.bits(mask, 7)
        for r in sorted(regs):
            put_vm_number(w, regs[r])
    if new:
        code = forge_program(*STANDARD[kind])
        put_vm_number(w, len(code))
        for b in code:
            w.bits(b, 8)
    return ("vm", flags, w.getvalue())


def put_filter_record(w, flags, record):
    """Symbol 257's operand (`read_filter`): the flags byte with the record
    length in its low 3 bits (n - 1 for 1-6, 6: a byte n - 7 follows, 7:
    16 bits n follow), then the record."""
    n = len(record)
    if n <= 6:
        w.bits(flags | (n - 1), 8)
    elif n < 7 + 256:
        w.bits(flags | 6, 8)
        w.bits(n - 7, 8)
    else:
        w.bits(flags | 7, 8)
        w.bits(n, 16)
    for b in record:
        w.bits(b, 8)


def compress3(files, solid, rng, block_tokens=2500, filters=None):
    """Packed RAR 3 LZ streams for `files`. In a solid group every other
    file starts without tables (the file before ends with "no new table"),
    reusing the tables of the file before, which are built to cover both.
    Each file ends with symbol 256, 0 (end of file), then 1 if the next
    file starts with tables."""
    reads = [(not solid) or i == 0 or i % 2 == 0 for i in range(len(files))]
    blocked = []
    m = st = None
    for i, data in enumerate(files):
        if not solid or i == 0:
            m = Matcher(min_len=2, max_len=255)
            st = Rar3Distances()
        start = m.feed(data)
        toks = rar3_tokens(m, start, start + len(data), st, rng, block_tokens, reads[i], (filters or {}).get(i, ()))
        blocked.append([toks[j : j + block_tokens] for j in range(0, len(toks), block_tokens)] or [[]])
    out = []
    enc = None
    for i, blocks in enumerate(blocked):
        if not solid or i == 0:
            enc = Rar3Encoder()
        w = BitWriter()
        for j, block in enumerate(blocks):
            cover = block
            # The last block's tables also serve the next file if it reads
            # none.
            if j == len(blocks) - 1 and i + 1 < len(blocked) and not reads[i + 1]:
                cover = block + blocked[i + 1][0]
            keep = FEATURES["keep_old"] and (i + j) % 2 == 1
            if j == 0:
                if reads[i]:
                    enc.put_tables(w, cover, keep_old=keep)
            else:
                # Symbol 256, 1: new tables follow.
                enc.codes["main"].put(w, 256)
                w.bits(1, 1)
                enc.put_tables(w, cover, keep_old=keep)
            enc.put_tokens(w, block)
        enc.codes["main"].put(w, 256)
        w.bits(0, 1)
        w.bits(1 if i + 1 < len(blocked) and reads[i + 1] else 0, 1)
        out.append(w.getvalue())
    return out


# ---------------------------------------------------------------------------
# Containers


def rar4(entries, solid=False):
    """A RAR 4 archive (the header layout of libarchive's `read_header`).
    `entries`: (name, packed, data, method, dictionary bits, solid file,
    unpack version)."""
    out = bytearray(b"Rar!\x1a\x07\x00")

    def block(kind, flags, body, add=b""):
        head = struct.pack("<BHH", kind, flags, 7 + len(body)) + body
        return struct.pack("<H", zlib.crc32(head) & 0xFFFF) + head + add

    out += block(0x73, 0x0008 if solid else 0, struct.pack("<HI", 0, 0))
    for name, packed, data, method, dict_bits, file_solid, version in entries:
        raw = name.encode()
        # Data follows (0x8000), dictionary size, solid (0x10).
        flags = 0x8000 | (dict_bits << 5) | (0x10 if file_solid else 0)
        # Packed and unpacked size, host OS (3: Unix), CRC32, DOS time,
        # unpack version, method, name length, attributes.
        body = struct.pack(
            "<IIBIIBBHI", len(packed), len(data), 3, zlib.crc32(data), 0x5A6B_4C21, version, method, len(raw), 0x81A4
        )
        out += block(0x74, flags, body + raw, packed)
    out += block(0x7B, 0x4000, b"")
    return bytes(out)


def vint(v):
    """A RAR 5 variable-length integer: 7 bits per byte, low first, the
    top bit set on all but the last byte."""
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if not v:
            out.append(b)
            return bytes(out)
        out.append(b | 0x80)


def rar5(entries, solid=False):
    """A RAR 5 archive (technote layout). `entries`: (name, packed, data,
    method, dictionary exponent, solid file, algorithm version)."""
    out = bytearray(b"Rar!\x1a\x07\x01\x00")

    def header(body, data=b""):
        size = vint(len(body))
        return struct.pack("<I", zlib.crc32(size + body)) + size + body + data

    # Main header: type 1, no header flags, archive flags (0x04 solid).
    out += header(vint(1) + vint(0) + vint(0x04 if solid else 0))
    for name, packed, data, method, dict_n, file_solid, version in entries:
        raw = name.encode()
        info = version | (0x40 if file_solid else 0) | (method << 7) | (dict_n << 10)
        # File header: type 2, header flags 0x02 (data size follows), data
        # size, file flags 0x04 (CRC32) | 0x02 (mtime), unpacked size,
        # attributes, mtime, CRC32, compression info, host OS (1: Unix),
        # name.
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
            + vint(len(raw))
            + raw
        )
        out += header(body, packed)
    # End of archive: type 5.
    out += header(vint(5) + vint(0) + vint(0))
    return bytes(out)


# ---------------------------------------------------------------------------
# Forward filter transforms: the inverses of what the decoders apply


def e8_encode(data, file_offset, e9, rar5):
    """x86 CALL (and JMP) operands relative -> absolute: the inverse of
    `execute_filter_e8` (RAR 3) and `run_e8e9_filter` (RAR 5, positions
    modulo 16 MiB)."""
    data = bytearray(data)
    size = 0x1000000
    i = 0
    while i + 4 < len(data):
        b = data[i]
        i += 1
        if b == 0xE8 or (e9 and b == 0xE9):
            pos = (i + file_offset) & 0xFFFFFFFF
            if rar5:
                pos %= size
            rel = int.from_bytes(data[i : i + 4], "little", signed=True)
            if -pos <= rel < size - pos:
                absolute = rel + pos
            elif size - pos <= rel < size:
                absolute = rel - size
            else:
                absolute = rel
            data[i : i + 4] = (absolute & 0xFFFFFFFF).to_bytes(4, "little")
            i += 4
    return bytes(data)


def delta_encode(data, channels):
    """The inverse of the DELTA filters: channel by channel, each byte
    stored as the previous one minus it."""
    out = bytearray()
    for ch in range(channels):
        prev = 0
        for i in range(ch, len(data), channels):
            out.append((prev - data[i]) & 0xFF)
            prev = data[i]
    return bytes(out)


def arm_encode(data, file_offset):
    """The inverse of `run_arm_filter`: BL word offsets made absolute."""
    data = bytearray(data)
    i = 0
    while i + 3 < len(data):
        if data[i + 3] == 0xEB:
            v = data[i] | data[i + 1] << 8 | data[i + 2] << 16
            v = (v + (file_offset + i) // 4) & 0xFFFFFF
            data[i : i + 3] = v.to_bytes(3, "little")
        i += 4
    return bytes(data)


def rgb_encode(data, stride, byte_offset):
    """The inverse of `execute_filter_rgb`. The decoder rebuilds each of
    the three planes from its bytes, each the prediction minus the stored
    byte, predicting from the previous byte of the plane and, from offset
    `stride` on, the bytes at -`stride` + 3 ("up") and -`stride`
    ("up-left") in the output; it then adds green to red and blue. So:
    red and blue are first made relative to green, then each plane is
    stored as prediction minus value."""
    n = len(data)
    dst = bytearray(data)
    for i in range(byte_offset, n - 2, 3):
        dst[i] = (dst[i] - dst[i + 1]) & 0xFF
        dst[i + 2] = (dst[i + 2] - dst[i + 1]) & 0xFF

    src = bytearray()
    for i in range(3):
        byte = 0
        for j in range(i, n, 3):
            if j >= stride:
                up = dst[j - stride + 3]
                up_left = dst[j - stride]
                delta1 = abs(up - up_left)
                delta2 = abs(byte - up_left)
                delta3 = abs(up - up_left + byte - up_left)
                if delta1 > delta2 or delta1 > delta3:
                    byte = up if delta2 <= delta3 else up_left
            src.append((byte - dst[j]) & 0xFF)
            byte = dst[j]
    return bytes(src)


def audio_encode(data, channels):
    """The inverse of `execute_filter_audio`: per channel, each byte stored
    as an adaptive linear prediction minus it (a signed `delta`), the
    predictor's three weights nudged every 32 bytes towards the smallest
    accumulated error."""
    n = len(data)
    src = bytearray()

    def s8(v):
        return (v & 0xFF) - 256 if v & 0x80 else v & 0xFF

    for i in range(channels):
        lastbyte = 0
        lastdelta = 0
        deltas = [0, 0, 0]
        weight = [0, 0, 0]
        error = [0] * 7
        count = 0
        for j in range(i, n, channels):
            deltas[2] = deltas[1]
            deltas[1] = lastdelta - deltas[0]
            deltas[0] = lastdelta
            predbyte = (
                8 * lastbyte
                + weight[0] * deltas[0]
                + weight[1] * deltas[1]
                + weight[2] * deltas[2]
            ) >> 3 & 0xFF
            delta = s8(predbyte - data[j])
            src.append(delta & 0xFF)
            byte = (predbyte - delta) & 0xFF
            prederror = delta * 8
            error[0] += abs(prederror)
            for k in range(3):
                error[1 + 2 * k] += abs(prederror - deltas[k])
                error[2 + 2 * k] += abs(prederror + deltas[k])
            lastdelta = s8(byte - lastbyte)
            lastbyte = byte
            if count & 0x1F == 0:
                idx = 0
                for k in range(1, 7):
                    if error[k] < error[idx]:
                        idx = k
                error = [0] * 7
                if idx:
                    w = (idx - 1) // 2
                    if idx % 2 == 1:
                        if weight[w] >= -16:
                            weight[w] -= 1
                    elif weight[w] < 16:
                        weight[w] += 1
            count += 1
    return bytes(src)
