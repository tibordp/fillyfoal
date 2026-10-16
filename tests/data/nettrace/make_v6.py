"""Synthetic NetTrace format 6 trace, written from TraceEvent's
`NetTraceFormat.md` (format 6). No writer of format 6 was available (the
.NET runtime writes format 4/5), so this checks only that the dissector
follows the document; it is not evidence that the reading is right.

Run from the repository root:

    python3 tests/data/nettrace/make_v6.py
"""

import struct

out = "tests/fixtures/synthetic/nettrace/v6.nettrace"


def varuint(n):
    b = bytearray()
    while True:
        x = n & 0x7F
        n >>= 7
        if n:
            b.append(x | 0x80)
        else:
            b.append(x)
            return bytes(b)


def s(text):
    raw = text.encode("utf-8")
    return varuint(len(raw)) + raw


def block(kind, body):
    return struct.pack("<I", len(body) | (kind << 24)) + body


# Trace block: sync time, ticks, frequency, pointer size, key/values.
trace = struct.pack("<8h", 2026, 1, 4, 1, 12, 0, 0, 0)
trace += struct.pack("<qqii", 1_000_000, 1_000_000_000, 8, 2)
trace += s("ProcessId") + s("4242") + s("HardwareThreadCount") + s("4")

# Metadata block: no extra header, two rows.
def field(name, code, extra=b""):
    body = s(name) + bytes([code]) + extra
    return struct.pack("<H", len(body)) + body


def row(mid, provider, eid, name, fields, opt):
    body = varuint(mid) + s(provider) + varuint(eid) + s(name)
    body += struct.pack("<H", len(fields)) + b"".join(fields)
    body += struct.pack("<H", len(opt)) + opt
    return struct.pack("<H", len(body)) + body


opt1 = bytes([8, 4]) + bytes([3]) + struct.pack("<Q", 0x10) + bytes([4]) + s("Hello {Name}")
meta = struct.pack("<H", 0)
meta += row(1, "Fillyfoal-Demo", 1, "Hello", [field("Name", 18), field("Count", 9)], opt1)
meta += row(2, "Fillyfoal-Demo", 2, "Tick", [field("N", 21), field("Delta", 20), field("Ok", 26)], bytes([1, 10]))

# Thread block: one thread with a name, process and thread IDs.
t = varuint(1) + bytes([1]) + s("main") + bytes([2]) + varuint(4242) + bytes([3]) + varuint(4243)
threads = struct.pack("<H", len(t)) + t

# Stack block: IDs 1 and 2.
stacks = struct.pack("<II", 1, 2)
stacks += struct.pack("<I", 16) + struct.pack("<QQ", 0x401000, 0x402000)
stacks += struct.pack("<I", 8) + struct.pack("<Q", 0x403000)

# Label list block: list 1 is an activity ID and a key/value (last).
labels = struct.pack("<II", 1, 1)
labels += bytes([1]) + bytes(range(16)) + bytes([0x85]) + s("request") + s("42")


def payload_hello(name, count):
    return name.encode("utf-16-le") + b"\0\0" + struct.pack("<i", count)


# Event block, compressed headers.
events = struct.pack("<hhqq", 20, 1, 1_000_100, 1_000_300)
p1 = payload_hello("fillyfoal", 1)
events += bytes([0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x40 | 0x80])
events += varuint(1) + varuint(0) + varuint(1) + varuint(0) + varuint(1) + varuint(1)
events += varuint(1_000_100) + varuint(1) + varuint(len(p1)) + p1
p2 = payload_hello("fillyfoal", 2)  # same size: no DataLength
events += bytes([0x0]) + varuint(100) + p2
p3 = varuint(7) + varuint(5) + bytes([1])  # Tick: N=7, Delta=-3 (zigzag 5), Ok=true
events += bytes([0x1 | 0x8 | 0x80]) + varuint(2) + varuint(2) + varuint(100) + varuint(len(p3)) + p3

# Event block, uncompressed headers.
raw = struct.pack("<hhqq", 20, 0, 1_000_400, 1_000_400)
p4 = payload_hello("x", 9)
hdr = struct.pack("<IIQQIIQII", 1, 4, 1, 1, 0, 0, 1_000_400, 0, len(p4))
raw += struct.pack("<I", len(hdr) + len(p4)) + hdr + p4

sp = struct.pack("<QII", 1_000_500, 3, 1) + varuint(1) + varuint(4)
remove = varuint(1) + varuint(4)

data = b"Nettrace" + struct.pack("<III", 0, 6, 0)
data += block(1, trace)
data += block(3, meta)
data += block(6, threads)
data += block(5, stacks)
data += block(8, labels)
data += block(2, events)
data += block(2, raw)
data += block(4, sp)
data += block(7, remove)
data += block(0, b"")
open(out, "wb").write(data)
