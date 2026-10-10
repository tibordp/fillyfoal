"""Writes tests/fixtures/synthetic/etl/sample.etl: a small Event Trace Log
built from the structure layouts documented in `crates/system/src/formats/forensics/etl.rs`
(Microsoft's public `evntrace.h`/`evntcons.h` structs, and WMI_BUFFER_HEADER
and the in-buffer header layouts from memory). There is no ETL writer on
macOS, so this is our own encoder; the fixture is synthetic.

    python3 tests/data/etl/make_etl.py
"""

import os
import struct
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
OUT = os.path.join(ROOT, "tests/fixtures/synthetic/etl/sample.etl")

BUFFER = 0x1000
EPOCH = 116444736000000000  # FILETIME of 1970-01-01
START = EPOCH + 1741944413 * 10_000_000  # 2025-03-14 09:26:53 UTC
FREQ = 10_000_000
QPC0 = 1_000_000_000


def align8(n):
    return (n + 7) & ~7


def guid(text):
    return uuid.UUID(text).bytes_le


def utf16z(s):
    return s.encode("utf-16-le") + b"\0\0"


def system(header_type, hook, tid, pid, ts, payload, compact=False):
    size = (0x18 if compact else 0x20) + len(payload)
    out = struct.pack("<HBBHHIIq", 2, header_type, 0xC0, size, hook, tid, pid, ts)
    if not compact:
        out += struct.pack("<II", 10, 20)
    return out + payload


def perfinfo(hook, ts, payload):
    return struct.pack("<HBBHHQ", 2, 0x11, 0xC0, 0x10 + len(payload), hook, ts) + payload


def ext_items(items):
    out = b""
    for i, (ext_type, data) in enumerate(items):
        linkage = 1 if i + 1 < len(items) else 0
        item = struct.pack("<HHHH", 0, ext_type, linkage, len(data)) + data
        out += item + b"\0" * (align8(len(item)) - len(item))
    return out


def event_header(provider, eid, version, level, opcode, task, keyword, tid, pid, ts, items, payload, channel=0):
    ext = ext_items(items)
    flags = 0x0040 | (0x0001 if items else 0)  # 64-bit header, extended info
    size = 0x50 + len(ext) + len(payload)
    out = struct.pack("<HBBHHIIq", size, 0x13, 0xC0, flags, 0, tid, pid, ts)
    out += guid(provider)
    out += struct.pack("<HBBBBHQ", eid, version, channel, level, opcode, task, keyword)
    out += struct.pack("<II", 0, 0) + guid("00000000-0000-0000-0000-000000000000")
    return out + ext + payload


def classic(guid_text, kind, level, version, tid, pid, ts, payload):
    size = 0x30 + len(payload)
    out = struct.pack("<HBBBBHIIq", size, 0x14, 0xC0, kind, level, version, tid, pid, ts)
    return out + guid(guid_text) + struct.pack("<II", 1, 2) + payload


def instance(kind, level, version, tid, pid, ts, payload):
    size = 0x38 + len(payload)
    out = struct.pack("<HBBBBHIIq", size, 0x15, 0xC0, kind, level, version, tid, pid, ts)
    out += struct.pack("<QIIIIQ", 0xFFFF8000_12345678, 7, 3, 0, 0, 0xFFFF8000_87654321)
    return out + payload


def logfile_header():
    tz_name = "Coordinated Universal Time".encode("utf-16-le").ljust(64, b"\0")
    tz = struct.pack("<i", 0) + tz_name + b"\0" * 16 + struct.pack("<i", 0)
    tz += tz_name + b"\0" * 16 + struct.pack("<i", -60)
    assert len(tz) == 172
    h = struct.pack("<IBBBBIIqIIIIIIII", BUFFER, 10, 0, 1, 8, 19041, 2, START + 5 * 10_000_000,
                    156250, 0, 0x00000001, 3, 1, 8, 0, 2400)
    h += struct.pack("<QQ", 0x000001D0_00001000, 0x000001D0_00002000)
    h += tz
    h += b"\0" * (align8(len(h)) - len(h))
    h += struct.pack("<qqqII", START - 3600 * 10_000_000, FREQ, START, 1, 0)
    assert len(h) == 0x118, hex(len(h))
    return h + utf16z("fillyfoal-test") + utf16z("C:\\Traces\\sample.etl")


def tl_metadata():
    fields = [
        (b"Message\0", bytes([1])),  # UNICODESTRING
        (b"Count\0", bytes([8])),  # UINT32
        (b"Ratio\0", bytes([12])),  # DOUBLE
        (b"Ok\0", bytes([13])),  # BOOL32
        (b"Id\0", bytes([15])),  # GUID
        (b"Values\0", bytes([0x46]) + struct.pack("<H", 3)),  # UINT16[3], constant count
    ]
    body = b"\x00" + b"Greeting\0" + b"".join(name + t for name, t in fields)
    return struct.pack("<H", 2 + len(body)) + body


def prov_traits():
    name = b"Fillyfoal.Test\0"
    return struct.pack("<H", 2 + len(name)) + name


def buffer(events, cpu, buffer_type, ts, flags=0):
    body = b""
    for e in events:
        body += e + b"\0" * (align8(len(e)) - len(e))
    used = 0x48 + len(body)
    header = struct.pack("<IIIiqq", BUFFER, used, used, 0, ts, 0)
    header += struct.pack("<Q", 1 | (FREQ << 3))  # clock type 1 (QPC), frequency
    header += struct.pack("<BBHIIHH", cpu, 0, 0x22, 1, used, flags, buffer_type)
    header += struct.pack("<qq", START, QPC0)  # reference time: FILETIME, QPC
    assert len(header) == 0x48
    return (header + body).ljust(BUFFER, b"\xff")


def main():
    hdr = logfile_header()
    b0 = buffer(
        [
            system(0x02, 0x0000, 0x10, 0x4, QPC0, hdr),
            system(0x02, 0x0301, 0x10, 0x4, QPC0 + 100, struct.pack("<QIIIi", 0xFFFF8000_00001000, 1234, 4, 1, 0) + b"notepad.exe\0"),
            system(0x04, 0x0524, 0x0, 0x0, QPC0 + 250, struct.pack("<IIbbbbbbbb", 88, 77, 0, 0, 2, 5, 0, 0, 0, 0), compact=True),
            perfinfo(0x0F2E, QPC0 + 400, struct.pack("<QII", 0xFFFFF800_01234567, 88, 1)),
        ],
        cpu=0,
        buffer_type=4,
        ts=QPC0 + 500,
    )
    provider = "6E2D5A9A-1B2C-4D3E-8F90-0A1B2C3D4E5F"
    tl_provider = "B3864C38-4273-58C5-545B-8B3608343471"
    message = utf16z("Hello, ETW")
    tl_payload = message + struct.pack("<Id?xxx", 42, 0.5, True) + guid("01234567-89AB-CDEF-0123-456789ABCDEF")
    tl_payload += struct.pack("<HHH", 1, 2, 3)
    b1 = buffer(
        [
            event_header(provider, 1, 0, 4, 0, 0, 0x8000000000000000, 0x2210, 0x1220, QPC0 + 1_000_000,
                         [(1, guid("11111111-2222-3333-4444-555555555555"))], utf16z("started")),
            event_header(tl_provider, 0, 0, 5, 0, 0, 0x0000400000000000, 0x2210, 0x1220, QPC0 + 2_000_000,
                         [(12, prov_traits()), (11, tl_metadata())], tl_payload, channel=11),
        ],
        cpu=1,
        buffer_type=0,
        ts=QPC0 + 2_500_000,
    )
    b2 = buffer(
        [
            classic("9E814AAD-3204-11D2-9A82-006008A86939", 1, 4, 2, 0x30, 0x8, QPC0 + 3_000_000, b"MOF data\0\0"),
            instance(2, 4, 0, 0x30, 0x8, QPC0 + 3_100_000, b"\x01\x02\x03\x04"),
        ],
        cpu=0,
        buffer_type=0,
        ts=QPC0 + 3_200_000,
        flags=0x0002,
    )
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "wb") as f:
        f.write(b0 + b1 + b2)


main()
