"""Writes tests/fixtures/synthetic/msg/full.msg: an Outlook message with
recipients, a file attachment, an embedded message, named properties
(numeric and string), multi-valued properties and a compressed RTF body.

    uv run --with compressed_rtf==1.0.6 python tests/data/msg/make.py <out.msg>
"""

import struct
import sys
import uuid

import compressed_rtf

sys.path.insert(0, __import__("os").path.join(__import__("os").path.dirname(__file__), "..", "cfb"))
import cfbwriter  # noqa: E402

PS_PUBLIC_STRINGS = 2
PSETID_COMMON = uuid.UUID("00062008-0000-0000-c000-000000000046")

FILETIME = 133_500_000_000_000_000  # 2024-01-21


def tag(pid, ptype):
    return (pid << 16) | ptype


class Props:
    def __init__(self):
        self.fixed = []
        self.streams = {}

    def add(self, pid, ptype, value):
        t = tag(pid, ptype)
        name = "__substg1.0_%08X" % t
        # String streams hold no terminator; the size counts one.
        if ptype == 0x001F:
            data = value.encode("utf-16-le")
            self.streams[name] = data
            self.fixed.append(struct.pack("<IIII", t, 6, len(data) + 2, 0))
        elif ptype == 0x001E:
            data = value.encode("cp1252")
            self.streams[name] = data
            self.fixed.append(struct.pack("<IIII", t, 6, len(data) + 1, 0))
        elif ptype in (0x0102, 0x000D):
            self.streams[name] = value
            self.fixed.append(struct.pack("<IIII", t, 6, len(value), 0))
        elif ptype == 0x101F:
            lengths = b""
            for i, v in enumerate(value):
                data = v.encode("utf-16-le")
                self.streams["%s-%08X" % (name, i)] = data
                lengths += struct.pack("<I", len(data) + 2)
            self.streams[name] = lengths
            self.fixed.append(struct.pack("<IIII", t, 6, len(lengths), 0))
        elif ptype == 0x1003:
            data = b"".join(struct.pack("<i", v) for v in value)
            self.streams[name] = data
            self.fixed.append(struct.pack("<IIII", t, 6, len(data), 0))
        else:
            raw = {
                0x0002: lambda v: struct.pack("<h", v) + b"\0" * 6,
                0x0003: lambda v: struct.pack("<i", v) + b"\0" * 4,
                0x000B: lambda v: struct.pack("<H", 1 if v else 0) + b"\0" * 6,
                0x0040: lambda v: struct.pack("<Q", v),
                0x0014: lambda v: struct.pack("<q", v),
                0x0005: lambda v: struct.pack("<d", v),
            }[ptype](value)
            self.fixed.append(struct.pack("<II", t, 6) + raw)

    def storage(self, header):
        out = dict(self.streams)
        out["__properties_version1.0"] = header + b"".join(self.fixed)
        return out


def message(subject, body, embedded=False, recipients=(), attachments=()):
    p = Props()
    p.add(0x001A, 0x001F, "IPM.Note")
    p.add(0x0037, 0x001F, subject)
    p.add(0x0E1D, 0x001F, subject)
    p.add(0x1000, 0x001F, body)
    p.add(0x0C1A, 0x001F, "Fillyfoal Sender")
    p.add(0x0C1F, 0x001F, "sender@example.org")
    p.add(0x0C1E, 0x001F, "SMTP")
    p.add(0x0017, 0x0003, 2)
    p.add(0x0036, 0x0003, 0)
    p.add(0x0E07, 0x0003, 0x13)
    p.add(0x0039, 0x0040, FILETIME)
    p.add(0x0E06, 0x0040, FILETIME + 600_000_000)
    p.add(0x3FDE, 0x0003, 65001)
    p.add(0x0E1B, 0x000B, bool(attachments))
    p.add(0x0E08, 0x0003, 4096)
    p.add(0x0E04, 0x001F, "; ".join(r[0] for r in recipients))
    storage = {}
    for i, (name, addr, kind) in enumerate(recipients):
        r = Props()
        r.add(0x3001, 0x001F, name)
        r.add(0x3003, 0x001F, addr)
        r.add(0x39FE, 0x001F, addr)
        r.add(0x3002, 0x001F, "SMTP")
        r.add(0x0C15, 0x0003, kind)
        r.add(0x0FFE, 0x0003, 6)
        storage["__recip_version1.0_#%08X" % i] = r.storage(b"\0" * 8)
    for i, att in enumerate(attachments):
        a = Props()
        a.add(0x0E21, 0x0003, i)
        a.add(0x0FFE, 0x0003, 7)
        if isinstance(att, tuple):
            fname, data = att
            a.add(0x3705, 0x0003, 1)
            a.add(0x3707, 0x001F, fname)
            a.add(0x3704, 0x001F, fname[:8])
            a.add(0x3703, 0x001F, "." + fname.rsplit(".", 1)[1])
            a.add(0x370E, 0x001F, "text/plain")
            a.add(0x3701, 0x0102, data)
            a.add(0x0E20, 0x0003, len(data))
            storage["__attach_version1.0_#%08X" % i] = a.storage(b"\0" * 8)
        else:
            a.add(0x3705, 0x0003, 5)
            a.add(0x3001, 0x001F, "Embedded message")
            st = a.storage(b"\0" * 8)
            st["__substg1.0_3701000D"] = att
            storage["__attach_version1.0_#%08X" % i] = st
    if not embedded:
        # Named properties: one numeric (PSETID_Common 0x8510), one by name.
        p.add(0x8000, 0x0003, 369)
        p.add(0x8001, 0x101F, ["fixture", "fillyfoal"])
        p.add(0x6800, 0x1003, [1, 2, 3])
        rtf = b"{\\rtf1\\ansi\\ansicpg1252\\deff0{\\fonttbl{\\f0 Arial;}}\\f0\\fs20 Hello, \\b RTF\\b0  body.\\par}"
        p.add(0x1009, 0x0102, compressed_rtf.compress(rtf, compressed=True))
        p.add(0x10F4, 0x000B, False)
    header = struct.pack("<8xIIII", len(recipients), len(attachments), len(recipients), len(attachments))
    if not embedded:
        header += b"\0" * 8
    out = p.storage(header)
    out.update(storage)
    return out


def nameid():
    guids = PSETID_COMMON.bytes_le
    name = "Keywords".encode("utf-16-le")
    strings = struct.pack("<I", len(name)) + name
    strings += b"\0" * ((-len(strings)) % 4)
    entries = struct.pack("<II", 0x8510, (0 << 16) | ((3 + 0) << 1) | 0)
    entries += struct.pack("<II", 0, (1 << 16) | (PS_PUBLIC_STRINGS << 1) | 1)
    return {
        "__substg1.0_00020102": guids,
        "__substg1.0_00030102": entries,
        "__substg1.0_00040102": strings,
    }


inner = message("Forwarded note", "The embedded message body.", embedded=True,
                recipients=[("Inner Recipient", "inner@example.org", 1)])
msg = message(
    "Fillyfoal test message",
    "Hello,\r\n\r\nThis is the plain text body.\r\n",
    recipients=[("Alice Example", "alice@example.org", 1), ("Bob Example", "bob@example.org", 2)],
    attachments=[("notes.txt", b"Attached text file.\n"), inner],
)
msg["__nameid_version1.0"] = nameid()
cfbwriter.write(sys.argv[1], msg)
