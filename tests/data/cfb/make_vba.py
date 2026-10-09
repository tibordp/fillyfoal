"""Writes tests/fixtures/synthetic/cfb/vbaProject.bin: a VBA project storage
as Office keeps it inside .docm/.xlsm files (and under Macros or
_VBA_PROJECT_CUR in binary documents), with one procedural module and one
document module. `dir` and the module sources use MS-OVBA compression
(written here from the specification; olevba decodes the result).

    python tests/data/cfb/make_vba.py <out>
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(__file__))
import cfbwriter  # noqa: E402


def compress(data):
    """MS-OVBA 2.4.1: greedy matching within each 4096-byte chunk."""
    out = bytearray(b"\x01")
    for c in range(0, max(len(data), 1), 4096):
        chunk = data[c:c + 4096]
        body = bytearray()
        pos = 0
        while pos < len(chunk):
            flags = 0
            group = bytearray()
            for bit in range(8):
                if pos >= len(chunk):
                    break
                # Bit count of the copy token at this position.
                diff = pos
                bits = 4
                while (1 << bits) < diff:
                    bits += 1
                max_len = (0xFFFF >> bits) + 3
                best_len, best_off = 0, 0
                for start in range(max(0, pos - (1 << bits)), pos):
                    n = 0
                    while n < max_len and pos + n < len(chunk) and chunk[start + n] == chunk[pos + n]:
                        n += 1
                    if n > best_len:
                        best_len, best_off = n, pos - start
                if best_len >= 3:
                    token = ((best_off - 1) << (16 - bits)) | (best_len - 3)
                    group += struct.pack("<H", token)
                    flags |= 1 << bit
                    pos += best_len
                else:
                    group.append(chunk[pos])
                    pos += 1
            body.append(flags)
            body += group
        if len(body) >= 4096 and len(chunk) == 4096:
            out += struct.pack("<H", 0x3000 | 4095) + chunk
        else:
            out += struct.pack("<H", 0xB000 | (len(body) + 2 - 3)) + body
    return bytes(out)


def rec(rid, data):
    return struct.pack("<HI", rid, len(data)) + data


CODEPAGE = 1252
modules = [
    ("Module1", "Module1", False,
     'Attribute VB_Name = "Module1"\r\nSub Hello()\r\n    MsgBox "Hello from fillyfoal"\r\n'
     '    Dim i As Integer\r\n    For i = 1 To 3\r\n        Debug.Print "line " & i\r\n    Next i\r\nEnd Sub\r\n'),
    ("ThisDocument", "ThisDocument", True,
     'Attribute VB_Name = "ThisDocument"\r\nAttribute VB_Base = "1Normal.ThisDocument"\r\n'
     'Attribute VB_GlobalNameSpace = False\r\nAttribute VB_Creatable = False\r\n'
     'Attribute VB_PredeclaredId = True\r\nAttribute VB_Exposed = True\r\n'),
]

d = b""
d += rec(0x0001, struct.pack("<I", 1))
d += rec(0x004A, struct.pack("<I", 0x0B2))
d += rec(0x0002, struct.pack("<I", 0x0409))
d += rec(0x0014, struct.pack("<I", 0x0409))
d += rec(0x0003, struct.pack("<H", CODEPAGE))
d += rec(0x0004, b"Project")
d += rec(0x0005, b"") + rec(0x0040, b"")
d += rec(0x0006, b"") + rec(0x003D, b"")
d += rec(0x0007, struct.pack("<I", 0))
d += rec(0x0008, struct.pack("<I", 0))
d += struct.pack("<HIIH", 0x0009, 4, 1, 0x05A1)
d += rec(0x000C, b"") + rec(0x003C, b"")
libid = b"*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\System32\\stdole2.tlb#OLE Automation"
d += rec(0x0016, b"stdole") + rec(0x003E, "stdole".encode("utf-16-le"))
d += struct.pack("<HII", 0x000D, 4 + len(libid) + 6, len(libid)) + libid + struct.pack("<IH", 0, 0)
d += rec(0x000F, struct.pack("<H", len(modules)))
d += rec(0x0013, struct.pack("<H", 0xFFFF))

streams = {}
for name, stream, document, source in modules:
    d += rec(0x0019, name.encode())
    d += rec(0x0047, name.encode("utf-16-le"))
    d += rec(0x001A, stream.encode()) + rec(0x0032, stream.encode("utf-16-le"))
    d += rec(0x001C, b"") + rec(0x0048, b"")
    d += rec(0x0031, struct.pack("<I", 0))
    d += rec(0x001E, struct.pack("<I", 0))
    d += rec(0x002C, struct.pack("<H", 0xFFFF))
    d += rec(0x0022 if document else 0x0021, b"")
    d += rec(0x002B, b"")
    streams[stream] = compress(source.encode("cp1252"))
d += rec(0x0010, b"")

vba = dict(streams)
vba["dir"] = compress(d)
vba["_VBA_PROJECT"] = struct.pack("<HHBH", 0x61CC, 0xFFFF, 0, 0)

project = (
    'ID="{00000000-0000-0000-0000-000000000000}"\r\n'
    "Document=ThisDocument/&H00000000\r\n"
    "Module=Module1\r\n"
    'Name="Project"\r\n'
    'HelpContextID="0"\r\n'
    'VersionCompatible32="393222000"\r\n'
    'CMG="0705D8E3D8EDDBF1DBF1DBF1DBF1"\r\n'
    'DPB="0E0CD1ECDFF4E7F5E7F5E7"\r\n'
    'GC="1517CAF1D6F9D7F9D706"\r\n'
    "\r\n[Host Extender Info]\r\n"
    "&H00000001={3832D640-CF90-11CF-8E43-00A0C911005A};VBE;&H00000000\r\n"
    "\r\n[Workspace]\r\n"
    "ThisDocument=0, 0, 0, 0, C\r\n"
    "Module1=26, 26, 1000, 600, Z\r\n"
).encode("cp1252")
wm = b""
for name, _, _, _ in modules:
    wm += name.encode() + b"\0" + name.encode("utf-16-le") + b"\0\0"
wm += b"\0\0"

cfbwriter.write(sys.argv[1], {"VBA": vba, "PROJECT": project, "PROJECTwm": wm})
