"""Writes tests/fixtures/synthetic/cfb/ole10native.cfb: an OLE object
storage as Office keeps one for a file dropped into a document (an
oleObject*.bin part, or an ObjectPool/_NNN storage): class Package, with
\\x01CompObj and a \\x01Ole10Native stream holding a Packager object that
wraps a small text file. The Packager layout follows oletools' oleobj
(OleNativeStream): size, signature 2, label, source path, type 0x00030000,
temporary path, file size and bytes, then the three paths in UTF-16.

    python tests/data/cfb/make_ole10native.py <out>
"""

import os
import struct
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(__file__))
import cfbwriter  # noqa: E402

PACKAGE_CLSID = struct.pack("<IHH", 0x0003000C, 0, 0) + bytes([0xC0, 0, 0, 0, 0, 0, 0, 0x46])

label = b"notes.txt"
source = b"C:\\Data\\notes.txt"
temp = b"C:\\Temp\\notes.txt"
data = b"Packaged by fillyfoal.\nThis line is the second one.\n"


def wide(s):
    return struct.pack("<I", len(s)) + s.decode().encode("utf-16-le")


native = (struct.pack("<H", 2) + label + b"\0" + source + b"\0"
          + struct.pack("<HH", 0, 3)
          + struct.pack("<I", len(temp) + 1) + temp + b"\0"
          + struct.pack("<I", len(data)) + data
          + wide(temp) + wide(label) + wide(source))
ole10 = struct.pack("<I", len(native)) + native


def ansi(s):
    return struct.pack("<I", len(s) + 1) + s + b"\0"


compobj = (struct.pack("<IIi", 0xFFFE0001, 0x00000A03, -1) + PACKAGE_CLSID
           + ansi(b"Package") + struct.pack("<I", 0) + ansi(b"Package")
           + struct.pack("<I", 0x71B239F4) + struct.pack("<III", 0, 0, 0))

cfbwriter.write(sys.argv[1], {
    "\x01CompObj": compobj,
    "\x01Ole10Native": ole10,
}, root_clsid=PACKAGE_CLSID)
