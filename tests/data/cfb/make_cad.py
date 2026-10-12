"""Writes the synthetic CAD compound files: no SolidWorks, Inventor or
Revit writer runs here, so each file only carries the root entry names
(and class) that identify it, with placeholder content:

- solidworks/part.sldprt: storages SwDocContentMgr and SwDocMgrTempStorage
  (the names Apache Tika's POIFSContainerDetector checks for SolidWorks
  2014 and earlier).
- inventor/part.ipt: root class {4D29B490-49B2-11D0-93C3-7E0706000000}
  and storages RSeStorage, RSeEmbeddings, RSeDb, RefdFiles and Templates
  (libmagic's ole2compounddocs entry for Inventor parts and its samples).
- revit/family.rfa: streams BasicFileInfo (UTF-16 text), TransmissionData,
  PartAtom (an Atom XML entry, as family files have) and RevitPreview4.0
  (a placeholder header, then a 2x2 PNG), storages Global, Partitions and
  Formats (the root names of real Revit files as the ODA BimRv
  documentation lists them).

    python tests/data/cfb/make_cad.py <fixtures dir>
"""

import os
import struct
import sys
import zlib

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(__file__))
import cfbwriter  # noqa: E402

out = sys.argv[1]


def png(width, height, rgb):
    def chunk(kind, data):
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    rows = b"".join(b"\0" + bytes(rgb) * width for _ in range(height))
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(rows, 9))
        + chunk(b"IEND", b"")
    )


def path(*parts):
    p = os.path.join(out, *parts)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    return p


cfbwriter.write(
    path("solidworks", "part.sldprt"),
    {
        "SwDocContentMgr": {"Placeholder": b"fillyfoal SolidWorks placeholder\n"},
        "SwDocMgrTempStorage": {},
    },
)

INVENTOR_PART = struct.pack("<IHH", 0x4D29B490, 0x49B2, 0x11D0) + bytes(
    [0x93, 0xC3, 0x7E, 0x07, 0x06, 0, 0, 0]
)
cfbwriter.write(
    path("inventor", "part.ipt"),
    {
        "RSeStorage": {"Placeholder": b"fillyfoal Inventor placeholder\n"},
        "RSeEmbeddings": {},
        "RSeDb": {},
        "RefdFiles": {},
        "Templates": {},
    },
    root_clsid=INVENTOR_PART,
)

info = "Worksharing: Not enabled\r\nUsername: \r\nFormat: 2024\r\nBuild: fillyfoal\r\n"
atom = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n'
    b'<entry xmlns="http://www.w3.org/2005/Atom">'
    b"<title>fillyfoal family</title><category><term>Generic Models</term></category>"
    b"</entry>\n"
)
cfbwriter.write(
    path("revit", "family.rfa"),
    {
        "BasicFileInfo": info.encode("utf-16-le"),
        "TransmissionData": b"\0" * 16,
        "PartAtom": atom,
        "RevitPreview4.0": b"fillyfoal preview header".ljust(32, b"\0") + png(2, 2, (40, 120, 200)),
        "Global": {"Placeholder": b"fillyfoal Revit placeholder\n"},
        "Partitions": {},
        "Formats": {},
    },
)
