"""Writes the synthetic ZIP samples that pin the ZIP-family probes and name
decoding (Python's zipfile writes the container; the entries are ours):

  zip/project-code.zip       a project zip with a `code/` directory (not
                             TorchScript, which needs `code/__torch__` etc.)
  zip/nested-streamed.zip    streamed (bit 3) stored entry holding a streamed
                             OOXML-like zip: the probe must not walk into it
  zip/cp866-unicode-path.zip CP866 name bytes with an Info-ZIP Unicode Path
                             extra field (0x7075) giving "Привет.txt"
  xlsx/macros.xlsm           an .xlsx with a VBA project and printer settings
                             (`.bin` parts that do not make it XLSB)

    python3 -I tests/data/zip/make_probe_samples.py tests/fixtures/synthetic
"""

import io
import os
import struct
import sys
import zipfile
import zlib

OUT = sys.argv[1]
WHEN = (2026, 1, 1, 0, 0, 0)


class Unseekable(io.RawIOBase):
    """A write-only stream zipfile cannot seek in, so it streams entries
    with data descriptors (general purpose bit 3)."""

    def __init__(self):
        self.buf = bytearray()

    def writable(self):
        return True

    def write(self, b):
        self.buf += b
        return len(b)


def entry(name, method=zipfile.ZIP_DEFLATED):
    info = zipfile.ZipInfo(name, WHEN)
    info.compress_type = method
    return info


def write(path, data):
    path = os.path.join(OUT, path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def plain(entries):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        for info, data in entries:
            z.writestr(info, data)
    return out.getvalue()


def streamed(entries):
    out = Unseekable()
    with zipfile.ZipFile(out, "w") as z:
        for info, data in entries:
            with z.open(info, "w") as f:
                f.write(data)
    return bytes(out.buf)


CONTENT_TYPES = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n'
    b'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    b'<Default Extension="xml" ContentType="application/xml"/></Types>\n'
)

write(
    "zip/project-code.zip",
    plain(
        [
            (entry("myproject/README"), b"A project with its sources under code/.\n"),
            (entry("myproject/code/main.py"), b'print("hello")\n'),
        ]
    ),
)

inner = streamed(
    [
        (entry("[Content_Types].xml"), CONTENT_TYPES),
        (entry("word/document.xml"), b"<w:document/>\n"),
    ]
)
write(
    "zip/nested-streamed.zip",
    streamed(
        [
            (entry("inner.zip", zipfile.ZIP_STORED), inner),
            (entry("notes.txt"), b"The first entry is a stored, streamed zip.\n"),
        ]
    ),
)

# zipfile writes names as ASCII or UTF-8 only: write a placeholder of the
# same length, then put the CP866 bytes in the local and central headers.
raw = "Привет.txt".encode("cp866")
placeholder = b"XXXXXX.txt"
assert len(raw) == len(placeholder)
extra = struct.pack("<BI", 1, zlib.crc32(raw)) + "Привет.txt".encode("utf-8")
info = entry(placeholder.decode())
info.extra = struct.pack("<HH", 0x7075, len(extra)) + extra
info.create_system = 0
data = plain([(info, b"hello\n")])
assert data.count(placeholder) == 2
write("zip/cp866-unicode-path.zip", data.replace(placeholder, raw))

write(
    "xlsx/macros.xlsm",
    plain(
        [
            (entry("[Content_Types].xml"), CONTENT_TYPES),
            (entry("xl/workbook.xml"), b"<workbook/>\n"),
            (entry("xl/vbaProject.bin"), b"\xd0\xcf\x11\xe0" + bytes(60)),
            (entry("xl/printerSettings/printerSettings1.bin"), bytes(64)),
        ]
    ),
)
