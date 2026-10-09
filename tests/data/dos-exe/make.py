"""Writes tests/fixtures/synthetic/dos-exe/reloc.exe: an MS-DOS MZ
executable built by hand from the format description (no DOS toolchain is
available here). Two segments (code and data), a relocation table with
three entries, a stack, a non-default header size with padding, and an
overlay after the load module.

    python3 tests/data/dos-exe/make.py [output directory]
"""

import struct
import sys
from pathlib import Path

out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parents[2] / "fixtures/synthetic/dos-exe"

# Code segment (paragraph 0 of the load module): set DS to the data
# segment (relocated), print the message, exit.
code = bytes(
    [
        0xB8, 0x00, 0x00,  # mov ax, seg data      (relocation 1 at +1)
        0x8E, 0xD8,        # mov ds, ax
        0xBA, 0x00, 0x00,  # mov dx, offset msg
        0xB4, 0x09,        # mov ah, 9
        0xCD, 0x21,        # int 21h
        0x9A, 0x00, 0x00, 0x00, 0x00,  # call far helper (relocation 2 at +15)
        0xB8, 0x00, 0x4C,  # mov ax, 4C00h
        0xCD, 0x21,        # int 21h
    ]
)
code += b"\x90" * (32 - len(code))
helper = b"\xCB" + b"\x90" * 15  # retf, padded to a paragraph
data = b"Relocated hello from fillyfoal!\r\n$" + struct.pack("<H", 0)  # far pointer slot
data += b"\0" * (-len(data) % 16)
stack = b"\0" * 64

code_para = 0
helper_para = len(code) // 16
data_para = helper_para + len(helper) // 16
stack_para = data_para + len(data) // 16
module = bytearray(code + helper + data + stack)
# Relocated words hold segment numbers relative to the load segment.
struct.pack_into("<H", module, 1, data_para)
struct.pack_into("<HH", module, 13, 0, helper_para)
pointer_at = data_para * 16 + 34
struct.pack_into("<H", module, pointer_at, code_para)

relocations = [(1, 0), (15, 0), (pointer_at % 16, pointer_at // 16)]
header_paragraphs = 4  # 64 bytes: 28 fixed + 12 relocation bytes + padding
header = bytearray(header_paragraphs * 16)
table_at = 0x1C
image_len = len(header) + len(module)
struct.pack_into(
    "<2sHHHHHHHHHHHHH",
    header,
    0,
    b"MZ",
    image_len % 512,
    (image_len + 511) // 512,
    len(relocations),
    header_paragraphs,
    0x0010,  # minalloc: 256 bytes of BSS
    0xFFFF,  # maxalloc
    stack_para,  # ss
    len(stack),  # sp
    0,  # checksum
    0,  # ip
    code_para,  # cs
    table_at,
    0,  # overlay number
)
for i, (offset, segment) in enumerate(relocations):
    struct.pack_into("<HH", header, table_at + 4 * i, offset, segment)
overlay = b"OVL1" + bytes(range(28))
(out / "reloc.exe").write_bytes(bytes(header) + bytes(module) + overlay)
