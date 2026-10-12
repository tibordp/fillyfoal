"""Write synthetic/minidump/padded.dmp: a minimal minidump whose thread,
module and memory lists have 4 bytes of padding after their counts, the
layout Breakpad's processor and rust-minidump accept ("may be padded with 4
bytes on 64bit ABIs"). Hand-built from the dbghelp structure layouts.

    python3 tests/data/minidump/padded.py tests/fixtures/synthetic/minidump/padded.dmp
"""
import struct
import sys

out = bytearray(b"\0" * 0x20)  # header, filled in at the end
streams = []  # (type, rva, size)

def utf16_string(s):
    data = s.encode("utf-16-le")
    return struct.pack("<I", len(data)) + data + b"\0\0"

def align(n=4):
    while len(out) % n:
        out.append(0)

directory_rva = len(out)
out += b"\0" * (12 * 3)

# Payloads first: stack memory, module name.
stack_rva = len(out)
stack = bytes(range(32))
out += stack
align()
name_rva = len(out)
out += utf16_string("C:\\fillyfoal\\filly.exe")
align(8)

# ThreadList: count, pad, one MINIDUMP_THREAD (48 bytes).
rva = len(out)
out += struct.pack("<II", 1, 0)
out += struct.pack("<IIIIQQIIII", 0x1234, 0, 0x20, 0, 0x7ff0_0000_0000,
                   0x0010_0000, len(stack), stack_rva, 0, 0)
streams.append((3, rva, len(out) - rva))

# ModuleList: count, pad, one MINIDUMP_MODULE (108 bytes).
rva = len(out)
out += struct.pack("<II", 1, 0)
vs = struct.pack("<13I", 0xFEEF04BD, 0x10000, 0x10002, 0x30004, 0x10002,
                 0x30004, 0x3F, 0, 0x40004, 1, 0, 0, 0)
out += struct.pack("<QIIII", 0x1_4000_0000, 0x2000, 0, 0x5F5E_1000, name_rva)
out += vs + struct.pack("<IIIIQQ", 0, 0, 0, 0, 0, 0)
streams.append((4, rva, len(out) - rva))

# MemoryList: count, pad, one MINIDUMP_MEMORY_DESCRIPTOR (16 bytes).
rva = len(out)
out += struct.pack("<II", 1, 0)
out += struct.pack("<QII", 0x0010_0000, len(stack), stack_rva)
streams.append((5, rva, len(out) - rva))

for i, (kind, srva, size) in enumerate(streams):
    struct.pack_into("<III", out, directory_rva + 12 * i, kind, size, srva)
struct.pack_into("<4sIIIIIQ", out, 0, b"MDMP", 0xA793, len(streams),
                 directory_rva, 0, 0x5F5E_1000, 0)

with open(sys.argv[1], "wb") as f:
    f.write(out)
