#!/usr/bin/env python3
"""Writes tests/fixtures/synthetic/qemu-vmstate/features.vmstate (and
v2.vmstate, see the end): a QEMU migration stream exercising what the real
fixtures do not (hand-made from the layout QEMU 10.0 writes, not by QEMU):

- configuration subsections: target page bits (1 KiB pages), capabilities,
  UUID;
- RAM pages of every kind: zero (with a zero and a non-zero fill byte),
  data, XBZRLE, zlib-compressed, CONTINUE records, a multifd flush;
- a device section whose VM description has an array, a nested structure
  and a subsection;
- a packaged stream (MIG_CMD_PACKAGED) holding another device section;
- the VM description at the end.

    python3 tests/data/qemu-vmstate/make-synthetic.py
"""
import json
import os
import struct
import zlib

PAGE_BITS = 10
PAGE = 1 << PAGE_BITS


def be32(v):
    return struct.pack(">I", v)


def be64(v):
    return struct.pack(">Q", v)


def idstr(s):
    b = s.encode()
    return bytes([len(b)]) + b


def footer(sid):
    return b"\x7e" + be32(sid)


def full(sid, name, instance, version, payload):
    return b"\x04" + be32(sid) + idstr(name) + be32(instance) + be32(version) + payload + footer(sid)


def subsection(name, version, payload):
    return b"\x05" + idstr(name) + be32(version) + payload


out = bytearray(b"QEVM" + be32(3))

# Configuration.
out += b"\x07" + be32(9) + b"pc-q35-10"
out += subsection("configuration/target-page-bits", 1, be32(PAGE_BITS))
caps = [b"xbzrle", b"events"]
out += subsection("configuration/capabilities", 1, be32(len(caps)) + b"".join(bytes([len(c)]) + c for c in caps))
out += subsection("configuration/uuid", 1, bytes(range(16)))

# RAM setup: two blocks.
blocks = [("pc.ram", 16 * PAGE), ("pc.bios", 4 * PAGE)]
total = sum(n for _, n in blocks)
ram = be64(total | 0x04)
for name, n in blocks:
    ram += idstr(name) + be64(n)
ram += be64(0x10)
out += b"\x01" + be32(1) + idstr("ram") + be32(0) + be32(4) + ram + footer(1)

# RAM part.
page = bytes((i * 7) & 0xFF for i in range(PAGE))
part = b""
part += be64(0 * PAGE | 0x02) + idstr("pc.ram") + b"\x00"  # zero
part += be64(1 * PAGE | 0x22) + b"\x00"  # zero, continue
part += be64(2 * PAGE | 0x22) + b"\x00"
part += be64(3 * PAGE | 0x22) + b"\xff"  # filled with 0xff
part += be64(4 * PAGE | 0x28) + page  # data, continue
part += be64(5 * PAGE | 0x28) + page
delta = b"\x04\x02ab"  # XBZRLE: skip 4, copy 2 bytes
part += be64(6 * PAGE | 0x60) + b"\x01" + struct.pack(">H", len(delta)) + delta
comp = zlib.compress(page, 9)
part += be64(7 * PAGE | 0x120) + be32(len(comp)) + comp
part += be64(0x200)  # multifd flush
part += be64(0 * PAGE | 0x08) + idstr("pc.bios") + page
part += be64(1 * PAGE | 0x22) + b"\x00"
part += be64(0x10)
out += b"\x02" + be32(1) + part + footer(1)
out += b"\x03" + be32(1) + be64(0x10) + footer(1)

# A device: two uint32s, an array of three uint16s, a nested structure
# and a subsection.
dev = be32(0xDEADBEEF) + struct.pack(">i", -2)
dev += struct.pack(">HHH", 1, 2, 3)
dev += struct.pack(">BQ", 1, 0x1122334455667788)
dev += subsection("widget/extra", 2, b"\x01" + b"pad!")
out += full(2, "widget", 0, 3, dev)

# A packaged stream with one more device section.
inner = full(3, "gadget", 1, 1, struct.pack(">Q", 42)) + b"\x00"
out += b"\x08" + struct.pack(">HH", 7, 4) + be32(len(inner)) + inner

out += b"\x00"

desc = {
    "configuration": {"vmsd_name": "configuration", "version": 1, "fields": []},
    "page_size": PAGE,
    "devices": [
        {
            "name": "widget",
            "instance_id": 0,
            "vmsd_name": "widget",
            "version": 3,
            "fields": [
                {"name": "magic", "type": "uint32", "size": 4},
                {"name": "delta", "type": "int32", "size": 4},
                {"name": "regs", "array_len": 3, "type": "uint16", "size": 2},
                {
                    "name": "inner",
                    "type": "struct",
                    "struct": {
                        "vmsd_name": "widget/inner",
                        "version": 1,
                        "fields": [
                            {"name": "enabled", "type": "bool", "size": 1},
                            {"name": "base", "type": "uint64", "size": 8},
                        ],
                    },
                    "size": 9,
                },
            ],
            "subsections": [
                {
                    "vmsd_name": "widget/extra",
                    "version": 2,
                    "fields": [
                        {"name": "flag", "type": "uint8", "size": 1},
                        {"name": "tag", "type": "buffer", "size": 4},
                    ],
                }
            ],
        },
        {
            "name": "gadget",
            "instance_id": 1,
            "vmsd_name": "gadget",
            "version": 1,
            "fields": [{"name": "counter", "type": "uint64", "size": 8}],
        },
    ],
}
js = json.dumps(desc).encode()
out += b"\x06" + be32(len(js)) + js

here = os.path.dirname(os.path.abspath(__file__))
dst = os.path.join(here, "..", "..", "fixtures", "synthetic", "qemu-vmstate", "features.vmstate")
os.makedirs(os.path.dirname(dst), exist_ok=True)
with open(dst, "wb") as f:
    f.write(out)
print(dst, len(out))

# v2.vmstate: the pre-0.13 layout (QEMU_VM_FILE_VERSION_COMPAT), which has
# no section types: records of ID string, instance, version and a 64-bit
# length. Shown as unsupported after its header.
v2 = b"QEVM" + be32(2)
v2 += bytes([5]) + b"timer" + be32(0) + be32(2) + be64(8) + be64(0x1234)
dst = os.path.join(here, "..", "..", "fixtures", "synthetic", "qemu-vmstate", "v2.vmstate")
with open(dst, "wb") as f:
    f.write(v2)
print(dst, len(v2))
