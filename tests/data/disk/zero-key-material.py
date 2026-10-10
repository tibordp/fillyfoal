"""Zeroes the anti-forensic key material of LUKS1/LUKS2 key slots (also the
LUKS header inside an encrypted qcow2 image), so the fixtures compress:
the material is random by design and nothing in the dissector reads its
content. Headers, checksums and everything else are left as written.

usage: python3 zero-key-material.py <image>...
"""

import json
import struct
import sys


def zero_luks(buf, base):
    version = struct.unpack_from(">H", buf, base + 6)[0]
    if version == 1:
        key_bytes = struct.unpack_from(">I", buf, base + 108)[0]
        for i in range(8):
            slot = base + 208 + 48 * i
            state, _, = struct.unpack_from(">II", buf, slot)
            material, stripes = struct.unpack_from(">II", buf, slot + 40)
            if material == 0:
                continue
            start = base + material * 512
            length = -(-key_bytes * stripes // 512) * 512
            buf[start:start + length] = bytes(min(length, len(buf) - start))
    elif version == 2:
        hdr_size = struct.unpack_from(">Q", buf, base + 8)[0]
        text = bytes(buf[base + 4096:base + hdr_size]).split(b"\0", 1)[0]
        meta = json.loads(text)
        for slot in meta.get("keyslots", {}).values():
            area = slot["area"]
            start = base + int(area["offset"])
            length = int(area["size"])
            buf[start:start + length] = bytes(min(length, len(buf) - start))


def main():
    for path in sys.argv[1:]:
        buf = bytearray(open(path, "rb").read())
        if buf[:4] == b"QFI\xfb":
            # qcow2: the full disk encryption header extension (0x0537be77).
            header_len = 72
            if struct.unpack_from(">I", buf, 4)[0] >= 3:
                header_len = struct.unpack_from(">I", buf, 100)[0]
            at = header_len
            while True:
                kind, length = struct.unpack_from(">II", buf, at)
                if kind == 0:
                    break
                if kind == 0x0537BE77:
                    zero_luks(buf, struct.unpack_from(">Q", buf, at + 8)[0])
                at += 8 + (length + 7) // 8 * 8
        elif buf[:6] == b"LUKS\xba\xbe":
            zero_luks(buf, 0)
        open(path, "wb").write(buf)


main()
