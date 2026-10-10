"""Rewrites the host kernel string in pcapng shb_os / if_os options to "Linux".

dumpcap records the kernel release of the machine running Docker; the
fixtures keep only the OS name. Block and option lengths are recomputed;
everything else is copied byte for byte. Usage: scrub-pcapng.py IN OUT
"""
import struct
import sys

SHB, IDB = 0x0A0D0D0A, 1


def pad4(n):
    return (n + 3) & ~3


def options(body, e):
    out, at = [], 0
    while at + 4 <= len(body):
        code, n = struct.unpack(e + "HH", body[at:at + 4])
        out.append((code, body[at + 4:at + 4 + n]))
        at += 4 + pad4(n)
        if code == 0:
            break
    return out


def pack_options(opts, e):
    out = b""
    for code, val in opts:
        out += struct.pack(e + "HH", code, len(val)) + val + b"\0" * (pad4(len(val)) - len(val))
    return out


def main(src, dst):
    data = open(src, "rb").read()
    out, at, e = b"", 0, "<"
    while at + 12 <= len(data):
        if struct.unpack("<I", data[at:at + 4])[0] == SHB:
            e = "<" if data[at + 8:at + 12] == b"\x4d\x3c\x2b\x1a" else ">"
        kind, length = struct.unpack(e + "II", data[at:at + 8])
        block = data[at:at + length]
        fixed = {SHB: 16, IDB: 8}.get(kind)
        if fixed is not None:
            head = block[8:8 + fixed]
            opts = options(block[8 + fixed:length - 4], e)
            os_code = 3 if kind == SHB else 12
            opts = [(c, b"Linux" if c == os_code else v) for c, v in opts]
            body = head + pack_options(opts, e)
            n = len(body) + 12
            block = struct.pack(e + "II", kind, n) + body + struct.pack(e + "I", n)
        out += block
        at += length
    open(dst, "wb").write(out)


main(sys.argv[1], sys.argv[2])
