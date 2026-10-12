"""Writes tests/fixtures/synthetic/sqlite-shm/be.db-shm: the external
little-endian WAL index (external/sqlite-shm/t.db-shm) rewritten in big-endian
order, as a big-endian machine would have written it, with the header
checksums recomputed.

    python3 -I tests/data/sqlite/shm_be.py IN OUT
"""
import struct
import sys


def checksum(words):
    s1 = s2 = 0
    for i in range(0, len(words), 2):
        s1 = (s1 + words[i] + s2) & 0xFFFFFFFF
        s2 = (s2 + words[i + 1] + s1) & 0xFFFFFFFF
    return s1, s2


def header(src):
    w = list(struct.unpack("<12I", src[:48]))
    init, big, size = struct.unpack("<BBH", src[12:16])
    out = bytearray(struct.pack(">3I", *w[:3]) + struct.pack(">BBH", init, big, size))
    out += struct.pack(">8I", *w[4:12])
    words = struct.unpack(">10I", out[:40])
    out[40:48] = struct.pack(">2I", *checksum(words))
    return bytes(out)


def main(src_path, out_path):
    d = open(src_path, "rb").read()
    out = bytearray()
    out += header(d[0:48])
    out += header(d[48:96])
    ck = struct.unpack("<6I", d[96:120])
    out += struct.pack(">6I", *ck) + d[120:128] + struct.pack(">2I", *struct.unpack("<2I", d[128:136]))
    nfirst = 4096 - 136 // 4
    out += struct.pack(">%dI" % nfirst, *struct.unpack_from("<%dI" % nfirst, d, 136))
    out += struct.pack(">8192H", *struct.unpack_from("<8192H", d, 136 + 4 * nfirst))
    assert len(out) == len(d) == 32768
    open(out_path, "wb").write(out)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
