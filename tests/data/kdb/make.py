"""Synthetic KeePass 1.x (.kdb) fixtures, assembled from the layout as we
understand it (no KeePass 1 writer is installable here).

    uv run --with pycryptodomex==3.23.0 --with pykeepass==4.2.0 \
        python tests/data/kdb/make.py OUTDIR

AES via pycryptodome; Twofish via pykeepass's pure-Python port. Password
"fillyfoal", 100 key transform rounds. Deterministic.
"""

import hashlib
import struct
import sys
from pathlib import Path

from Cryptodome.Cipher import AES
from pykeepass.kdbx_parsing.pytwofish import Twofish

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
PASSWORD = b"fillyfoal"
ROUNDS = 100


def packed(y, mo, d, h, mi, s):
    v = (y << 26) | (mo << 22) | (d << 17) | (h << 12) | (mi << 6) | s
    return v.to_bytes(5, "big")


T = packed(2024, 5, 6, 7, 8, 9)
NEVER = packed(2999, 12, 28, 23, 59, 59)


def field(kind, data):
    return struct.pack("<HI", kind, len(data)) + data


def text(s):
    return s.encode() + b"\0"


def group(gid, name, level):
    return b"".join([
        field(1, struct.pack("<I", gid)),
        field(2, text(name)),
        field(3, T), field(4, T), field(5, T), field(6, NEVER),
        field(7, struct.pack("<I", 1)),
        field(8, struct.pack("<H", level)),
        field(9, struct.pack("<I", 0)),
        field(0xFFFF, b""),
    ])


def entry(n, gid, title, url, user, password, notes, desc=b"", data=b""):
    return b"".join([
        field(1, bytes([n]) * 16),
        field(2, struct.pack("<I", gid)),
        field(3, struct.pack("<I", 0)),
        field(4, text(title)),
        field(5, text(url)),
        field(6, text(user)),
        field(7, text(password)),
        field(8, text(notes)),
        field(9, T), field(10, T), field(11, T), field(12, NEVER),
        field(13, desc + b"\0" if desc else b"\0"),
        field(14, data),
        field(0xFFFF, b""),
    ])


def body():
    groups = [group(1, "General", 0), group(2, "Web", 1), group(3, "Mail", 0)]
    entries = [
        entry(1, 1, "Router", "http://192.168.0.1/", "admin", "hunter2", "Behind the TV"),
        entry(2, 2, "Example", "https://example.com/", "alice", "correct horse", ""),
        entry(3, 3, "Mailbox", "imaps://mail.example.com", "alice@example.com", "s3cret", "",
              b"hello.txt", b"Hello from an attachment.\n"),
        entry(4, 1, "Meta-Info", "$", "SYSTEM", "", "KPX_GROUP_TREE_STATE",
              b"bin-stream", b"\x01\x00\x00\x00\x01\x00\x00\x00\x01"),
    ]
    return len(groups), len(entries), b"".join(groups + entries)


def write(name, cipher):
    ngroups, nentries, plain = body()
    master_seed = bytes(range(16))
    iv = bytes(range(16, 32))
    transform_seed = bytes(range(32, 64))
    key = hashlib.sha256(PASSWORD).digest()
    ecb = AES.new(transform_seed, AES.MODE_ECB)
    for _ in range(ROUNDS):
        key = ecb.encrypt(key)
    final = hashlib.sha256(master_seed + hashlib.sha256(key).digest()).digest()
    pad = 16 - len(plain) % 16
    padded = plain + bytes([pad]) * pad
    if cipher == "aes":
        flags = 1 | 2
        ct = AES.new(final, AES.MODE_CBC, iv).encrypt(padded)
    else:
        flags = 1 | 8
        tf = Twofish(final)
        prev, out = iv, b""
        for i in range(0, len(padded), 16):
            block = bytes(a ^ b for a, b in zip(padded[i:i + 16], prev))
            prev = tf.encrypt(block)
            out += prev
        ct = out
    header = struct.pack("<IIII", 0x9AA2D903, 0xB54BFB65, flags, 0x00030004)
    header += master_seed + iv + struct.pack("<II", ngroups, nentries)
    header += hashlib.sha256(plain).digest() + transform_seed + struct.pack("<I", ROUNDS)
    assert len(header) == 124
    (OUT / name).write_bytes(header + ct)


write("aes.kdb", "aes")
write("twofish.kdb", "twofish")
