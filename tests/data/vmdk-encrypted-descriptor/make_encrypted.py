"""Synthetic VMware encrypted disk descriptors (layout as VMware Fusion 13
writes them for a VM encrypted to protect its virtual TPM): u32-length-
prefixed clear header, key safe and ciphertext. Key material and ciphertext
are deterministic filler, not real keys.

    python3 make_encrypted.py OUTDIR
"""
import base64
import hashlib
import struct
import sys


def filler(label, n):
    out = b""
    i = 0
    while len(out) < n:
        out += hashlib.sha256(f"{label}{i}".encode()).digest()
        i += 1
    return out[:n]


def block(data):
    return struct.pack("<I", len(data)) + data


def descriptor(adapter, pairs, ct_len):
    header = adapter.ljust(16, b"\0") + struct.pack("<II", 22, 0x12345678)
    safe = "vmware:key/list/(" + ",".join(
        f"pair/({loc},HMAC%2dSHA%2d1,{base64.b64encode(filler(loc, 144)).decode().replace('/', '%2f').replace('=', '%3d').replace('+', '%2b')})"
        for loc in pairs
    ) + ")"
    return block(header) + block(safe.encode() + b"\0") + block(filler("ct", ct_len))


out = sys.argv[1]
# No password: the key is wrapped by the empty key (TPM-only encryption).
open(f"{out}/tpm-only.vmdk", "wb").write(
    descriptor(b"lsilogic", ["null/%3cVMWARE%2dEMPTYSTRING%3e"], 16 + 64 * 16 + 20)
)
# Password-protected, two locators.
open(f"{out}/phrase.vmdk", "wb").write(
    descriptor(
        b"nvme",
        ["phrase/fillyfoal%2dtest/pass2key%3dPBKDF2%2dHMAC%2dSHA%2d1%3arounds%3d10000",
         "null/%3cVMWARE%2dEMPTYSTRING%3e"],
        16 + 32 * 16 + 20,
    )
)
# Cut off inside the encrypted descriptor: its length field says 548 bytes,
# the file holds 96.
open(f"{out}/truncated.vmdk", "wb").write(open(f"{out}/phrase.vmdk", "rb").read()[:700])
