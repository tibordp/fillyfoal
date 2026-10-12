"""Writes tests/fixtures/synthetic/ppt/encrypted.ppt: the external
LibreOffice deck (tests/fixtures/external/ppt/deck.ppt) encrypted with RC4
CryptoAPI the way PowerPoint 2002-2003 encrypts (MS-PPT 2.3.7), password
`fillyfoal`.

No tool at hand writes an encrypted .ppt (LibreOffice and
msoffcrypto-tool only read them), so this script appends a
CryptSession10Container (an RC4 CryptoAPI EncryptionHeader and
EncryptionVerifier, MS-OFFCRYPTO 2.3.5.1) as a new persist object, a
PersistDirectoryAtom for it and a UserEditAtom whose
encryptSessionPersistIdRef names it; points the Current User atom at the
new edit with the "encrypted" header token; and encrypts every other
persist object, header included, with an RC4 keystream started afresh
with the block key of its persist ID.

Checked with msoffcrypto-tool 6.0.0, which verifies the password and
decrypts every persist object back to the original bytes (LibreOffice
26.8 does not open encrypted .ppt files at all):

    uv run --with olefile python tests/data/ppt/make_encrypted.py [out.ppt]
    uv run --with msoffcrypto-tool==6.0.0 msoffcrypto-tool -p fillyfoal out.ppt plain.ppt
"""

import hashlib
import os
import struct
import sys
import uuid
from pathlib import Path

import olefile

here = Path(__file__).resolve().parent
sys.path.insert(0, str(here.parent / "cfb"))
import cfbwriter  # noqa: E402

root = here.parents[1]
src = root / "fixtures/external/ppt/deck.ppt"
out = Path(sys.argv[1]) if len(sys.argv) > 1 else root / "fixtures/synthetic/ppt/encrypted.ppt"
PASSWORD = "fillyfoal"
SALT = bytes(range(0x10, 0x20))
VERIFIER = b"fillyfoal-verify"
BITS = 128


def rc4(key, data):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


H0 = hashlib.sha1(SALT + PASSWORD.encode("utf-16-le")).digest()


def block_key(block):
    return hashlib.sha1(H0 + struct.pack("<I", block)).digest()[: BITS // 8]


def header(ver_inst, kind, body):
    return struct.pack("<HHI", ver_inst, kind, len(body)) + body


ole = olefile.OleFileIO(str(src))
streams = {"/".join(p): ole.openstream(p).read() for p in ole.listdir(streams=True)}
doc = bytearray(streams["PowerPoint Document"])
cu = bytearray(streams["Current User"])

# The edit chain and its persist directory (newer entries win).
first_edit = struct.unpack_from("<I", cu, 8 + 8)[0]
table = {}
at = first_edit
edit_body = None
while True:
    _, kind, n = struct.unpack_from("<HHI", doc, at)
    assert kind == 0x0FF5
    body = doc[at + 8 : at + 8 + n]
    edit_body = edit_body or bytes(body)
    prev, dir_at = struct.unpack_from("<II", body, 8)
    _, dkind, dn = struct.unpack_from("<HHI", doc, dir_at)
    assert dkind == 0x1772
    p = dir_at + 8
    while p < dir_at + 8 + dn:
        (h,) = struct.unpack_from("<I", doc, p)
        first, count = h & 0xFFFFF, h >> 20
        for k in range(count):
            table.setdefault(first + k, struct.unpack_from("<I", doc, p + 4 + 4 * k)[0])
        p += 4 + 4 * count
    if prev == 0:
        break
    at = prev

# Encrypt each persist object in place: one keystream per object, keyed
# with its persist ID, over its header and body.
for pid, off in table.items():
    n = struct.unpack_from("<I", doc, off + 4)[0]
    doc[off : off + 8 + n] = rc4(block_key(pid), bytes(doc[off : off + 8 + n]))

# CryptSession10Container: RC4 CryptoAPI header (version 4.2, fCryptoAPI).
csp = "Microsoft Enhanced Cryptographic Provider v1.0\0".encode("utf-16-le")
enc_header = struct.pack("<IIIIIIII", 0x04, 0, 0x6801, 0x8004, BITS, 1, 0, 0) + csp
verifier = rc4(block_key(0), VERIFIER + hashlib.sha1(VERIFIER).digest())
info = (
    struct.pack("<HHII", 4, 2, 0x04, len(enc_header))
    + enc_header
    + struct.pack("<I", len(SALT))
    + SALT
    + verifier[:16]
    + struct.pack("<I", 20)
    + verifier[16:]
)
# An encrypted document has exactly one UserEditAtom (MS-PPT 2.3.7): the
# deck's single edit and its directory, at the end of the stream, are
# replaced by the crypt session, a directory with every persist object
# (IDs 1 to N in one run, the crypt session last) and the new edit.
ids = sorted(table)
assert ids == list(range(1, len(ids) + 1))
old_dir = struct.unpack_from("<I", edit_body, 12)[0]
assert struct.unpack_from("<I", edit_body, 8)[0] == 0 and old_dir < first_edit
assert max(table.values()) < old_dir
del doc[old_dir:]
new_id = len(ids) + 1
crypt_at = len(doc)
doc += header(0x000F, 0x2F14, info)
dir_at = len(doc)
offsets = [table[i] for i in ids] + [crypt_at]
doc += header(0x0000, 0x1772, struct.pack(f"<I{len(offsets)}I", 1 | (len(offsets) << 20), *offsets))
edit = bytearray(edit_body[:28])
struct.pack_into("<II", edit, 8, 0, dir_at)  # offsetLastEdit, offsetPersistDirectory
struct.pack_into("<I", edit, 20, new_id)  # persistIdSeed
edit += struct.pack("<I", new_id)  # encryptSessionPersistIdRef
edit_at = len(doc)
doc += header(0x0000, 0x0FF5, bytes(edit))

# Current User: the new edit, and the "encrypted" header token.
struct.pack_into("<II", cu, 8 + 4, 0xF3D1C4DF, edit_at)

streams["PowerPoint Document"] = bytes(doc)
streams["Current User"] = bytes(cu)
tree = {}
for path, data in streams.items():
    node = tree
    parts = path.split("/")
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = data
cfbwriter.write(out, tree, root_clsid=uuid.UUID(ole.root.clsid).bytes_le)
print(out, len(doc), "persist objects:", sorted(table), "crypt session id", new_id)
