"""Writes the synthetic putty-key fixtures: our own PPK writer (after
PuTTY's ppk_save_sb, from memory; PuTTYgen was not available), with real
key pairs from `cryptography` (fixed private values, so the output is
reproducible) and Argon2 from `argon2-cffi`.

    uv run --with cryptography --with argon2-cffi python tests/data/putty-key/make.py <repo root>
"""

import base64
import hashlib
import hmac
import struct
import sys
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

PASSPHRASE = b"fillyfoal"


def string(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def mpint(n: int) -> bytes:
    b = n.to_bytes((n.bit_length() + 8) // 8, "big")
    return string(b)


def lines(data: bytes) -> list[str]:
    text = base64.b64encode(data).decode()
    return [text[i : i + 64] for i in range(0, len(text), 64)]


def ed25519_key(seed: bytes):
    pk = ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key()
    raw = pk.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return "ssh-ed25519", string(b"ssh-ed25519") + string(raw), string(seed)


def ecdsa_key(d: int):
    pub = ec.derive_private_key(d, ec.SECP256R1()).public_key()
    q = pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    alg = "ecdsa-sha2-nistp256"
    return alg, string(alg.encode()) + string(b"nistp256") + string(q), mpint(d)


def ppk(version, key, comment, encrypt, argon=None):
    alg, public, private = key
    encryption = "aes256-cbc" if encrypt else "none"
    block = 16 if encrypt else 1
    padded = private
    if len(padded) % block:
        pad = block - len(padded) % block
        digest = hashlib.sha1 if version == 2 else hashlib.sha256
        padded += digest(private).digest()[:pad]
    kdf_lines = []
    if version == 2:
        if encrypt:
            k = hashlib.sha1(b"\0\0\0\0" + PASSPHRASE).digest()
            k += hashlib.sha1(b"\0\0\0\1" + PASSPHRASE).digest()
            cipher_key, iv = k[:32], bytes(16)
        mac_key = hashlib.sha1(
            b"putty-private-key-file-mac-key" + (PASSPHRASE if encrypt else b"")
        ).digest()
        mac_hash = hashlib.sha1
    else:
        mac_hash = hashlib.sha256
        if encrypt:
            memory, passes, parallel, salt = argon
            out = hash_secret_raw(
                PASSPHRASE, salt, passes, memory, parallel, 80, Type.ID
            )
            cipher_key, iv, mac_key = out[:32], out[32:48], out[48:]
            kdf_lines = [
                "Key-Derivation: Argon2id",
                f"Argon2-Memory: {memory}",
                f"Argon2-Passes: {passes}",
                f"Argon2-Parallelism: {parallel}",
                f"Argon2-Salt: {salt.hex()}",
            ]
        else:
            mac_key = b""
    mac_data = b"".join(
        string(x)
        for x in [alg.encode(), encryption.encode(), comment.encode(), public, padded]
    )
    mac = hmac.new(mac_key, mac_data, mac_hash).hexdigest()
    blob = padded
    if encrypt:
        enc = Cipher(algorithms.AES(cipher_key), modes.CBC(iv)).encryptor()
        blob = enc.update(padded) + enc.finalize()
    pub_lines, priv_lines = lines(public), lines(blob)
    out = [
        f"PuTTY-User-Key-File-{version}: {alg}",
        f"Encryption: {encryption}",
        f"Comment: {comment}",
        f"Public-Lines: {len(pub_lines)}",
        *pub_lines,
        *kdf_lines,
        f"Private-Lines: {len(priv_lines)}",
        *priv_lines,
        f"Private-MAC: {mac}",
    ]
    return "\n".join(out).encode() + b"\n"


def main():
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    out = root / "tests/fixtures/synthetic/putty-key"
    out.mkdir(parents=True, exist_ok=True)
    ed = ed25519_key(bytes(range(1, 33)))
    # A fixed scalar below the P-256 order.
    ecd = ecdsa_key(int.from_bytes(hashlib.sha256(b"fillyfoal").digest(), "big") >> 1)
    argon = (64, 1, 1, bytes(range(16)))
    files = {
        "ed25519-v2.ppk": ppk(2, ed, "v2 plain", False),
        "ed25519-v2-aes.ppk": ppk(2, ed, "v2 encrypted", True),
        "ecdsa-v3.ppk": ppk(3, ecd, "v3 plain", False),
        "ed25519-v3-argon2.ppk": ppk(3, ed, "v3 argon2", True, argon),
    }
    for name, data in files.items():
        (out / name).write_bytes(data)


main()
