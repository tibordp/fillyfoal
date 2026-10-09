"""Writes tests/fixtures/synthetic/pe/authenticode.exe: a small x64 image
linked by lld-link (zig 0.15.2) with an Authenticode signature built here:
a PKCS #7 SignedData whose content is an SpcIndirectDataContent holding the
image's Authenticode SHA-256 digest (SpcPeImageData), signed attributes
contentType, SpcSpOpusInfo, SpcStatementType and messageDigest, an ECDSA
signature made by OpenSSL with a throwaway self-signed test certificate, and
an RFC 3161 counter-signature (SpcRfc3161Timestamp, made by `openssl ts`
with a throwaway test TSA) as an unsigned attribute. The image checksum is
then recomputed (pefile).

Synthetic: no Windows signing tool is available here, so the DER is
assembled by this script; the structures follow the Authenticode PE
specification ("Windows Authenticode Portable Executable Signature
Format") and the digest is checked against pefile's layout below.

    uv run --with pefile==2024.8.26 python3 tests/data/pe/make_authenticode.py [output directory]
"""

import hashlib
import os
import struct
import subprocess
import sys
from pathlib import Path

import pefile

out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[2] / "fixtures/synthetic/pe"
build = Path("/tmp/fixtures/followups-authenticode")
build.mkdir(parents=True, exist_ok=True)
os.chdir(build)


# --- DER ------------------------------------------------------------------
def tlv(tag, body):
    n = len(body)
    if n < 0x80:
        head = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        head = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + head + body


def seq(*items):
    return tlv(0x30, b"".join(items))


def set_of(*items):
    return tlv(0x31, b"".join(sorted(items)))


def oid(dotted):
    parts = [int(p) for p in dotted.split(".")]
    body = bytearray([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7F))
            p >>= 7
        body += bytes(reversed(chunk))
    return tlv(0x06, bytes(body))


def integer(v):
    raw = v.to_bytes((v.bit_length() + 8) // 8, "big")
    return tlv(0x02, raw)


def first(data):
    """(tag, content, rest) of the first element of `data`."""
    tag, n = data[0], data[1]
    at = 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(data[2 : 2 + k], "big")
        at += k
    return tag, data[at : at + n], data[at + n :], data[: at + n]


NULL = b"\x05\x00"
SHA256 = seq(oid("2.16.840.1.101.3.4.2.1"), NULL)
SPC_INDIRECT_DATA = "1.3.6.1.4.1.311.2.1.4"

# --- A tiny image ---------------------------------------------------------
Path("main.c").write_text(
    "__declspec(dllimport) void __stdcall ExitProcess(unsigned);\n"
    "void start(void) { ExitProcess(7); }\n"
)
Path("kernel32.def").write_text("LIBRARY kernel32.dll\nEXPORTS\n  ExitProcess\n")
subprocess.run(["zig", "cc", "-target", "x86_64-windows-gnu", "-c", "-Os", "-fno-ident", "main.c", "-o", "main.obj"], check=True)
subprocess.run(["zig", "dlltool", "-m", "i386:x86-64", "-d", "kernel32.def", "-l", "kernel32.lib"], check=True)
subprocess.run(
    ["zig", "lld-link", "/nologo", "/nodefaultlib", "/machine:x64", "/subsystem:console", "/entry:start",
     "/Brepro", "/out:image.exe", "main.obj", "kernel32.lib"],
    check=True,
)
image = bytearray(Path("image.exe").read_bytes())
image += b"\0" * (-len(image) % 8)

# --- Authenticode digest: everything but the checksum, the certificate
# table directory entry and the certificate table (appended later) ---------
pe = pefile.PE(data=bytes(image))
checksum_at = pe.OPTIONAL_HEADER.get_file_offset() + 64
dir_at = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].get_file_offset()
digest = hashlib.sha256(
    bytes(image[:checksum_at]) + bytes(image[checksum_at + 4 : dir_at]) + bytes(image[dir_at + 8 :])
).digest()

obsolete = "<<<Obsolete>>>".encode("utf-16-be")
pe_image_data = seq(
    tlv(0x03, b"\x00"),  # flags: none
    tlv(0xA0, tlv(0xA2, tlv(0x80, obsolete))),  # file: SpcLink.file, SpcString.unicode
)
indirect = seq(
    seq(oid("1.3.6.1.4.1.311.2.1.15"), pe_image_data),
    seq(SHA256, tlv(0x04, digest)),
)
_, indirect_body, _, _ = first(indirect)

# --- Certificates ---------------------------------------------------------
def openssl(*args):
    subprocess.run(["openssl", *args], check=True, capture_output=True)


openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
        "-keyout", "key.pem", "-out", "cert.pem", "-days", "3650", "-set_serial", "4097",
        "-subj", "/CN=fillyfoal test code signer", "-addext", "extendedKeyUsage=codeSigning")
openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
        "-keyout", "tsakey.pem", "-out", "tsa.pem", "-days", "3650", "-set_serial", "4098",
        "-subj", "/CN=fillyfoal test TSA", "-addext", "extendedKeyUsage=critical,timeStamping")
openssl("x509", "-in", "cert.pem", "-outform", "DER", "-out", "cert.der")
cert = Path("cert.der").read_bytes()
_, cert_body, _, _ = first(cert)
_, tbs, _, _ = first(cert_body)
_, _, rest, _ = first(tbs)  # [0] version
_, _, rest, serial = first(rest)
_, _, rest, _ = first(rest)  # signature algorithm
_, _, _, issuer = first(rest)


def attribute(kind, *values):
    return seq(oid(kind), set_of(*values))


signed_attrs = [
    attribute("1.2.840.113549.1.9.3", oid(SPC_INDIRECT_DATA)),
    attribute(
        "1.3.6.1.4.1.311.2.1.12",
        seq(
            tlv(0xA0, tlv(0x80, "fillyfoal test".encode("utf-16-be"))),
            tlv(0xA1, tlv(0x80, b"https://example.invalid/")),
        ),
    ),
    attribute("1.3.6.1.4.1.311.2.1.11", seq(oid("1.3.6.1.4.1.311.2.1.21"))),
    attribute("1.2.840.113549.1.9.4", tlv(0x04, hashlib.sha256(indirect_body).digest())),
]
to_sign = set_of(*signed_attrs)
Path("attrs.der").write_bytes(to_sign)
openssl("dgst", "-sha256", "-sign", "key.pem", "-out", "sig.bin", "attrs.der")
signature = Path("sig.bin").read_bytes()

# --- RFC 3161 counter-signature over the signature value ------------------
Path("ts.cnf").write_text(
    "[ tsa ]\ndefault_tsa = tsa1\n"
    "[ tsa1 ]\nserial = tsaserial\ncrypto_device = builtin\nsigner_cert = tsa.pem\n"
    "signer_key = tsakey.pem\nsigner_digest = sha256\ndefault_policy = 1.2.3.4.1\n"
    "digests = sha256\naccuracy = secs:1\nordering = no\ntsa_name = no\n"
    "ess_cert_id_chain = no\ness_cert_id_alg = sha256\n"
)
Path("tsaserial").write_text("01\n")
Path("sigvalue.bin").write_bytes(signature)
openssl("ts", "-query", "-data", "sigvalue.bin", "-sha256", "-no_nonce", "-cert", "-out", "q.tsq")
openssl("ts", "-reply", "-config", "ts.cnf", "-queryfile", "q.tsq", "-token_out", "-out", "token.der")
token = Path("token.der").read_bytes()

signer = seq(
    integer(1),
    seq(issuer, serial),
    SHA256,
    tlv(0xA0, first(to_sign)[1]),
    seq(oid("1.2.840.10045.4.3.2")),
    tlv(0x04, signature),
    tlv(0xA1, attribute("1.3.6.1.4.1.311.3.3.1", token)),
)
signed_data = seq(
    integer(1),
    set_of(SHA256),
    seq(oid(SPC_INDIRECT_DATA), tlv(0xA0, indirect)),
    tlv(0xA0, cert),
    set_of(signer),
)
pkcs7 = seq(oid("1.2.840.113549.1.7.2"), tlv(0xA0, signed_data))

# --- Certificate table ----------------------------------------------------
entry = struct.pack("<IHH", 8 + len(pkcs7), 0x0200, 0x0002) + pkcs7
entry += b"\0" * (-len(entry) % 8)
struct.pack_into("<II", image, dir_at, len(image), len(entry))
image += entry
pe = pefile.PE(data=bytes(image))
struct.pack_into("<I", image, checksum_at, pe.generate_checksum())
(out / "authenticode.exe").write_bytes(bytes(image))
print(len(image), digest.hex())
