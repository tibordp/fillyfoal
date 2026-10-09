"""Writes tests/fixtures/synthetic/pe/rich-signed.exe: a small x64 image
linked by lld-link (zig 0.15.2) with a DOS stub we build here that carries
a Rich header (the undocumented record MSVC's linker writes, which LLD does
not), and a certificate table appended afterwards holding a PKCS #7
SignedData made by OpenSSL with a throwaway self-signed test certificate
(not an Authenticode signature: the signed content is a placeholder, not
the image hash). The image checksum is then recomputed (pefile).

Synthetic: the Rich header's entries are invented and its checksum is
computed with the algorithm under test; the certificate is not a real
code-signing signature.

    uv run --with pefile==2024.8.26 python3 tests/data/pe/make_synthetic.py [output directory]
"""

import os
import struct
import subprocess
import sys
from pathlib import Path

import pefile

out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parents[2] / "fixtures/synthetic/pe"
build = Path("/tmp/fixtures/pe-synthetic")
build.mkdir(parents=True, exist_ok=True)
os.chdir(build)

# --- DOS stub with a Rich header -------------------------------------------
dos = bytearray(64)
struct.pack_into("<2sHHHHHHHHHHHHH", dos, 0, b"MZ", 0x90, 3, 0, 4, 0, 0xFFFF, 0, 0xB8, 0, 0, 0, 0x40, 0)
program = bytes([0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21])
program += b"This program cannot be run in DOS mode.\r\r\n$"
program += b"\0" * (-len(program) % 16)
stub = bytes(dos) + program
start = len(stub)

entries = [
    (0x0104 << 16 | 30148, 5),  # Utc1900_C, VS2019 build
    (0x0105 << 16 | 30148, 12),  # Utc1900_CPP
    (0x0103 << 16 | 30148, 2),  # Masm1400
    (0x0101 << 16 | 30148, 7),  # Implib1400
    (0x00FF << 16 | 30148, 1),  # Cvtres1400
    (0x0102 << 16 | 30148, 1),  # Linker1400
]


def rol(v, n):
    n %= 32
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


key = start
for i, b in enumerate(stub):
    if 0x3C <= i < 0x40:
        continue
    key = (key + rol(b, i)) & 0xFFFFFFFF
for comp, count in entries:
    key = (key + rol(comp, count)) & 0xFFFFFFFF

rich = struct.pack("<IIII", 0x536E6144 ^ key, key, key, key)
for comp, count in entries:
    rich += struct.pack("<II", comp ^ key, count ^ key)
rich += b"Rich" + struct.pack("<I", key)
stub += rich
stub += b"\0" * (-len(stub) % 16)
Path("stub.bin").write_bytes(stub)

# --- A tiny image ---------------------------------------------------------
Path("main.c").write_text(
    "__declspec(dllimport) void __stdcall ExitProcess(unsigned);\n"
    "void start(void) { ExitProcess(42); }\n"
)
Path("kernel32.def").write_text("LIBRARY kernel32.dll\nEXPORTS\n  ExitProcess\n")
subprocess.run(["zig", "cc", "-target", "x86_64-windows-gnu", "-c", "-Os", "-fno-ident", "main.c", "-o", "main.obj"], check=True)
subprocess.run(["zig", "dlltool", "-m", "i386:x86-64", "-d", "kernel32.def", "-l", "kernel32.lib"], check=True)
subprocess.run(
    ["zig", "lld-link", "/nologo", "/nodefaultlib", "/machine:x64", "/subsystem:console", "/entry:start",
     "/stub:stub.bin", "/Brepro", "/out:image.exe", "main.obj", "kernel32.lib"],
    check=True,
)
image = bytearray(Path("image.exe").read_bytes())
image += b"\0" * (-len(image) % 8)

# --- Certificate table ----------------------------------------------------
subprocess.run(
    ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
     "-keyout", "key.pem", "-out", "cert.pem", "-days", "3650", "-subj", "/CN=fillyfoal test signer"],
    check=True,
    capture_output=True,
)
Path("content.bin").write_bytes(b"fillyfoal: placeholder for the Authenticode digest\n")
subprocess.run(
    ["openssl", "smime", "-sign", "-binary", "-noattr", "-nodetach", "-in", "content.bin", "-signer", "cert.pem",
     "-inkey", "key.pem", "-outform", "DER", "-out", "sig.p7"],
    check=True,
)
pkcs7 = Path("sig.p7").read_bytes()
cert = struct.pack("<IHH", 8 + len(pkcs7), 0x0200, 0x0002) + pkcs7
cert += b"\0" * (-len(cert) % 8)
pe = pefile.PE(data=bytes(image))
security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
dir_at = security.get_file_offset()
struct.pack_into("<II", image, dir_at, len(image), len(cert))
image += cert
pe = pefile.PE(data=bytes(image))
struct.pack_into("<I", image, pe.OPTIONAL_HEADER.get_file_offset() + 64, pe.generate_checksum())
(out / "rich-signed.exe").write_bytes(bytes(image))
print(len(image), hex(key))
