"""Writes a small BitLocker (Windows 7+) volume, synthetic: no tool here
creates BitLocker volumes, so the layout follows the libbde documentation
of the format. Encrypted areas hold a byte pattern, not real ciphertext.

The volume header is a FAT32-shaped boot sector with the "-FVE-FS-"
signature, the BitLocker GUID and the offsets of three FVE metadata block
copies. Each block: block header (version 2), metadata header (AES-XTS
128), and entries: two volume master keys (password: stretch key with a
nested AES-CCM key, then the AES-CCM encrypted VMK; recovery password:
same with a description), the full volume encryption key, a description
and the location of the relocated (encrypted) original volume header.

usage: python3 bitlocker.py <out.img>
"""

import struct
import sys
import uuid

SECTOR = 512
SIZE = 40 * 1024
BLOCKS = [0x2000, 0x4000, 0x6000]
VOLUME_HEADER = 0x8000
VOLUME_HEADER_SECTORS = 8
BITLOCKER_GUID = uuid.UUID("4967d63b-2e29-4ad8-8399-f6a339e3d001").bytes_le
VOLUME_GUID = uuid.UUID("5ea7f00d-1111-4222-8333-444455556666").bytes_le
FILETIME = 133_000_000_000_000_000  # 2022-06-15


def entry(kind, value_type, data, version=1):
    return struct.pack("<HHHH", 8 + len(data), kind, value_type, version) + data


def utf16(text):
    return (text + "\0").encode("utf-16-le")


def aes_ccm(counter, length):
    # Nonce time, nonce counter, then MAC and encrypted key (a pattern).
    payload = bytes((0x40 + i) & 0xFF for i in range(16 + length))
    return struct.pack("<QI", FILETIME, counter) + payload


def vmk(key_id, protection, nested):
    data = uuid.UUID(key_id).bytes_le + struct.pack("<QHH", FILETIME, 0, protection)
    return entry(2, 8, data + b"".join(nested))


def metadata(block_at):
    stretch = entry(0, 3, struct.pack("<I", 0x1000) + bytes(range(16)) + entry(0, 5, aes_ccm(1, 44)))
    entries = [
        vmk(
            "11112222-3333-4444-5555-666677778888",
            0x2000,
            [entry(0, 2, utf16("Password")), stretch, entry(0, 5, aes_ccm(2, 44))],
        ),
        vmk(
            "99990000-aaaa-4bbb-8ccc-ddddeeeeffff",
            0x0800,
            [stretch, entry(0, 5, aes_ccm(3, 44))],
        ),
        entry(3, 5, aes_ccm(4, 44)),
        entry(7, 2, utf16("FILLYFOAL C: 10/10/2026")),
        entry(0xF, 0xF, struct.pack("<QQ", VOLUME_HEADER, VOLUME_HEADER_SECTORS * SECTOR)),
    ]
    body = b"".join(entries)
    size = 48 + len(body)
    header = struct.pack("<IIII", size, 1, 48, size) + VOLUME_GUID
    header += struct.pack("<IIQ", 5, 0x8004, FILETIME)
    block = struct.pack(
        "<8sHHHHQIIQQQQ",
        b"-FVE-FS-",
        64,
        2,
        4,
        4,
        SIZE,
        0,
        VOLUME_HEADER_SECTORS,
        BLOCKS[0],
        BLOCKS[1],
        BLOCKS[2],
        VOLUME_HEADER,
    )
    return block + header + body


def boot_sector():
    b = bytearray(SECTOR)
    b[0:3] = b"\xeb\x58\x90"
    b[3:11] = b"-FVE-FS-"
    struct.pack_into("<HBH", b, 11, SECTOR, 8, 0)
    b[21] = 0xF8
    struct.pack_into("<HHI", b, 24, 63, 255, 2048)
    struct.pack_into("<I", b, 36, 0x1FE0)
    b[64] = 0x80
    b[66] = 0x29
    struct.pack_into("<I", b, 67, 0x0F11F0A1)
    b[71:82] = b"NO NAME    "
    b[82:90] = b"FAT32   "
    b[90:96] = b"\x33\xc9\x8e\xd1\xbc\xf4"
    b[160:176] = BITLOCKER_GUID
    struct.pack_into("<QQQ", b, 176, *BLOCKS)
    b[200:206] = b"\xfa\x31\xc0\x8e\xd8\xb8"
    b[510:512] = b"\x55\xaa"
    return bytes(b)


def main():
    out = bytearray(bytes((i * 7 + 3) & 0xFF for i in range(SIZE)))
    out[0:SECTOR] = boot_sector()
    for at in BLOCKS:
        m = metadata(at)
        out[at:at + 0x2000] = m.ljust(0x2000, b"\0")
    open(sys.argv[1], "wb").write(out)


main()
