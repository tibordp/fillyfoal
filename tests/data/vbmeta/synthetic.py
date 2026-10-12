"""Writes synthetic/vbmeta/vbmeta.img by hand from libavb's
`AvbVBMetaImageHeader` (avb_vbmeta_image.h): an unsigned image (algorithm
NONE, so no authentication block), rollback index 7 at location 0, and an
auxiliary block holding one property descriptor, padded to 64 bytes as
avbtool does. Every header field sits at its libavb offset (the release
string at 0x80, after the rollback index, flags and location).

    python3 -I tests/data/vbmeta/synthetic.py OUT
"""
import struct
import sys


def pad64(b):
    return b + b'\0' * ((-len(b)) % 64)


key, value = b'com.fillyfoal.build', b'test'
body = struct.pack('>QQ', len(key), len(value)) + key + b'\0' + value + b'\0'
body += b'\0' * ((-len(body)) % 8)
descriptor = struct.pack('>QQ', 0, len(body)) + body  # AVB_DESCRIPTOR_TAG_PROPERTY
aux = pad64(descriptor)

header = b'AVB0'
header += struct.pack('>II', 1, 0)  # required libavb version 1.0
header += struct.pack('>QQ', 0, len(aux))  # authentication, auxiliary block sizes
header += struct.pack('>I', 0)  # algorithm NONE
header += struct.pack('>QQQQ', 0, 0, 0, 0)  # hash, signature (none)
header += struct.pack('>QQQQ', 0, 0, 0, 0)  # public key, key metadata (none)
header += struct.pack('>QQ', 0, len(descriptor))  # descriptors
header += struct.pack('>QII', 7, 0, 0)  # rollback index, flags, rollback location
header += b'avbtool 1.2.0'.ljust(48, b'\0')
header = header.ljust(256, b'\0')
assert header.index(b'avbtool') == 0x80
with open(sys.argv[1], 'wb') as f:
    f.write(header + aux)
