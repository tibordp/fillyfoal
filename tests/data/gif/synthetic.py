"""Synthetic GIF fixture with the application extensions no tool at hand
writes together: NETSCAPE2.0 with both a loop-count and a buffering-size
sub-block, ANIMEXTS1.0, and an XMP packet stored the Adobe way (raw bytes
followed by the 258-byte "magic trailer"), then two interlaced frames, the
second with a local color table and "restore to previous" disposal.

    python3 tests/data/gif/synthetic.py

Written from the GIF89a specification, the XMP specification (part 3,
"GIF") and the Netscape looping extension as documented by its users.
"""

import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "..", "fixtures", "synthetic", "gif", "xmp-netscape.gif")

XMP = (
    b'<?xpacket begin="\xef\xbb\xbf" id="W5M0MpCehiHzreSzNTczkc9d"?>'
    b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
    b'<rdf:Description rdf:about="" xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmp:CreatorTool="fillyfoal"/>'
    b'</rdf:RDF></x:xmpmeta><?xpacket end="r"?>'
)

# LZW data for a 2x2 image of index 0 with a minimum code size of 2: clear (4),
# 0, 0, 0 (3-bit codes), 0, end (5) (4-bit codes: the table reached 8 entries),
# packed least significant bit first.
LZW = bytes([0x02, 0x03, 0x04, 0x00, 0x05, 0x00])


def app(identifier, data_blocks):
    out = b"\x21\xff\x0b" + identifier
    for b in data_blocks:
        out += bytes([len(b)]) + b
    return out + b"\x00"


def gce(flags, delay, transparent):
    return b"\x21\xf9\x04" + struct.pack("<BHB", flags, delay, transparent) + b"\x00"


def image(flags, table=b""):
    return b"\x2c" + struct.pack("<HHHHB", 0, 0, 2, 2, flags) + table + LZW


def main():
    out = b"GIF89a" + struct.pack("<HHBBB", 2, 2, 0x91, 0, 49)
    out += bytes([0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 255, 0])
    out += app(b"NETSCAPE2.0", [b"\x01\x00\x00", b"\x02" + struct.pack("<I", 65536)])
    out += app(b"ANIMEXTS1.0", [b"\x01\x03\x00"])
    trailer = b"\x01" + bytes(range(255, -1, -1))
    out += b"\x21\xff\x0bXMP DataXMP" + XMP + trailer + b"\x00"
    out += gce(0x04, 50, 0)
    out += image(0x40)
    out += gce(0x0D, 7, 1)
    out += image(0xC1, bytes([10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120]))
    out += b"\x3b"
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "wb") as f:
        f.write(out)


if __name__ == "__main__":
    main()
