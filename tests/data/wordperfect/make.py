"""Writes `wp51.wpd` (synthetic): a WordPerfect 5.1 prefix as libwpd reads
it (`WPXHeader::constructHeader`): magic FF 'WPC', document offset, product
type 1, file type 10 (document), major version 0 (WordPerfect 5), minor
version 1 (5.1), no encryption, then plain text.

Usage: python3 make.py OUT
"""

import struct
import sys


def main(out):
    header = b"\xffWPC" + struct.pack("<IBBBBHH", 16, 1, 10, 0, 1, 0, 0)
    with open(out, "wb") as f:
        f.write(header + b"Dear Fillyfoal,")


if __name__ == "__main__":
    main(sys.argv[1])
