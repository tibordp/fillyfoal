"""Cuts the installer data out of a makensis setup.exe: from the first
header (flags, 0xDEADBEEF, "NullsoftInst"), which the stub looks for at
512-byte boundaries, to the end of the file. Usage: cut.py SETUP.EXE OUT"""

import sys

data = open(sys.argv[1], "rb").read()
for at in range(0, len(data), 512):
    if data[at + 4 : at + 20] == b"\xef\xbe\xad\xdeNullsoftInst":
        open(sys.argv[2], "wb").write(data[at:])
        print(f"{sys.argv[1]}: installer data at {at:#x}, {len(data) - at} bytes")
        break
else:
    sys.exit(f"{sys.argv[1]}: no NSIS first header")
