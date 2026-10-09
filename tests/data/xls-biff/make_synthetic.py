"""Writes the Excel 2.x-4.0 worksheets in tests/fixtures/synthetic/xls-biff/:
biff2.xls, biff3.xls and biff4.xls, one per BIFF version, each with fonts,
number formats, XF records, a defined name, row and column records, cells of
every kind and formulas exercising the version-specific token layouts
(8-bit function indices before BIFF4, 8-bit tAttr data in BIFF2, the
BIFF2-5 cell reference form with its relative flags in the row).

No tool here writes BIFF2-4, so the records are assembled by this script
following the OpenOffice.org "Microsoft Excel File Format" documentation;
LibreOffice (which imports them) is the oracle:

    soffice --headless -env:UserInstallation=file:///tmp/fixtures/lo-profile \\
        --convert-to fods --outdir /tmp/fixtures/followups-biff biff2.xls

shows the formulas listed next to each record below.

    python3 tests/data/xls-biff/make_synthetic.py [output directory]
"""

import struct
import sys
from pathlib import Path

out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parents[2] / "fixtures/synthetic/xls-biff"


def rec(kind, body=b""):
    return struct.pack("<HH", kind, len(body)) + body


def s8(text):
    raw = text.encode("latin-1")
    return bytes([len(raw)]) + raw


def s16(text):
    raw = text.encode("latin-1")
    return struct.pack("<H", len(raw)) + raw


def ref(row, col, rel_row=True, rel_col=True):
    """BIFF2-5 cell reference: 14-bit row with the relative flags, 8-bit column."""
    return struct.pack("<HB", row | (0x8000 if rel_row else 0) | (0x4000 if rel_col else 0), col)


def area(r1, r2, c1, c2, rel=True):
    flags = 0xC000 if rel else 0
    return struct.pack("<HHBB", r1 | flags, r2 | flags, c1, c2)


ATTR = b"\x00\x00\x00"  # BIFF2 cell attributes: XF 0, format 0, font 0


def biff2():
    r = rec(0x0009, struct.pack("<HH", 0x0002, 0x0010))
    r += rec(0x0042, struct.pack("<H", 1252))
    r += rec(0x0031, struct.pack("<HH", 200, 0x0001) + s8("Arial"))  # 10 pt, bold
    r += rec(0x0045, struct.pack("<H", 0x7FFF))
    r += rec(0x001F, struct.pack("<H", 2))
    r += rec(0x001E, s8("General"))
    r += rec(0x001E, s8("0.00"))
    r += rec(0x0043, bytes([0, 0, 0x40, 0x00]))  # font 0, format 0, locked
    r += rec(0x0043, bytes([0, 0, 0x41, 0x0A]))  # format 1, locked; centred, left border
    # Total = $B$1:$B$2 (flags, a byte LibreOffice skips, shortcut, name
    # and formula lengths)
    r += rec(0x0018, bytes([0, 0, 0, 5, 7]) + b"Total" + b"\x25" + area(0, 1, 1, 1, rel=False))
    r += rec(0x0000, struct.pack("<HHHH", 0, 4, 0, 3))
    r += rec(0x0024, struct.pack("<BBH", 0, 0, 12 * 256))
    r += rec(0x0025, struct.pack("<H", 255))
    r += rec(0x0008, struct.pack("<HHHHHBH", 0, 0, 3, 255, 0, 0, 0))
    r += rec(0x0004, struct.pack("<HH", 0, 0) + ATTR + s8("Widgets"))
    r += rec(0x0002, struct.pack("<HH", 0, 1) + ATTR + struct.pack("<H", 12))
    r += rec(0x0005, struct.pack("<HH", 0, 2) + ATTR + bytes([1, 0]))  # TRUE
    r += rec(0x0004, struct.pack("<HH", 1, 0) + ATTR + s8("Gadgets"))
    r += rec(0x0003, struct.pack("<HH", 1, 1) + bytes([1, 0x41, 0]) + struct.pack("<d", 3.25))
    r += rec(0x0005, struct.pack("<HH", 1, 2) + ATTR + bytes([0x07, 1]))  # #DIV/0!
    r += rec(0x0001, struct.pack("<HH", 2, 0) + ATTR)
    # B3 = SUM(B1:B2)*2: tAreaV, tAttr sum (8-bit data), tInt, tMul
    fmla = b"\x45" + area(0, 1, 1, 1) + b"\x19\x10\x00" + b"\x1e" + struct.pack("<H", 2) + b"\x05"
    r += rec(0x0006, struct.pack("<HH", 2, 1) + ATTR + struct.pack("<d", 30.5) + bytes([0, len(fmla)]) + fmla)
    # C3 = ROUND(B2,1): tRefV, tInt, tFuncV with an 8-bit index (27)
    fmla = b"\x44" + ref(1, 1) + b"\x1e" + struct.pack("<H", 1) + b"\x41" + bytes([27])
    r += rec(0x0006, struct.pack("<HH", 2, 2) + ATTR + struct.pack("<d", 3.3) + bytes([0, len(fmla)]) + fmla)
    # A4 = A1&"!": a string result, then STRING with an 8-bit length
    fmla = b"\x44" + ref(0, 0) + b"\x17" + s8("!") + b"\x08"
    result = bytes([0, 0, 0, 0, 0, 0, 0xFF, 0xFF])
    r += rec(0x0006, struct.pack("<HH", 3, 0) + ATTR + result + bytes([0, len(fmla)]) + fmla)
    r += rec(0x0007, s8("Widgets!"))
    r += rec(0x003D, struct.pack("<hhHHB", 0, 0, 8000, 5000, 0))
    r += rec(0x003E, bytes([0, 1, 1, 0, 1]) + struct.pack("<HH", 0, 0) + bytes([1]) + struct.pack("<I", 0))
    r += rec(0x000A)
    return r


def biff3():
    r = rec(0x0209, struct.pack("<HHH", 0, 0x0010, 0))
    r += rec(0x0042, struct.pack("<H", 1252))
    r += rec(0x0231, struct.pack("<HHH", 240, 0x0002, 0x7FFF) + s8("Times New Roman"))  # 12 pt italic
    r += rec(0x001E, s8("General"))
    r += rec(0x001E, s8("#,##0"))
    # font 0, format 1, locked, used attributes: number format and font;
    # right-aligned, parent XF 0; solid pattern; no borders
    r += rec(0x0243, struct.pack("<BBBBHHI", 0, 1, 0x01, 0x0C, 0x0003, 0x0001 | (8 << 6) | (9 << 11), 0))
    r += rec(0x0293, struct.pack("<HBB", 0x8000, 0, 0xFF))  # built-in "Normal"
    r += rec(0x0218, struct.pack("<HBBH", 0, 0, 4, 3) + b"Rate" + b"\x1e" + struct.pack("<H", 7))
    r += rec(0x0200, struct.pack("<HHHHH", 0, 3, 0, 3, 0))
    r += rec(0x0208, struct.pack("<HHHHHHHH", 0, 0, 3, 300, 0, 0, 0x0100, 0x0000))
    r += rec(0x0204, struct.pack("<HHH", 0, 0, 0) + s16("Rate"))
    r += rec(0x027E, struct.pack("<HHHI", 0, 1, 0, (7 << 2) | 2))  # RK integer 7
    r += rec(0x0205, struct.pack("<HHHBB", 0, 2, 0, 0, 0))  # FALSE
    r += rec(0x0203, struct.pack("<HHHd", 1, 1, 0, 1.5))
    r += rec(0x0201, struct.pack("<HHH", 1, 2, 0))
    # A2 = Rate*B2: tNameV (BIFF3-4: index and 8 unused bytes), tRefV, tMul
    fmla = b"\x43" + struct.pack("<H", 1) + bytes(8) + b"\x44" + ref(1, 1) + b"\x05"
    r += rec(0x0206, struct.pack("<HHHdHH", 1, 0, 0, 10.5, 0, len(fmla)) + fmla)
    # C1 = ABS(-$B$2): tRefV absolute, tUminus, tFuncV with an 8-bit index (24)
    fmla = b"\x44" + ref(1, 1, False, False) + b"\x13" + b"\x41" + bytes([24])
    r += rec(0x0206, struct.pack("<HHHdHH", 2, 2, 0, 1.5, 0, len(fmla)) + fmla)
    r += rec(0x003D, struct.pack("<hhHHB", 0, 0, 8000, 5000, 0))
    r += rec(0x023E, struct.pack("<HHHI", 0x00B6, 0, 0, 0))
    r += rec(0x000A)
    return r


def biff4():
    r = rec(0x0409, struct.pack("<HHH", 0, 0x0010, 0))
    r += rec(0x0042, struct.pack("<H", 1252))
    r += rec(0x0231, struct.pack("<HHH", 200, 0, 0x7FFF) + s8("Courier New"))
    r += rec(0x041E, struct.pack("<H", 0) + s8("General"))
    r += rec(0x041E, struct.pack("<H", 0) + s8("0.0%"))
    # font 0, format 1, locked cell XF with parent 0; centred, wrapped,
    # bottom; used: number format; no fill; no borders
    r += rec(0x0443, struct.pack("<BBHBBHI", 0, 1, 0x0001, 0x02 | 0x08 | (2 << 4), 0x04, 0, 0))
    r += rec(0x0293, struct.pack("<HBB", 0x8000, 0, 0xFF))
    r += rec(0x0099, struct.pack("<H", 8))
    r += rec(0x007D, struct.pack("<HHHHHH", 0, 1, 14 * 256, 0, 0, 0))
    # Print_Area (built-in name code 6) = $A$1:$C$3
    r += rec(0x0218, struct.pack("<HBBH", 0x0020, 0, 1, 7) + b"\x06" + b"\x25" + area(0, 2, 0, 2, rel=False))
    r += rec(0x0200, struct.pack("<HHHHH", 0, 3, 0, 3, 0))
    r += rec(0x0204, struct.pack("<HHH", 0, 0, 0) + s16("Share"))
    r += rec(0x0203, struct.pack("<HHHd", 0, 1, 0, 0.25))
    r += rec(0x027E, struct.pack("<HHHI", 1, 1, 0, (75 << 2) | 3))  # RK 0.75 (75 / 100)
    # B3 = SUM(B1:B2): tAreaR, tFuncVarV with argument count and a 16-bit index (4)
    fmla = b"\x25" + area(0, 1, 1, 1) + b"\x42" + bytes([1]) + struct.pack("<H", 4)
    r += rec(0x0406, struct.pack("<HHHdHH", 2, 1, 0, 1.0, 0, len(fmla)) + fmla)
    # C1 = IF(B1>0.5,"big","small"): tAttr if/goto with 16-bit data, tFuncVar IF
    small = b"\x17" + s8("small")
    big = b"\x17" + s8("big")
    fmla = b"\x44" + ref(0, 1) + b"\x1f" + struct.pack("<d", 0.5) + b"\x0d"
    fmla += b"\x19\x02" + struct.pack("<H", len(big) + 4)
    fmla += big + b"\x19\x08" + struct.pack("<H", len(small) + 4 - 1)
    fmla += small + b"\x19\x08" + struct.pack("<H", 3)
    fmla += b"\x42" + bytes([3]) + struct.pack("<H", 1)
    result = bytes([0, 0, 0, 0, 0, 0, 0xFF, 0xFF])
    r += rec(0x0406, struct.pack("<HHH", 0, 2, 0) + result + struct.pack("<HH", 0, len(fmla)) + fmla)
    r += rec(0x0207, s16("small"))
    r += rec(0x003D, struct.pack("<hhHHB", 0, 0, 8000, 5000, 0))
    r += rec(0x023E, struct.pack("<HHHI", 0x02B6, 0, 0, 0))
    r += rec(0x000A)
    return r


def fix_book4(path):
    """BOOK4.XLS's FORMULA record had the BIFF5 layout (a 4-byte calculation
    chain field BIFF3-4 do not have): drop it."""
    data = bytearray(path.read_bytes())
    at = data.find(b"\x06\x04\x19\x00")
    if at < 0:
        return
    body = data[at + 4 : at + 4 + 0x19]
    fixed = body[:16] + body[20:]
    data[at : at + 4 + 0x19] = struct.pack("<HH", 0x0406, len(fixed)) + fixed
    path.write_bytes(bytes(data))


out.mkdir(parents=True, exist_ok=True)
(out / "biff2.xls").write_bytes(biff2())
(out / "biff3.xls").write_bytes(biff3())
(out / "biff4.xls").write_bytes(biff4())
if len(sys.argv) <= 1:
    fix_book4(out / "BOOK4.XLS")
