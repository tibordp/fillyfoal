"""Writes tests/fixtures/synthetic/xls/biff5.xls: an Excel 5.0/95
workbook (a BIFF5 "Book" stream in a compound file) with two sheets, a
defined name and formulas exercising the BIFF5 token layouts: references
with an 8-bit column and the relative flags in the row, 8-bit strings
without a flags byte, tName with 12 unused bytes, and 3-D references
(tRef3d, tArea3d) with their signed EXTERNSHEET index, 8 unused bytes and
first/last sheet indices.

No installed tool writes BIFF5 (LibreOffice only imports it), so the
records are assembled by this script following the OpenOffice.org
"Microsoft Excel File Format" documentation; LibreOffice is the oracle:

    soffice --headless -env:UserInstallation=file:///tmp/fixtures/lo-profile \\
        --convert-to fods --outdir /tmp/fixtures/biff5 biff5.xls

shows the formulas listed next to each record below.

    python3 tests/data/xls/make_biff5.py [output file]
"""

import os
import struct
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "cfb"))
import cfbwriter  # noqa: E402

out = (
    Path(sys.argv[1])
    if len(sys.argv) > 1
    else Path(__file__).parents[2] / "fixtures/synthetic/xls/biff5.xls"
)


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


def ref3d(ixals, tab, row, col, rel=True):
    """BIFF5 tRef3d data: EXTERNSHEET index (negative: this workbook),
    8 unused bytes, first and last sheet, the reference."""
    return struct.pack("<h", ixals) + bytes(8) + struct.pack("<HH", tab, tab) + ref(row, col, rel, rel)


def area3d(ixals, tab, r1, r2, c1, c2, rel=True):
    return struct.pack("<h", ixals) + bytes(8) + struct.pack("<HH", tab, tab) + area(r1, r2, c1, c2, rel)


def tint(v):
    return b"\x1e" + struct.pack("<H", v)


def func(index):
    return b"\x41" + struct.pack("<H", index)


def funcvar(argc, index):
    return b"\x42" + bytes([argc]) + struct.pack("<H", index)


STRING_RESULT = bytes([0, 0, 0, 0, 0, 0, 0xFF, 0xFF])


def formula(row, col, value, fmla):
    result = value if isinstance(value, bytes) else struct.pack("<d", value)
    return rec(0x0006, struct.pack("<HHH", row, col, 0) + result + struct.pack("<HIH", 0, 0, len(fmla)) + fmla)


def sheet_data():
    r = rec(0x0809, struct.pack("<HHHH", 0x0500, 0x0010, 0x0DBB, 0x07CC))
    r += rec(0x0200, struct.pack("<HHHHH", 0, 2, 0, 4, 0))
    r += rec(0x0203, struct.pack("<HHHd", 0, 0, 15, 2.0))
    r += rec(0x0203, struct.pack("<HHHd", 0, 1, 15, 0.5))
    # C1 = A1*Rate+SUM(A1:B1): tRefV, tNameV (index and 12 unused bytes),
    # tMul, tAreaR, tAttr sum, tAdd
    fmla = b"\x44" + ref(0, 0) + b"\x43" + struct.pack("<H", 1) + bytes(12) + b"\x05"
    fmla += b"\x25" + area(0, 0, 0, 1) + b"\x19\x10\x00\x00" + b"\x03"
    r += formula(0, 2, 3.5, fmla)
    # D1 = 'Other Sheet'!C1*2: tRef3dV to the second EXTERNSHEET entry
    fmla = b"\x5a" + ref3d(-2, 1, 0, 2) + tint(2) + b"\x05"
    r += formula(0, 3, 2.0, fmla)
    r += rec(0x0204, struct.pack("<HHH", 1, 0, 15) + s16("apple"))
    # B2 = IF(A1>1,"big","small")&A2: tAttr if/goto, 8-bit tStr, tFuncVarV IF
    small = b"\x17" + s8("small")
    big = b"\x17" + s8("big")
    fmla = b"\x44" + ref(0, 0) + tint(1) + b"\x0d"
    fmla += b"\x19\x02" + struct.pack("<H", len(big) + 4)
    fmla += big + b"\x19\x08" + struct.pack("<H", len(small) + 4 - 1)
    fmla += small + b"\x19\x08" + struct.pack("<H", 3)
    fmla += funcvar(3, 1) + b"\x44" + ref(1, 0) + b"\x08"
    r += formula(1, 1, STRING_RESULT, fmla)
    r += rec(0x0207, s16("bigapple"))
    # C2 = ROUND(PI()*$A$1,2): tFuncV PI, absolute tRefV, tFuncV ROUND
    fmla = func(19) + b"\x44" + ref(0, 0, False, False) + b"\x05" + tint(2) + func(27)
    r += formula(1, 2, 6.28, fmla)
    r += rec(0x023E, struct.pack("<HHHI", 0x06B6, 0, 0, 0))
    r += rec(0x000A)
    return r


def sheet_other():
    r = rec(0x0809, struct.pack("<HHHH", 0x0500, 0x0010, 0x0DBB, 0x07CC))
    r += rec(0x0200, struct.pack("<HHHHH", 0, 1, 0, 3, 0))
    # A1 = Data!A1+Data!B1: two tRef3dV, tAdd
    fmla = b"\x5a" + ref3d(-1, 0, 0, 0) + b"\x5a" + ref3d(-1, 0, 0, 1) + b"\x03"
    r += formula(0, 0, 2.5, fmla)
    # B1 = SUM(Data!$A$1:$B$2): tArea3dR, tFuncVarV SUM
    fmla = b"\x3b" + area3d(-1, 0, 0, 1, 0, 1, rel=False) + funcvar(1, 4)
    r += formula(0, 1, 2.5, fmla)
    # C1 = AVERAGE(A1:B1,3,-4): tAreaR, tInt, tUminus, tFuncVarV AVERAGE
    fmla = b"\x25" + area(0, 0, 0, 1) + tint(3) + tint(4) + b"\x13" + funcvar(3, 5)
    r += formula(0, 2, 1.0, fmla)
    r += rec(0x023E, struct.pack("<HHHI", 0x02B6, 0, 0, 0))
    r += rec(0x000A)
    return r


def xf(font, fmt, style):
    # BIFF5 XF: font, format, type/protection/parent, alignment, colours
    # and borders; a style XF (0xFFF5) or a cell XF with parent 0
    typ = 0xFFF5 if style else 0x0001
    return rec(0x00E0, struct.pack("<HHHHIII", font, fmt, typ, 0x0020, 0x20C0, 0, 0))


def globals_(offsets):
    r = rec(0x0809, struct.pack("<HHHH", 0x0500, 0x0005, 0x0DBB, 0x07CC))
    r += rec(0x0042, struct.pack("<H", 1252))
    r += rec(0x003D, struct.pack("<hhHHHHHHH", 0, 0, 8000, 5000, 0x38, 0, 0, 1, 600))
    for _ in range(4):
        r += rec(0x0031, struct.pack("<HHHHHBBBB", 200, 0, 0x7FFF, 400, 0, 0, 2, 0, 0) + s8("Arial"))
    r += rec(0x041E, struct.pack("<H", 0xA4) + s8("0.0%"))
    for _ in range(15):
        r += xf(0, 0, True)
    r += xf(0, 0, False)
    r += rec(0x0293, struct.pack("<HBB", 0x8000, 0, 0xFF))  # built-in "Normal"
    # EXTERNSHEET: one entry per sheet of this workbook (0x03 + sheet name)
    r += rec(0x0016, struct.pack("<H", 2))
    r += rec(0x0017, s8("\x03Data"))
    r += rec(0x0017, s8("\x03Other Sheet"))
    # Rate = Data!$B$1: flags, shortcut, name and formula lengths,
    # EXTERNSHEET and sheet indices, four description lengths, the name,
    # a tRef3dR to the first EXTERNSHEET entry
    fmla = b"\x3a" + ref3d(-1, 0, 0, 1, rel=False)
    r += rec(0x0018, struct.pack("<HBBHHHBBBB", 0, 0, 4, len(fmla), 0, 0, 0, 0, 0, 0) + b"Rate" + fmla)
    for name, at in zip(("Data", "Other Sheet"), offsets):
        r += rec(0x0085, struct.pack("<IBB", at, 0, 0) + s8(name))
    r += rec(0x000A)
    return r


sheets = [sheet_data(), sheet_other()]
head = len(globals_([0, 0]))
offsets = [head, head + len(sheets[0])]
book = globals_(offsets) + b"".join(sheets)
out.parent.mkdir(parents=True, exist_ok=True)
cfbwriter.write(str(out), {"Book": book})
