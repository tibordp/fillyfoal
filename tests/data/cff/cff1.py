"""Writes `fonttools.cff`: the CFF (version 1) table of a small OpenType
font built with fontTools (`uv run --with fonttools==4.66.1 python3
cff1.py OUT`).

Top DICT with version/Notice/FullName/FamilyName/Weight, FontBBox,
charset and CharStrings; a Private DICT with BlueValues, OtherBlues,
StdHW/StdVW, StemSnapH, defaultWidthX/nominalWidthX and local Subrs; three
glyphs, one calling a local subroutine. Names are neutral.
"""

import sys

from fontTools.fontBuilder import FontBuilder
from fontTools.misc.psCharStrings import T2CharString
from fontTools.ttLib import TTFont


def main(out):
    fb = FontBuilder(1000, isTTF=False)
    fb.setupGlyphOrder([".notdef", "A", "B"])
    fb.setupCharacterMap({0x41: "A", 0x42: "B"})
    fb.setupNameTable({"familyName": "Fillyfoal Test", "styleName": "Regular"})
    notdef = T2CharString(program=[500, 100, 0, "rmoveto", 400, 0, 0, 700, -400, 0, "hlineto", "endchar"])
    # "A" is drawn by local subroutine 0 (bias 107 for fewer than 1240 subrs).
    a = T2CharString(program=[50, 0, "rmoveto", -107, "callsubr", "endchar"])
    b = T2CharString(
        program=[600, 80, 0, "rmoveto", 300, 0, 100, 100, 0, 150, "rrcurveto", -400, 0, "rlineto", "endchar"]
    )
    private = {
        "BlueValues": [-12, 0, 700, 712],
        "OtherBlues": [-210, -200],
        "StdHW": 60,
        "StdVW": 80,
        "StemSnapH": [60, 64],
        "defaultWidthX": 600,
        "nominalWidthX": 500,
    }
    top = {
        "version": "1.0",
        "Notice": "Test font for fillyfoal",
        "Weight": "Regular",
        "FontBBox": [0, -200, 900, 800],
    }
    fb.setupCFF("FillyfoalTest-Regular", top, {".notdef": notdef, "A": a, "B": b}, private)
    subr = T2CharString(program=[250, 700, "rlineto", 250, -700, "rlineto", "return"])
    cff = fb.font["CFF "].cff
    td = cff.topDictIndex[0]
    from fontTools.cffLib import SubrsIndex

    subrs = SubrsIndex()
    subrs.append(subr)
    td.Private.Subrs = subrs
    for name in ("A",):
        td.CharStrings[name].private = td.Private
    td.CharStrings["A"].subrs = subrs
    fb.setupHorizontalMetrics({".notdef": (500, 100), "A": (600, 50), "B": (600, 80)})
    fb.setupHorizontalHeader(ascent=800, descent=-200)
    fb.setupOS2()
    fb.setupPost()
    path = out + ".otf"
    fb.save(path)
    data = TTFont(path).getTableData("CFF ")
    with open(out, "wb") as f:
        f.write(data)


if __name__ == "__main__":
    main(sys.argv[1])
