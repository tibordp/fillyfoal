"""Writes `variable.cff2`: the CFF2 table of a one-axis variable font built
with fontTools (`uv run --with fonttools==4.66.1 python3 variable.py OUT`).

Its Top DICT has a `vstore` operator (byte 24) pointing at a variation
store with one region, and the glyph "A" blends its outline between the
default and the bold master (charstring `blend`). Font names are neutral.
"""

import sys

from fontTools.fontBuilder import FontBuilder
from fontTools.misc.psCharStrings import T2CharString
from fontTools.ttLib import TTFont


def main(out):
    fb = FontBuilder(1000, isTTF=False)
    fb.setupGlyphOrder([".notdef", "A"])
    fb.setupCharacterMap({0x41: "A"})
    fb.setupNameTable({"familyName": "Fillyfoal Test", "styleName": "Regular"})
    fb.setupFvar(axes=[("wght", 100, 400, 900, "Weight")], instances=[])
    notdef = T2CharString(program=[100, 0, "rmoveto", 400, 0, 0, 700, -400, 0, "hlineto"])
    # Each blended operand pair is (default, delta at the bold master).
    a = T2CharString(
        program=[50, 0, "rmoveto", 500, 100, 0, 0, 2, "blend", "rlineto", 0, 700, "rlineto"]
    )
    fb.setupCFF2({".notdef": notdef, "A": a}, regions=[{"wght": (0, 1, 1)}])
    fb.setupHorizontalMetrics({".notdef": (600, 100), "A": (600, 50)})
    fb.setupHorizontalHeader(ascent=800, descent=-200)
    fb.setupOS2()
    fb.setupPost()
    path = out + ".otf"
    fb.save(path)
    data = TTFont(path).getTableData("CFF2")
    with open(out, "wb") as f:
        f.write(data)


if __name__ == "__main__":
    main(sys.argv[1])
