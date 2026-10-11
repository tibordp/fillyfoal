"""Writes tests/fixtures/external/sfnt/fonttools-cff2-svg-dsig.otf with
fontTools' FontBuilder: a two-glyph font with CFF2 outlines, an SVG table
(one plain and one gzipped document, gzipped by fontTools) and a DSIG table whose one signature
block holds the DER PKCS#7 SignedData in SIG (made by make_cff2_svg_dsig.sh
with OpenSSL and a throwaway key).

    uv run --with fonttools==4.66.1 python3 -I make_cff2_svg_dsig.py SIG OUT
"""

import sys

from fontTools.fontBuilder import FontBuilder
from fontTools.pens.t2CharStringPen import T2CharStringPen
from fontTools.ttLib import newTable
from fontTools.ttLib.tables.D_S_I_G_ import SignatureRecord
from fontTools.ttLib.tables.S_V_G_ import SVGDocument

sig_path, out = sys.argv[1], sys.argv[2]

glyphs = [".notdef", "A"]
fb = FontBuilder(1000, isTTF=False)
fb.setupGlyphOrder(glyphs)
fb.setupCharacterMap({0x41: "A"})


def box(width):
    pen = T2CharStringPen(None, None, CFF2=True)
    pen.moveTo((50, 0))
    pen.lineTo((50, 700))
    pen.lineTo((width - 50, 700))
    pen.lineTo((width - 50, 0))
    pen.closePath()
    return pen.getCharString()


fb.setupCFF2({".notdef": box(500), "A": box(600)})
fb.setupHorizontalMetrics({".notdef": (500, 50), "A": (600, 50)})
fb.setupHorizontalHeader(ascent=800, descent=-200)
fb.setupNameTable({"familyName": "Fillyfoal Test", "styleName": "Regular"})
fb.setupOS2(sTypoAscender=800, usWinAscent=800, usWinDescent=200)
fb.setupPost()

svg = newTable("SVG ")
doc0 = '<svg xmlns="http://www.w3.org/2000/svg"><g id="glyph0"/></svg>'
# Long enough that fontTools keeps the gzipped form (it keeps whichever is
# smaller).
rings = "".join(
    f'<rect x="{50 + 10 * i}" y="{-700 + 10 * i}" width="{500 - 20 * i}" '
    f'height="{700 - 20 * i}" fill="none" stroke="red"/>'
    for i in range(8)
)
doc1 = f'<svg xmlns="http://www.w3.org/2000/svg"><g id="glyph1">{rings}</g></svg>'
svg.docList = [SVGDocument(doc0, 0, 0, False), SVGDocument(doc1, 1, 1, True)]
fb.font["SVG "] = svg

dsig = newTable("DSIG")
dsig.ulVersion = 1
dsig.usFlag = 1
dsig.usNumSigs = 1
rec = SignatureRecord()
rec.ulFormat = 1
rec.ulOffset = 0
rec.usReserved1 = 0
rec.usReserved2 = 0
rec.pkcs7 = open(sig_path, "rb").read()
dsig.signatureRecords = [rec]
fb.font["DSIG"] = dsig

fb.save(out)
