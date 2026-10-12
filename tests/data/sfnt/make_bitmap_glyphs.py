"""Writes tests/fixtures/external/sfnt/fonttools-glyf-bitmaps.ttf with
fontTools' FontBuilder: five TrueType glyphs (an empty space, two simple
outlines, a composite of both with a scale, and .notdef), horizontal and
vertical metrics (hmtx/vmtx), and the glyphs' bitmaps three ways: an sbix
strike (a PNG and a 'dupe'), a CBDT/CBLC strike (format 17 PNG, index
subtable format 1) and an EBDT/EBLC strike (format 5 bit-aligned bitmaps with
the metrics in index subtable format 2). The PNGs are 8x8 images Pillow writes.

    uv run --with fonttools==4.66.1 --with pillow==11.3.0 \\
        python3 -I make_bitmap_glyphs.py OUT
"""

import io
import sys

from fontTools.fontBuilder import FontBuilder
from fontTools.pens.ttGlyphPen import TTGlyphPen
from fontTools.ttLib import newTable
from fontTools.ttLib.tables import _g_l_y_f
from fontTools.ttLib.tables.sbixGlyph import Glyph as SbixGlyph
from fontTools.ttLib.tables.sbixStrike import Strike as SbixStrike
from PIL import Image

out = sys.argv[1]

order = [".notdef", "space", "A", "B", "C"]
fb = FontBuilder(1000, isTTF=True)
fb.setupGlyphOrder(order)
fb.setupCharacterMap({0x20: "space", 0x41: "A", 0x42: "B", 0x43: "C"})


def outline(points):
    pen = TTGlyphPen(None)
    pen.moveTo(points[0])
    for p in points[1:]:
        pen.lineTo(p)
    pen.closePath()
    return pen.glyph()


notdef = outline([(50, 0), (50, 700), (450, 700), (450, 0)])
a = outline([(0, 0), (250, 700), (500, 0)])
# B has a run of repeated on-curve flags and long coordinates.
b = outline([(0, 0), (0, 700), (300, 700), (400, 600), (400, 400), (300, 350), (0, 350)])
space = _g_l_y_f.Glyph()
glyphs = {".notdef": notdef, "space": space, "A": a, "B": b}
fb.setupGlyf(glyphs)
glyf = fb.font["glyf"]
c = _g_l_y_f.Glyph()
c.numberOfContours = -1
comp_a = _g_l_y_f.GlyphComponent()
comp_a.glyphName, comp_a.x, comp_a.y, comp_a.flags = "A", 0, 0, 0x0204
comp_b = _g_l_y_f.GlyphComponent()
comp_b.glyphName, comp_b.x, comp_b.y, comp_b.flags = "B", 600, -20, 0x0004
comp_b.transform = [[0.5, 0], [0, 0.5]]
c.components = [comp_a, comp_b]
glyf["C"] = c
glyf.glyphOrder = order
metrics = {".notdef": (500, 50), "space": (250, 0), "A": (500, 0), "B": (450, 0), "C": (800, 0)}
fb.setupHorizontalMetrics(metrics)
fb.setupHorizontalHeader(ascent=800, descent=-200)
fb.setupVerticalMetrics({g: (1000, 100) for g in order})
fb.setupVerticalHeader(ascent=500, descent=-500)
fb.setupNameTable({"familyName": "Fillyfoal Bitmaps", "styleName": "Regular"})
fb.setupOS2(sTypoAscender=800, usWinAscent=800, usWinDescent=200)
fb.setupPost()


def png(colour):
    buf = io.BytesIO()
    Image.new("RGBA", (8, 8), colour).save(buf, "PNG")
    return buf.getvalue()


png_a = png((200, 30, 30, 255))

# sbix: one 16 ppem strike; A is a PNG, B duplicates A.
sbix = newTable("sbix")
strike = SbixStrike(ppem=16, resolution=72)
strike.glyphs["A"] = SbixGlyph(glyphName="A", graphicType="png ", imageData=png_a,
                               originOffsetX=0, originOffsetY=-1)
strike.glyphs["B"] = SbixGlyph(glyphName="B", graphicType="dupe")
strike.glyphs["B"].referenceGlyphName = "A"
sbix.strikes[16] = strike
fb.font["sbix"] = sbix


def line_metrics(direction):
    names = ["ascender", "descender", "widthMax", "caretSlopeNumerator",
             "caretSlopeDenominator", "caretOffset", "minOriginSB", "minAdvanceSB",
             "maxBeforeBL", "minAfterBL", "pad1", "pad2"]
    values = [8, -2, 8, 1, 0, 0, 0, 0, 8, -2, 0, 0]
    inner = "".join(f'<{n} value="{v}"/>' for n, v in zip(names, values))
    return f'<sbitLineMetrics direction="{direction}">{inner}</sbitLineMetrics>'


def size_table(depth):
    return (
        "<bitmapSizeTable>" + line_metrics("hori") + line_metrics("vert")
        + '<colorRef value="0"/><startGlyphIndex value="2"/><endGlyphIndex value="3"/>'
        + f'<ppemX value="8"/><ppemY value="8"/><bitDepth value="{depth}"/>'
        + '<flags value="1"/></bitmapSizeTable>'
    )


small = ('<SmallGlyphMetrics><height value="8"/><width value="8"/>'
         '<BearingX value="0"/><BearingY value="8"/><Advance value="8"/></SmallGlyphMetrics>')
bitmap_a = "18 18 24 24 42 7e 81 81"
bitmap_b = "fc 82 82 fc 82 82 82 fc"
xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<ttFont sfntVersion="\\x00\\x01\\x00\\x00" ttLibVersion="4.66">
<CBDT><header version="3.0"/><strikedata index="0">
<cbdt_bitmap_format_17 name="A">{small}<rawimagedata>{png_a.hex()}</rawimagedata></cbdt_bitmap_format_17>
<cbdt_bitmap_format_17 name="B">{small}<rawimagedata>{png((30, 30, 200, 255)).hex()}</rawimagedata></cbdt_bitmap_format_17>
</strikedata></CBDT>
<CBLC><header version="3.0"/><strike index="0">{size_table(32)}
<eblc_index_sub_table_1 imageFormat="17" firstGlyphIndex="2" lastGlyphIndex="3">
<glyphLoc name="A"/><glyphLoc name="B"/></eblc_index_sub_table_1>
</strike></CBLC>
<EBDT><header version="2.0"/><strikedata index="0">
<ebdt_bitmap_format_5 name="A"><rawimagedata>{bitmap_a}</rawimagedata></ebdt_bitmap_format_5>
<ebdt_bitmap_format_5 name="B"><rawimagedata>{bitmap_b}</rawimagedata></ebdt_bitmap_format_5>
</strikedata></EBDT>
<EBLC><header version="2.0"/><strike index="0">{size_table(1)}
<eblc_index_sub_table_2 imageFormat="5" firstGlyphIndex="2" lastGlyphIndex="3"><imageSize value="8"/>
<BigGlyphMetrics><height value="8"/><width value="8"/><horiBearingX value="0"/>
<horiBearingY value="8"/><horiAdvance value="8"/><vertBearingX value="-4"/>
<vertBearingY value="0"/><vertAdvance value="8"/></BigGlyphMetrics>
<glyphLoc name="A"/><glyphLoc name="B"/></eblc_index_sub_table_2>
</strike></EBLC>
</ttFont>
"""
fb.font.importXML(io.StringIO(xml))
fb.save(out)
