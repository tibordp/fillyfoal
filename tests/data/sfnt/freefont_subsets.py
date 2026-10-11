"""External font fixtures: GNU FreeFont 20120503 subset with fontTools.

- sfnt/freeserif-subset.ttf: FreeSerif.ttf (TrueType outlines)
- sfnt/freeserif-subset.otf: FreeSerif.otf (CFF outlines)
- woff/freeserif-subset.woff: the TrueType subset as WOFF 1.0 (zlib)
- woff2/freeserif-subset.woff2: the TrueType subset as WOFF2 (Brotli,
  transformed glyf/loca as fontTools writes by default)
- ttc/freefont-subset.ttc: FreeSans and FreeSerif TrueType subsets in one
  collection, identical tables shared (fontTools TTCollection)

Each subset keeps the glyphs of TEXT plus what the default layout features
reach, and all name records (copyright, licence and its URL included).

    uv run --with fonttools==4.66.1 --with brotli==1.2.0 \\
        python3 tests/data/sfnt/freefont_subsets.py FREEFONT_DIR OUTDIR

FREEFONT_DIR holds FreeSerif.ttf, FreeSerif.otf and FreeSans.ttf of GNU
FreeFont 20120503 (here, TeX Live 2026's gnu-freefont package:
texmf-dist/fonts/{truetype,opentype}/public/gnu-freefont).

GNU FreeFont is licensed under the GNU GPL version 3 or later with the GPL
font exception; the subsets are modified versions under the same terms.
"""

import os
import sys

from fontTools import subset
from fontTools.ttLib import TTFont
from fontTools.ttLib.ttCollection import TTCollection

TEXT = "FreeFont fi fl 0123 ffi?!"


def make_subset(path):
    options = subset.Options()
    options.name_IDs = ["*"]
    options.name_languages = ["*"]
    options.notdef_outline = True
    options.recalc_timestamp = False
    font = subset.load_font(path, options)
    subsetter = subset.Subsetter(options)
    subsetter.populate(text=TEXT)
    subsetter.subset(font)
    font.recalcTimestamp = False
    return font, options


def save(font, options, path, flavor=None):
    options.flavor = flavor
    subset.save_font(font, path, options)
    options.flavor = None


src, out = sys.argv[1], sys.argv[2]
for d in ("sfnt", "woff", "woff2", "ttc"):
    os.makedirs(os.path.join(out, d), exist_ok=True)

serif, options = make_subset(os.path.join(src, "FreeSerif.ttf"))
save(serif, options, os.path.join(out, "sfnt", "freeserif-subset.ttf"))
save(serif, options, os.path.join(out, "woff", "freeserif-subset.woff"), "woff")
save(serif, options, os.path.join(out, "woff2", "freeserif-subset.woff2"), "woff2")

cff, options = make_subset(os.path.join(src, "FreeSerif.otf"))
save(cff, options, os.path.join(out, "sfnt", "freeserif-subset.otf"))

# Reload the saved subsets so the collection writer sees compiled tables.
sans, options = make_subset(os.path.join(src, "FreeSans.ttf"))
tmp = os.path.join(out, "ttc", "sans.tmp")
save(sans, options, tmp)
collection = TTCollection()
collection.fonts = [
    TTFont(tmp, recalcTimestamp=False),
    TTFont(os.path.join(out, "sfnt", "freeserif-subset.ttf"), recalcTimestamp=False),
]
collection.save(os.path.join(out, "ttc", "freefont-subset.ttc"))
os.remove(tmp)
