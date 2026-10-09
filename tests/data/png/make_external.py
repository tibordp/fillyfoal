"""External PNG fixtures written by Pillow and pypng (the encoders, not us):
palette-metadata.png, interlaced-sbit.png, gray-alpha16.png, gray2-trns.png.

    uv run --with pillow==12.3.0 --with pypng==0.20220715.0 \
        python tests/data/png/make_external.py tests/fixtures/external/png
"""
import sys, os
from PIL import Image, ImageCms, PngImagePlugin
import png  # pypng
out = sys.argv[1]
os.makedirs(out, exist_ok=True)
# 1. Pillow: palette + tRNS, iCCP, pHYs, eXIf, tEXt/zTXt/iTXt incl. XMP
im = Image.new("P", (8, 6))
im.putpalette([0,0,0, 255,0,0, 0,255,0, 0,0,255])
for y in range(6):
    for x in range(8):
        im.putpixel((x, y), (x + y) % 4)
info = PngImagePlugin.PngInfo()
info.add_text("Title", "fillyfoal palette test")
info.add_text("Comment", "compressed comment " * 4, zip=True)
info.add_itxt("Description", "Grüße aus dem Test", lang="de", tkey="Beschreibung")
xmp = ('<?xpacket begin="﻿" id="W5M0MpCehiHzreSzNTczkc9d"?>'
       '<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
       '<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:format>image/png</dc:format>'
       '</rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end="w"?>')
info.add_itxt("XML:com.adobe.xmp", xmp, zip=True)
exif = Image.Exif()
exif[0x010f] = "fillyfoal"
exif[0x0110] = "Pillow test"
exif[0x0131] = "Pillow"
icc = ImageCms.ImageCmsProfile(ImageCms.createProfile("sRGB")).tobytes()
im.save(f"{out}/palette-metadata.png", pnginfo=info, transparency=bytes([0, 128, 255]), dpi=(72, 72), exif=exif, icc_profile=icc)
# 2. pypng: interlaced RGB, 5-bit (sBIT), gamma, bKGD, tRNS, pHYs, split IDATs
rows = [[(x * 4 + c * 7 + y * 3) % 32 for x in range(9) for c in range(3)] for y in range(7)]
w = png.Writer(9, 7, greyscale=False, bitdepth=5, interlace=True, gamma=0.45455,
               background=(1, 2, 3), transparent=(31, 0, 0), chunk_limit=48,
               x_pixels_per_unit=2835, y_pixels_per_unit=2835, unit_is_meter=True)
with open(f"{out}/interlaced-sbit.png", "wb") as f:
    w.write(f, rows)
# 3. pypng: 16-bit grey + alpha
rows = [[(x * 4000 + y * 900) % 65536 if c == 0 else 65535 - x * 1000 for x in range(5) for c in range(2)] for y in range(4)]
w = png.Writer(5, 4, greyscale=True, alpha=True, bitdepth=16)
with open(f"{out}/gray-alpha16.png", "wb") as f:
    w.write(f, rows)
# 4. pypng: 2-bit greyscale with tRNS and bKGD
rows = [[(x + y) % 4 for x in range(10)] for y in range(3)]
w = png.Writer(10, 3, greyscale=True, bitdepth=2, transparent=0, background=3)
with open(f"{out}/gray2-trns.png", "wb") as f:
    w.write(f, rows)
