"""Input PNGs for the external WebP fixtures, which cwebp and img2webp
(libwebp 1.6.0) write from them; see tests/fixtures/external/SOURCES.md.

    uv run --with pillow==12.3.0 python tests/data/webp/make_inputs.py <dir>
"""
import sys
from PIL import Image, ImageCms, PngImagePlugin
out = sys.argv[1]
im = Image.new("RGBA", (16, 16))
for y in range(16):
    for x in range(16):
        im.putpixel((x, y), (x * 16, y * 16, 128, 255 if x < 8 else y * 16))
info = PngImagePlugin.PngInfo()
xmp = ('<?xpacket begin="﻿" id="W5M0MpCehiHzreSzNTczkc9d"?>'
       '<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
       '<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:format>image/webp</dc:format>'
       '</rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end="w"?>')
info.add_itxt("XML:com.adobe.xmp", xmp)
exif = Image.Exif()
exif[0x010f] = "fillyfoal"
exif[0x0110] = "cwebp test"
icc = ImageCms.ImageCmsProfile(ImageCms.createProfile("sRGB")).tobytes()
im.save(f"{out}/rgba-meta.png", pnginfo=info, exif=exif, icc_profile=icc)
im.save(f"{out}/rgba.png")
for i in range(3):
    f = Image.new("RGBA", (16, 16))
    for y in range(16):
        for x in range(16):
            f.putpixel((x, y), ((x + i * 5) * 16 % 256, y * 16, 64 * i, 255 if (x + y + i) % 5 else 0))
    f.save(f"{out}/frame{i}.png")
