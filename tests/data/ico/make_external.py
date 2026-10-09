"""External ICO fixtures written by Pillow: pillow-png.ico (PNG images) and
pillow-bmp.ico (DIB images with AND masks).

    uv run --with pillow==12.3.0 python tests/data/ico/make_external.py tests/fixtures/external/ico
"""
import sys
from PIL import Image
out = sys.argv[1]
im = Image.new("RGBA", (48, 48))
for y in range(48):
    for x in range(48):
        im.putpixel((x, y), (x * 5, y * 5, 128, 255 if (x - 24) ** 2 + (y - 24) ** 2 < 400 else 0))
im.save(f"{out}/pillow-png.ico", sizes=[(16, 16), (32, 32), (48, 48)])
im.save(f"{out}/pillow-bmp.ico", sizes=[(16, 16), (24, 24)], bitmap_format="bmp")
for f in ["pillow-png.ico", "pillow-bmp.ico"]:
    i = Image.open(f"{out}/{f}")
    print(f, i.info.get("sizes"), [(e.width, e.height, e.bpp, e.size, e.offset) for e in i.ico.entry])
