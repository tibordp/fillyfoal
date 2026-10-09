"""External GIF fixture written by Pillow: pillow-anim.gif (NETSCAPE loop,
comment, per-frame delays and disposal, transparency, local color tables).

    uv run --with pillow==12.3.0 python tests/data/gif/make_external.py tests/fixtures/external/gif
"""
import sys, os
from PIL import Image
out = sys.argv[1]
os.makedirs(out, exist_ok=True)
frames = []
for i in range(3):
    im = Image.new("P", (32, 24))
    pal = []
    for c in range(8):
        pal += [(c * 30 + i * 70) % 256, (c * 50) % 256, (255 - c * 30 - i * 40) % 256]
    im.putpalette(pal)
    for y in range(24):
        for x in range(32):
            im.putpixel((x, y), (x // 2 + y + i) % 8)
    frames.append(im)
frames[0].save(f"{out}/pillow-anim.gif", save_all=True, append_images=frames[1:],
               duration=[100, 250, 40], loop=2, disposal=[1, 2, 1], transparency=0,
               comment=b"written by Pillow", interlace=True, optimize=False)
