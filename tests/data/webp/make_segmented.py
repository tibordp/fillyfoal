"""Input for external/webp/segmented.webp: a 64x48 gradient, noisy on the
right, as a binary PPM (no dependencies). Then, with libwebp 1.6.0:

    python3 tests/data/webp/make_segmented.py grad.ppm
    cwebp -quiet -q 60 -segments 4 -sns 80 -f 40 -sharpness 3 grad.ppm -o segmented.webp
"""
import random
import sys

random.seed(7)
w, h = 64, 48
px = bytearray()
for y in range(h):
    for x in range(w):
        n = random.randint(0, 40) if x > 32 else 0
        px += bytes([min(255, x * 4 + n), min(255, y * 5), min(255, 128 + n * 2 if y > 24 else 60)])
with open(sys.argv[1], "wb") as f:
    f.write(b"P6\n%d %d\n255\n" % (w, h) + px)
