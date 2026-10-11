"""Builds synthetic/android-boot/qcom-dt.img: a Qualcomm (CAF) style boot
image, which has `dt_size` at offset 40 (where AOSP has header_version)
and an `unused` word at 44, and the device-tree blob in its own pages
after the second stage.

It is external/android-boot/boot-v0.img (AOSP mkbootimg, page size 2048,
with a second stage) with those two words patched and the DTB of
external/android-boot/boot-v2.img appended. No CAF mkbootimg is packaged
anywhere convenient, hence synthetic.

    python3 -I tests/data/android-boot/qcom.py
"""
import os
import struct

here = os.path.dirname(os.path.abspath(__file__))
ext = os.path.join(here, '..', '..', 'fixtures', 'external', 'android-boot')
out = os.path.join(here, '..', '..', 'fixtures', 'synthetic', 'android-boot', 'qcom-dt.img')


def pages(n, page):
    return (n + page - 1) // page * page


v2 = open(os.path.join(ext, 'boot-v2.img'), 'rb').read()
assert v2[:8] == b'ANDROID!' and struct.unpack_from('<I', v2, 40)[0] == 2
k, r, s = struct.unpack_from('<I', v2, 8)[0], struct.unpack_from('<I', v2, 16)[0], struct.unpack_from('<I', v2, 24)[0]
page = struct.unpack_from('<I', v2, 36)[0]
dtbo = struct.unpack_from('<I', v2, 1632)[0]
dtb_size = struct.unpack_from('<I', v2, 1648)[0]
at = pages(1660, page) + pages(k, page) + pages(r, page) + pages(s, page) + pages(dtbo, page)
dtb = v2[at:at + dtb_size]
assert dtb[:4] == b'\xd0\x0d\xfe\xed'

v0 = bytearray(open(os.path.join(ext, 'boot-v0.img'), 'rb').read())
assert struct.unpack_from('<I', v0, 40)[0] == 0
page = struct.unpack_from('<I', v0, 36)[0]
k, r, s = (struct.unpack_from('<I', v0, o)[0] for o in (8, 16, 24))
end = pages(1632, page) + pages(k, page) + pages(r, page) + pages(s, page)
assert len(v0) == end, 'boot-v0.img has trailing data'
struct.pack_into('<II', v0, 40, len(dtb), 0)
v0 += dtb + bytes(pages(len(dtb), page) - len(dtb))
open(out, 'wb').write(v0)
print(out, len(v0), 'dt_size', len(dtb))
