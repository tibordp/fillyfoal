"""Synthetic PSD fixtures for global tagged blocks:

- psd/lr16.psd: a 16-bit RGB document with two layers ("red", "green")
  written by psd-tools, then rearranged the way Photoshop stores 16-bit
  layers: the Layer Info section is emptied and its contents (without the
  length prefix, padded to 4) moved into a global `Lr16` tagged block.
- psd/unpadded-blocks.psd: a 2x2 RGB document whose global tagged blocks
  follow psd-tools' writer, which pads each block body to 4 bytes without
  counting the padding in the length: `zzz1` (5 bytes + 3 padding), an
  empty `Patt` and `abcd`. psd-tools reads all three back.

    uv run --with psd-tools==1.24.0 --with pillow==12.3.0 --with numpy==2.5.4 \\
        python3 tests/data/psd/layer_blocks.py OUTDIR

Both are synthetic: lr16.psd is a container our script rearranged around
psd-tools output, unpadded-blocks.psd is written by hand. Each is read back
with psd-tools as a check.
"""

import os
import struct
import sys

from PIL import Image
from psd_tools import PSDImage
from psd_tools.api.layers import PixelLayer

be32 = lambda v: struct.pack(">I", v)


def lr16(path):
    psd = PSDImage.new("RGB", (8, 8), depth=16)
    psd.append(PixelLayer.frompil(Image.new("RGB", (8, 8), (255, 0, 0)), psd, "red"))
    psd.append(PixelLayer.frompil(Image.new("RGB", (8, 8), (0, 255, 0)), psd, "green"))
    tmp = path + ".tmp"
    psd.save(tmp)
    with open(tmp, "rb") as f:
        d = f.read()
    os.remove(tmp)
    # Header, color mode data, image resources.
    p = 26
    p += 4 + struct.unpack(">I", d[p : p + 4])[0]
    p += 4 + struct.unpack(">I", d[p : p + 4])[0]
    lmi_at = p
    lmi_len = struct.unpack(">I", d[p : p + 4])[0]
    p += 4
    li_len = struct.unpack(">I", d[p : p + 4])[0]
    li = d[p + 4 : p + 4 + li_len]
    rest = d[p + 4 + li_len : lmi_at + 4 + lmi_len]
    mask_len = struct.unpack(">I", rest[:4])[0]
    mask = rest[: 4 + mask_len]
    li += b"\0" * ((-len(li)) % 4)
    lmi = be32(0) + mask + b"8BIMLr16" + be32(len(li)) + li
    out = d[:lmi_at] + be32(len(lmi)) + lmi + d[lmi_at + 4 + lmi_len :]
    with open(path, "wb") as f:
        f.write(out)
    psd = PSDImage.open(path)
    blocks = psd._record.layer_and_mask_information.tagged_blocks
    assert len(blocks) == 1, blocks
    assert [layer.name for layer in psd] == ["red", "green"], list(psd)


def unpadded(path):
    def block(key, data, pad=4):
        return b"8BIM" + key + be32(len(data)) + data + b"\0" * ((-len(data)) % pad)

    tb = block(b"zzz1", b"\1\2\3\4\5") + block(b"Patt", b"") + block(b"abcd", b"\0" * 4)
    lmi = be32(0) + be32(0) + tb
    hdr = b"8BPS" + struct.pack(">H6xHIIHH", 1, 3, 2, 2, 8, 3)
    body = hdr + be32(0) + be32(0) + be32(len(lmi)) + lmi + struct.pack(">H", 0) + b"\0" * 12
    with open(path, "wb") as f:
        f.write(body)
    blocks = PSDImage.open(path)._record.layer_and_mask_information.tagged_blocks
    assert len(blocks) == 3, blocks


out = sys.argv[1]
lr16(os.path.join(out, "lr16.psd"))
unpadded(os.path.join(out, "unpadded-blocks.psd"))
