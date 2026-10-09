"""An ADIF stream assembled from FFmpeg's ADTS frames.

    python3 tests/data/aac/make_adif.py

Reads tests/fixtures/external/aac/tone.aac (AAC LC, 8 kHz, mono, ADTS),
drops the ADTS headers and writes the raw data blocks after a hand-made
ADIF header (variable rate, one program config element with one single
channel element and a comment) to tests/fixtures/synthetic/aac/tone.adif.
"""

import os

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.abspath(os.path.join(HERE, "..", "..", "fixtures"))


class Bits:
    def __init__(self):
        self.bits = []

    def put(self, value, n):
        self.bits += [(value >> (n - 1 - i)) & 1 for i in range(n)]

    def align(self):
        while len(self.bits) % 8:
            self.bits.append(0)

    def bytes(self):
        self.align()
        return bytes(
            int("".join(map(str, self.bits[i : i + 8])), 2) for i in range(0, len(self.bits), 8)
        )


with open(os.path.join(FIX, "external", "aac", "tone.aac"), "rb") as f:
    adts = f.read()
raw = b""
pos = 0
while pos + 7 <= len(adts):
    h = adts[pos : pos + 7]
    length = ((h[3] & 3) << 11) | (h[4] << 3) | (h[5] >> 5)
    header = 7 if h[1] & 1 else 9
    raw += adts[pos + header : pos + length]
    pos += length

b = Bits()
for c in b"ADIF":
    b.put(c, 8)
b.put(0, 1)  # copyright_id_present
b.put(0, 1)  # original_copy
b.put(0, 1)  # home
b.put(1, 1)  # bitstream_type: variable rate
b.put(16000, 23)  # bitrate (peak)
b.put(0, 4)  # num_program_config_elements - 1
# program_config_element()
b.put(0, 4)  # element_instance_tag
b.put(1, 2)  # object_type: LC
b.put(11, 4)  # sampling_frequency_index: 8000 Hz
b.put(1, 4)  # num_front_channel_elements
b.put(0, 4)  # num_side_channel_elements
b.put(0, 4)  # num_back_channel_elements
b.put(0, 2)  # num_lfe_channel_elements
b.put(0, 3)  # num_assoc_data_elements
b.put(0, 4)  # num_valid_cc_elements
b.put(0, 1)  # mono_mixdown_present
b.put(0, 1)  # stereo_mixdown_present
b.put(0, 1)  # matrix_mixdown_idx_present
b.put(0, 1)  # front_element_is_cpe
b.put(0, 4)  # front_element_tag_select
b.align()
comment = b"tone"
b.put(len(comment), 8)
for c in comment:
    b.put(c, 8)
os.makedirs(os.path.join(FIX, "synthetic", "aac"), exist_ok=True)
with open(os.path.join(FIX, "synthetic", "aac", "tone.adif"), "wb") as f:
    f.write(b.bytes() + raw)
