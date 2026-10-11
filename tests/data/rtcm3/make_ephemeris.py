"""An RTCM 3 stream that starts with ephemeris messages.

    uv run --with pyrtcm==1.1.4 python tests/data/rtcm3/make_ephemeris.py OUT.rtcm3

Frames (RTCM 10403.3): 1019 GPS ephemeris for satellite 5 (DF009), 1045
Galileo F/NAV ephemeris for satellite 11 (DF252), 1020 GLONASS ephemeris
for satellite 7 (DF038), then 1005 for reference station 2003 (DF003).
Ephemeris fields other than the satellite ID are zero. Each frame is
checked by parsing it with pyrtcm, which knows the field layout.
Synthetic: the frames are built by this script.
"""

import sys

from pyrtcm import RTCMReader


def crc24q(data):
    crc = 0
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def frame(fields, total_bits):
    """fields: (value, width) pairs from the message number on."""
    acc, n = 0, 0
    for value, width in fields:
        acc = (acc << width) | (value & ((1 << width) - 1))
        n += width
    acc <<= total_bits - n
    payload_len = (total_bits + 7) // 8
    acc <<= payload_len * 8 - total_bits
    payload = acc.to_bytes(payload_len, "big")
    head = bytes([0xD3, payload_len >> 8, payload_len & 0xFF])
    body = head + payload
    return body + crc24q(body).to_bytes(3, "big")


frames = [
    frame([(1019, 12), (5, 6)], 488),
    frame([(1045, 12), (11, 6)], 496),
    frame([(1020, 12), (7, 6)], 360),
    # 1005: station 2003, ITRF 0, GPS flag, ECEF X/Y/Z of 1 m, 2 m, 3 m.
    frame(
        [
            (1005, 12),
            (2003, 12),
            (0, 6),
            (0b1000, 4),
            (10000, 38),
            (0, 2),
            (20000, 38),
            (0, 2),
            (30000, 38),
        ],
        152,
    ),
]
data = b"".join(frames)
with open(sys.argv[1], "wb") as f:
    f.write(data)

with open(sys.argv[1], "rb") as f:
    seen = [(m.identity, getattr(m, "DF009", getattr(m, "DF252", getattr(m, "DF038", getattr(m, "DF003", None))))) for _, m in RTCMReader(f)]
assert seen == [("1019", 5), ("1045", 11), ("1020", 7), ("1005", 2003)], seen
