"""A BLF log written by python-can, with objects straddling containers.

    uv run --with python-can==4.6.1 python tests/data/vector-blf/make_python_can.py OUT.blf

python-can's BLFWriter cuts zlib-compressed LOG_CONTAINERs at a fixed
uncompressed size (128 KiB by default; 1000 bytes here, to keep the file
small), so CAN_MESSAGE objects (48 bytes) run on from one container into
the next. 120 frames on channel 1 with extended and standard IDs, 1 ms
apart; reading it back with can.BLFReader gives all 120.
"""

import sys

import can

out = sys.argv[1]
writer = can.BLFWriter(out)
writer.max_container_size = 1000
for i in range(120):
    writer.on_message_received(
        can.Message(
            timestamp=1_700_000_000 + i / 1000,
            arbitration_id=0x100 + i if i % 2 else 0x7F0 - i,
            is_extended_id=bool(i % 2),
            channel=0,
            data=bytes([(i + k) & 0xFF for k in range(i % 9)]),
        )
    )
writer.stop()

frames = list(can.BLFReader(out))
assert len(frames) == 120, len(frames)
