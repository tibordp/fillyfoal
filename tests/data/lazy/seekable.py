"""Writes blocks.xz, frames.zst and seekable.zst here: 32 MiB of
`(i * 7 + (i >> 12) + (i >> 20) * 29) & 255` (every MiB different) as an xz
stream of 32 one-MiB blocks (`xz -T4 --block-size=1MiB`, XZ Utils 5.8.4),
as 32 one-MiB zstd frames recording their content size (`zstd -19
--no-check`, 1.5.7), and as those frames with a seek table (the seekable
format, no checksums), for the seeded decoding tests in
`tests/session_control.rs`:

    python3 tests/data/lazy/seekable.py
"""

import os
import struct
import subprocess
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
N = 32 << 20
MIB = 1 << 20

data = bytes((i * 7 + (i >> 12) + (i >> 20) * 29) & 255 for i in range(N))


def run(cmd, data):
    return subprocess.run(cmd, input=data, capture_output=True, check=True).stdout


def frame(chunk):
    # From a file, so the frame records its content size.
    with tempfile.NamedTemporaryFile() as f:
        f.write(chunk)
        f.flush()
        return subprocess.run(["zstd", "-q", "-c", "-19", "--no-check", f.name], capture_output=True, check=True).stdout


frames = [frame(data[at : at + MIB]) for at in range(0, N, MIB)]
table = b"".join(struct.pack("<II", len(f), MIB) for f in frames)
footer = struct.pack("<IBI", len(frames), 0, 0x8F92EAB1)
seek = struct.pack("<II", 0x184D2A5E, len(table) + len(footer)) + table + footer
outputs = {
    "frames.zst": b"".join(frames),
    "seekable.zst": b"".join(frames) + seek,
    "blocks.xz": run(["xz", "-T4", "--block-size=1MiB", "-c"], data),
}
for name, out in outputs.items():
    with open(os.path.join(HERE, name), "wb") as f:
        f.write(out)
