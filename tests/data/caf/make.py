"""A CAF file with an instrument chunk (`inst`), which neither ffmpeg nor
afconvert writes.

    python3 tests/data/caf/make.py

Writes tests/fixtures/synthetic/caf/instrument.caf: the external
caf/pcm.caf with an `inst` chunk inserted before its `data` chunk. The
chunk follows CAFInstrumentChunk in AudioToolbox's CAFFile.h (base note,
MIDI low note, high note, low velocity, high velocity, gain, start,
sustain and release region IDs, instrument ID), with distinct values so
that a swapped field shows.
"""

import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.abspath(os.path.join(HERE, "..", "..", "fixtures"))
SRC = os.path.join(FIXTURES, "external", "caf", "pcm.caf")
OUT = os.path.join(FIXTURES, "synthetic", "caf")


def chunk(kind, body):
    return kind + struct.pack(">q", len(body)) + body


def main():
    src = open(SRC, "rb").read()
    at = src.index(b"data")
    inst = struct.pack(
        ">fBBBBfIIII",
        60.25,  # base note: middle C, a quarter tone sharp
        36,  # MIDI low note
        96,  # MIDI high note
        1,  # MIDI low velocity
        127,  # MIDI high velocity
        -3.0,  # gain (dB)
        1,  # start region ID
        2,  # sustain region ID
        3,  # release region ID
        0,  # instrument ID (no name)
    )
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "instrument.caf"), "wb") as f:
        f.write(src[:at] + chunk(b"inst", inst) + src[at:])


main()
