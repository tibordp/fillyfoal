"""Audio files with what some taggers and rippers put in front of them.

    python3 tests/data/id3/prefixed.py

Built from external fixtures (real encoder output), so the results are
synthetic:

- tests/fixtures/synthetic/{ape,musepack,tta,wavpack}/id3v2.*: the
  format's fixture with an ID3v2.3 tag (title, artist, padding) in front.
  These formats keep their own tags as APEv2 at the end, but taggers that
  only know ID3 prepend one anyway (Monkey's Audio and the WavPack, TTA
  and Musepack decoders skip it).
- tests/fixtures/synthetic/mp3/zero-padded.mp3: external
  mp3/cbr-id3v23.mp3 with its ID3v2 tag replaced by 700 zero bytes, as a
  tagger that blanks a tag in place leaves it.
"""

import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.abspath(os.path.join(HERE, "..", "..", "fixtures"))


def syncsafe(n):
    return bytes((n >> (7 * i)) & 0x7F for i in reversed(range(4)))


def text_frame(frame_id, text):
    body = b"\x00" + text.encode("latin-1")
    return frame_id + struct.pack(">I", len(body)) + b"\x00\x00" + body


def tag23(padding):
    frames = text_frame(b"TIT2", "Tone") + text_frame(b"TPE1", "fillyfoal")
    frames += b"\x00" * padding
    return b"ID3\x03\x00\x00" + syncsafe(len(frames)) + frames


def v2_len(data):
    if not data.startswith(b"ID3"):
        return 0
    size = 0
    for b in data[6:10]:
        size = (size << 7) | b
    return size + 10


def read(*path):
    with open(os.path.join(FIXTURES, *path), "rb") as f:
        return f.read()


def write(data, *path):
    out = os.path.join(FIXTURES, *path)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "wb") as f:
        f.write(data)


for src, dst in [
    (("synthetic", "ape", "tone.ape"), ("synthetic", "ape", "id3v2.ape")),
    (("synthetic", "musepack", "tone.mpc"), ("synthetic", "musepack", "id3v2.mpc")),
    (("external", "tta", "tone.tta"), ("synthetic", "tta", "id3v2.tta")),
    (("external", "wavpack", "tone.wv"), ("synthetic", "wavpack", "id3v2.wv")),
]:
    write(tag23(200) + read(*src), *dst)

mp3 = read("external", "mp3", "cbr-id3v23.mp3")
write(b"\x00" * 700 + mp3[v2_len(mp3):], "synthetic", "mp3", "zero-padded.mp3")
