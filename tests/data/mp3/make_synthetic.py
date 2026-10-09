"""MP3 files assembled by this script around LAME frames.

    python3 tests/data/mp3/make_synthetic.py

Needs `lame` and `ffmpeg`. Writes to tests/fixtures/synthetic/mp3/:

- junk-tags.mp3: frames with 37 bytes of junk between two of them, a
  second file's ID3v2.3 tag and frames concatenated after the first, then
  the tags that can end a file: an appended ID3v2.4 tag (with a footer),
  Lyrics3v2, an Enhanced TAG+ and an ID3v1.0 tag.
- vbri.mp3: CBR frames whose first frame was replaced by a Fraunhofer
  VBRI header (frame count, size, a two-entry seek table).
"""

import os
import struct
import subprocess
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.abspath(os.path.join(HERE, "..", "..", "fixtures", "synthetic", "mp3"))
TMP = tempfile.mkdtemp()


def syncsafe(n):
    return bytes((n >> (7 * i)) & 0x7F for i in reversed(range(4)))


def frames(path):
    """Splits a stream of MPEG-2 Layer III 32 kbps 16 kHz frames."""
    with open(path, "rb") as f:
        data = f.read()
    size = 144  # 72 * 32000 / 16000, no padding at this rate
    return [data[i : i + size] for i in range(0, len(data) - size + 1, size)]


wav = os.path.join(TMP, "tone.wav")
subprocess.run(
    ["ffmpeg", "-v", "error", "-y", "-f", "lavfi", "-i",
     "sine=frequency=440:sample_rate=16000:duration=0.4", "-ac", "1", wav],
    check=True,
)
mp3 = os.path.join(TMP, "tone.mp3")
subprocess.run(["lame", "--quiet", "-t", "-b", "32", "-m", "m", wav, mp3], check=True)
f = frames(mp3)


def tag23(title):
    body = b"TIT2" + struct.pack(">IH", len(title) + 1, 0) + b"\x00" + title
    return b"ID3\x03\x00\x00" + syncsafe(len(body)) + body


def tag24_footer(title):
    body = b"TIT2" + syncsafe(len(title) + 1) + b"\x00\x00\x03" + title
    return (b"ID3\x04\x00\x10" + syncsafe(len(body)) + body
            + b"3DI\x04\x00\x10" + syncsafe(len(body)))


def lyrics3(fields):
    body = b"LYRICSBEGIN"
    for key, value in fields:
        body += key + b"%05d" % len(value) + value
    return body + b"%06d" % len(body) + b"LYRICS200"


def fixed(text, n):
    return text.ljust(n, b"\x00")[:n]


audio = b"".join(f[:3]) + b"JUNK" * 9 + b"!" + b"".join(f[3:6])
audio += tag23(b"Second file") + b"".join(f[6:9])
tail = tag24_footer(b"Appended")
tail += lyrics3([(b"IND", b"10"), (b"LYR", b"[00:00]la la\r\n[00:01]la"), (b"ETT", b"Tone (extended)")])
tail += (b"TAG+" + fixed(b"Tone", 60) + fixed(b"fillyfoal", 60) + fixed(b"Fixtures", 60)
         + b"\x02" + fixed(b"Synthwave", 30) + b"000:00" + b"000:01")
tail += (b"TAG" + fixed(b"Tone", 30) + fixed(b"fillyfoal", 30) + fixed(b"Fixtures", 30)
         + b"2019" + fixed(b"no track number", 30) + b"\x12")
os.makedirs(OUT, exist_ok=True)
with open(os.path.join(OUT, "junk-tags.mp3"), "wb") as out:
    out.write(audio + tail)

# VBRI: the header sits 36 bytes into the first frame.
count = len(f)
toc = struct.pack(">HH", 5 * 144, (count - 6) * 144)
vbri = (b"VBRI" + struct.pack(">HHHIIHHHH", 1, 576, 75, count * 144, count - 1, 2, 1, 2, 5)
        + toc)
first = f[0][:36] + vbri
first += b"\x00" * (144 - len(first))
with open(os.path.join(OUT, "vbri.mp3"), "wb") as out:
    out.write(first + b"".join(f[1:]))
