"""Raw AC-3 and DTS streams with an ID3v2.3 tag before them and an ID3v1
tag after them, as taggers write them: FFmpeg encodes the audio and
mutagen adds the tags.

    uv run --with mutagen==1.47.0 python3 tests/data/ac3/tagged.py OUTDIR

writes OUTDIR/ac3/id3v2.ac3 and OUTDIR/dts/id3v2.dts (build them in a
neutral directory, then copy them to tests/fixtures/external/).
"""

import os
import subprocess
import sys

from mutagen.id3 import ID3, TIT2, TPE1

BITEXACT = ["-fflags", "+bitexact", "-flags:a", "+bitexact"]


def ffmpeg(*args):
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", *args], check=True)


def tag(path):
    tags = ID3()
    tags.add(TIT2(encoding=3, text="Tone"))
    tags.add(TPE1(encoding=3, text="fillyfoal"))
    tags.save(path, v1=2, v2_version=3, padding=lambda info: 0)


def main():
    out = sys.argv[1]
    os.makedirs(os.path.join(out, "ac3"), exist_ok=True)
    os.makedirs(os.path.join(out, "dts"), exist_ok=True)
    ac3 = os.path.join(out, "ac3", "id3v2.ac3")
    ffmpeg("-f", "lavfi", "-i", "sine=frequency=440:sample_rate=32000:duration=0.1",
           "-ac", "1", "-b:a", "32k", *BITEXACT, "-f", "ac3", ac3)
    tag(ac3)
    dts = os.path.join(out, "dts", "id3v2.dts")
    ffmpeg("-f", "lavfi", "-i", "sine=frequency=440:sample_rate=48000:duration=0.01",
           "-af", "aformat=channel_layouts=5.1(side)", "-c:a", "dca", "-strict", "-2",
           "-b:a", "768k", *BITEXACT, "-f", "dts", dts)
    tag(dts)


if __name__ == "__main__":
    main()
