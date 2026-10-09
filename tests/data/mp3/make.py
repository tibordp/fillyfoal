"""Compressed audio and tag fixtures, written by LAME, FFmpeg and mutagen.

    uv run --with mutagen==1.48.1 python tests/data/mp3/make.py

Needs `lame` (LAME 4.0) and `ffmpeg` (8.1) on the PATH. Writes, under
tests/fixtures/external/:

- mp3/lame-vbr-tags.mp3: LAME VBR (Xing + LAME tag), then mutagen adds an
  ID3v2.4 tag with most frame types (pictures, chapters, synchronised
  lyrics, ...), an APEv2 tag with cover art and an ID3v1.1 tag.
- mp3/lame-crc-v23.mp3: LAME CBR with CRC-protected frames (Info + LAME
  tag), then an ID3v2.3 tag with chapters and a picture.
- mp3/freeformat.mp3: LAME free-format bitstream.
- flac/cuesheet.flac: FFmpeg FLAC with an attached picture, then mutagen
  adds a cue sheet, a seek table, an APPLICATION block and padding.
- opus/picture.opus: FFmpeg Opus, then mutagen adds METADATA_BLOCK_PICTURE.
- aac/tone.loas: FFmpeg AAC in LOAS/LATM.
- ac3/surround.ac3, ac3/surround.eac3: FFmpeg 5.1 AC-3 (alternate bit
  stream syntax) and E-AC-3 with mixing metadata.
- dts/surround.dts: FFmpeg's (experimental) DTS encoder, 5.1.

Picture contents are 16×16 images FFmpeg draws from a test pattern.
"""

import base64
import os
import struct
import subprocess
import tempfile

from mutagen import apev2, flac, id3, oggopus

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
EXT = os.path.join(ROOT, "tests", "fixtures", "external")
TMP = tempfile.mkdtemp()
BITEXACT = ["-fflags", "+bitexact", "-flags", "+bitexact", "-map_metadata", "-1"]


def out(fmt, name):
    os.makedirs(os.path.join(EXT, fmt), exist_ok=True)
    return os.path.join(EXT, fmt, name)


def ffmpeg(*args):
    subprocess.run(["ffmpeg", "-v", "error", "-y", *args], check=True)


def sine(path, rate, seconds, channels=1):
    layout = {1: "mono", 2: "stereo", 6: "5.1"}[channels]
    ffmpeg(
        "-f", "lavfi", "-i", f"sine=frequency=440:sample_rate={rate}:duration={seconds}",
        "-af", f"aformat=channel_layouts={layout}", "-c:a", "pcm_s16le", path,
    )


def picture(name, codec):
    path = os.path.join(TMP, name)
    ffmpeg("-f", "lavfi", "-i", "testsrc=size=16x16:rate=1", "-frames:v", "1",
           *BITEXACT, "-c:v", codec, path)
    with open(path, "rb") as f:
        return f.read()


jpeg = picture("cover.jpg", "mjpeg")
png = picture("cover.png", "png")


def chapters(tag, v23=False):
    tag.add(id3.CTOC(element_id="toc", flags=id3.CTOCFlags.TOP_LEVEL | id3.CTOCFlags.ORDERED,
                     child_element_ids=["ch0", "ch1"],
                     sub_frames=[id3.TIT2(encoding=3, text=["Contents"])]))
    tag.add(id3.CHAP(element_id="ch0", start_time=0, end_time=250,
                     start_offset=0xFFFFFFFF, end_offset=0xFFFFFFFF,
                     sub_frames=[id3.TIT2(encoding=3, text=["Intro"])]))
    tag.add(id3.CHAP(element_id="ch1", start_time=250, end_time=500,
                     start_offset=0xFFFFFFFF, end_offset=0xFFFFFFFF,
                     sub_frames=[id3.TIT2(encoding=1 if v23 else 3, text=["Main part"])]))


# --- MP3, VBR, ID3v2.4 + APEv2 + ID3v1.1 ---------------------------------
wav = os.path.join(TMP, "tone16.wav")
sine(wav, 16000, 0.5)
path = out("mp3", "lame-vbr-tags.mp3")
subprocess.run(["lame", "--quiet", "-V", "6", "-m", "m", wav, path], check=True)
tag = id3.ID3()
tag.add(id3.TIT2(encoding=3, text=["Tone"]))
tag.add(id3.TPE1(encoding=3, text=["fillyfoal", "FFmpeg"]))
tag.add(id3.TALB(encoding=1, text=["Fixtures"]))
tag.add(id3.TDRC(encoding=3, text=["2019-05-01"]))
tag.add(id3.TRCK(encoding=3, text=["3/12"]))
tag.add(id3.TPOS(encoding=3, text=["1/2"]))
tag.add(id3.TCON(encoding=3, text=["17", "Synthwave"]))
tag.add(id3.TLEN(encoding=3, text=["500"]))
tag.add(id3.TXXX(encoding=3, desc="REPLAYGAIN_TRACK_GAIN", text=["-3.50 dB"]))
tag.add(id3.TIPL(encoding=3, people=[["producer", "Alice"], ["mixer", "Bob"]]))
tag.add(id3.COMM(encoding=1, lang="eng", desc="note", text=["A 440 Hz sine"]))
tag.add(id3.USLT(encoding=3, lang="eng", desc="", text="la la la\nla la"))
tag.add(id3.SYLT(encoding=3, lang="eng", format=2, type=1, desc="words",
                 text=[("la ", 0), ("la ", 120), ("la", 240)]))
tag.add(id3.ETCO(format=2, events=[(2, 0), (3, 250), (5, 500)]))
tag.add(id3.APIC(encoding=3, mime="image/jpeg", type=3, desc="front", data=jpeg))
tag.add(id3.APIC(encoding=0, mime="image/png", type=4, desc="back", data=png))
tag.add(id3.POPM(email="user@example.com", rating=196, count=7))
tag.add(id3.PCNT(count=12))
tag.add(id3.PRIV(owner="com.apple.streaming.transportStreamTimestamp",
                 data=struct.pack(">Q", 900000)))
tag.add(id3.UFID(owner="http://musicbrainz.org", data=b"8a6b0c5e-0e2b-4c4b-9e0e-4f3b1f1f1f1f"))
tag.add(id3.RVA2(desc="track", channel=1, gain=-3.5, peak=0.75))
tag.add(id3.WOAR(url="https://example.com/artist"))
tag.add(id3.WXXX(encoding=3, desc="home", url="https://example.com/"))
tag.add(id3.GEOB(encoding=3, mime="text/plain", filename="notes.txt", desc="notes",
                 data=b"hello\n"))
chapters(tag)
tag.save(path, v2_version=4, v1=2)
ape = apev2.APEv2()
ape["Artist"] = "fillyfoal"
ape["Title"] = "Tone"
ape["Album"] = "Fixtures"
ape["Year"] = "2019"
ape["Track"] = "3/12"
ape["Genre"] = ["Techno", "Synthwave"]
ape["Cover Art (Front)"] = apev2.APEValue(b"cover.jpg\x00" + jpeg, apev2.BINARY)
ape.save(path)

# --- MP3, CBR with CRC, ID3v2.3 --------------------------------------------
path = out("mp3", "lame-crc-v23.mp3")
subprocess.run(["lame", "--quiet", "-p", "-b", "32", "-m", "m", wav, path], check=True)
tag = id3.ID3()
tag.add(id3.TIT2(encoding=1, text=["Tone"]))
tag.add(id3.TPE1(encoding=0, text=["fillyfoal"]))
tag.add(id3.TALB(encoding=0, text=["Fixtures"]))
tag.add(id3.TDRC(encoding=0, text=["2019"]))
tag.add(id3.TCON(encoding=0, text=["(17)Rock"]))
tag.add(id3.TRCK(encoding=0, text=["3"]))
tag.add(id3.APIC(encoding=0, mime="image/png", type=3, desc="", data=png))
chapters(tag, v23=True)
tag.save(path, v2_version=3, v1=0)

# --- MP3, free format --------------------------------------------------------
path = out("mp3", "freeformat.mp3")
wav44 = os.path.join(TMP, "tone44.wav")
sine(wav44, 44100, 0.1, channels=2)
subprocess.run(["lame", "--quiet", "--freeformat", "-b", "400", "-t", wav44, path], check=True)

# --- FLAC with picture, cue sheet, seek table, application ----------------
path = out("flac", "cuesheet.flac")
pic = os.path.join(TMP, "cover.png")
ffmpeg("-f", "lavfi", "-i", "sine=frequency=440:sample_rate=8000:duration=0.3", "-i", pic,
       "-map", "0", "-map", "1", "-c:a", "flac", "-c:v", "copy", "-disposition:v", "attached_pic",
       "-ac", "1", *BITEXACT, "-metadata", "title=Tone", "-metadata", "artist=fillyfoal", path)
f = flac.FLAC(path)
sheet = flac.CueSheet(None)
sheet.media_catalog_number = b"1234567890123"
sheet.lead_in_samples = 88200
sheet.compact_disc = True
for number, start in ((1, 0), (2, 1176)):
    track = flac.CueSheetTrack(number, start, isrc=b"USRC17607839" if number == 1 else b"")
    track.indexes = [flac.CueSheetTrackIndex(1, 0)]
    sheet.tracks.append(track)
sheet.tracks.append(flac.CueSheetTrack(170, 2352))
f.metadata_blocks.append(sheet)
seek = flac.SeekTable(None)
seek.seekpoints = [flac.SeekPoint(0, 0, 4096), flac.SeekPoint(0xFFFFFFFFFFFFFFFF, 0, 0)]
f.metadata_blocks.append(seek)
app = flac.MetadataBlock(b"test" + b"application data")
app.code = 2
f.metadata_blocks.append(app)
f.save()

# --- Opus with a METADATA_BLOCK_PICTURE comment ----------------------------
path = out("opus", "picture.opus")
ffmpeg("-f", "lavfi", "-i", "sine=frequency=440:sample_rate=48000:duration=0.1",
       "-c:a", "libopus", "-b:a", "16k", *BITEXACT, path)
o = oggopus.OggOpus(path)
p = flac.Picture()
p.type = 3
p.mime = "image/png"
p.desc = "front"
p.width = p.height = 16
p.depth = 24
p.data = png
o["METADATA_BLOCK_PICTURE"] = [base64.b64encode(p.write()).decode("ascii")]
o["ARTIST"] = ["fillyfoal"]
o["TITLE"] = ["Tone"]
o.save()

# --- AAC in LOAS/LATM ---------------------------------------------------------
ffmpeg("-f", "lavfi", "-i", "sine=frequency=440:sample_rate=8000:duration=0.3", "-ac", "1",
       "-c:a", "aac", "-b:a", "16k", "-smc-interval", "4", *BITEXACT, "-f", "latm",
       out("aac", "tone.loas"))

# --- AC-3 and E-AC-3, 5.1 with metadata ---------------------------------------
surround = ["-f", "lavfi", "-i", "sine=frequency=440:sample_rate=48000:duration=0.1",
            "-af", "aformat=channel_layouts=5.1"]
ffmpeg(*surround, "-c:a", "ac3", "-b:a", "192k", "-dialnorm", "-24", "-mixing_level", "105",
       "-room_type", "small", "-dmix_mode", "ltrt", "-ltrt_cmixlev", "0.707",
       "-ltrt_surmixlev", "0.5", "-loro_cmixlev", "0.707", "-loro_surmixlev", "0.5",
       "-dsurex_mode", "on", "-ad_conv_type", "hdcd", "-copyright", "1", *BITEXACT,
       out("ac3", "surround.ac3"))
ffmpeg(*surround, "-c:a", "eac3", "-b:a", "192k", "-dialnorm", "-24", "-dmix_mode", "loro",
       "-ltrt_cmixlev", "0.707", "-loro_cmixlev", "0.595", "-mixing_level", "100",
       "-room_type", "large", *BITEXACT, out("ac3", "surround.eac3"))

# --- DTS, 5.1 -------------------------------------------------------------------
ffmpeg("-f", "lavfi", "-i", "sine=frequency=440:sample_rate=48000:duration=0.03",
       "-af", "aformat=channel_layouts=5.1(side)", "-c:a", "dca", "-strict", "-2",
       "-b:a", "768k", *BITEXACT, "-f", "dts", out("dts", "surround.dts"))
