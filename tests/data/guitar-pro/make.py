#!/usr/bin/env python3
"""Generates the Guitar Pro test fixtures.

- GP3/GP4/GP5 files are written by PyGuitarPro 0.11 (an independent
  reader/writer of the binary formats), so they go to
  tests/fixtures/external/guitar-pro/:

      uv run --with pyguitarpro==0.11 python tests/data/guitar-pro/make.py

  The song exercises measure-header features (time and key changes,
  repeats, an alternative ending, markers), a chord diagram, beat text,
  beat effects (stroke, tremolo bar, slap), mix-table changes and note
  effects (bend, grace, slide, harmonic, trill, palm mute, ties, dead
  notes), tuplets, rests, a second voice (GP5) and a drum track.

- No GPX writer is available, so the Guitar Pro 6 fixture is ours
  (tests/fixtures/synthetic/guitar-pro-6/): a BCFS image (directory entry,
  a small score.gpif and misc.xml) compressed with the small BCFZ encoder
  below (greedy matches, literal runs of up to 3 bytes), plus the same
  image uncompressed.
"""

import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, '..', '..', 'fixtures'))


def gp_song():
    import guitarpro as gp

    song = gp.Song()
    song.title = 'Fillyfoal Blues'
    song.artist = 'The Foals'
    song.album = 'Debut'
    song.words = 'Filly'
    song.music = 'Foal'
    song.copyright = '2026 nobody'
    song.tab = 'fillyfoal'
    song.instructions = 'Play it slow'
    song.notice = ['generated for tests']
    song.tempo = 96
    song.lyrics.trackChoice = 1
    song.lyrics.lines[0].startingMeasure = 1
    song.lyrics.lines[0].lyrics = 'la la la'

    headers = song.measureHeaders
    h1 = headers[0]
    h1.marker = gp.Marker('Intro', gp.Color(0, 128, 255))
    h1.isRepeatOpen = True
    for i in range(2, 5):
        h = gp.MeasureHeader(number=i)
        headers.append(h)
    h2, h3, h4 = headers[1], headers[2], headers[3]
    h2.repeatClose = 2
    h2.repeatAlternative = 1
    h3.timeSignature = gp.TimeSignature(numerator=3)
    h3.keySignature = gp.KeySignature.GMajor
    h3.marker = gp.Marker('Verse', gp.Color(255, 0, 0))
    h4.hasDoubleBar = True
    start = gp.Duration.quarterTime
    for h in headers:
        h.start = start
        start += h.length

    guitar = song.tracks[0]
    guitar.name = 'Lead'
    guitar.offset = 2  # capo
    guitar.color = gp.Color(10, 200, 30)
    guitar.channel = gp.MidiChannel(channel=0, effectChannel=1, instrument=29)
    guitar.measures = [gp.Measure(guitar, h) for h in headers]

    bass = gp.Track(song, number=2, name='Bass', fretCount=20)
    bass.strings = [gp.GuitarString(n, v) for n, v in [(1, 43), (2, 38), (3, 33), (4, 28)]]
    bass.channel = gp.MidiChannel(channel=2, effectChannel=3, instrument=33)
    bass.measures = [gp.Measure(bass, h) for h in headers]

    drums = gp.Track(song, number=3, name='Drums', isPercussionTrack=True)
    drums.strings = [gp.GuitarString(n, 0) for n in range(1, 7)]
    drums.channel = gp.MidiChannel(channel=9, effectChannel=9, instrument=0)
    drums.measures = [gp.Measure(drums, h) for h in headers]
    song.tracks = [guitar, bass, drums]

    def beat(voice, value, notes=(), **kw):
        b = gp.Beat(voice, duration=gp.Duration(value=value), status=gp.BeatStatus.normal)
        b.start = (voice.beats[-1].start + voice.beats[-1].duration.time) if voice.beats else voice.measure.start
        for string, fret, effect in notes:
            n = gp.Note(b, value=fret, string=string, type=gp.NoteType.normal)
            if effect:
                effect(n)
            b.notes.append(n)
        for k, v in kw.items():
            setattr(b, k, v)
        voice.beats.append(b)
        return b

    def bend(n):
        n.effect.bend = gp.BendEffect(type=gp.BendType.bend, value=100,
                                      points=[gp.BendPoint(0, 0), gp.BendPoint(6, 2), gp.BendPoint(12, 2)])

    def grace(n):
        n.effect.grace = gp.GraceEffect(fret=3, duration=32, transition=gp.GraceEffectTransition.hammer)

    def slide(n):
        n.effect.slides = [gp.SlideType.shiftSlideTo]

    def harmonic(n):
        n.effect.harmonic = gp.NaturalHarmonic()

    def trill(n):
        n.effect.trill = gp.TrillEffect(fret=7, duration=gp.Duration(value=16))

    def mute(n):
        n.effect.palmMute = True
        n.effect.hammer = True

    def tie(n):
        n.type = gp.NoteType.tie

    def dead(n):
        n.type = gp.NoteType.dead

    # Guitar.
    v = guitar.measures[0].voices[0]
    b = beat(v, 4, [(1, 0, None), (2, 1, None), (3, 0, None)], text='C')
    b.effect.chord = gp.Chord(6, name='C', strings=[0, 1, 0, 2, 3, -1], firstFret=1, newFormat=True,
                              root=gp.PitchClass(0), type=gp.ChordType.major)
    b.effect.stroke = gp.BeatStroke(gp.BeatStrokeDirection.down, gp.Duration.sixteenth)
    beat(v, 4, [(2, 5, bend)])
    b = beat(v, 8, [(3, 7, grace)])
    b.duration.isDotted = True
    beat(v, 16, [(3, 9, slide)])
    beat(v, 4, [(1, 12, harmonic)])
    v = guitar.measures[1].voices[0]
    b = beat(v, 8, [(2, 5, trill)])
    b.duration.tuplet = gp.Tuplet(3, 2)
    b = beat(v, 8, [(4, 2, mute)])
    b.duration.tuplet = gp.Tuplet(3, 2)
    b = beat(v, 8, [(4, 2, tie)])
    b.duration.tuplet = gp.Tuplet(3, 2)
    b = beat(v, 4, [(5, 0, dead)])
    b.effect.mixTableChange = gp.MixTableChange(tempo=gp.MixTableItem(120, 2), volume=gp.MixTableItem(100, 0),
                                                tempoName='Faster')
    b = beat(v, 2, [])
    b.status = gp.BeatStatus.rest
    v = guitar.measures[2].voices[0]
    b = beat(v, 2, [(6, 3, None)], text='verse')
    b.effect.tremoloBar = gp.BendEffect(type=gp.BendType.dip, value=-100,
                                        points=[gp.BendPoint(0, 0), gp.BendPoint(6, -2), gp.BendPoint(12, 0)])
    b = beat(v, 4, [(6, 3, None)])
    b.effect.slapEffect = gp.SlapEffect.popping
    v = guitar.measures[3].voices[0]
    beat(v, 1, [(1, 0, None), (6, 0, None)])
    # A second voice (GP5 only; GP3/GP4 write the first voice).
    v2 = guitar.measures[3].voices[1]
    beat(v2, 2, [(4, 2, None)])
    beat(v2, 2, [(4, 4, None)])

    # Bass and drums.
    for m in bass.measures:
        n = m.timeSignature.numerator
        for i in range(n):
            beat(m.voices[0], 4, [(4, (i * 2) % 5, None)])
    for m in drums.measures:
        n = m.timeSignature.numerator
        for i in range(n):
            beat(m.voices[0], 4, [(6, 36 if i % 2 == 0 else 38, None), (1, 42, None)])
    return song


def write_gp():
    import guitarpro as gp
    out = os.path.join(ROOT, 'external', 'guitar-pro')
    os.makedirs(out, exist_ok=True)
    for name, version in [('pyguitarpro.gp3', (3, 0, 0)), ('pyguitarpro.gp4', (4, 0, 6)),
                          ('pyguitarpro.gp5', (5, 1, 0)), ('pyguitarpro-500.gp5', (5, 0, 0))]:
        path = os.path.join(out, name)
        gp.write(gp_song(), path, version=version)
        # Read back with PyGuitarPro as a check.
        gp.parse(path)
        print(path, os.path.getsize(path))


# ---------------------------------------------------------------------------
# GPX


class Bits:
    def __init__(self):
        self.out = bytearray()
        self.n = 0

    def bit(self, b):
        if self.n % 8 == 0:
            self.out.append(0)
        if b:
            self.out[-1] |= 0x80 >> (self.n % 8)
        self.n += 1

    def msb(self, v, n):
        for i in reversed(range(n)):
            self.bit(v >> i & 1)

    def lsb(self, v, n):
        for i in range(n):
            self.bit(v >> i & 1)


def bcfz(data):
    w = Bits()
    pos = 0
    pending = bytearray()

    def flush():
        for i in range(0, len(pending), 3):
            chunk = pending[i:i + 3]
            w.bit(0)
            w.lsb(len(chunk), 2)
            for c in chunk:
                w.msb(c, 8)
        pending.clear()

    while pos < len(data):
        best = (0, 0)
        for off in range(1, min(pos, 0x7fff) + 1):
            length = 0
            # Copies never overlap their output.
            while length < off and pos + length < len(data) and length < 0x7fff \
                    and data[pos - off + length] == data[pos + length]:
                length += 1
            if length > best[1]:
                best = (off, length)
        off, length = best
        if length >= 4:
            flush()
            n = max(off.bit_length(), length.bit_length())
            w.bit(1)
            w.msb(n, 4)
            w.lsb(off, n)
            w.lsb(length, n)
            pos += length
        else:
            pending.append(data[pos])
            pos += 1
    flush()
    return b'BCFZ' + struct.pack('<I', len(data)) + bytes(w.out)


SCORE = b'''<?xml version="1.0" encoding="utf-8"?>
<GPIF>
<GPRevision>1</GPRevision>
<Score>
<Title><![CDATA[Fillyfoal Blues]]></Title>
<SubTitle><![CDATA[]]></SubTitle>
<Artist><![CDATA[The Foals]]></Artist>
<Album><![CDATA[Debut]]></Album>
</Score>
<MasterTrack>
<Tracks>0 1</Tracks>
<Automations>
<Automation><Type>Tempo</Type><Linear>false</Linear><Bar>0</Bar><Position>0</Position><Value>96 2</Value></Automation>
</Automations>
</MasterTrack>
<Tracks>
<Track id="0">
<Name><![CDATA[Lead]]></Name>
<Instrument ref="e-gtr6" />
<GeneralMidi table="Instrument"><Program>29</Program></GeneralMidi>
<Properties>
<Property name="Tuning"><Pitches>40 45 50 55 59 64</Pitches></Property>
<Property name="CapoFret"><Fret>2</Fret></Property>
</Properties>
</Track>
<Track id="1">
<Name><![CDATA[Bass]]></Name>
<Instrument ref="e-bass4" />
<GeneralMidi table="Instrument"><Program>33</Program></GeneralMidi>
<Properties>
<Property name="Tuning"><Pitches>28 33 38 43</Pitches></Property>
</Properties>
</Track>
</Tracks>
<MasterBars>
<MasterBar><Key><AccidentalCount>0</AccidentalCount><Mode>Major</Mode></Key><Time>4/4</Time><Repeat start="true" end="false" count="0"/><Section><Letter><![CDATA[A]]></Letter><Text><![CDATA[Intro]]></Text></Section><Bars>0 1</Bars></MasterBar>
<MasterBar><Key><AccidentalCount>0</AccidentalCount><Mode>Major</Mode></Key><Time>3/4</Time><Repeat start="false" end="true" count="2"/><Bars>2 3</Bars></MasterBar>
</MasterBars>
<Bars>
<Bar id="0"><Clef>G2</Clef><Voices>0 -1 -1 -1</Voices></Bar>
<Bar id="1"><Clef>F4</Clef><Voices>1 -1 -1 -1</Voices></Bar>
<Bar id="2"><Clef>G2</Clef><Voices>2 -1 -1 -1</Voices></Bar>
<Bar id="3"><Clef>F4</Clef><Voices>3 -1 -1 -1</Voices></Bar>
</Bars>
<Voices>
<Voice id="0"><Beats>0</Beats></Voice>
<Voice id="1"><Beats>1</Beats></Voice>
<Voice id="2"><Beats>0</Beats></Voice>
<Voice id="3"><Beats>1</Beats></Voice>
</Voices>
<Beats>
<Beat id="0"><Rhythm ref="0"/><Notes>0</Notes></Beat>
<Beat id="1"><Rhythm ref="0"/><Notes>1</Notes></Beat>
</Beats>
<Notes>
<Note id="0"><Properties><Property name="String"><String>5</String></Property><Property name="Fret"><Fret>0</Fret></Property></Properties></Note>
<Note id="1"><Properties><Property name="String"><String>3</String></Property><Property name="Fret"><Fret>3</Fret></Property></Properties></Note>
</Notes>
<Rhythms>
<Rhythm id="0"><NoteValue>Whole</NoteValue></Rhythm>
</Rhythms>
</GPIF>
'''

# Pad the score past one sector so its content takes two pieces.
SCORE = SCORE.replace(b'<GPIF>\n', b'<GPIF>\n' + b' ' * 4160 + b'\n', 1)

MISC = b'<?xml version="1.0" encoding="utf-8"?>\n<Misc><Version>1</Version></Misc>\n'


def bcfs():
    sector = 0x1000
    sectors = {}

    def entry(kind, name, size, data_sectors):
        e = struct.pack('<I', kind) + name.ljust(127, b'\0') + b'\0'
        e += struct.pack('<IIII', 0, 1, size, 0)
        e += b''.join(struct.pack('<I', s) for s in data_sectors) + b'\0\0\0\0'
        return e.ljust(sector, b'\0')

    sectors[0] = b'\0' * sector
    sectors[1] = entry(1, b'/', 20, [])
    # score.gpif spans two sectors (2 and 3 hold its entry and data).
    score_sectors = [3, 4]
    sectors[2] = entry(2, b'score.gpif', len(SCORE), score_sectors)
    padded = SCORE.ljust(sector * len(score_sectors), b'\0')
    for i, s in enumerate(score_sectors):
        sectors[s] = padded[i * sector:(i + 1) * sector]
    sectors[5] = entry(2, b'misc.xml', len(MISC), [6])
    sectors[6] = MISC.ljust(sector, b'\0')
    image = b''.join(sectors[i] for i in range(len(sectors)))
    return b'BCFS' + image


def write_gpx():
    out = os.path.join(ROOT, 'synthetic', 'guitar-pro-6')
    os.makedirs(out, exist_ok=True)
    image = bcfs()
    assert 0x1000 < len(SCORE) <= 0x2000
    with open(os.path.join(out, 'score.gpx'), 'wb') as f:
        f.write(bcfz(image))
    with open(os.path.join(out, 'uncompressed.gpx'), 'wb') as f:
        f.write(image)


if __name__ == '__main__':
    if 'gpx' in sys.argv[1:] or not sys.argv[1:]:
        write_gpx()
    if 'gp' in sys.argv[1:] or not sys.argv[1:]:
        write_gp()
