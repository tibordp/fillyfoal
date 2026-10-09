"""Writes tests/fixtures/external/midi/band.mid with mido.

    uv run --with mido==1.3.3 python tests/data/midi/make.py

A format 1 file with a conductor track (tempo change, time and key
signatures, SMPTE offset, marker, sequencer-specific event), a piano track
(GM System On, controllers, notes in running status, pitch bend) and a drum
track on channel 10 (GS reset, drum kit, percussion notes).
"""

import pathlib

import mido

OUT = pathlib.Path(__file__).resolve().parents[3] / "tests/fixtures/external/midi/band.mid"

mid = mido.MidiFile(type=1, ticks_per_beat=96)

conductor = mido.MidiTrack()
conductor.append(mido.MetaMessage("track_name", name="Conductor", time=0))
conductor.append(mido.MetaMessage("smpte_offset", frame_rate=25, hours=1, minutes=0, seconds=0, frames=0, sub_frames=0, time=0))
conductor.append(mido.MetaMessage("time_signature", numerator=6, denominator=8, clocks_per_click=36, notated_32nd_notes_per_beat=8, time=0))
conductor.append(mido.MetaMessage("key_signature", key="Em", time=0))
conductor.append(mido.MetaMessage("set_tempo", tempo=500000, time=0))
conductor.append(mido.MetaMessage("marker", text="Chorus", time=192))
conductor.append(mido.MetaMessage("set_tempo", tempo=666667, time=0))
conductor.append(mido.MetaMessage("sequencer_specific", data=[0x43, 0x7B, 0x01], time=0))
conductor.append(mido.MetaMessage("end_of_track", time=192))
mid.tracks.append(conductor)

piano = mido.MidiTrack()
piano.append(mido.MetaMessage("track_name", name="Piano", time=0))
piano.append(mido.Message("sysex", data=[0x7E, 0x7F, 0x09, 0x01], time=0))
piano.append(mido.Message("program_change", channel=0, program=4, time=0))
piano.append(mido.Message("control_change", channel=0, control=7, value=100, time=0))
piano.append(mido.Message("control_change", channel=0, control=10, value=40, time=0))
piano.append(mido.Message("control_change", channel=0, control=64, value=127, time=0))
for i, note in enumerate([60, 64, 67, 72]):
    piano.append(mido.Message("note_on", channel=0, note=note, velocity=90 - i * 5, time=0 if i == 0 else 48))
piano.append(mido.Message("pitchwheel", channel=0, pitch=-2048, time=24))
piano.append(mido.Message("pitchwheel", channel=0, pitch=0, time=24))
for note in [60, 64, 67, 72]:
    piano.append(mido.Message("note_off", channel=0, note=note, velocity=64, time=0 if note != 60 else 48))
piano.append(mido.Message("control_change", channel=0, control=64, value=0, time=0))
piano.append(mido.Message("aftertouch", channel=0, value=20, time=12))
piano.append(mido.Message("polytouch", channel=0, note=60, value=10, time=0))
piano.append(mido.MetaMessage("lyrics", text="la", time=0))
piano.append(mido.MetaMessage("end_of_track", time=0))
mid.tracks.append(piano)

drums = mido.MidiTrack()
drums.append(mido.MetaMessage("track_name", name="Drums", time=0))
drums.append(mido.Message("sysex", data=[0x41, 0x10, 0x42, 0x12, 0x40, 0x00, 0x7F, 0x00, 0x41], time=0))
drums.append(mido.Message("program_change", channel=9, program=25, time=0))
for beat in range(4):
    drums.append(mido.Message("note_on", channel=9, note=36 if beat % 2 == 0 else 38, velocity=100, time=0 if beat == 0 else 72))
    drums.append(mido.Message("note_on", channel=9, note=42, velocity=80, time=0))
    drums.append(mido.Message("note_on", channel=9, note=36 if beat % 2 == 0 else 38, velocity=0, time=24))
    drums.append(mido.Message("note_on", channel=9, note=42, velocity=0, time=0))
drums.append(mido.MetaMessage("end_of_track", time=0))
mid.tracks.append(drums)

OUT.parent.mkdir(parents=True, exist_ok=True)
mid.save(OUT)
print(OUT, OUT.stat().st_size, "bytes,", round(mid.length, 3), "s")
