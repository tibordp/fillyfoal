# Synthetic fixtures

Everything in this tree was produced by us rather than by an independent
implementation of the format:

- written byte by byte by our generator scripts or by hand, usually from
  memory of a specification (which may be incomplete or misremembered);
- hand-written text formats (JSON, XML, INI, subtitles, logs, ...);
- containers our scripts assembled around real codec output (for example an
  FFmpeg-encoded stream wrapped in a hand-made header, or a real file with a
  hand-made tag appended or its magic changed);
- files whose provenance is unclear or could not be established: when in
  doubt, a fixture is synthetic.

Their snapshots lock in the dissector's current behaviour, so changes show up
in review. They do **not** show that the dissector is correct: the fixture and
the dissector may share the same misunderstanding of the format. Treat a
synthetic snapshot as a regression test, not as conformance evidence.

Files written by real tools or libraries, or found in the wild, live in
`../external/` and are listed with their producers in
`../external/SOURCES.md`. When you can produce a sample with a real tool, put
it there instead.
