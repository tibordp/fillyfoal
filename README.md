# fillyfoal

A collection of file format dissectors for every file format under the sun 
(probably - if your favourite file format is not in, file an issue with a 
few examples and I'll do my best).

**Status: just horsing around.** fillyfoal is for curiosity: seeing what is inside
a file and how its format is put together and it is not meant for anything
that depends on getting every detail right. Some dissectors are incomplete and 
some are plain wrong. The philosophy is that something is better than nothing.

Point it at a file and you get a tree of fields, each with the bytes it came
from, instead of a wall of hex. Expand a node to look deeper; nothing gets
read or decoded until you do.

## What's in the box

About 400 kLOC of Rust. It takes a while to compile. You've been warned.
The workspace splits it into a core (`crates/core`, with the codecs in
`crates/codec`) and one crate per category of formats (`crates/av`,
`crates/exec`, ...). The `fillyfoal` crate at the root pulls them together;
each category is a feature, all on by default, so it's still the only
dependency you need, from a path or straight from git.

About 1,500 formats so far: executables, archives, disk images and
filesystems, audio and video, images, documents, databases, game assets,
ROMs, scientific data, logs, and a long tail of random ones you've probably
never heard of.

A few things it tries to do well:

- **It never does I/O itself.** You hand it bytes when it asks for them, so
  it fits anywhere: sync, async, a file, a network stream. There's a
  blocking adapter in `sync` if you just want to read a file.
- **It's lazy.** Unexpanded nodes cost nothing, and long lists (a zip with
  100,000 entries) come in pages.
- **Every field knows where it lives.** Spans point back into the file, even
  through decompression and fragmented data.
- **Broken files are fine.** Truncated or mangled input still shows whatever
  made sense, with notes on where things went wrong.
- **It goes all the way down.** A PNG inside a zip inside a disk image is
  found and dissected like any other file.
- **Safe Rust, no dependencies,** and built to survive hostile input: no
  panics, bounded memory and work.

## Trying it

The quickest way is in the browser, at
[tibordp.github.io/fillyfoal](https://tibordp.github.io/fillyfoal/): fillyfoal
compiled to WebAssembly, running entirely on your machine (see `web/`).

fillyfoal would rather trot around interactively: it is designed to sit under a 
UI, doing just enough work when you expand a node to show what is inside. For a
quick look without one, `examples/inspect.rs` expands the tree to a given depth
and dumps it as text. Each field ends with its byte range, as offset+length. 

Here's the header of a Game Boy cartridge:

```
$ cargo run --example inspect -- test.gb --depth 2
▾ test.gb — "FILLYFOAL", MBC3+RAM+BATTERY  [0x0+0x400]
    Interrupt vectors and RST  [0x0+0x100]
  ▾ Cartridge header  [0x100+0x50]
      Entry point: 00 c3 50 01  |..P.|  [0x100+0x4]
      Nintendo logo: ce ed 66 66 cc 0d 00 0b 03 73 00 83 00 0c 00 0d …  |..ff.....s......|  [0x104+0x30]
      Title: "FILLYFOAL"  [0x134+0xf]
      CGB flag: DMG only (0x0)  [0x143+0x1]
      New licensee code: "01"  [0x144+0x2]
      SGB flag: No SGB functions (0x0)  [0x146+0x1]
      Cartridge type: MBC3+RAM+BATTERY (0x13)  [0x147+0x1]
      ROM size: 0 — 32 KiB  [0x148+0x1]
      RAM size: 8 KiB (0x2)  [0x149+0x1]
      Destination: Overseas (0x1)  [0x14a+0x1]
      Old licensee code: 0x33  [0x14b+0x1]
      Mask ROM version: 0  [0x14c+0x1]
      Header checksum: 0x9b  [0x14d+0x1]
      Global checksum: 0x0  [0x14e+0x2]
    Program  [0x150+0x2b0]
```

`cargo run --example formats` lists everything it recognises. `DESIGN.md`
explains how it's put together, and `docs/DISSECTORS.md` covers writing a
new dissector.

## License

Copyright (C) 2026 Tibor Djurica Potpara

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version. See [COPYING](COPYING).

Parts are derived from or credit other works under GPL-compatible licenses;
their notices are in [THIRD-PARTY.md](THIRD-PARTY.md).
