# License review (temporary, undecided)

Notes for a later decision about fillyfoal's license. Nothing here is
resolved; this file is not part of the published crate (it is outside the
`include` list in `Cargo.toml`). Not legal advice.

## The question

fillyfoal is licensed MIT OR Apache-2.0. Code (or protected expression)
taken from GPL/LGPL/AGPL projects cannot be included under those terms.
Most of the library was written from public specifications, real files, and
general knowledge, but some decoders were written by agents working from
memory of — or by reading — copyleft reference implementations. Facts about a
file format (layouts, field meanings, the algorithm) are not protected; the
concern is copied expression: code structure, comments, and non-trivial
tables lifted verbatim.

Options the owner is considering (no decision yet):

1. Relicense fillyfoal as GPL (the main consumer, Newt, is GPL). Simplest;
   limits adoption.
2. Keep MIT/Apache and move doubtful pieces behind an opt-in `gpl` Cargo
   feature. Whether that is legally sound needs checking: a feature only
   helps if the default build truly excludes the code and the crate as
   published says clearly which license applies with the feature on.
3. Keep MIT/Apache and split GPL-only formats/codecs into a separate crate
   (e.g. `fillyfoal-gpl`) that registers extra codecs/formats.
4. Clean up instead: re-derive doubtful parts from public specifications or
   published papers (or independent clean-room notes), document provenance
   per module, and keep everything MIT/Apache.

## Items to review

| Item | Where | Written from | License of the reference | Concern | Cheapest clean-up |
|---|---|---|---|---|---|
| DjVu ZP-coder adaptation table (256 entries) | `src/codec/bzz.rs` (DjVu branch, merging) | Agent's memory of DjVuLibre's `ZPCodec.cpp` table | GPL-2.0+ | Highest: a non-trivial data table reproduced from GPL source | Regenerate from the procedure in Bottou et al.'s Z-coder papers, or verify against the table in LizardTech's DjVu specification and cite that; or gate BZZ |
| BZZ / DjVu layouts generally | `src/codec/bzz.rs`, `src/formats/documents/djvu.rs` | Memory of DjVuLibre | GPL-2.0+ | Algorithm and layouts are facts; check the code isn't a transliteration | Review against the DjVu spec |
| MeatPack decoder | `src/codec/meatpack.rs` | Agent read libbgcode's sources; docs say it "reproduces `MeatPack::unbinarize` exactly" | AGPL-3.0 (libbgcode) | Medium: behaviour matched by reading AGPL code | Rewrite from Prusa's public `specifications.md` (MeatPack is small and fully specified there) and the original MeatPack description |
| Prusa bgcode block layout | `src/formats/engineering/fabrication.rs` | libbgcode `doc/specifications.md` + sources | AGPL-3.0 | Low: the spec document describes the format; check no code was transliterated | Note the spec as the source |
| libbgcode reference outputs | `tests/data/bgcode/*.ref.gcode` | Output of libbgcode's converter on our own G-code | (program output) | Low; test data only, not in the published crate | — |
| LZX decoder | `src/codec/lzx.rs` | "Modelled on libmspack's `lzxd.c`" (and wimlib) | LGPL-2.1 (libmspack), LGPL-3 / GPL (wimlib) | Medium: structure modelled on LGPL code; tables are derived from the format (position slots) | Re-check against the MS-PATCH/LZX specification ([MS-PATCH] / CAB LZX docs), rewrite comments citing the spec |
| Quantum decoder | `src/codec/quantum.rs` | "As described by libmspack's `qtmd.c`" | LGPL-2.1 | Medium | Re-derive from Russotto's format notes; review |
| StuffIt methods (RLE90, Huffman, LZAH, 13, Arsenic) | `src/codec/stuffit.rs`, `src/formats/archive/stuffit.rs` | Memory of The Unarchiver (XADMaster) | LGPL-2.1 | Medium | Review; StuffIt formats are otherwise undocumented, so XADMaster is the de-facto spec |
| ACE decompression | `src/codec/ace.rs`, `src/formats/archive/ace.rs` | `unace` 2.5 behaviour via `acefile` | unace: freeware/own license; acefile: check (believed BSD-2-Clause) | Low–medium: check acefile's license and that code follows the format, not acefile's code | Confirm licenses |
| LZH family (LHA/ARJ/ZOO), PSARC, SZDD/KWAJ | (agent still running) | Check its report | — | Check on merge | — |
| RAR 2.9/3.x and 5 decompression | (agent still running) | Knowledge of unRAR source | unRAR license (allows decoders; forbids recreating the RAR compressor) | Check on merge: decoding is allowed; ensure no verbatim tables/code | — |
| Guitar Pro GP3–5 layout | `src/formats/audio/guitar_pro/mod.rs` | Agent read the installed PyGuitarPro 0.11 source | LGPL-3.0 | Low: format facts; check structure isn't transliterated | Review |
| Delphi DCU layouts | `src/formats/executable/dcu.rs` | Memory of DCU32INT | (check; distributed with source) | Low: layouts are facts | Review |
| p7zip / libarchive mentions | `sevenzip.rs`, `tar.rs` | Comments referencing behaviour | LGPL (p7zip parts), BSD (libarchive) | Low: behavioural references | — |
| Brotli static dictionary | `src/codec/brotli_dictionary.bin` | Extracted from the installed libbrotlicommon | MIT (listed in THIRD-PARTY.md) | None | — |

Fixtures and test data are not shipped in the crate, but are in the
repository: several were produced by GPL/AGPL tools (program output, generally
not covered by the tool's license) — see `tests/fixtures/external/SOURCES.md`.

## When deciding

- Re-run a search for references to other implementations:
  `grep -rniE "libmspack|XADMaster|DjVuLibre|libbgcode|unrar|DCU32INT|PyGuitarPro|acefile|unace|wimlib" src`
- Add any new item from the remaining agents' reports (PST, OneNote, RAR,
  Inno/NSIS/InstallShield, LZH/ARJ/ZOO, keys, databases, science formats).
