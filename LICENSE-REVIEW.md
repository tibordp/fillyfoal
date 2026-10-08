# License review

Notes on fillyfoal's licensing and on modules whose provenance needed review.
This file is not part of the published crate (it is outside the `include`
list in `Cargo.toml`). Not legal advice.

## Decision (2026-10-08)

fillyfoal is relicensed from MIT OR Apache-2.0 to **GPL-3.0-or-later**, so
that it can be distributed under one license. That makes code derived from
GPL-2.0-or-later, GPL-3.0, LGPL-2.1 and LGPL-3.0 sources (DjVuLibre,
libmspack, XADMaster, PyGuitarPro) acceptable, with credit in
`THIRD-PARTY.md`.

Still to resolve, because these licenses cannot be unified under GPLv3:

- **unRAR** (freeware, GPL-incompatible): the RAR LZ/filter decoders are a
  transliteration of unRAR and are being rewritten from RARLAB's technote with
  libarchive (BSD-2-Clause) as the reference implementation.
- **AGPL-3.0** (libbgcode): the MeatPack decoder is being rewritten from Scott
  Mudge's BSD-3-Clause packer (OctoPrint-MeatPack) and the format description.
- A sweep of the rest of the library for material from GPL-incompatible
  sources and for credits owed: done, see "Library-wide sweep" below.

## Findings of the source comparison (2026-10-08)

Each flagged item was compared against the actual reference source (fetched
for the comparison only, not committed): shared numeric runs, shared
distinctive identifiers, shared comment wording, and a side-by-side reading of
the corresponding functions, separating what the format forces from what was
a free choice. Verdicts: **A** format-determined / independent expression;
**B** some borrowed expression; **C** substantially a transliteration.

| Item | Verdict | Reference license | What carries over | Remedy options |
|---|---|---|---|---|
| RAR LZ + filters (`src/codec/rar/bits.rs`, `v3.rs`, `v5.rs`, `filters.rs`) | **C** | unRAR license (freeware; derivatives must carry its §2 paragraph incl. the no-compressor clause; not open source) | Function-by-function: `MakeDecodeTables`/`DecodeNumber`, `Unpack29`, `ReadTables30`, `AddVMCode`, `Unpack5`, `ReadBlockHeader`, `ReadFilter`, standard filters incl. unRAR's guard limits and quirks; quick-bits 10/7 matches older unRAR | Rewrite from the RAR 5 technote + an independent permissive implementation (libarchive, BSD) as reference, or carry the unRAR terms (incompatible with MIT/Apache and with GPL) |
| RAR streaming driver (`rar/mod.rs`), dissector (`archive/rar.rs`) | A | — | Format facts only | — |
| PPMd var. H (`rar/ppmd.rs`) | A w.r.t. unRAR | Shkarin / 7-Zip Ppmd7: public domain | Organised like 7-Zip's Ppmd7 (not verified against its source) | Credit PPMd var. H (Shkarin) and 7-Zip Ppmd7 (Pavlov) |
| `tests/data/rar/rarenc.py` (test encoder) | not examined | — | Re-creates RAR compression; matters under unRAR §2 only if derived from unRAR | Examine before deciding |
| DjVu BZZ (`src/codec/bzz.rs`) | **B, near C** | GPL-2.0+ (DjVuLibre) | ZP decode routines (names, fence shortcut, `delay = 25`), inverse BWT (`posn` packing, fill loop — not forced), MTF/frequency update; ZP table identical (forced, needs attribution) | Rewrite decode routines from the DjVu spec / ZP paper; keep the table with attribution |
| `tests/data/djvu/bzz.py` (test encoder) | B | GPL-2.0+ | Carries DjVuLibre's per-row table comments (state counts) on 168 rows | Strip the annotations; review the encoder |
| DjVu dissector (`documents/djvu.rs`) | A | — | Format formulas; `HAS_NAME`/`HAS_TITLE` names | Optional rename |
| MeatPack (`src/codec/meatpack.rs`) | **B, near C** | AGPL-3.0 (libbgcode; itself adapted from Scott Mudge's MeatPack, partly GPL) | `receive`, signal/command loop, libbgcode's output post-processing (`put`), `G_PARAMETERS` order | Rewrite from the MeatPack description + specifications.md, deciding independently how to format output |
| Heatshrink (`src/codec/heatshrink.rs`) | A | ISC | — | — |
| bgcode layout (`engineering/fabrication.rs`) | A | spec (specifications.md) | Enum tables from the published spec | Keep the attribution |
| Quantum (`src/codec/quantum.rs`) | **B, near C** | LGPL-2.1 (libmspack) | `Coder::symbol` = `GET_SYMBOL` step by step; `Model::{new,bump,update}` = `qtmd_*`; tables in libmspack's names/layout | Rewrite from Russotto's notes |
| LZX (`src/codec/lzx.rs`) | B (minor) | LGPL-2.1 (libmspack) | `slot_tables()` loop shape; field names `block_remaining`, `header_read`; block-header step order | Literal tables cited to the spec; rename fields |
| CAB/MSZIP (`codec/cab.rs`), SZDD/KWAJ (`codec/lzh.rs`) | A | — | — | — |
| StuffIt 13 + Arsenic (`src/codec/stuffit.rs`) | **B/C** | LGPL-2.1 (XADMaster) | Arsenic: constants, model functions, block reader nearly line by line; method 13 code-length parser + loop; `META_CODES` table (forced, attribute) | Rewrite, or license compatibly |
| StuffIt LZAH (method 5) | B | Okumura's `lzhuf.c` (freely redistributable) | lzhuf's names and 4 comments verbatim | Credit Okumura |
| StuffIt 5 parser (`archive/stuffit.rs`) | A | — | Reverse-engineered layout known via XADMaster | Acknowledge |
| ACE (`src/codec/ace.rs`) | **C** | BSD-2-Clause (acefile) | Huffman quicksort/tree, sound channels, blocked driver — throughout | Attribution: acefile's copyright + license notice |
| Delphi DCU (`executable/dcu.rs`) | A | zlib-style (DCU32INT) | Packed-index encoding, magics (facts) | Optional credit |
| Guitar Pro (`audio/guitar_pro/`) | A (thin vocabulary) | LGPL-3.0 (PyGuitarPro) | Flag/enum label names (mod.rs:276–512) | Credit, or rename labels |

Not compared (no reference fetched): NSIS, Inno Setup, the LHA/ARJ/ZOO LZH
decoder, DWG, OneNote, PST, statistics codecs — their sources are specs or
permissive projects, or the agents reported no specific implementation.

## Library-wide sweep (2026-10-08)

Three read-only sweeps, each against fetched reference sources with the same
method as above: codecs and crypto; curated name tables; and mentions of other
implementations plus the GPL-incompatible lineages (Linux kernel, OpenZFS,
Apple/APSL, The Sleuth Kit, Volatility 3, VirtualBox, Ghostscript, LHa for
UNIX, unarj, zoo).

**No 4-clause BSD material.** The only BSD-lineage code (ncompress for
`unixz.rs`, OpenBSD `blowfish.c`) is public domain or 3-clause.

| Item | Reference (license) | Verdict | Action |
|---|---|---|---|
| ARJ method 4 numbers (`lzh.rs` `arj_number`) | unarj `decode.c` (non-free; field-of-use restriction) | B (thin) | **Rewritten** from the format description |
| `lzh.rs` static Huffman, `-lzs-`/`-lz5-`, ZOO LZW | LHa for UNIX, zoo `lzd.c` (both GPL-incompatible); Okumura ar002 | A for LHa/zoo; ar002 names only | Acknowledged (ar002) |
| `lzh.rs` `-lh1-` | Okumura `LZHUF.C` (free) | B | THIRD-PARTY (LZHUF entry widened) |
| `inflate.rs` Huffman construction/decoding | zlib `contrib/puff` (zlib) | B, near C | THIRD-PARTY notice; marked altered |
| `implode.rs` DCL decoder and packed tables | zlib `contrib/blast` (zlib) | B | THIRD-PARTY notice; marked altered |
| `brotli.rs` code-length prefix lookup | brotli `decode.c` (MIT) | B (minor) | Brotli entry widened |
| `lzfse.rs` FSE table builder and tables | Apple lzfse (BSD-3-Clause) | B, near C | THIRD-PARTY notice |
| `crypto/bcrypt.rs` | OpenBSD `bcrypt_pbkdf.c` (ISC), `blowfish.c` (BSD-3) | B | THIRD-PARTY notices |
| `crypto/poly1305.rs` | poly1305-donna (PD/MIT) | B | Acknowledged |
| `lzo.rs` | LZO (GPL-2.0+); Linux `lzo1x_decompress_safe.c` (GPL-2.0-only) | A/B against upstream LZO, A against Linux | Acknowledged |
| `lzma.rs`, `xz.rs` | LZMA SDK, XZ Utils (PD/0BSD) | A/B | Acknowledged |
| `zstd.rs`, `lz.rs`, `bzip2.rs`, `legacy.rs`, `unixz.rs`, `filters.rs`, `xpress.rs`, `lznt1.rs`, `statdata.rs`, `dwg.rs`, `capnp.rs`, `pbz.rs`, `wim.rs`, `psarc.rs`, `lzfu.rs`, `bcfz.rs`, `crc.rs` and the remaining crypto | specs, RFCs; references permissive | A | — |
| Filesystem dissectors (ext, btrfs, xfs, f2fs, squashfs, erofs, …) | Linux `fs/` (GPL-2.0-only) | A | — |
| `disk/udf.rs` sparing/VAT/metadata partition | Linux `fs/udf` (GPL-2.0-only) | A (different control flow; rules from UDF 2.50/2.60) | — |
| `disk/zfs.rs` | OpenZFS (CDDL) | A | — |
| `security/keychain.rs` | Apple `AppleDatabase.cpp` (APSL) | A (different record logic) | chainbreaker acknowledged |
| `disk/hfs.rs`, `disk/apfs.rs` | Apple `hfs_format.h` (APSL), APFS Reference | A | — |
| Disk/filesystem parsers vs The Sleuth Kit | CPL/IPL | A | — |
| `forensics/evidence.rs` vmss, VirtualBox `.sav`, `disk/vdi.rs` | Volatility 3 (VSL), VirtualBox (GPL-3.0-only) | A | — |
| PostScript, PDF, filters | Ghostscript (AGPL) | A | — |
| `disk/ptypes.rs` names | util-linux (public domain) | B | Acknowledged |
| Other curated tables (EXIF/maker notes, Unity class IDs, file-type and machine names, …) | ExifTool, UnityPy (MIT), specs | A or facts | — |

Not compared: PuTTY `sshpubk.c` (MIT; fetch failed), QEMU qcow2, browser
artifacts, ETL against public parsers, DuckDB/Realm/WiredTiger sources. All
are under GPL-compatible licenses, so they cannot introduce an
incompatibility.

## Initial list (before the comparison)

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
| LZH family (LHA `-lh*-`, ARJ, ZOO), SZDD/KWAJ, PSARC | `src/codec/lzh.rs`, `src/codec/psarc.rs` | Memory of the reference decoders (LHa for UNIX / ar002 lineage, libmspack for SZDD/KWAJ) | Varies (LHa for UNIX: own license; libmspack: LGPL-2.1) | Low–medium; the algorithms are widely documented (Okumura's LZHUF, ar002) | Review; cite the published algorithm descriptions |
| RAR 2.9/3.x and 5/7 decompression | `src/codec/rar/` | Memory of unrar's source; checked with libarchive | unRAR license (decoders allowed; recreating the RAR compressor forbidden) | Low: decoding is what the license permits; check no tables/code were copied verbatim | — |
| PPMd var. H (RAR, usable for 7z/ZIP) | `src/codec/rar/ppmd.rs` | Memory of 7-Zip's `Ppmd7` (checked against pyppmd) | Public domain (Igor Pavlov / Dmitry Shkarin's PPMd) | None expected | — |
| NSIS script decoding | `src/formats/archive/installer/nsis.rs` | Memory; opcode/string-code details corrected by comparing with 7-Zip's extraction | 7-Zip's NSIS handler is LGPL-2.1 (behaviour compared, not code) | Low | — |
| Inno Setup layouts | `src/formats/archive/installer/inno.rs` | Memory (innoextract lineage) | innoextract: zlib license | Low | — |
| SAS/SPSS/Stata decoders | `src/codec/statdata.rs`, `src/formats/science/stats/` | Memory of ReadStat and pandas | ReadStat: MIT; pandas: BSD-3-Clause | None (permissive) | Attribute if desired |
| DWG layouts and LZ77 | `src/formats/engineering/autocad/`, `src/codec/dwg.rs` | Memory of the ODA "Open Design Specification for .dwg files" | Published specification | Low | Cite the spec |
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
