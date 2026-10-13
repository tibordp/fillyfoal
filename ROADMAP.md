# Roadmap

Where fillyfoal stands and where it could go next. Written at the end of the
first phase (October 2026), when the project was put on hold. `DESIGN.md`
explains how the pieces fit; this file is about direction. Ideas here are
deliberately loose: most of them need a design pass before any code.

## Where it stands

- About 1,500 formats across eleven category crates. The tree is lazy,
  work per step is bounded and accounted for, and large inputs are read
  through checkpoints rather than all at once.
- A review audit covering every area, followed by fixes for all the
  verified findings, real-tool fixtures from Windows and Linux VMs, and
  fuzz-style truncation and mutation sweeps. The lessons are written up in
  `DESIGN.md` ("Findings from the review audit") and turned into rules in
  `docs/DISSECTORS.md`.
- One consumer so far: a file manager's viewer, for human eyes.

## How it gets built

fillyfoal is, and will stay, heavily AI-assisted. That changes what limits
progress, and so how this roadmap should be read:

- **Writing dissectors is cheap; trusting them is not.** Agents can add a
  format in an hour. What took the time was checking them against files
  that real tools wrote. Synthetic fixtures only prove the code agrees with
  itself; the audit's bugs were found with real files.
- **Fixtures that need the physical world are the bottleneck:** Windows-only
  writers, kernel modules, commercial software, hardware, licences.
- **Maintainer judgement is the scarcest resource.** Provenance, privacy,
  licensing and scope calls can't be delegated. Work should be shaped so
  those decisions arrive batched, with a recommendation attached.
- **Tooling has to hold up under parallel agents:** isolated build
  directories per worktree, no line-based merging of code, tests that never
  depend on wall-clock time.

So timelines are in days and waves rather than quarters, and the items that
matter most are the ones that scale trust, not code.

## Directions

### Machine-readable access: a visitor / query API

The tree is built for people: names are labels, summaries are prose. Other
programs want the same structure: a file manager that mounts archives and
disk images as folders (every file system and archive fillyfoal knows,
"for free", since the binary already carries them), a registry browser, a
table export from SQLite or a database page.

The idea, still underspecified:

- **Generic metadata on every node, attached by the core**, so formats
  don't have to opt in:
  - a stable **key**, separate from the display name (most fields are
    already created from a `&'static str` label);
  - an **element** flag for nodes produced by `cx.push` (members, entries,
    rows, subkeys), so a consumer can ask for "the elements under this
    node" without knowing their names;
  - an **embedded-content** marker for nodes made by `embedded()` and
    `content()` (the content's span and detected format are already known);
  - typed values, as today.
- **A sans-IO visitor driver** in the facade, in the style of `Session`. A
  mapping supplies callbacks that see each node's key, flags, value, span
  and format and answer descend, skip or take. The driver expands only what
  is needed, pages through large collections, trims behind itself and
  surfaces byte and secret requests the usual way.
- **Mappings live outside fillyfoal** (an archive VFS, a registry browser,
  a table export). fillyfoal promises only that spans, values and keys are
  accurate.
- **Keys become a contract where a mapping depends on them.** Pin those
  explicitly (`.key("uncompressed_size")`) and keep a per-format test that
  lists them, so a display rename can't silently break a consumer.
- **Hot paths may need typed attributes directly on element nodes**
  (listing 100,000 zip entries shouldn't expand 100,000 header nodes).

How to find out whether it holds: add the automatic metadata and the
visitor, then write three small mappings (zip entries, registry keys and
values, SQLite tables and rows) and see how much each needs beyond the
automatic metadata.

**A VFS raises the correctness bar.** The viewer tolerates approximation;
a file copied out of an archive is trusted. Any format a VFS mapping relies
on needs:

- failing loudly instead of approximating (unsupported methods, sparse
  regions, alternate streams, missing keys, truncation all make content
  unavailable with a reason);
- an extraction comparison against a real extractor (bsdtar, 7z, unzip,
  debugfs, a loop mount in a container): every file's bytes, metadata and
  the directory structure;
- deliberate path handling: encodings, `..` and absolute paths, duplicates,
  case collisions, hard links.

Rollout by how often people meet the format: zip, tar (all compressions),
7z, rar; then ISO 9660, UDF, DMG, cpio/deb/rpm/ar, cab, MSI; then FAT,
exFAT, NTFS, ext4, HFS+, APFS, squashfs.

### Multi-file inputs

Some formats span several files, and fillyfoal sees one at a time:

- split VMDK (`-s001.vmdk` extents next to a descriptor), and encrypted VMDK
  descriptors, whose extents are listed only inside the encrypted text;
- EWF segment sets (`.E01`, `.E02`, ...), split and multi-volume archives;
- MyISAM tables (`.MYI` holds the row format, `.MYD` the rows);
- any format with a sidecar index.

The shape: a host "sibling file" request, analogous to byte and secret
requests. A dissector asks for a named file next to the current one; the
host may decline. Joined inputs become a piecewise source, so the rest of
the core doesn't change. Open questions: naming rules per format, how the
tree shows a set (a virtual root?), and what happens when one member is
missing.

### Unlocking

The secrets flow exists; more formats could use it, and some need no
password at all:

- VMware encrypted VMs wrap the descriptor key with an empty key when the
  VM is encrypted only for its virtual TPM (every Windows 11 VM), so the
  descriptor could be decrypted without asking;
- RC4 CryptoAPI `.xls`, XOR-obfuscated `.xls`, encrypted PowerPoint
  streams, MS Money (MSISAM) page encryption.

### Trust at scale

Turn "1,500 formats" into "1,500 formats at a known quality level":

- **A maturity level per format**, tracked in the repository: probe only;
  real-tool fixture; negatives in the probe conflict matrix; fuzzed;
  compared against a reference tool. The table also picks the next waves of
  work.
- **Differential testing** against reference tools (7z, libarchive,
  exiftool, qemu-img, readelf, fsck, zdb, ...): compare structure and
  values, not just "doesn't crash".
- **Coverage-guided fuzzing** per format, with crash triage delegated. It
  also backs the work-bounding claims.
- **A probe conflict matrix:** every fixture against every probe, beyond
  "the first match is right". Probes are what users see first, and they
  held the most visible defects in the audit.
- From `DESIGN.md`'s open questions: **detection confidence** (scores
  instead of first match wins) and **refinement probes** (a variant probed
  after its generic parent matched, removing ordering constraints).

### Release and consumption

- A deliberate public surface (`Session`, `Node`, `Value`, the registry) and
  a versioned, documented tree output.
- A first tagged release, and crates.io if there are consumers beyond the
  file manager.
- Binary size and compile time per feature: worth measuring before anyone
  embeds the whole thing.

### Deeper decoding

Formats that are recognised and structured but stop short of their content.
A sample of the larger ones:

- ZFS: follow the root block pointer into the MOS to list datasets and
  files. RAID5 member data is shown opaque.
- CHD: decompress hunks (needs a FLAC decoder in the codec crate, and MAME's
  Huffman codec).
- MP4: fragmented files (`moof`/`trun`), audio and subtitle samples.
- git packs: resolve ref-deltas (needs an object-ID index of the pack).
- DWARF in Mach-O and MinGW PE, call frame instructions, GCC location views.
- Database internals: InnoDB and SQL Server log records, compressed InnoDB
  pages, instant ADD/DROP COLUMN.
- Lua, pyc, wasm component and SPIR-V bodies; Inno Setup entries; Illustrator
  native data; Revit and Visio records; UEFI Brotli and Tiano compression.
- Node links (to nodes, not just spans) for graph-shaped formats.

### Breadth

New formats stay welcome as a background activity, under the same bar as
everything else: a real-tool fixture where one can be made, negatives for
the probe, bounded work. The TempleOS family (RedSea, `.Z`, `.BIN`, DolDoc,
HolyC, sprites, GR) is the model: public-domain source as the
specification, and one fixture written by TempleOS itself, booted in QEMU.

## Fixtures still wanted

Formats whose fixtures are synthetic only, because no writer runs here:

- Third-party corpora that need a licence check first: ExifTool's test
  images (camera raws, maker notes), SAS-written `.sas7bdat`, Microsoft
  LZX/Quantum CAB and CHM, InstallShield, StuffIt, older tracker formats
  (MTM, STM, 669, ULT, MED, OKT).
- Commercial writers: AutoCAD DWG (AppInfo layout), Illustrator `.ai`
  (CS-era and 2020+), SolidWorks, Inventor, Revit, Outlook for Mac `.olm`,
  Blu-ray authoring (BD-J, sub-paths, multi-angle).
- Forensic images: AD1 (no published layout), logical and bzip2 EWF2,
  encrypted EnCase 7, AFF4 variants.
- Windows kernel and complete memory dumps (only a small memory dump is
  real).
- An HFS+ directory hard link; Android OAT from Android 12–14.

## Decisions waiting for the maintainer

- Add a FLAC decoder to the codec crate (CHD, and useful elsewhere)?
- `big5` decodes as Big5-HKSCS (the WHATWG meaning) from CPython's table,
  and `cp950` is now code page 950 rather than an alias: keep?
- Facts cross-checked against references whose code can't be used (UModel
  for UE3 packages; RAR 5 password-check offsets confirmed by reproducing a
  real archive): accept, or re-check against an open reference?
- Inno Setup fixtures: six real installers at about 2 MB each, and Inno
  Setup 7's licensing terms for the 7.1.0 one.
- Generators that rely on a locally built container image should install
  their tools from the distribution instead, so anyone can rerun them.
- Real files that were cut short to fit (TempleOS `.MAP` and AutoComplete
  `.DATA`) are filed as external with the edits noted: keep, or treat as
  synthetic?
- Large snapshots (a few over 200 KB, some in the megabytes): shrink the
  fixtures, or cap expansion in the snapshot harness?

Smaller follow-ups found along the way (cosmetic slips, missing
cross-checks, single-format gaps) are deliberately not listed: the maturity
table and fuzzing will rediscover the ones that matter.
