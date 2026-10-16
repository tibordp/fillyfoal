# fillyfoal design

Structural inspection of files, in the spirit of Wireshark dissectors: an
interactive, lazily expandable tree of typed fields with byte provenance.
The first consumer is the F3 viewer of an orthodox file manager; the model is
independent of any UI.

Success criterion: pressing F3 quickly reveals something useful, and deeper
exploration pays for additional work only as needed.

## Goals

- **Library first, UI-independent.** Hosts render the tree however they like.
- **Sans-I/O core.** The host supplies bytes and performs all I/O. The core
  never touches files, sockets or an executor. Adapters sit on top of it
  (`sync`, a blocking one; the WebAssembly viewer in `web/`).
- **Structural and data laziness.** Unexpanded subtrees are not constructed;
  content is not read or decompressed merely because it exists. Prerequisite
  work is allowed, but its cost should be explicit.
- **Large-file support.** Collections are enumerated incrementally (pages),
  never by materialising millions of nodes or assuming cheap random indexing.
- **Rich, structured output.** Typed values, enum and flag interpretations,
  descriptions and diagnostics; presentation is the frontend's choice.
- **Byte provenance.** Every field can say which bytes it came from, in which
  byte space (source).
- **Partial results.** Malformed or truncated input leaves useful structure
  behind, with diagnostics attached where the problem is.
- **Composability.** Embedded formats reuse other dissectors.
- **100% safe Rust.** `unsafe_code` is forbidden crate-wide.
- **Hermetic.** No external crates for parsing concrete formats or parts of
  them. Generic facilities only, and judiciously. See the codec policy below.
- **Readable dissectors.** A Rust-embedded DSL (helpers, macros, eventually
  derives) derived from working dissectors, not designed upfront. Provenance
  should be a side effect of reading a field, so authors cannot forget it.
- **Hostile-input robustness.** No panics, bounded memory, guaranteed
  termination on any input. Enforced by lints (`indexing_slicing`,
  `arithmetic_side_effects`, `unwrap_used`, `panic`, ...), budget checkpoints
  in input-dependent loops, allocation sized only by bytes actually read, and
  truncation/mutation sweeps in tests (fuzzing later).
- **Determinism.** The same bytes and the same request produce the same nodes.
  This is what makes discarding and re-deriving subtrees safe, and keeps
  snapshot tests stable.

## Non-goals

- **Performance.** Constant factors don't matter: copying, re-reading through
  the cache and boxing are fine. Still required: bounded memory, no
  pathological (e.g. quadratic) algorithms, and fast time-to-first-output.
- **Complete depth.** Bailing out on an uncommon extension is fine. It becomes
  a leaf with its span and an `Unsupported` diagnostic, distinct from
  `Malformed`, `Truncated` and `Limit`.
- **Writing or editing files.**
- **API stability**, for now.

## Codec policy

- Container structure (ZIP, tar, ...) is always dissected in-house; that is the
  product.
- Codecs (generic compression) sit behind an internal push-style interface:
  feed input, receive output, keep state between calls, with checkpoint and
  restore. External implementations are allowed **only** through optional
  features, and **only** if they offer such a push-style, sans-I/O interface.
  Anything built around `Read`/`Write` or file handles is excluded at runtime.
  (`miniz_oxide`: acceptable. `zip`: not.)
- No external codec is a default feature (including `iluvatar`). The default
  build is fully hermetic; content in a codec we lack becomes an
  `Unsupported` leaf that names the codec and keeps its span.
- In practice every codec so far is in-house (`crates/codec/src/codec/`, no features
  needed):
  - general-purpose: DEFLATE/zlib, bzip2 (and NSIS's variant), LZMA/LZMA2/xz
    (+ BCJ x86/ARM/ARM64, Delta), Zstandard, Brotli, LZ4, Snappy,
    LZFSE/LZVN and Apple `pbz*`, Unix `.Z`, LZO1X/lzop, LZF;
  - archivers: RAR 2.9/3.x and 5/7 (LZ, PPMd var. H, standard filters),
    7z PPMd (var. H) and BCJ2, ZIP PPMd (var. I rev. 1),
    MSZIP/LZX/Quantum (CAB, CHM, WIM), LZMS (WIM/ESD, solid resources),
    XPRESS (plain, Huffman) and LZNT1,
    PKWARE implode and DCL implode, the LHA/ARJ/ZOO/`COMPRESS.EXE` LZSS and
    LZH family (`-lh1-`, `-lh4-`..`-lh7-`, `-lzs-`, `-lz5-`, ARJ 1-4, ZOO LZW,
    SZDD, KWAJ, UEFI EFI/Tiano), PSARC blocks, ACE 1.0/2.0 (acefile as
    oracle), the StuffIt methods (RLE90, LZW, Huffman, LZAH, 13, Arsenic; no
    oracle), ADC;
  - format-specific: compressed RTF (LZFu), Guitar Pro 6 BCFZ, Heatshrink and
    MeatPack (Prusa binary G-code), DjVu BZZ, the DWG R2004+ LZ77 variant,
    SPSS bytecode and SAS7BDAT RLE/RDC row compression, Cap'n Proto packing,
    the ntfsclone image command stream, Partclone block areas, the
    PDF/PostScript filters and predictors, TempleOS `.Z` LZW (TOSZ as oracle);
  - ciphers and KDFs that unlock content: ZipCrypto, AES (CBC, CTR, GCM), RC4,
    ChaCha20/Poly1305, Twofish, Type 1 eexec, MPQ; Argon2, BLAKE2b, bcrypt_pbkdf,
    7-Zip's SHA-256 key derivation.

  Each is checked byte-exact against a real encoder where one was available
  (CLI tools, Python packages via `uv`, `hdiutil`, `compression_tool`,
  liblzo2, 7-Zip or libarchive as extraction oracles), otherwise against spec
  vectors and spec-derived encoders; the test names and comments say which.
  CRCs share one table-driven engine (`codec::crc`).
  Where a decoder was written from a reference implementation rather than
  a specification, its module documentation says so and `THIRD-PARTY.md`
  carries the notice.
- Every codec does bounded work per call (about `step` bytes of output, or
  a bounded slice of input) and returns to be called again, so decoding can
  be budgeted and interrupted like everything else. No codec uses
  `filters::Whole` (decode once all input is in) any more; it is reserved
  for inputs bounded by a small constant.
- No optional codec features exist today, so the hermetic build is the only
  one.

## Architecture (current)

The workspace (MSRV 1.88, edition 2024) has three layers:

- `crates/codec` (`fillyfoal-codec`): byte primitives, spans, diagnostics,
  text helpers and every codec. No dependencies.
- `crates/core` (`fillyfoal-core`): `Session`, `Cx`, nodes and values, the
  DSL (`record!`, `Fields`, `Cursor`), the format plumbing (`Format`,
  `Probe`, `DeepProbe`, `Registry`) and shared helpers
  (`formats::util`).
- Eleven category crates of dissectors: `text`, `archive`, `data`,
  `image`, `av`, `security`, `exec`, `docs`, `system`, `science`, `games`.
  Each depends on the core and on the categories it embeds; the graph has
  no cycles, and a format in a crate that depends on yours is embedded by
  name (`embedded_named`).

The `fillyfoal` facade at the root has one feature per category (all on by
default, each enabling the categories it needs) and assembles the
registry in `src/formats.rs`: `FORMATS` (first-phase probes, in order),
`STREAMING` and `DEEP`. `fillyfoal::Session` is the core's session over
that registry.

```
host ──expand(node, n)──▶ Session ──poll(budget)──▶ Progress::{Idle, Yielded, NeedBytes, NeedSecret}
     ◀─NeedBytes(reqs)───          (no I/O, no executor)
     ──supply(bytes)────▶
     ◀─NeedSecret(reqs)──
     ──answer_secret()──▶
```

- **Session** owns the node arena, a bounded byte cache, and one in-flight
  expansion per expanded node. The host calls `expand`, `poll` and `supply`,
  and reads nodes and child state. `poll_node(id, budget)` runs one
  expansion only; the others stay parked with their children and resume
  state until polled. Expansions never wait on each other (lazily decoded
  sources belong to the session and are advanced by whichever read reaches
  them), so polling one node is always enough to finish it. A host cancels
  by not polling; `collapse` discards the work. `address(id)` names a node
  by its path of child indices, stable across collapses and sessions over
  the same bytes.
  `work_done()` totals the units every expansion charged, however polls
  split them; tests bound work with it instead of a clock. There is no
  overall cap by default: `Limits::max_work` (units per expansion, or
  per page of children) is for hosts that poll to completion unattended
  (batch runs, CI, thumbnailers); an interactive host cancels instead.
- **Progress.** `activity(id)` describes a running expansion, and
  `progress(id)` gives its best single estimate as `(done, total)`, in
  this order: what the dissector reported (`Cx::progress`, or
  `Cx::progress_in`, which over a lazily decoded source is the encoded
  bytes consumed, read live) or children out of an exact count; else, while
  it is suspended inside a read that decodes, the innermost stream of that
  read's chain with a measure (decoded front out of the wanted position
  when the stream's length is known, else encoded bytes consumed out of
  the encoded length); else where its last read ended, within the node's
  span (or the whole source, if its length is known). A dissector that
  reports knows its work best, but one stuck in a far read cannot report,
  and a walker that never reports still reads. The chain is recorded only
  when a read suspends: `Shared::read_lazy` notes each lazy source it was
  decoding as an unfinished read unwinds (outermost first), and
  `Cx::read_avail` moves that list into the expansion's output;
  `read_activity()` gives the same for a host's own `read_step`. All of
  this is reporting only: it changes nothing that is decoded or charged.
- **Dissectors are ordinary `async fn`s.** The session polls their futures
  with a no-op waker. A future suspends only through the context (`Cx`):
  - `cx.read(span).await` suspends while bytes are missing (**waiting for
    bytes**) and records which chunks it needs;
  - `cx.checkpoint().await` and every read/push charge a work budget, and
    suspend when it is exhausted (**yielded**). The core has no clock and no
    preemption, so the work between two suspension points must be bounded
    independently of the input (see "Accounting for work" in
    `docs/DISSECTORS.md`). Synchronous work already done is charged with
    `cx.charge(n).await`. Decoding a lazy source
    charges as it goes, so a read far into a large stream yields partway
    and continues on the next poll; `Session::read_step` gives hosts the
    same bounded reads (`Session::read` decodes in one call);
  - `cx.push(node).await` suspends once the requested page is full.
  A node that was never expanded has no future at all (**not requested**).
  Suspending on any other future is reported as an internal error.
  Cancellation is not polling (the future stays parked) or dropping it
  (`collapse`).
- **Nodes** carry a name, an optional typed `Value`, summary, description,
  `span`, optional `target` (what the field points to), diagnostics, and an
  optional *expander*: a plain-data state plus an `async fn` that emits the
  children. Expanders are re-runnable (determinism), which is what makes
  eviction possible.
- **Spans** are `(source, offset, len)`. Sources are host-provided or
  derived: decoded streams (`Cx::add_derived`, `codec::decode_span`, lazily
  `Cx::decode_lazy`) and piece lists over other sources (`Cx::add_pieces`),
  memoized by `Origin { parent, transform }`. A stream whose decoded size
  nothing records is decoded lazily with `Cx::decode_lazy_unsized`: its
  length is an upper bound (`Cx::len_known` is false) until it has been
  decoded to its end, and only `formats::STREAMING` formats see it before
  then. A stream whose first header records a size that more may follow
  (a zstd file's first frame) is decoded with that length
  (`Cx::decode_lazy_checked`), checked when decoding reaches it: a
  stream that goes on is reported on the node whose read found it, never
  cut short silently. Optional reads far into such content (a backup
  header at the end of a disk) are offered as nodes read on request
  (`Cx::read_is_cheap`, `formats::util::far`).
- **Holes.** A host may declare the holes of a sparse source
  (`Session::set_holes`, from `SEEK_HOLE`/`SEEK_DATA` or `FIEMAP`). Reads
  wholly inside them are answered as zeros without asking the host, and
  `Cx::next_data` lets a walker skip them and the zero pieces of piecewise
  sources.
- **Identification** has two phases. The first runs every `Probe` in
  `FORMATS` order over the head (`HEAD_LEN`, 66 KiB) and tail (`TAIL_LEN`,
  1 KiB); it is charged as work (`Registry::identify_costed`), since custom
  probes scan the head. The second phase (`DeepProbe`, listed in
  `formats::DEEP`) runs only when the first matched nothing or matched a
  format a candidate lists in `over`; it may read the last
  `DEEP_TAIL_LEN` (128 KiB) and the node's name (`Deep::name`), which only
  breaks ties for a signature too weak to stand alone. A dissector that
  finds its content is really another format hands it over
  (`Cx::hand_off`), and the node takes that format. The host can force a
  format: `Session::open_as` for a file, `Session::reinterpret` (or
  `reinterpret_at` by address) for content inside one; a forced node is
  never handed off.
- **Secrets.** `cx.unlock(realm, prompt, verify)` suspends an expansion until
  the host answers a `SecretRequest` (`Progress::NeedSecret`, reported only
  when nothing else can run). Answers are cached per realm and attempt, so
  one password serves a whole archive; a declined request yields `None` and
  the content stays an "encrypted" leaf.
- **Pagination.** `expand(node, n)` asks for at least `n` children; the
  expansion suspends when that many are emitted and resumes when more are
  requested. Collections may announce `Count::{Exact, AtLeast, Unknown}`.
- **Memory.** Everything the session holds is bounded or reproducible:
  - *Nodes*: `Session::seek(node, start, len)` keeps a window of a
    collection's children (`Children::first` is its start) and releases the
    rest; `Session::trim` collapses least recently used subtrees. Re-running
    an expander reproduces what was released. Seeking forward continues the
    expansion, dropping children before the window; seeking backward
    restarts it, from the nearest **resume mark** when the walker records
    them (`cx.mark(|| state)` before pushing, `cx.resume::<State>()` at the
    start; marks are kept sparsely, every 256 children). Without marks a
    restart re-walks from the start, skipping.
  - *Decoded sources*: `Limits::max_derived` is a budget, not a cap. Sources
    decoded with a codec record it (a recipe) and are evicted least
    recently read first; an evicted source decodes again on demand from its
    parent. Bytes a dissector computed itself (`add_derived`) stay.
  - *Long streams*: a lazily decoded source keeps a sliding window. Codecs
    report what they no longer need (consumed input; output before their
    LZ window; see "Releasing" in `codec::pipeline`), and the source drops
    it once its output exceeds twice the keep size (16 MiB, or a quarter of
    `max_derived`). A read behind the window resumes from the nearest
    **checkpoint**: a clone of the decoder plus the window its history
    reaches, taken while decoding from codecs that report their state
    size (`Decode::heap_size`, giving `Decoder::checkpoint`), spaced at
    least eight times their cost apart and thinned when they outgrow
    their share of memory. Containers that record restart points (xz
    index records, zstd frames, BGZF blocks, WIM and CHM chunk
    tables) pass them as **seeds** (`Cx::decode_lazy_seeded`, `Seed`), so
    a far read decodes from the nearest one, the first time too. Seeds are
    trusted only until decoding disagrees with one at a boundary the
    codec reports (`Decode::boundary`); then they are dropped. Codec tests
    check checkpoints with `pipeline::verify_checkpoints`.
  - *Damage*: `Streaming` treats a malformed-data error as a possible
    shortage of input until the input ends. A codec that reports every
    shortage as `Truncated` opts out (`Decode::truncation_is_exact`), so
    damage early in a large stream is reported at once. A lazily decoded
    source that stopped on an error reports it on the short read
    ("decoding stopped: ...").
  - *Bytes* are an LRU cache of host chunks (`Limits::cache_bytes`);
    parsed values shared through `cx.cache` are bounded too.
- **Partial results.** Children are pushed as they are produced; if the
  expansion fails, what was emitted stays and the error is attached to the
  expanded node.
- **Composition.** A format entry point is `async fn(Cx, Input)` over a
  region (`Input { span, nesting, outer }`), so the same dissector serves a
  whole file, a PE resource or a decompressed ZIP member.
  `formats::embedded` produces a lazy node that detects and dissects a
  region on expansion.

### DSL, version 0

`Fields` decodes a block, records each field's span automatically, and either
emits nodes or stays silent. The same layout function both extracts values
for the dissector's own use and renders the struct on expansion:

```rust
fn file_header(f: &mut Fields<'_>, _: &()) -> Result<FileHeader> {
    let machine = f.u16("Machine").enumeration(MACHINE).emit()?;
    let sections = f.u16("NumberOfSections").emit()?;
    f.u32("TimeDateStamp").timestamp().emit()?;
    ...
}
```

Fixed layouts have since moved to `record!` (struct, decoder, size and
rendering from one declaration); derives have not been needed.

## Decisions that are expensive to reverse

1. **Node identity = re-runnable expander state**, not pointers into a parsed
   object graph.
2. **Children are pushed through the context**, not returned, giving partial
   results and pagination with one mechanism.
3. **Spans name a source**; derived sources map back to their parents either
   exactly (piecewise) or opaquely (anchored at checkpoints).
4. **The value vocabulary** (`Value`) is the frontend contract.
5. **Graph edges** (`target` today, links to nodes later) instead of embedding
   shared or cyclic structure.
6. **`Send` everywhere.** Sessions can move to a worker thread; dissector
   futures must be `Send`.
7. **Suspension via `async`/`await` with a no-op waker**, no executor.

Cheap to change: the DSL surface, detection, cache policy, adapters, crate
layout.

## Roadmap

The slices that were meant to test the core are done: PE, ZIP (stored, then
deflate through the in-house inflate), tar.gz with lazily decoded members
and decoder checkpoints, SQLite (page graph, overflow chains as piecewise
sources), MP4 (recursive boxes, large sample tables) and PDF (xref,
incremental updates, object streams), and the core carries all of them.
What remains open is listed under "Open questions"; where the project could
go next is in `ROADMAP.md`.

## Findings from the PE slice

- **Async suspension works as hoped.** Dissectors read like straight-line
  parsers; byte waits, budget yields and page boundaries needed no author
  effort. Results are identical across chunk sizes (1 byte to 64 KiB),
  budgets (1 unit per poll) and page sizes, and after collapse/re-expand.
- **One sharp edge:** an `async fn` that creates a lazy node pointing at
  *itself* (recursive resource directories) trips a `Send` auto-trait cycle.
  Routing the `lazy` call through a plain `fn` fixes it. A future macro layer
  should generate this automatically.
- **Dual-use layouts pay off.** One layout function both extracts values and
  renders fields; that is most of what a derive would generate.
- **Two span flavours are needed.** `sub` clamps to the region (structures may
  be cut off; field decoding reports the exact truncated field), and
  `sub_exact` fails up front (arrays whose declared size exceeds the region are
  rejected before anything is read or allocated).
- **Laziness is real.** On a 160 KB DLL, F3 (top level) reads 4 KiB; fully
  expanding real binaries reads 10–30% of the file, because section bodies,
  resources and overlays stay unread until opened.
- **Not yet done in PE:** Rich header, delay imports, base relocations,
  exception/TLS/load-config tables, .NET metadata. These appear as leaves with
  spans. (Version resources and Authenticode via the ASN.1 dissector are done.)
  *Since done:* all of these (`pe/extra.rs`, `loadcfg.rs`, `unwind.rs`,
  `clr.rs`, `metadata.rs`).

## Findings from scaling out (hundreds of formats)

- **The registry scales.** A format is a file plus one line in `FORMATS`;
  families share a dissector and register one `Format` per member. Sections
  per family let parallel branches merge with a union of lines.
- **Probe collisions are the main integration risk.** Weak probes (frame
  syncs, size checks, two-byte magics) shadow other formats. Two tests keep
  this honest: every fixture must be identified as the format its directory
  names, and format names must be unique. Weak probes go last in their
  section; generic text goes last overall.
- **The robustness harness finds real bugs fast.** Truncation and mutation
  sweeps over every fixture found infinite loops (a header scan reading past
  EOF through a clamped span), exponential self-embedding (a partition table
  pointing at its own image), and probe overreach. Two framework guards came
  out of it: embedded regions in the same source must be strictly smaller than
  their container, and `Limits::max_work` stops any runaway expansion with a
  local `Limit` diagnostic. (*Since* opt-in: an interactive host relies on
  interrupting budgeted polls instead, and a limit failed legitimate long
  decodes; batch hosts and the robustness tests set one.)
- **Piecewise sources** (`Cx::add_pieces`) cover fragmented data without
  copying: CBM sector chains, MSF (PDB) streams and their directory,
  filesystem extents, NTFS update-sequence fixups (sector bodies plus 2-byte
  pieces of the fixup array, so every field keeps its true file offset).
  `Session::resolve` maps them back to file offsets. Holes are spans of a
  virtual `SourceId::ZEROS`, so a sparse 2 TiB disk costs nothing.
- **Probe window.** `HEAD_LEN` grew from 36 KiB to 66 KiB so superblocks at
  64 KiB (btrfs, UFS2) are detectable. Signatures near the end of a device
  (md v0.90/1.0) are not visible in the 1 KiB tail; *resolved* by the
  second phase (`DeepProbe`).
- **Composition compounds.** Each new format improves others: text inside
  archives, JPEG frames inside AVI, PNG inside game packs, TAR inside Android
  backups. Snapshot diffs after merges are mostly such improvements.
- **API sharp edges seen in practice:** `cx.read(region.sub(..))` silently
  returns short data past the end (by design, for partial structures) — loops
  must be bounded by the region; inline flag tables must be `const` (they call
  `flag()`); `expander!` needs a `self::` path when a local variable shadows
  the function name.

## Findings from the parallel scale-out (1,500 formats)

Twelve agents worked in parallel worktrees, one format family each, merged by
unioning `mod.rs` sections. What they reported, consolidated:

- **Duplicates happen across families,** even with lanes assigned (TFLite,
  ISO 8211, ESRI headers, WKT, PDS/VICAR, BinHex, TPL, JKS, keras/npz/pytorch
  variants). The unique-names test catches same-name duplicates; same-format
  under different names (WKT `esri-prj` vs `wkt-crs`) needs review at merge.
  The deeper implementation was kept each time.
- **Probe order is the biggest structural constraint.** Detection stops at
  the first match, so a variant of a generic container (ZIP, CFB, RIFF,
  TIFF, DER/PKCS#7, bplist, gzip for BGZF) must be registered before its
  parent, outside its family's section. GeoTIFF, IMG4, mobileprovision and
  webarchive were skipped for this reason. Wanted: *refinement probes* — a
  `Format` with a `parent` whose probe runs after the parent matches and
  can claim the input.
- **Wire formats want a shared module.** Protobuf walkers were written three
  times and FlatBuffers readers twice (`ml::proto`, `ml::flatbuf`, `geo`,
  `archive::crx`, `geo::osm`). They should move to a public
  `formats::wire` (protobuf with static schemas, FlatBuffers tables,
  MSB-first bit reader). *Resolved:* `formats::util::wire` (protobuf,
  FlatBuffers, Thrift, Cap'n Proto).
- **Hand-off to text dissectors** (an XML vocabulary, a JSON schema) works
  by calling `xml::dissect`/`json::dissect` and annotating afterwards; a
  public "dissect as XML/JSON with this summary" entry point would be cleaner.
- **Cursor gaps** reported repeatedly: counted byte strings that error on
  truncation (`bytes_counted`), length-prefixed and UTF-16 strings, 24-bit
  integers, MSB-first base-128 integers; `record!` arrays and `u24`.
- **Text helpers:** splitting a region into sections at header lines came up
  six times (crash reports, tombstones, build.prop...); small value helpers
  (`text`, `uint`, `hex`) are copied into most modules and belong in core.
- **Self-delimiting structures** without a length prefix (Photoshop
  descriptors, OpenStep plists, NBT) must be measured before they can be lazy
  nodes; an iterative "measure, then expose lazily" helper would generalise
  the pattern.
- **`add_pieces`/`add_derived` memoize by `Origin`;** two derived sources
  with the same parent span and transform collide silently. The parent must
  identify the stream (its directory entry, inode or table entry).
- **Recursive async helpers** hit the `Send` auto-trait cycle (documented in
  `docs/DISSECTORS.md`); it still bit several agents.
- **Layouts written from memory** are flagged in each family's module docs
  and commit messages; their fixtures are self-generated, so those
  dissectors are self-consistent but unverified against real files. The
  corpus says which is which: `tests/fixtures/external/` holds files made by
  other implementations (listed with their producer in `SOURCES.md`),
  `tests/fixtures/synthetic/` everything we generated or wrote by hand.

## Findings from the codec pass

Five agents wrote codecs in parallel, a sixth wired existing ones into
containers. Consolidated:

- **`filters::Whole` is not incremental.** Most codecs were whole-input
  filters wrapped in `Streaming`; they reported all input as consumed (so the
  "bytes follow the stream" note never fired) and `decode_lazy` decoded
  everything on the first read. *Resolved:* every codec is now incremental
  with bounded work per call (see the codec policy).
- **Expected-size and single-frame modes are missing** for some codecs:
  `Lz4Block` fails on trailing padding (ZSO with alignment), Zstd decodes
  every frame it finds (qcow2 has to walk the frame header itself). A
  per-codec "stop at the expected size" would cover both. *Partly
  resolved:* `Codec::ZstdFrame` decodes exactly one frame.
- **Lazy decode errors are dropped:** if a lazily decoded source fails
  partway, reads come back short with no diagnostic. *Resolved:* the short
  read fails with the stream's error ("decoding stopped: ...").
- **Post-filters inside `Codec`.** 7z BCJ/Delta chains decode in memory
  because the filters are not `Codec` stages; making them stages would let
  them decode lazily. *Resolved:* they are (`Codec::PostFilter`).
- **Bit-at-a-time Huffman** (inflate, LZX, implode) is fine for viewing but
  slow on very large members; table-driven decoding is the obvious next
  step if it ever matters.
- **Probing magic-less codecs** (Brotli) is done by a bounded trial decode
  of small, complete files only; measured at about 1 in 10⁶ false positives
  on random 4–63 byte inputs and none on short text.

## Findings from the review audit (2026-10)

A review of every category, then independent verification of each finding,
then fixes. What it showed:

- **Synthetic fixtures check consistency, not correctness.** A generator
  written from the same misreading as the dissector agrees with it. MAT
  padding, the GDBM 64-bit header, AY, Arm FIP UUIDs, the ZFS uberblock
  slot size, TraceLogging array flags, PCL XL opcodes and MSI transform
  masks were all wrong with green snapshots. Fixtures from the real tool
  found bugs almost every time they were added.
- **Probes held the most visible defects:** false positives from
  Markdown, JSON, LRC and legacy-text probes; LibreOffice OOXML identified
  as plain ZIP; probes that needed the whole structure inside the head and
  failed on large files. The fixes were tighter probes with a negative
  fixture for each, and the deep phase for evidence past the head.
- **Bounded work has to be measured, not assumed.** Identification was not
  charged at all; EVTX undercharged Binary XML; probes rescanned the head
  per probe; 7z PPMd cloned its model on every step; wall-clock assertions
  in tests flaked under load. Time per unit across the robustness sweep
  (`SWEEP_TIMES`) finds such outliers mechanically; tests now assert work
  units and yield counts, with `common::POLL_CEILING` only as a backstop.
- **Laziness regresses silently.** QCOW2 and VMDK images and zisofs files
  were decoded whole on expand; DMG and Android sparse images were never
  assembled.
  One pattern fixed all of them: the image as a pieces source, each
  compressed cluster, grain or chunk a `decode_lazy` piece decoded when a
  read reaches it.
- **Process.** Review, independent verification (which refuted several
  confident findings), then fixes. Provenance was checked at every merge:
  what was read, and whether it is credited in `THIRD-PARTY.md`. A gate
  was added the first time a class of breakage escaped: the MSRV build
  (an `if let` guard), Windows-invalid fixture names (`nul.log`).

## Open questions

- **Multi-file inputs.** Some formats span several files: EWF segment sets
  (`.E01`, `.E02`, ...), MyISAM tables (`.MYI` holds the row length and
  index, `.MYD` the rows), split archives. Each file is dissected alone
  today (EWF says the rest of the media is in other segment files;
  fixed-length MyISAM rows show as one region). A host "sibling file"
  facility, a request for a named file next to the current one that the
  host may decline, would let a dissector join them.
- **Node links** (to other nodes, not just spans, as `target` is) for
  graph-shaped formats.
- **Refinement probes.** A variant of a generic container (ZIP, CFB,
  RIFF, TIFF) must still be registered before its parent; a `Format` with
  a parent whose probe runs after the parent matched would remove that
  ordering constraint.
- **Detection confidence.** The first matching probe wins; there is no
  score, so a weak probe early in `FORMATS` can still shadow a stronger
  one later.
- **Table-driven Huffman** for inflate, LZX and implode, if decoding speed
  on very large members ever matters.
- **Fuzzing** beyond the truncation and mutation sweeps.
