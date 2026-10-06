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
  never touches files, sockets or an executor. Adapters (sync, later Tokio)
  live outside the core.
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
- **API stability** before the core survives SQLite and PDF.

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
  build is fully hermetic; compressed content becomes an `Unsupported` leaf
  that names the codec and keeps its span.
- Inflate is the exception worth writing in-house early (ZIP, PDF 1.5+ object
  streams, PNG); external crates may serve as differential-testing oracles
  (dev-dependencies are not subject to the runtime rule).
- CI tests both the hermetic and the feature-enabled build.

## Architecture (current)

```
host ──expand(node, n)──▶ Session ──poll(budget)──▶ Progress::{Idle, Yielded, NeedBytes}
     ◀─NeedBytes(reqs)───          (no I/O, no executor)
     ──supply(bytes)────▶
```

- **Session** owns the node arena, a bounded byte cache, and one in-flight
  expansion per expanded node. The host calls `expand`, `poll` and `supply`,
  and reads nodes and child state.
- **Dissectors are ordinary `async fn`s.** The session polls their futures
  with a no-op waker. A future suspends only through the context (`Cx`):
  - `cx.read(span).await` suspends while bytes are missing (**waiting for
    bytes**) and records which chunks it needs;
  - `cx.checkpoint().await` and every read/push charge a work budget, and
    suspend when it is exhausted (**yielded**);
  - `cx.push(node).await` suspends once the requested page is full.
  A node that was never expanded has no future at all (**not requested**).
  Suspending on any other future is reported as an internal error.
  Cancellation is dropping the future (`collapse`).
- **Nodes** carry a name, an optional typed `Value`, summary, description,
  `span`, optional `target` (what the field points to), diagnostics, and an
  optional *expander*: a plain-data state plus an `async fn` that emits the
  children. Expanders are re-runnable (determinism), which is what will make
  eviction possible later.
- **Spans** are `(source, offset, len)`. Today every source is host-provided;
  derived sources (decompressed streams, reassembled fragments) are the next
  step.
- **Pagination.** `expand(node, n)` asks for at least `n` children; the
  expansion suspends when that many are emitted and resumes when more are
  requested. Collections may announce `Count::{Exact, AtLeast, Unknown}`.
- **Partial results.** Children are pushed as they are produced; if the
  expansion fails, what was emitted stays and the error is attached to the
  expanded node.
- **Composition.** A format entry point is `async fn(Cx, Input)` over a
  region (`Input { span, nesting }`), so the same dissector serves a whole
  file, a PE resource or (later) a decompressed ZIP member. `formats::embedded`
  produces a lazy node that detects and dissects a region on expansion.

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

Macros or derives will be extracted from repetition once PE, ZIP and tar
exist.

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

1. Core + PE (headers, sections, data directories, imports, exports,
   resources with embedded-object detection, debug/CodeView, certificates,
   overlay). Done, plus version resources.
2. ZIP (stored members first) + PNG member: derived sources and composition.
   Done.
3. In-house inflate behind the codec interface; ZIP deflate members. Done
   (whole-member decoding into memory, budgeted; streaming is still open).
4. tar.gz: streaming-only derived source, checkpoints, budgets under load.
   Partly done: large members are decoded lazily (`Cx::inflate_lazy`), so
   the first page of a huge tarball costs only what it reads. Decoded bytes
   are kept (bounded by `max_derived`); checkpoints that allow discarding
   and re-decoding are still open.
5. SQLite: page graph, resume keys with traversal stacks, overflow chains as
   fragmented sources.
6. MP4: generic recursive boxes, huge fixed-stride tables, random index access.
7. PDF: tokenized parsing, xref, incremental updates, object streams.

The core is not considered stable until SQLite and PDF fit without contortion.

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
  local `Limit` diagnostic.
- **Piecewise sources** (`Cx::add_pieces`) cover fragmented data without
  copying: CBM sector chains, MSF (PDB) streams and their directory,
  filesystem extents, NTFS update-sequence fixups (sector bodies plus 2-byte
  pieces of the fixup array, so every field keeps its true file offset).
  `Session::resolve` maps them back to file offsets. Holes are spans of a
  virtual `SourceId::ZEROS`, so a sparse 2 TiB disk costs nothing.
- **Probe window.** `HEAD_LEN` grew from 36 KiB to 66 KiB so superblocks at
  64 KiB (btrfs, UFS2) are detectable; signatures at the end of a device (md
  v0.90/1.0) still are not, since probes see only the last 1 KiB.
- **Composition compounds.** Each new format improves others: text inside
  archives, JPEG frames inside AVI, PNG inside game packs, TAR inside Android
  backups. Snapshot diffs after merges are mostly such improvements.
- **API sharp edges seen in practice:** `cx.read(region.sub(..))` silently
  returns short data past the end (by design, for partial structures) — loops
  must be bounded by the region; inline flag tables must be `const` (they call
  `flag()`); `expander!` needs a `self::` path when a local variable shadows
  the function name.

## Open questions

- Eviction: re-deriving collapsed subtrees and resume keys for pages, so that
  memory stays bounded in long sessions.
- Random access into collections (`seek(index)`) for fixed-stride arrays.
- Node links (to other nodes, not just spans) for graph-shaped formats.
- Text encodings beyond ASCII/UTF-8/UTF-16 (CP437 for ZIP names, etc.).
- Format detection beyond magic bytes; confidence and "inspect as…".
