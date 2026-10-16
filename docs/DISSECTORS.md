# Writing a dissector

This is the practical guide for adding a format. Read `DESIGN.md` for the
why; this is the how. Good examples to copy from:

| Pattern | Example |
|---|---|
| Fixed header + chunk stream (big-endian, CRCs) | `crates/image/src/formats/image/png.rs` |
| Header + compressed payload dissected in place | `crates/archive/src/formats/compression/gzip.rs` |
| Directory at the end, paged entries, variants by probe | `crates/archive/src/formats/archive/zip.rs` |
| Pointers/RVAs, many lazy sub-structures, recursion | `crates/exec/src/formats/executable/pe/` |
| Recursive variable-length blocks | `crates/exec/src/formats/executable/pe/version.rs` |
| Text: windowed lines/tokens, encodings, base64 into derived sources | `crates/text/src/formats/text/` (`scan`, `piece`, `encoding`, `decode`) |

## 1. Register the format

Create `<name>.rs` in the family the format belongs to (`archive`,
`audio`, `image`, `data`, `forensics`, ...; each family's `mod.rs`
summarises what it holds), or a subdirectory for a big format. Families are
grouped into one crate per category: `crates/<category>/src/formats/<family>/`
(`crates/av/src/formats/audio/`, `crates/exec/src/formats/executable/`; the
category crates are listed in the root `Cargo.toml`). Add the format in two
places: the `pub mod` list of the family's `mod.rs`, and the `FORMATS` array
in `src/formats.rs`, inside the right section, behind the `cfg` of its
category's feature. Order in `FORMATS` matters: probes run top to bottom, so
specific formats go before generic ones. Shared helpers live in
`crates/core/src/formats/util/`.

Dissectors name things by their paths in one tree (`crate::cx::Cx`,
`crate::formats::Input`, `crate::formats::text::scan`): each category
crate's `lib.rs` imports the core at its root and re-exports the families of
the categories it depends on into its `formats`. A dissector may use another
family directly only if that family's crate is among its crate's
dependencies; the dependency graph has no cycles. To embed a format from a
crate that depends on yours, name it instead:
`embedded_named("Runtime", input, "elf")`.

```rust
pub static FORMAT: Format = Format {
    name: "bmp",                       // short, unique, lowercase
    title: "Windows bitmap",
    extensions: &["bmp", "dib"],
    mime: "image/bmp",
    probe: Probe::Magic(&[(0, b"BM")]),  // or Probe::Custom(fn(&Head) -> bool)
    dissect: crate::expander!(dissect: Input),
};

pub async fn dissect(cx: Cx, input: Input) -> Result<()> { ... }
```

Probes see the first `HEAD_LEN` (0x10800 bytes, 66 KiB: enough for the
btrfs and UFS2 superblocks at 64 KiB) and last `TAIL_LEN` (1 KiB) bytes
and the total length. Probes run on every file the host opens, so be
conservative: a false positive hides the right format, and probe bugs are
the ones users see first. Make them cheap and specific: check more than two
magic bytes when you can (versions, sizes that must be sane). Weak magics
(one or two bytes) need a `Probe::Custom` with extra checks. Never rely on
the whole structure being inside the head: on a large file a header table,
a record list or a text document runs past `HEAD_LEN`, so check what the
head holds and accept a structure the head cuts off. A format with no
reliable signature at all (schemaless protobuf, Thrift) gets
`Probe::Never`: it is offered by `formats::by_extension` and dissected
through `Session::open_as`, and the test harness dissects its fixtures as
the format their directory names (and checks that no probe claims them).

When you fix a probe that claimed the wrong file, add that file as a
negative fixture, under the directory of the format it really is (see
section 9): `fixtures_are_identified_correctly` then keeps both probes
honest.

**Second phase.** Identification runs on every file the host opens, maybe
over remote storage where each range read costs, so the first phase reads
only the head and the 1 KiB tail. A few formats need more: md RAID 1.0 and
0.90 superblocks sit 8 to 128 KiB before the end of the device, and a bare
768-byte Photoshop colour table has nothing to check but its `.act` name.
Such a format adds a `DeepProbe` next to its `Format` and lists it in
`DEEP` in `src/formats.rs`:

```rust
pub static DEEP: DeepProbe = DeepProbe {
    format: &FORMAT,
    tail: true,                 // wants Deep::tail, the last DEEP_TAIL_LEN (128 KiB)
    over: &["ext", "xfs", ...], // first-phase answers it may override; empty: none
    probe: deep_probe,          // fn(&Deep) -> bool
};
```

The second phase runs at a node's detection step only when the first
phase matched nothing, or matched a format some candidate lists in
`over`, so files identified otherwise never pay for it; the deeper tail
is read once, only if a candidate that runs asks for it (and not for
content decoded on demand). Candidates are tried in `DEEP` order and the
first match wins. `Deep::bytes(offset, n)` reads from the head or the
deep tail by absolute offset. `Deep::name` is the node's name (the file
name the host opened it under, an archive member's path) at the node's
own detection step only; names lie, so use it as a tie-breaker for a
signature too weak to stand alone (`Deep::extension_is`), never instead
of one, and never in `over` probes. `fixtures_are_identified_correctly`
runs both phases with each fixture's name.

A probe cannot always tell; when the dissector finds out later that the
content is really another format, it hands it over with `Cx::hand_off`
(see section 6) rather than dissecting it as itself.

A family of related formats (RIFF → WAV/AVI/WebP, ISO BMFF → MP4/HEIC/AVIF,
ZIP → DOCX/EPUB/APK) shares one dissector and registers one `Format` per
member, each with its own probe. See `zip.rs`.

## 2. The model in five lines

- `dissect(cx, input)` runs when the user expands the file node. It **emits
  children** with `cx.emit(node)` (small fixed sets) or
  `cx.push(node).await` (collections; this is what makes paging work).
- A child can be **lazy**: `node.lazy(f, state)` where `f` is an
  `async fn(Cx, State) -> Result<()>` and `State: Clone + Send + Sync`.
  Nothing runs until the user expands it. Keep the state small and plain
  (spans, offsets, an `Arc` of parsed tables).
- **All reads go through `cx`** (`read`, `read_avail`, `block`, `cstr`) or
  a `Cursor`. They may suspend; the framework handles that.
- **Spans** (`Span { source, offset, len }`) say where bytes came from.
  `input.span` is the region you dissect; never assume it starts at 0 or is
  the whole file (you may be inside a ZIP member or a PE resource).
- **Errors are local.** Returning `Err` fails only this expansion; whatever
  was emitted before stays visible. So emit structure *before* parsing what
  depends on it, and attach non-fatal problems with `node.diag(...)` or
  `cx.diag(...)` instead of failing.

## 3. Declaring structures

Fixed layouts are declared once with `record!`; the struct, its decoder, its
size and its rendering all come from this:

```rust
record! {
    /// BITMAPFILEHEADER
    pub struct FileHeader {
        magic: ascii[2] "bfType",
        size: u32 "bfSize" .hex(),
        _reserved: u32 "bfReserved",
        offset: u32 "bfOffBits" .hex() .desc("Offset of the pixel array"),
    }
}
```

Kinds: `u8 u16 u32 u64 i8 i16 i32 i64 f32 f64 ascii[N] utf16[N] bytes[N]
guid`. Decorators (any `Field` method): `.hex()`, `.enumeration(TABLE)`,
`.flags(TABLE)`, `.timestamp()`, `.unix_millis()` (`_micros`, `_nanos`), `.filetime()`, `.mac_time()`,
`.desc("...")`, `.summary(...)`, `.target(span)`,
`.with(|&v, node| node...)`, `.check(|&v| Option<Diagnostic>)`. Closures can
use fields declared earlier (they are local variables).

Endianness is chosen by the reader, not the record:

```rust
let (header, span) = cursor.record::<FileHeader>().await?;   // silent decode
cx.emit(FileHeader::node("File Header", span, Endian::Little)); // lazy fields
```

Tables:

```rust
const COMPRESSION: EnumTable = &[(0, "BI_RGB"), (1, "BI_RLE8"), (3, "BI_BITFIELDS")];
const FLAGS: FlagTable = &[flag(0x1, "READONLY"), field(0xf0, 0x10, "KIND_A")];
```

Variable layouts are ordinary Rust over `Fields` (a cursor over an in-memory
`Block` that emits as it decodes) or `Cursor` (async, over a region). A
*layout function* `fn(&mut Fields<'_>, &Ctx) -> Result<T>` serves both
purposes: `parse(&cx, span, endian, &ctx, layout)` decodes silently,
`struct_node(name, span, endian, ctx, layout)` renders it lazily.

## 4. Walking sequences

```rust
let mut cur = Cursor::new(&cx, input.span, Endian::Big);
while !cur.at_end() {
    let start = cur.pos();
    let (h, _) = cur.record::<ChunkHeader>().await?;
    cur.skip(h.len.into());
    let span = cur.since(start);
    cx.push(Node::new(h.name()).span(span).summary(...).lazy(chunk, (input, span))).await;
}
```

Cursor has `record`, `bytes`, `peek`, `u8..u64`, `int::<T>`, `uleb128`,
`sleb128`, `cstr`, `skip`, `seek`, `pos`, `remaining`, `at_end`, `span(n)`,
`since(start)`.

**Chunked formats** (an ID and a size, repeated) use `cur.chunk(layout)`,
which returns the next `Chunk { id, span, body }` and advances past it and
any padding. `ChunkLayout::IFF` and `ChunkLayout::RIFF` are predefined;
others are built: `ChunkLayout::new(4, 4, Endian::Big).size_first()
.inclusive().align(2)` (ID bytes, size bytes, byte order; size before ID;
size counts the header; alignment). Undersized or overrunning chunks are
errors, so a loop over it always terminates:

```rust
while let Some(chunk) = cur.chunk(ChunkLayout::new(4, 4, Endian::Little)).await? {
    let mut node = chunk.node();          // "ID — N bytes"
    if chunk.id == b"NAME" { /* read chunk.body */ }
    cx.push(node).await;
}
```

**Large collections** (thousands of entries or more: archive members,
lines, records) should record **resume marks**, so a host that seeks deep
into the collection does not re-walk it from the start. Mark the walker's
state right before pushing, and restore it at the start:

```rust
let (pos, mut index) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
cur.seek(pos);
while !cur.at_end() {
    let at = (cur.pos(), index);
    cx.mark(move || at);            // cheap: kept every 256 children
    // ... read the entry, push it ...
    index += 1;
}
```

On a resumed run the next child pushed must be the one the mark was taken
before, so the state must include everything the loop carries (counters,
totals used in a later `annotate`). Children emitted before the loop are
not re-emitted on a resumed run, so keep marks to walkers whose children
are all pushed in the loop (see `tar.rs`, `zip.rs`, `text/plain.rs`).
`cx.skipping()` tells a walker that the next child lies before the host's
window and will be dropped, if building it is expensive.

A walker over a file that is mostly holes (lastlog, indexed by UID; a
sparse table) asks `cx.next_data(span).await` where data may resume, like
`SEEK_DATA`: the offset into `span` of the first byte not known to be a
hole, or `None` if the rest is holes. Holes are what the host declared
with `Session::set_holes` (from `SEEK_HOLE`/`SEEK_DATA` or `FIEMAP`) and
the zero pieces of piecewise sources (sparse files inside a file system
image), and the gaps decoding has already passed in content decoded on
demand by a codec that skips them (an ntfsclone or Partclone volume); a
host that declares none gets `Some(0)`, so the walker behaves as before.
Reads wholly inside declared holes are answered as zeros without asking
the host. What decoding has found depends on what was read before, so use
the answer only to skip reading bytes you would find to be zeros, never to
decide what nodes or summaries to build.

A walker that does not know its count up front (tar, a scan over records)
should report progress for the host's display: `cx.progress(done, total)`,
or `cx.progress_in(input.span, pos)` with its position in its input (over a
lazily decoded source that reports encoded bytes consumed, read when the
host asks, since the decoded length may not be known yet). With an exact
count from `cx.set_count`, the session reports children produced instead.

The session also measures what it can without help, used when nothing
was reported (`Session::activity`): while an expansion is suspended
inside a read that decodes a stream (a far read into a decompressed
member), how far that decoding has got; otherwise where its last read
ended within the node's span. So a dissector need not report from inside
a read, and a plain sequential walk gets progress for free. Report it
yourself when your position says more than your reads do: a walk that
jumps around (reads a directory at the end first), one over a lazily
decoded source (where only you know your position is in the encoded
stream), or one with a known count. Once you report, your report wins,
so report from inner loops too, not only per outer element: a walker
that reports at each frame but then walks a single frame of a million
blocks shows no movement (zstd and LZ4 report every 4096 blocks).

### Accounting for work

This is the rule most easily broken and most expensive to get wrong. The
host drives expansions in budgeted steps (`Session::poll`/`poll_node`, a
few thousand units each) from a UI thread pool, releasing its lock between
steps so the hex view, other nodes and cancellation stay responsive. That
only works if **every stretch of work between two suspension points is
bounded by a constant, whatever the input**. One unbounded step freezes the
viewer on a large or hostile file, and nothing the host does can interrupt
it: the core has no clock and no preemption, by design. Budget units are
the only signal, so work that is not charged is invisible.

- Suspension points: a read (`cx.read`, `read_avail`, `block`, `cstr`),
  `cx.push`, `cx.checkpoint().await` (1 unit) and `cx.charge(n).await`
  (n units, for bounded synchronous work already done). Reads charge for
  their size, and reads of lazily decoded sources charge as they decode.
  Identification charges for the custom probes it ran over the head
  (about 1,500 units when nothing matches a full head), so content
  identified many times over (one node per BGZF block) is not free. A
  dissector that runs identification itself (to label a ZIP by its
  content, or to look past a long ID3 tag) calls
  `cx.registry().identify_costed(&head)` and charges the units it returns
  with `cx.charge`.
  Probes run on every identification: keep them cheap, and remember that
  dozens of them see the same head (text probes share one memoized
  encoding check, `text::encoding::classify`).
- Any loop whose iteration count depends on the input must reach one every
  iteration or every few hundred to few thousand cheap iterations. A single
  read does not pay for a loop over what it returned: reading 16 MiB costs
  about 4k units, but a byte-at-a-time parse of it is millions of
  operations. Charge the parse, not just the read.
- Charge in proportion to the work, not per call: if one iteration can be
  expensive (a KDF round, a hash of a large buffer, a nested scan), call
  `checkpoint` per chunk of that work (see `codec::crypto::run`). Aim for
  a unit to be on the order of a microsecond.
- Synchronous helpers count too. A pure function that parses, decodes,
  hashes, sorts or searches an input-sized buffer is an unbounded step
  however fast it looks on small fixtures. Make it async with checkpoints,
  make it resumable (a state struct with a `step`), or bound its input by a
  small constant. Recursive parsers become async with boxed recursion, or
  iterative with an explicit stack.
- Watch for hidden quadratics: a linear lookup (`iter().find`, `contains`,
  `position`) inside a loop over the input, re-parsing a prefix for each
  element, cloning an accumulated buffer per element. Each step may be
  charged, but the total explodes; index once (`BTreeMap`, `partition_point`,
  a cached table via `cx.cache`) instead.
- Codecs: a `Decode`/`Decoder` must do bounded work per call (about `step`
  bytes of output, or a bounded amount of input) and return `More` to be
  called again. A decoder that waits for all its input and decodes it in
  one call (`filters::Whole`) is only acceptable for inputs bounded by a
  small constant.
- Loops must also make progress every iteration: if an element has size
  zero, stop (or advance by a minimum) rather than looping forever. Beware
  `cx.read(region.sub(pos, n))` past the end: `sub` clamps, so the read
  succeeds with *fewer* (or zero) bytes; a loop that only stops at a
  terminator then never stops. Bound such loops by the region
  (`while pos < region.len`) or use `sub_exact`.

Interruption is what keeps a host responsive: every expansion runs in
budgeted polls, so an interactive host lets the user cancel whatever takes
too long, and sets no work limit (`Limits::max_work` is `None` by
default), since a limit would only fail legitimate long work: decoding far
into a large stream, a key derivation the user asked for. A host that
polls to completion unattended (batch runs, CI, thumbnailers) sets one,
and the session then stops an expansion after that many units with a
`Limit` diagnostic. The robustness tests set their own limit and fail if
any fixture or variant reaches it, so a hang in CI is a failure, not a
timeout. The limit only catches work that is charged; uncharged work is
caught by review.
Small fixtures hide all of this, so when writing a loop, ask what it does on
an input a thousand times larger than the fixture.

Measure rather than assume. The robustness sweep with `SWEEP_TIMES` set
(see section 9) prints each fixture's time next to its work units; a
fixture whose time per unit is far above a microsecond does
uncharged work somewhere. Tests that bound work assert units
(`Session::work_done`) or yield counts, never wall-clock time: timings
flake on a loaded machine. `common::POLL_CEILING` exists only as a
generous backstop for a whole input parsed in one step. Where counts in
the input are not bounded by the structure that holds them (a count field
claiming millions of elements from a few bytes, an entry referenced many
times, nesting by reference), add a test with a crafted input that checks
work and output stay bounded (see `tests/data_bounds.rs`).

## 5. Spans: `sub` versus `sub_exact`

- `span.sub(off, len)` clamps to the region. Reading it yields fewer bytes;
  field decoding then reports exactly which field is truncated. Use this for
  structures (partial results).
- `span.sub_exact(off, len)` fails with `Truncated` if the range does not
  fit. Use this before reading arrays whose size comes from the file, so a
  bogus count is rejected before anything is read or allocated.
- `span.tail(off)` is everything from `off` to the end.

## 6. Embedded content and compression

- `embedded(name, input.nested(span))`: lazy node that detects the format of
  `span` and dissects it (e.g. EXIF in a JPEG, an icon in a PE).
- `embedded_as(name, input.nested(span), &other::FORMAT)`: known format.
- `content(name, input, span, codec, expected)`: decodes on expansion into
  a derived source, then dissects in place. Large members (with a plausible
  `expected` size) are decoded lazily, only as far as reads reach. `codec`
  is a `crate::codec::Codec`: a single codec or `Codec::chain(name,
  lazy_name, [stages])` (filters, decryption, then decompression).
- Hand nested content to one of these (or to `formats::dissect_or_data` /
  `formats::dissect` from your own expander), never to another format's
  dissect function directly: that is where "inspect as"
  (`Session::reinterpret`) takes effect. The first detection step an
  expansion reaches is the node's own; later ones are content nested inside
  it and are identified as usual.
- **Handing off.** A dissector that finds the content it was given is
  really another format (the MP3 probe claims files whose long ID3v2 tag
  hides FLAC or WavPack from the probes) hands it over instead of
  dissecting it as itself:
  `if cx.hand_off(&input, format) { return (format.dissect)(cx, input).await; }`.
  When `input` is what the node's own detection step settled, the node's
  interpretation becomes `format`, so the host shows (and "inspect as"
  starts from) the real format. `hand_off` returns `false` when the host
  forced the node's format with `Session::reinterpret` (or opened it with
  `Session::open_as`, which forces the root's format the same way); the
  dissector then carries on as itself. Hand off only to a format that will not hand back,
  and only content you were given; content found inside is embedded. (A
  family sharing one dissector, like ZIP's, needs no hand-off: the probes
  already picked the member, and `zip.rs` only refines its label when it
  was asked for plain ZIP.)
- **Writing a codec:** implement `codec::pipeline::Decode` (decode from all
  input so far into all output so far, a bounded step at a time; running
  out of input is just an error) and add a `Codec` variant. `Streaming`
  makes it resumable by rolling back steps that ran short, so it works
  lazily and inside chains with no extra effort. Report checksum problems
  through `Decode::warning`. By default a malformed-data error counts as a
  possible shortage until the input ends, so damage early in a large
  stream surfaces only once the whole stream has been fed; a codec that
  reports every shortage as `DiagKind::Truncated` (and nothing else as
  truncated) returns `true` from `Decode::truncation_is_exact`, and its
  other errors are reported at once. Block codecs get there by checking a
  block is whole before decoding it (see `zstd.rs`). A codec with no
  window whose stream describes long runs of zeros cheaply (the gaps of a
  disk image) opts in to skipping them: `Decode::window_free` returns
  `true`, `Decode::zero_run` reports the zeros parsed and not yet written,
  `Decode::skip_zeros` advances past them, and the step returns
  `Step::More` right after parsing a run instead of writing it (see
  `ntfsclone.rs`, `partclone.rs`, and "Zero runs" in `pipeline.rs`). Test
  it with `pipeline::decode_all_skipping`.
- Look at the `Codec` enum before writing a decoder: most compression
  schemes in the wild already have a variant (see the list in `DESIGN.md`).
  Container framings that wrap a codec (WIM chunk tables, CAB folders,
  Apple `pbz*`) are codecs too (`Codec::WimResource`, `Codec::CabFolder`,
  `Codec::Pbz`), so the container dissector can stay a thin walker.
- For a codec we do not have, emit a leaf with
  `Diagnostic::unsupported("LZMA compression")` and the span. Do not pull in
  crates (see the codec policy in `DESIGN.md`).
- `crate::codec::decode_span(&cx, span, &codec, expected)` if you need the
  decoded bytes yourself (e.g. a compressed text chunk); `cx.decode_lazy`
  for a lazily decoded source. Never read the *end* of a large lazily
  decoded member unless the user asked for it. Where a dissector reads
  something optional far away (a backup header in the last sector of a
  disk, a backup boot sector, an end-of-volume anchor), it asks
  `cx.read_is_cheap(span)` first and, when the read would decode far into
  content decoded on demand, emits `formats::util::far::deferred` in its
  place: a node that reads it, and runs the checks that depend on it,
  when expanded (see `gpt.rs`, `ntfs.rs`). The answer depends only on how
  the content is decoded (from the start, or from the container's seeds),
  not on what has been decoded so far, so the tree is the same each
  time. Structures a format cannot do without (a ZIP central directory, a
  VHD footer) are read wherever they are.
- Where the decoded size is not recorded (bzip2, zstd or LZ4 written to a
  pipe, Brotli), `expand_content(.., None)` decodes small streams eagerly
  and large ones with `cx.decode_lazy_unsized`: the source's length is then
  an upper bound until the stream has been read to its end
  (`Cx::len_known` / `Session::source_len_known`). Do not compute a total
  by walking the whole encoded stream first (e.g. summing per-frame sizes
  over every zstd block): that reads the entire file before the first
  decoded byte, which is exactly what lazy decoding avoids. Where the
  stream's own first header records a size but more may follow it (a zstd
  frame's content size, with possibly more frames after it), use
  `cx.decode_lazy_checked`: the size is taken as the length, and a read
  that reaches it decodes on to check the stream ends there, reporting it
  on the node being expanded if it does not.
- Content of unknown length reaches only the formats in `formats::STREAMING`
  (tar, cpio, ntfsclone and Partclone images, plain text) with its length unknown; every
  other format gets the stream decoded to its end first and sees the real
  length, so ordinary dissectors can rely on `input.span.len`. A streaming format must not
  count, estimate, size spans or look for trailers from the length while
  `cx.len_known(input.span.source)` is false. To add one, make
  `tests/unsized.rs` and a large unsized test pass. Probes see
  `Head::len_known`: with the length unknown, `len` is only an upper bound,
  so a declared size that "fits" is no evidence (see the BSON probe).
- **Fragmented data** (FAT cluster chains, ext4 extents, NTFS runs, CFB
  sector chains, SQLite overflow pages): describe it as pieces instead of
  copying it: `cx.add_pieces(Origin { parent, transform: "fat-chain" },
  vec![span_a, span_b, ...])` returns a span of a new source whose reads are
  mapped onto the pieces (through the cache, no copy, any size). Then
  `embedded(name, input.nested(span))`. Provenance stays exact:
  `Session::resolve(span)` maps it back to file offsets. Holes (sparse
  files, unallocated virtual-disk blocks) are `Span::zeros(len)` pieces:
  they read as zeros and resolve to nothing. `formats::disk::PieceList`
  collects and merges pieces for you.
- **Images of compressed or sparse blocks** (QCOW2 clusters, VMDK grains,
  DMG and Android sparse chunks, zisofs blocks) are assembled the same way:
  one piece per unit, with each compressed unit a piece of its own
  `cx.decode_lazy(span, &codec, size)` source, so only the units a read
  reaches are decoded (see `qcow.rs`, `dmg.rs`). Never decode a whole image
  when the node is expanded: that worked on fixtures and froze on real
  disks. Where a container records restart points of one long stream (an
  xz index, a BGZF block list, a WIM chunk table), pass them as seeds
  (`cx.decode_lazy_seeded`, or `formats::expand_content_seeded`), so a far
  read starts at the nearest one.
- **Decoded data** you computed yourself (base64, quoted-printable, a custom
  decompressor): `cx.add_derived(Origin { parent, transform: "base64" },
  bytes, consumed, error)`. Counts against `Limits::max_derived`.

### Encrypted content

Ask for a password only when the user expands encrypted content, never in
a probe or a top-level listing:

```rust
// Try the free default first (PDF's empty user password, a known key).
let key = match derive_key(b"") {
    Some(k) => k,
    None => match cx.unlock(archive_span, "Password for the ZIP entries", |s| check(s)).await {
        Some(secret) => derive_key(secret.expose()).unwrap_or_default(),
        None => return Err(Diagnostic::unsupported("encrypted (no password)").at(span)),
    },
};
```

- The *realm* (first argument) is the container the password unlocks; use
  the same span for every entry so the user is asked once.
- `cx.unlock` asks up to `secret::MAX_ATTEMPTS` times while `verify`
  rejects the answer; `None` means declined or exhausted. Verify wherever
  the format has a check value (ZIP check byte, AES verifier, MAC, PDF `/U`).
- Derive sources from the plaintext only *after* verification: derived
  sources are memoized by `Origin`, which does not include the secret.
- Expensive key derivations (high-iteration PBKDF2, scrypt, Argon2) must
  run in budgeted steps: loop over `cx.secret(...)` yourself and run the
  derivation as a `codec::crypto::Stepped` through `codec::crypto::run`,
  which charges its work and reports its progress, so a host shows a long
  derivation running and the user can cancel it knowing what it is. Refuse
  a derivation up front only for what no host could afford (memory beyond
  `max_derived`), or for its cost when the host set a `max_work` it could
  not finish within; without one, it runs.
- Never put secrets or derived keys in node values or diagnostics.
- Test fixtures use the password `fillyfoal`; the test host answers with it.

## 7. Values and presentation

Prefer typed values over formatted strings: `Value::UInt` (with radix),
`Int`, `Float`, `Enum`, `Flags`, `Timestamp`, `Text`, `Bytes`, `Guid`,
`Checksum`, `Size`, `Duration`. Put
human interpretation in `summary` ("640×480, 24-bit") and meaning in
`desc`. Which value to use:

- **Floats:** construct with the width the file stores: `Value::f32(x)`
  (never widen an `f32` to `f64` first, or it prints `0.800000011920929`),
  `Value::f64`, `Value::f16` (already widened by `floats::f16`) and
  `Value::f80`. `Fields::f32`/`f64` do this. A float computed from
  integers (fixed point, a scale factor) is `Value::f64`. To print one in a
  summary, use `render::float(value, bits)`.
- **Radix:** `Radix::Hex` (`.hex()`, `val::hex`) for magic numbers, offsets
  and bit patterns; `Radix::Oct` (`.oct()`, `val::oct`) for Unix modes,
  with `unix_mode(..)` as the summary (`Mode: 0o100644 — -rw-r--r--`);
  `Radix::Bin` for a small bit field whose pattern matters.
- **Enums:** a static table through `.enumeration(T)` or `val::enumv`.
  When the name is computed (a known-ID function, a name built from parts),
  use `Value::named(raw, bits, name)` rather than a hex value with the name
  in the summary.
- **Timestamps:** `Value::Timestamp(Time)`, saying what the file recorded,
  never a date in `Text` or a number with a date summary:
  - *Zone:* `Time::utc(secs)` (or `Value::utc`) when the field is UTC;
    `Time::offset(utc_secs, minutes)` / `Time::offset_wall(wall_secs,
    minutes)` when the file records its offset (ISO 9660, UDF, exFAT, RFC
    5322 dates, ISO 8601 text with `+hh:mm`); `Time::local(wall_secs)` for a
    wall clock in an unrecorded zone (DOS dates, classic HFS and the HFS+
    creation date, SYSTEMTIME in files, Word DTTM, camera clocks, SQL
    DATETIME, TempleOS). Never convert a local time and never put
    "(local time)" or "UTC" in a field name: the value says it.
  - *Precision:* `.day()` for a date alone, `.minute()`, whole seconds by
    default, and the fraction with the digits the format stores:
    `.millis(ms)`, `.micros(us)`, `.nanos(ns)`, `.frac(nanos, digits)`;
    epoch counts through `Time::unix_millis` / `unix_micros` / `unix_nanos`
    (fields: `.unix_millis()` and friends), FILETIME through
    `Value::filetime` (`.filetime()`), DOS stamps through `val::dos` /
    `val::dos_stamp` (`Time::dos`, `Time::dos_date`). The text leaves out a
    zero fraction; `Time::text_full` keeps it (listings), `Time::iso8601`
    gives RFC 3339. ISO 8601 text parses with `formats::text::parse_time`.
  - *Sentinels:* a zero or all-zero timestamp that means "none" is
    `node.not_set()` (no value, summary "not set"); `.filetime()` does it
    for 0. A raw number that is not a time (ticks of a clock that starts
    at boot, a duration) stays a number with a summary.
- **Checksums** (CRCs, sums, digests, MACs, tags): a `Checksum(Check)`,
  never a hex number with "valid" in its summary or a digest in `Bytes`
  (which shows 16 bytes) or hex `Text`:
  - *Algorithm:* its usual name ("CRC-32", "CRC-32C", "Adler-32",
    "SHA-256", "HMAC-SHA-256"), with the variant when it matters
    ("CRC-32 (not inverted)", "CRC-32C (low 16 bits)"), or the format's
    own ("Internet checksum", "8-bit sum", "lookup3"). Keep a format's
    algorithm in one `const`.
  - *Verdict:* `Check::new(algo, stored)` is not checked;
    `.verify(computed)` makes it valid or a mismatch (keep the computed
    value: hosts show both); `.verified(ok)` when only a comparison is
    known (sums that must come to zero, AEAD tags, frames found by their
    CRC); `.skipped(reason)` when the dissector could but did not ("empty
    block", "covers 40 MiB", "needs the key"); `.on_decode()` when the
    decoder verifies it. A zero meaning "none" is
    `.skipped("zero: none recorded")`.
  - *Fields:* `.checksum(algo)` turns a number or byte field into an
    unchecked check, `.verify(computed)` / `.with_check(f)` give it its
    verdict, `.checksum_if(on, algo)` when a feature flag decides whether
    the field is one. A record verified from outside its own bytes:
    `Record::checked_node(name, span, endian, check.at(offset))`, or
    `Fields::verifying` in a hand-written layout. A node:
    `Node::checksum(check)` / `Node::with_check`.
  - *Mismatches* are warnings in one wording (`CRC-32 mismatch: stored
    X, computed Y`), added by `Node::checksum`; a parent that contains
    the field (a header, a page) repeats it with `node.check_diag(&check)`
    so it shows collapsed, and does not say "checksum valid" in its
    summary unless the check is not shown as a field.

- **Sizes** (a field that counts bytes): a `Size`, never a number with
  `fmt::size` as its summary (`Length: 698 — 698 bytes`). Fields:
  `.size()`, or `.size_in(block)` for a count of sectors, clusters or
  pages (`2048 × 512 bytes (1 MiB)`); nodes: `Value::size(n)` /
  `val::size(n, bits)`, `Value::blocks(n, block)`, or `node.as_size()`
  / `as_blocks(block)` on a node whose number is the size (readers that
  aren't `Fields`, bit fields, `Num::Size` for text-encoded archive
  numbers, protobuf `Ty::Size`). Don't put the unit in the name
  ("Capacity (sectors)"). Counts of other things stay `UInt`, and so do
  values that encode a size rather than count it (a log2 block size,
  zlib's CINFO, "size − 1"): those keep the size in the summary. A
  sentinel ("unlimited", "in the Zip64 extra field") is a summary on
  the number. A node without a value may give its own length as a
  summary (`fmt::size`).
- **Durations** (a span of time: a delay, a TTL, a media timestamp on a
  stream clock, an uptime, CPU time): a `Duration` of the ticks the file
  stores, `.duration(per_sec)` (1 for seconds, 1000 for ms, 100 for
  centiseconds, 10_000_000 for 100 ns units, 90_000 for MPEG, a track's
  timescale, a sample rate for sample counts), `Value::duration(ticks,
  per_sec)`, `node.as_duration(per_sec)`, protobuf `Ty::Duration`. Keep
  the stored ticks (don't divide them to milliseconds first), and don't
  put the unit in the name ("Interval (ms)"). A point in time is a
  `Timestamp`, including the sub-second part of one ("Modified (ns)"
  stays a number). A count of frames or samples whose duration is
  incidental may stay a count with a duration summary. Summaries use
  `fmt::duration(ticks, per_sec)` / `fmt::duration_of` /
  `fmt::seconds(f64)`; never write another duration formatter.

Annotate the file node with `cx.annotate("PE32+ DLL, AMD64")`: that
summary is the first thing the user sees on F3.

Helpers: `crate::bytes::{u16_le, u32_be, ..., uleb128}`,
`crate::text::{utf16z, latin1, until_nul, looks_like_text, dos_datetime,
filetime_to_unix, mac_to_unix}`, `crate::codec::{crc32, adler32}`,
`crate::codec::crc` (CRC-32C, CRC-64/XZ, CRC-24, CRC-16 variants, CRC-8, or
`Crc::new(width, poly, init, reflected, xorout)` for another; never write a
bitwise CRC loop), `crate::codec::charset` (single-byte and East Asian double-byte code pages by WHATWG
label).

## 8. Rules (enforced by lints and tests)

- No `unsafe`, no `unwrap`/`expect`/`panic!`, no indexing or slicing that can
  panic (`.get(..)`), no unchecked arithmetic (`saturating_*`, `checked_*`).
- Allocate only in proportion to bytes actually read, never from a count
  field alone. Use `sub_exact` + `cx.read` for tables.
- Bounded work between suspension points, charged in proportion to the
  work done (see "Accounting for work" in section 4).
- Deterministic output: no hash-map iteration order, no clocks.
- Recursion: an expander that refers to itself (directly or mutually) must
  use `node.lazy(crate::expander!(self::walk: State), state)`. If a local
  variable shadows the function name, use the `self::` path. A recursive
  *helper* `async fn` (not an expander) needs a boxed future with an
  explicit `Send` bound, e.g.
  `fn walk_boxed<'a>(..) -> Pin<Box<dyn Future<Output = Result<Node>> + Send + 'a>> { Box::pin(walk(..)) }`,
  and calls itself through that (see `nar_node` in `devtools.rs`).
- Graph-shaped formats: detect cycles and cap depth with `dsl::Path`
  (`path.enter(id, max_depth)` returns the child path or a diagnostic); keep
  the path in the expander state.
- Parsing the same structure for many nodes (an object stream, a string
  table)? Parse once and share it: `cx.cached::<T>(span, "kind")` /
  `cx.cache(span, "kind", Arc::new(value))`.
- Rust 1.88 (the MSRV): no `if let` guards in `match` arms or other syntax
  stabilised later.

A change must pass the whole gate before it is merged (CI runs the same):

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets
cargo test --workspace
for f in text archive data image av security exec docs system science games; do
  cargo check -p fillyfoal --lib --no-default-features --features "$f"
done
cargo +1.88 check --lib --workspace
```

## 9. Testing

Put small sample files in one of two trees, keeping the `<format>/<file>`
layout:

- `tests/fixtures/external/<format>/` for files written by an
  implementation other than ours: a real tool or library (`ffmpeg`, `xz`,
  `zstd`, `7zz`, `zip`, `bsdtar`, `hdiutil`, `aa`, `openssl`, `sqlite3`,
  clang, Python's `tarfile`/`zipfile`/`email`/`pickle`, pyarrow, pysam, ...)
  or found in the wild. **Every external fixture must be listed in
  `tests/fixtures/external/SOURCES.md`** with its producer (and version if
  known), the evidence (best: the command that reproduces it byte for byte)
  and any edits made afterwards (scrubbed IDs, fixed checksums, truncation).
- `tests/fixtures/synthetic/<format>/` for everything else: files written by
  our generator scripts or by hand from the spec, containers our scripts
  assembled around real codec output, and anything whose provenance is
  unclear. Their snapshots lock behaviour in; they do not show correctness
  (see `tests/fixtures/synthetic/README.md`).

Prefer external fixtures: a real writer is the only check that the
dissector agrees with the format as others implement it. A synthetic
fixture written from the same reading of the spec as the dissector agrees
with it whether or not that reading is right; such fixtures have hidden
wrong paddings, header sizes, flag bits and opcode tables that the first
real file exposed. So:

- Make a fixture with the real tool when one exists, and list it in
  `SOURCES.md` with the producer, its version and the exact commands.
- A synthetic binary fixture comes from a generator committed under
  `tests/data/<format>/` (hand-written text fixtures need none). If no real
  tool is at hand, cross-check the layout against a real file or a second
  independent description before trusting the snapshot, and say in the
  module docs which parts are unverified.
- Privacy: the repository is public. Build fixtures in a neutral
  directory under `/tmp`, with neutral authors, owners and host names
  (`fillyfoal`), and map build paths away (`-ffile-prefix-map`). Before
  committing, scan each new fixture for your user, full and host names and
  home path, in ASCII and UTF-16 and inside compressed streams and archive
  members. Never use someone's personal files as fixtures.
- Provenance of code: read only sources whose licence is compatible with
  GPLv3 (never unRAR's). If you followed an upstream implementation
  closely, say so in the module docs and add its notice and licence text
  to `THIRD-PARTY.md`. If you wrote a layout from memory, say that plainly.
- File names must be valid on Windows: no reserved device names (`nul`,
  `con`, `aux`, `prn`, `com1`, `lpt1`, whatever the extension) and none of
  `<>:"|?*\`, no trailing dot or space. `fixtures_are_classified`
  enforces it.

Every fixture is automatically fully explored and snapshotted
(`tests/snapshots/`, named `formats__<format>__<file>.snap` whichever tree
it is in), then truncated at many lengths and mutated hundreds of times;
every variant must settle without panics, hangs or internal errors. Keep
fixtures small (ideally < 16 KiB; larger only when the real tool cannot
write anything smaller), never commit files you did not create or that are
not freely redistributable, and never put the same `<format>/<file>` in
both trees. `fixtures_are_classified` checks the layout and that
`SOURCES.md` covers every external fixture.

```sh
FIXTURE=bmp INSTA_UPDATE=always cargo test --test formats   # write snapshots
cargo run --example inspect -- file --depth 3                # look at it
```

then the full gate from section 8.

Formats identified by an exact image size (e.g. D64, ADF) need full-size
fixtures; store those as `name.ext.gz` (`gzip -9 -n`) and the harness
decompresses them first. Whole filesystem images whose smallest size is
megabytes (XFS, F2FS, ...) are stored as `name.ext.raw.zst` (`zstd -19`):
the harness (`common::fixture_bytes`) decompresses them, so the dissector
sees the raw image, and their snapshots keep the stored file name. Other
`.zst` and `.gz` fixtures (and everything in `gzip/`) are genuine tests of
those formats. Robustness sweeps over images larger than 4 MiB truncate
mostly within the first 4 MiB and run fewer mutation rounds. A fixture
whose one exploration costs more than `common::HEAVY_WORK` units
(measured with `Session::work_done`, so the same on every machine; today
two key derivations a tool fixes) gets truncations and mutations in
inverse proportion to its work, at least 30 of each; fixtures whose time
is not charged in units are listed with a reason in `common::SLOW_SWEEPS`
until it is. `SWEEP_TIMES=20 cargo test --test formats --
fixtures_are_robust --nocapture` prints the slowest sweeps and every
scaled-down one. Each fixture's `<format>` directory names the format
it must be identified as (`fixtures_are_identified_correctly`).

Review the snapshot by eye: it is the best check that values and spans are
right.

**Snapshot size.** Every fixture is explored completely (the robustness
and resume tests compare whole trees), but its snapshot renders a bounded
view (`common::snapshot_tree`), so a large fixture cannot bloat the
repository with repetition:

- A list of at most 8 children (a file's sections, a record's fields) is
  always rendered whole.
- A longer list renders its children with their subtrees, in order, until
  it has rendered 64 KiB; later children show their own line (and
  diagnostics) with `(+N nodes elided)` for the subtree left out; after 256
  of those, `… K more children elided (N nodes)` stands for the rest,
  followed by the last child's line.
- Whatever remains is cut at 256 KiB, with a last line counting what was
  cut.

Elision lines count nodes and diagnostics, so a change in an elided part
still changes the snapshot. To review a part that is elided, run the
inspector on the fixture. If a fixture's snapshot hits the 256 KiB cut,
its interesting part may well be cut too: shrink the fixture rather than
raise the cap.
