# Writing a dissector

This is the practical guide for adding a format. Read `DESIGN.md` for the
why; this is the how. Good examples to copy from:

| Pattern | Example |
|---|---|
| Fixed header + chunk stream (big-endian, CRCs) | `src/formats/png.rs` |
| Header + compressed payload dissected in place | `src/formats/gzip.rs` |
| Directory at the end, paged entries, variants by probe | `src/formats/zip.rs` |
| Pointers/RVAs, many lazy sub-structures, recursion | `src/formats/pe/` |
| Recursive variable-length blocks | `src/formats/pe/version.rs` |
| Text: windowed lines/tokens, encodings, base64 into derived sources | `src/formats/text/` (`scan`, `piece`, `encoding`, `decode`) |

## 1. Register the format

Create `src/formats/<name>.rs` (or a directory for big families) and add it
to `src/formats/mod.rs` in two places, inside the right family section:
the `pub mod` list and the `FORMATS` array. Order in `FORMATS` matters:
probes run top to bottom, so specific formats go before generic ones.

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

Probes see the first `HEAD_LEN` (36 KiB) and last `TAIL_LEN` (1 KiB) bytes
and the total length. Make them cheap and specific: check more than two magic
bytes when you can (versions, sizes that must be sane), because a false
positive hides the right format. Weak magics (one or two bytes) need a
`Probe::Custom` with extra checks.

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
`.flags(TABLE)`, `.timestamp()`, `.filetime()`, `.mac_time()`,
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

Loops whose length depends on the input must make progress every iteration
and must hit a suspension point (`push`, a read, or `cx.checkpoint().await`).
If an element has size zero, stop (or advance by a minimum) rather than
looping forever. Beware `cx.read(region.sub(pos, n))` past the end: `sub`
clamps, so the read succeeds with *fewer* (or zero) bytes; a loop that only
stops at a terminator then never stops. Bound such loops by the region
(`while pos < region.len`) or use `sub_exact`. As a safety net the session
stops any expansion after `Limits::max_work` units, and the robustness
tests fail if that ever happens on a fixture.

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
- **Writing a codec:** implement `codec::pipeline::Decode` (decode from all
  input so far into all output so far, a bounded step at a time; running
  out of input is just an error) and add a `Codec` variant. `Streaming`
  makes it resumable by rolling back steps that ran short, so it works
  lazily and inside chains with no extra effort. Report checksum problems
  through `Decode::warning`.
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
  decoded member unless the user asked for it.
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
  run in budgeted steps: loop over `cx.secret(...)` yourself and call
  `cx.checkpoint().await` between rounds.
- Never put secrets or derived keys in node values or diagnostics.
- Test fixtures use the password `fillyfoal`; the test host answers with it.

## 7. Values and presentation

Prefer typed values over formatted strings: `Value::UInt` (with radix),
`Int`, `Float`, `Enum`, `Flags`, `Timestamp`, `Text`, `Bytes`, `Guid`. Put
human interpretation in `summary` ("640×480, 24-bit") and meaning in
`desc`. Annotate the file node with `cx.annotate("PE32+ DLL, AMD64")`: that
summary is the first thing the user sees on F3.

Helpers: `crate::bytes::{u16_le, u32_be, ..., uleb128}`,
`crate::text::{utf16z, latin1, until_nul, looks_like_text, dos_datetime,
filetime_to_unix, mac_to_unix}`, `crate::codec::{crc32, adler32}`,
`crate::codec::crc` (CRC-32C, CRC-64/XZ, CRC-24, CRC-16 variants, CRC-8, or
`Crc::new(width, poly, init, reflected, xorout)` for another; never write a
bitwise CRC loop), `crate::codec::charset` (single-byte code pages by WHATWG
label).

## 8. Rules (enforced by lints and tests)

- No `unsafe`, no `unwrap`/`expect`/`panic!`, no indexing or slicing that can
  panic (`.get(..)`), no unchecked arithmetic (`saturating_*`, `checked_*`).
- Allocate only in proportion to bytes actually read, never from a count
  field alone. Use `sub_exact` + `cx.read` for tables.
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
dissector agrees with the format as others implement it. Every fixture is
automatically fully explored and snapshotted (`tests/snapshots/`, named
`formats__<format>__<file>.snap` whichever tree it is in), then truncated at
many lengths and mutated hundreds of times; every variant must settle
without panics, hangs or internal errors. Keep fixtures small (ideally
< 16 KiB, never > 64 KiB), never commit files you did not create or that
are not freely redistributable, and never put the same `<format>/<file>` in
both trees. `fixtures_are_classified` checks the layout and that
`SOURCES.md` covers every external fixture.

```sh
FIXTURE=bmp INSTA_UPDATE=always cargo test --test formats   # write snapshots
cargo test && cargo clippy --all-targets                     # must be clean
cargo run --example inspect -- file --depth 3                # look at it
```

Formats identified by an exact image size (e.g. D64, ADF) need full-size
fixtures; store those as `name.ext.gz` (`gzip -9 -n`) and the harness
decompresses them first. Each fixture's `<format>` directory names the format
it must be identified as (`fixtures_are_identified_correctly`).

Review the snapshot by eye: it is the best check that values and spans are
right.
