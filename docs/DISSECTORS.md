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

Loops whose length depends on the input must make progress every iteration
and must hit a suspension point (`push`, a read, or `cx.checkpoint().await`).
If an element has size zero, stop (or advance by a minimum) rather than
looping forever.

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
- `content(name, input, span, Codec::{Stored, Deflate, Zlib}, expected)`:
  decompresses on expansion into a derived source, then dissects in place.
- For a codec we do not have, emit a leaf with
  `Diagnostic::unsupported("LZMA compression")` and the span. Do not pull in
  crates (see the codec policy in `DESIGN.md`).
- `crate::codec::inflate_span(&cx, span, zlib, expected)` if you need the
  decoded bytes yourself (e.g. a compressed text chunk).

## 7. Values and presentation

Prefer typed values over formatted strings: `Value::UInt` (with radix),
`Int`, `Float`, `Enum`, `Flags`, `Timestamp`, `Text`, `Bytes`, `Guid`. Put
human interpretation in `summary` ("640×480, 24-bit") and meaning in
`desc`. Annotate the file node with `cx.annotate("PE32+ DLL, AMD64")`: that
summary is the first thing the user sees on F3.

Helpers: `crate::bytes::{u16_le, u32_be, ..., uleb128}`,
`crate::text::{utf16z, latin1, until_nul, looks_like_text, dos_datetime,
filetime_to_unix, mac_to_unix}`, `crate::codec::{crc32, adler32}`.

## 8. Rules (enforced by lints and tests)

- No `unsafe`, no `unwrap`/`expect`/`panic!`, no indexing or slicing that can
  panic (`.get(..)`), no unchecked arithmetic (`saturating_*`, `checked_*`).
- Allocate only in proportion to bytes actually read, never from a count
  field alone. Use `sub_exact` + `cx.read` for tables.
- Deterministic output: no hash-map iteration order, no clocks.
- Recursion: an expander that refers to itself (directly or mutually) must
  use `node.lazy(crate::expander!(self::walk: State), state)`. If a local
  variable shadows the function name, use the `self::` path.
- Graph-shaped formats: detect cycles (keep the path of visited offsets in
  the state) and cap depth with a `Diagnostic::limit`.

## 9. Testing

Put small sample files in `tests/fixtures/<format>/`. Every fixture is
automatically fully explored and snapshotted (`tests/snapshots/`), then
truncated at many lengths and mutated hundreds of times; every variant must
settle without panics, hangs or internal errors. Generate fixtures with real
tools where possible (`ffmpeg`, `zip`, `tar`, `sqlite3`, `python3`), keep
them small (ideally < 16 KiB, never > 64 KiB), and never commit files you did
not create.

```sh
FIXTURE=bmp INSTA_UPDATE=always cargo test --test formats   # write snapshots
cargo test && cargo clippy --all-targets                     # must be clean
cargo run --example inspect -- file --depth 3                # look at it
```

Review the snapshot by eye: it is the best check that values and spans are
right.
