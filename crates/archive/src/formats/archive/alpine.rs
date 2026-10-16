//! Alpine Linux APK v3 packages and indexes: the "ADB" format of apk-tools
//! 3 (`apk mkpkg`, `apk mkndx`).
//!
//! A file is `ADB.` and a schema ID (`pckg` package, `indx` repository
//! index, `idb` installed database), then 8-byte aligned blocks, each with a
//! 32-bit tag (2 bits of type, 30 of size including the tag; type 3 is an
//! extended header with a 64-bit size): one ADB block holding the metadata
//! tree, SIG blocks with signatures of it, and DATA blocks with file
//! contents. A compressed file is `ADBd` and a raw DEFLATE stream of the
//! whole uncompressed file, or `ADBc`, an algorithm and level byte, and the
//! stream (DEFLATE or Zstandard).
//!
//! The ADB block starts with a small header (compatibility version, version
//! and the root value). Values are 32-bit tags: 4 bits of type and 28 bits
//! that are either the value (integers up to 2^28, null, true, false) or an
//! offset into the block (32- and 64-bit integers, blobs with an 8-, 16- or
//! 32-bit length, and arrays and objects: a slot count, itself included,
//! then the slots). The format carries no field names; they come from apk's
//! schemas, keyed by slot number. Equal values are stored once, so the
//! tree is a graph; expansion follows it with a cycle check.
//!
//! A DATA block holds a file's content after the 1-based indexes of its
//! directory in the package's `paths` and of the file in that directory's
//! `files`; the dissector resolves them to the file's path.
//!
//! Layout and schemas from apk-tools' `doc/apk-v3.5.scd`, `src/adb.h`,
//! `src/apk_adb.h`, `src/apk_adb.c` and `src/adb_comp.c` (GPL-2.0; facts
//! only), checked against files written by apk-tools 3.0.7.

use crate::bytes::{to_u64, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::dsl::Path;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::fmt::plural;
use crate::formats::{Codec, Head, Input, Probe, content, embedded};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Radix, Value, flag};

const LE: Endian = Endian::Little;
/// Arrays and objects nested deeper than this are not expanded.
const MAX_DEPTH: usize = 32;
/// Slots read at a time from a large array or object.
const SLOT_WINDOW: u64 = 4096;
/// How much of a blob is shown as text.
const TEXT_MAX: u64 = 4096;

pub static FORMAT: crate::formats::Format = crate::formats::Format {
    name: "alpine-apk-v3",
    title: "Alpine APK v3 package or index (ADB)",
    extensions: &["apk", "adb"],
    mime: "application/vnd.apk",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

/// `ADB.` with an ADB block next; `ADBd` with a DEFLATE block header that
/// is not the reserved type; `ADBc` with a known algorithm and level.
fn probe(h: &Head<'_>) -> bool {
    let d = h.data;
    if !h.starts_with(b"ADB") {
        return false;
    }
    match d.get(3) {
        Some(b'.') => u32_le(d, 8).is_some_and(|t| t >> 30 == 0 && (t & 0x3fff_ffff) >= 12),
        Some(b'd') => d.get(4).is_some_and(|b| (b >> 1) & 3 != 3),
        Some(b'c') => matches!(d.get(4), Some(0..=2)) && d.get(5).is_some_and(|&l| l <= 22),
        _ => false,
    }
}

const SCHEMA: EnumTable = &[
    (0x676b_6370, "pckg (package)"),
    (0x7864_6e69, "indx (repository index)"),
    (0x0062_6469, "idb (installed database)"),
];

const BLOCK_TYPE: EnumTable = &[(0, "ADB"), (1, "SIG"), (2, "DATA"), (3, "EXT")];

const COMPRESSION: EnumTable = &[(0, "none"), (1, "deflate"), (2, "zstd")];

const HASH_ALG: EnumTable = &[
    (0, "none"),
    // apk-tools has since dropped it (`APK_DIGEST_MD5`, "support removed").
    (1, "MD5"),
    (2, "SHA-1"),
    (3, "SHA-256"),
    (4, "SHA-512"),
    (5, "SHA-256/160"),
];

const DEP_MATCH: FlagTable = &[
    flag(1, "EQUAL"),
    flag(2, "LESS"),
    flag(4, "GREATER"),
    flag(8, "FUZZY"),
    flag(16, "CONFLICT"),
];

// ---------------------------------------------------------------------------
// Schemas (apk_adb.c)

/// How a value is shown.
#[derive(Clone, Copy, Debug)]
enum Ty {
    /// A string blob.
    Str,
    /// A multi-line string blob (scripts).
    MStr,
    /// A blob shown in hex (hashes).
    Hex,
    /// A symlink or device node target: the file mode, then the link text
    /// or device number.
    Target,
    /// An extended attribute: name, NUL, value.
    Xattr,
    Int,
    /// A Unix time.
    Time,
    /// A size in bytes.
    Size,
    /// A file mode.
    Oct,
    /// A dependency's version match.
    Match,
    Obj(&'static Obj),
    Arr(&'static Ty),
    /// A nested ADB (installed database packages); shown raw.
    Adb,
}

#[derive(Debug)]
struct Obj {
    name: &'static str,
    /// Field names and types, for slots 1, 2, ...
    fields: &'static [(&'static str, Ty)],
}

static STRINGS: Ty = Ty::Str;
static XATTRS: Ty = Ty::Xattr;

static DEPENDENCY: Obj = Obj {
    name: "dependency",
    fields: &[
        ("name", Ty::Str),
        ("version", Ty::Str),
        ("match", Ty::Match),
    ],
};
static DEPENDENCY_ITEM: Ty = Ty::Obj(&DEPENDENCY);

static PKGINFO: Obj = Obj {
    name: "package info",
    fields: &[
        ("name", Ty::Str),
        ("version", Ty::Str),
        ("hashes", Ty::Hex),
        ("description", Ty::Str),
        ("arch", Ty::Str),
        ("license", Ty::Str),
        ("origin", Ty::Str),
        ("maintainer", Ty::Str),
        ("url", Ty::Str),
        ("repo-commit", Ty::Hex),
        ("build-time", Ty::Time),
        ("installed-size", Ty::Size),
        ("file-size", Ty::Size),
        ("provider-priority", Ty::Int),
        ("depends", Ty::Arr(&DEPENDENCY_ITEM)),
        ("provides", Ty::Arr(&DEPENDENCY_ITEM)),
        ("replaces", Ty::Arr(&DEPENDENCY_ITEM)),
        ("install-if", Ty::Arr(&DEPENDENCY_ITEM)),
        ("recommends", Ty::Arr(&DEPENDENCY_ITEM)),
        ("layer", Ty::Int),
        ("tags", Ty::Arr(&STRINGS)),
    ],
};
static PKGINFO_ITEM: Ty = Ty::Obj(&PKGINFO);

static ACL: Obj = Obj {
    name: "acl",
    fields: &[
        ("mode", Ty::Oct),
        ("user", Ty::Str),
        ("group", Ty::Str),
        ("xattrs", Ty::Arr(&XATTRS)),
    ],
};

static FILE: Obj = Obj {
    name: "file",
    fields: &[
        ("name", Ty::Str),
        ("acl", Ty::Obj(&ACL)),
        ("size", Ty::Size),
        ("mtime", Ty::Time),
        ("hash", Ty::Hex),
        ("target", Ty::Target),
    ],
};
static FILE_ITEM: Ty = Ty::Obj(&FILE);

static DIR: Obj = Obj {
    name: "directory",
    fields: &[
        ("name", Ty::Str),
        ("acl", Ty::Obj(&ACL)),
        ("files", Ty::Arr(&FILE_ITEM)),
    ],
};
static DIR_ITEM: Ty = Ty::Obj(&DIR);

static SCRIPTS: Obj = Obj {
    name: "scripts",
    fields: &[
        ("trigger", Ty::MStr),
        ("pre-install", Ty::MStr),
        ("post-install", Ty::MStr),
        ("pre-deinstall", Ty::MStr),
        ("post-deinstall", Ty::MStr),
        ("pre-upgrade", Ty::MStr),
        ("post-upgrade", Ty::MStr),
    ],
};

static PACKAGE: Obj = Obj {
    name: "package",
    fields: &[
        ("info", Ty::Obj(&PKGINFO)),
        ("paths", Ty::Arr(&DIR_ITEM)),
        ("scripts", Ty::Obj(&SCRIPTS)),
        ("triggers", Ty::Arr(&STRINGS)),
        ("replaces-priority", Ty::Int),
    ],
};

static INDEX: Obj = Obj {
    name: "index",
    fields: &[
        ("description", Ty::Str),
        ("packages", Ty::Arr(&PKGINFO_ITEM)),
        ("pkgname-spec", Ty::Str),
    ],
};

static PACKAGE_ADB: Ty = Ty::Adb;

static IDB: Obj = Obj {
    name: "installed database",
    fields: &[("packages", Ty::Arr(&PACKAGE_ADB))],
};

static ANY: Obj = Obj {
    name: "object",
    fields: &[],
};

fn root_schema(schema: u32) -> &'static Obj {
    match schema {
        0x676b_6370 => &PACKAGE,
        0x7864_6e69 => &INDEX,
        0x0062_6469 => &IDB,
        _ => &ANY,
    }
}

// ---------------------------------------------------------------------------
// Values

const T_SPECIAL: u32 = 0x0;
const T_INT: u32 = 0x1;
const T_INT32: u32 = 0x2;
const T_INT64: u32 = 0x3;
const T_BLOB8: u32 = 0x8;
const T_BLOB16: u32 = 0x9;
const T_BLOB32: u32 = 0xa;
const T_ARRAY: u32 = 0xd;
const T_OBJECT: u32 = 0xe;

fn kind(v: u32) -> u32 {
    v >> 28
}

fn arg(v: u32) -> u64 {
    u64::from(v & 0x0fff_ffff)
}

/// The bytes of a blob value: its span inside the ADB block.
async fn blob(cx: &Cx, adb: Span, v: u32) -> Result<Option<Span>> {
    let width = match kind(v) {
        T_BLOB8 => 1u64,
        T_BLOB16 => 2,
        T_BLOB32 => 4,
        _ => return Ok(None),
    };
    let at = arg(v);
    let len_bytes = cx.read(adb.sub_exact(at, width)?).await?;
    let len = match width {
        1 => len_bytes.first().copied().map(u64::from),
        2 => u16_le(&len_bytes, 0).map(u64::from),
        _ => u32_le(&len_bytes, 0).map(u64::from),
    }
    .unwrap_or(0);
    Ok(Some(adb.sub_exact(at.saturating_add(width), len)?))
}

/// An integer value (direct or indirect).
async fn integer(cx: &Cx, adb: Span, v: u32) -> Result<Option<u64>> {
    Ok(match kind(v) {
        T_INT => Some(arg(v)),
        T_INT32 => u32_le(&cx.read(adb.sub_exact(arg(v), 4)?).await?, 0).map(u64::from),
        T_INT64 => u64_le(&cx.read(adb.sub_exact(arg(v), 8)?).await?, 0),
        _ => None,
    })
}

/// The slots of an array or object: where they start and how many (the
/// count slot excluded).
async fn slots(cx: &Cx, adb: Span, v: u32) -> Result<Option<(u64, u64)>> {
    if !matches!(kind(v), T_ARRAY | T_OBJECT) {
        return Ok(None);
    }
    let at = arg(v);
    let count = u32_le(&cx.read(adb.sub_exact(at, 4)?).await?, 0).unwrap_or(0);
    let n = u64::from(count).saturating_sub(1);
    // The slots must fit in the block.
    adb.sub_exact(at, n.saturating_add(1).saturating_mul(4))?;
    Ok(Some((at.saturating_add(4), n)))
}

/// Slot `i` (1-based) of an array or object, or `None` past its end.
async fn slot(cx: &Cx, adb: Span, v: u32, i: u64) -> Result<Option<u32>> {
    let Some((start, n)) = slots(cx, adb, v).await? else {
        return Ok(None);
    };
    if i == 0 || i > n {
        return Ok(None);
    }
    let at = start.saturating_add(i.saturating_sub(1).saturating_mul(4));
    Ok(u32_le(&cx.read(adb.sub_exact(at, 4)?).await?, 0))
}

async fn text_of(cx: &Cx, adb: Span, v: u32) -> Result<Option<String>> {
    match blob(cx, adb, v).await? {
        Some(span) => {
            let bytes = cx.read(span.sub(0, TEXT_MAX)).await?;
            Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
        }
        None => Ok(None),
    }
}

fn type_name(v: u32) -> &'static str {
    match kind(v) {
        T_SPECIAL => "special",
        T_INT => "int",
        T_INT32 => "int32",
        T_INT64 => "int64",
        T_BLOB8 => "blob8",
        T_BLOB16 => "blob16",
        T_BLOB32 => "blob32",
        T_ARRAY => "array",
        T_OBJECT => "object",
        _ => "invalid",
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Dissection

#[derive(Clone, Copy, Debug)]
struct Block {
    kind: u32,
    /// The whole block, header included (without padding).
    span: Span,
    /// The payload.
    body: Span,
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 8)).await?;
    match head.get(3) {
        Some(b'd') | Some(b'c') => return compressed(cx, input, &head).await,
        _ => {}
    }
    cx.emit(struct_node(
        "File header",
        file.sub(0, 8),
        LE,
        (),
        file_header,
    ));
    let schema = u32_le(&head, 4).unwrap_or(0);

    let mut pos = 8u64;
    let mut adb: Option<Span> = None;
    let mut counts = [0u64; 4];
    while pos < file.len {
        cx.progress_in(file, pos);
        let block = match read_block(&cx, file, pos).await {
            Ok(b) => b,
            Err(e) => {
                cx.diag(e);
                break;
            }
        };
        let raw = block.span.len;
        let node = match block.kind {
            0 => {
                if adb.is_none() {
                    adb = Some(block.body);
                }
                adb_block(&cx, input, block, schema).await?
            }
            1 => Node::new("SIG block")
                .span(block.span)
                .summary(format!("{} bytes", block.body.len))
                .lazy(sig_block, block),
            2 => data_block(&cx, input, block, adb, schema).await?,
            _ => Node::new(format!("Block type {}", block.kind))
                .span(block.span)
                .diag(Diagnostic::unsupported("unknown block type").at(block.span)),
        };
        if let Some(c) = counts.get_mut(usize::try_from(block.kind).unwrap_or(3).min(3)) {
            *c = c.saturating_add(1);
        }
        cx.push(node).await;
        // Blocks are 8-byte aligned.
        let next = pos.saturating_add(raw.div_ceil(8).saturating_mul(8));
        if next <= pos {
            break;
        }
        if next > file.len && pos.saturating_add(raw) < file.len {
            cx.diag(Diagnostic::malformed("block padding runs past the end").at(block.span));
        }
        pos = next;
    }

    let mut summary = format!("Alpine APK v3 {}", what(schema));
    if let Some(adb) = adb
        && let Some(name) = describe(&cx, adb, schema).await?
    {
        summary.push(' ');
        summary.push_str(&name);
    }
    let [_, sigs, data, _] = counts;
    if schema == 0x676b_6370 {
        summary.push_str(&format!(", {}", plural(data, "file")));
    }
    summary.push_str(if sigs > 0 { ", signed" } else { ", unsigned" });
    cx.annotate(summary);
    Ok(())
}

/// What a file of `schema` holds.
fn what(schema: u32) -> &'static str {
    match schema {
        0x676b_6370 => "package",
        0x7864_6e69 => "index",
        0x0062_6469 => "installed database",
        _ => "file",
    }
}

/// "package NAME VERSION (ARCH)" (or the index's description) from the
/// start of a compressed file's content: the file header and the ADB
/// block come first, so only they are decoded.
async fn compressed_summary(cx: &Cx, stream: Span, codec: &Codec) -> Option<String> {
    let decoded = match codec {
        Codec::Stored => stream,
        codec => cx.decode_lazy_unsized(stream, codec).ok()?,
    };
    let head = cx.read(decoded.sub(0, 8)).await.ok()?;
    if head.get(..4) != Some(b"ADB.".as_slice()) {
        return None;
    }
    let schema = u32_le(&head, 4)?;
    let mut out = what(schema).to_owned();
    let block = read_block(cx, decoded, 8).await.ok()?;
    if block.kind == 0
        && block.body.len <= 1 << 20
        && let Ok(Some(name)) = describe(cx, block.body, schema).await
    {
        out.push(' ');
        out.push_str(&name);
    }
    Some(out)
}

fn file_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.ascii("Magic", 4).emit()?;
    f.u32("Schema")
        .hex()
        .enumeration(SCHEMA)
        .desc("Schema of the ADB block's root object")
        .emit()?;
    Ok(())
}

async fn compressed(cx: Cx, input: Input, head: &[u8]) -> Result<()> {
    let file = input.span;
    let (hlen, alg) = if head.get(3) == Some(&b'c') {
        (6u64, head.get(4).copied().unwrap_or(0))
    } else {
        (4, 1)
    };
    cx.emit(struct_node(
        "Compression header",
        file.sub(0, hlen),
        LE,
        hlen,
        |f: &mut Fields<'_>, &hlen: &u64| {
            f.ascii("Magic", 4)
                .desc("ADBd: DEFLATE; ADBc: algorithm and level follow")
                .emit()?;
            if hlen == 6 {
                f.u8("Algorithm").enumeration(COMPRESSION).emit()?;
                f.u8("Level").emit()?;
            }
            Ok(())
        },
    ));
    let stream = file.sub(hlen, file.len.saturating_sub(hlen));
    let codec = match alg {
        0 => Codec::Stored,
        1 => Codec::Deflate,
        2 => Codec::Zstd,
        _ => {
            cx.emit(
                Node::new("Compressed data")
                    .span(stream)
                    .diag(Diagnostic::unsupported(format!(
                        "compression algorithm {alg}"
                    ))),
            );
            return Ok(());
        }
    };
    let name = crate::value::lookup(COMPRESSION, alg.into()).unwrap_or("?");
    let what = compressed_summary(&cx, stream, &codec)
        .await
        .unwrap_or_else(|| "package or index".to_owned());
    cx.emit(
        content("Content", input, stream, codec, None).summary(format!("{name}-compressed ADB")),
    );
    cx.annotate(format!("Alpine APK v3 {what}, {name}-compressed"));
    Ok(())
}

async fn read_block(cx: &Cx, file: Span, pos: u64) -> Result<Block> {
    let h = cx.read(file.sub_exact(pos, 4)?).await?;
    let tag = u32_le(&h, 0).unwrap_or(0);
    let ty = tag >> 30;
    if ty == 3 {
        let ext = cx.read(file.sub_exact(pos, 16)?).await?;
        let real = tag & 0x3fff_ffff;
        let size = u64_le(&ext, 8).unwrap_or(0);
        if size < 16 {
            return Err(
                Diagnostic::malformed("extended block smaller than its header")
                    .at(file.sub(pos, 16)),
            );
        }
        let span = file.sub_exact(pos, size)?;
        return Ok(Block {
            kind: real,
            span,
            body: span.sub(16, size.saturating_sub(16)),
        });
    }
    let size = u64::from(tag & 0x3fff_ffff);
    if size < 4 {
        return Err(Diagnostic::malformed("block smaller than its header").at(file.sub(pos, 4)));
    }
    let span = file.sub_exact(pos, size)?;
    Ok(Block {
        kind: ty,
        span,
        body: span.sub(4, size.saturating_sub(4)),
    })
}

fn block_header(f: &mut Fields<'_>, ext: &bool) -> Result<()> {
    f.u32("Type and size")
        .hex()
        .with(|&v, n| {
            let ty = v >> 30;
            let low = v & 0x3fff_ffff;
            if ty == 3 {
                // Extended: the low bits are the real type; the size
                // follows as a u64.
                let name = crate::value::lookup(BLOCK_TYPE, low.into()).unwrap_or("?");
                return n.summary(format!("extended {name}"));
            }
            let name = crate::value::lookup(BLOCK_TYPE, ty.into()).unwrap_or("?");
            n.summary(format!("{name}, {low} bytes"))
        })
        .desc("Top 2 bits: block type; low 30 bits: size including this tag")
        .emit()?;
    if *ext {
        f.u32("Reserved").emit()?;
        f.u64("Size")
            .desc("Extended size, header included")
            .emit()?;
    }
    Ok(())
}

fn header_node(block: Block) -> Node {
    let ext = block.body.offset.saturating_sub(block.span.offset) == 16;
    let len = if ext { 16 } else { 4 };
    struct_node(
        "Block header",
        block.span.sub(0, len),
        LE,
        ext,
        block_header,
    )
}

/// The ADB block: its header and the root object.
async fn adb_block(cx: &Cx, input: Input, block: Block, schema: u32) -> Result<Node> {
    let root = u32_le(&cx.read(block.body.sub(0, 8)).await?, 4).unwrap_or(0);
    let summary = format!(
        "{} bytes, root {} at {:#x}",
        block.body.len,
        type_name(root),
        arg(root)
    );
    Ok(Node::new("ADB block")
        .span(block.span)
        .summary(summary)
        .lazy(adb_contents, (input, block, schema)))
}

async fn adb_contents(cx: Cx, (input, block, schema): (Input, Block, u32)) -> Result<()> {
    cx.emit(header_node(block));
    let hdr = block.body.sub(0, 8);
    cx.emit(struct_node(
        "ADB header",
        hdr,
        LE,
        (),
        |f: &mut Fields<'_>, _: &()| {
            f.u8("adb_compat_ver").emit()?;
            f.u8("adb_ver").emit()?;
            f.u16("reserved").emit()?;
            f.u32("root")
                .hex()
                .desc("The root object's value tag")
                .emit()?;
            Ok(())
        },
    ));
    let root = u32_le(&cx.read(hdr).await?, 4).unwrap_or(0);
    let obj = root_schema(schema);
    let node = value_node(
        &cx,
        Ctx {
            input,
            adb: block.body,
        },
        "Root".into(),
        root,
        Ty::Obj(obj),
        Path::new(),
    )
    .await?;
    cx.emit(node);
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct Ctx {
    input: Input,
    adb: Span,
}

type Walk = (Ctx, u32, Ty, Path);

/// A node for value `v` of type `ty`.
async fn value_node(
    cx: &Cx,
    ctx: Ctx,
    label: std::borrow::Cow<'static, str>,
    v: u32,
    ty: Ty,
    path: Path,
) -> Result<Node> {
    let adb = ctx.adb;
    // Special values first, whatever the schema says.
    if kind(v) == T_SPECIAL {
        let value = match arg(v) {
            0 => Value::Text("null".into()),
            1 => Value::Bool(true),
            2 => Value::Bool(false),
            n => {
                return Ok(Node::new(label)
                    .diag(Diagnostic::malformed(format!("unknown special value {n}"))));
            }
        };
        return Ok(Node::new(label).value(value));
    }
    match ty {
        Ty::Obj(_) | Ty::Arr(_) => {
            let Some((start, n)) = slots(cx, adb, v).await? else {
                return Ok(Node::new(label).diag(Diagnostic::malformed(format!(
                    "expected an array or object, found {}",
                    type_name(v)
                ))));
            };
            let span = adb.sub(
                start.saturating_sub(4),
                n.saturating_add(1).saturating_mul(4),
            );
            let summary = match ty {
                Ty::Obj(o) => object_summary(cx, adb, v, o).await?,
                _ => plural(n, "item"),
            };
            let child = match path.enter(arg(v), MAX_DEPTH) {
                Ok(p) => p,
                Err(e) => return Ok(Node::new(label).span(span).summary(summary).diag(e)),
            };
            Ok(Node::new(label)
                .span(span)
                .summary(summary)
                .lazy(crate::expander!(self::walk: Walk), (ctx, v, ty, child)))
        }
        _ => scalar(cx, ctx, label, v, ty).await,
    }
}

/// A short description of an object: its name (and version, for packages
/// and dependencies).
async fn object_summary(cx: &Cx, adb: Span, v: u32, o: &'static Obj) -> Result<String> {
    let mut parts = Vec::new();
    for (i, (name, ty)) in o.fields.iter().enumerate().take(2) {
        if !matches!(ty, Ty::Str) || (i == 1 && *name != "version") {
            continue;
        }
        if let Some(s) = slot(cx, adb, v, to_u64(i).saturating_add(1)).await?
            && let Some(t) = text_of(cx, adb, s).await?
        {
            parts.push(t);
        }
    }
    if std::ptr::eq(o, &DEPENDENCY) && !parts.is_empty() {
        // `busybox>=1.36`, as apk writes a dependency: the match flags as
        // an operator between name and version, `!` for a conflict.
        let flags = match slot(cx, adb, v, 3).await? {
            Some(m) => integer(cx, adb, m).await?.unwrap_or(0),
            None => 0,
        };
        let name = parts.first().cloned().unwrap_or_default();
        let conflict = if flags & 16 != 0 { "!" } else { "" };
        return Ok(match parts.get(1) {
            Some(version) => {
                // No match with a version is EQUAL (apk writes `musl=1.2.5`
                // without one).
                let op = match flags & 15 {
                    0 | 1 => "=",
                    2 => "<",
                    3 => "<=",
                    4 => ">",
                    5 => ">=",
                    8 | 9 => "~",
                    _ => " ",
                };
                format!("{conflict}{name}{op}{version}")
            }
            None => format!("{conflict}{name}"),
        });
    }
    if std::ptr::eq(o, &DIR) && parts.is_empty() {
        return Ok("directory /".to_owned());
    }
    Ok(if parts.is_empty() {
        o.name.to_owned()
    } else {
        parts.join(" ")
    })
}

async fn scalar(
    cx: &Cx,
    ctx: Ctx,
    label: std::borrow::Cow<'static, str>,
    v: u32,
    ty: Ty,
) -> Result<Node> {
    let adb = ctx.adb;
    if let Some(span) = blob(cx, adb, v).await? {
        let node = Node::new(label).span(span);
        let bytes = cx.read(span.sub(0, TEXT_MAX)).await?;
        let cut = span.len > TEXT_MAX;
        let node = match ty {
            Ty::Hex => node.value(Value::Text(hex(&bytes))),
            Ty::Target => {
                let mode = u16_le(&bytes, 0).unwrap_or(0);
                let rest = bytes.get(2..).unwrap_or_default();
                match mode & 0xf000 {
                    0xa000 => node
                        .value(Value::Text(String::from_utf8_lossy(rest).into_owned()))
                        .summary(format!("symbolic link (mode {mode:o})")),
                    0x2000 | 0x6000 => node
                        .value(Value::UInt {
                            value: u64_le(rest, 0).unwrap_or(0),
                            bits: 64,
                            radix: Radix::Hex,
                        })
                        .summary(format!(
                            "{} device number",
                            if mode & 0xf000 == 0x2000 {
                                "character"
                            } else {
                                "block"
                            }
                        )),
                    _ => node.value(Value::Text(hex(&bytes))),
                }
            }
            Ty::Xattr => {
                let nul = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                let name = String::from_utf8_lossy(bytes.get(..nul).unwrap_or_default());
                let value = bytes.get(nul.saturating_add(1)..).unwrap_or_default();
                node.value(Value::Text(format!("{name}={}", hex(value))))
            }
            Ty::Adb => embedded("nested ADB", ctx.input.nested(span))
                .summary(format!("{} bytes", span.len)),
            _ => {
                let node = node.value(Value::Text(String::from_utf8_lossy(&bytes).into_owned()));
                if cut {
                    node.summary(format!("{} bytes", span.len))
                } else {
                    node
                }
            }
        };
        return Ok(node);
    }
    let Some(n) = integer(cx, adb, v).await? else {
        return Ok(Node::new(label).diag(Diagnostic::malformed(format!(
            "unexpected {} value",
            type_name(v)
        ))));
    };
    let node = Node::new(label);
    let node = match kind(v) {
        T_INT32 => node.span(adb.sub(arg(v), 4)),
        T_INT64 => node.span(adb.sub(arg(v), 8)),
        _ => node,
    };
    Ok(match ty {
        Ty::Time => node.value(Value::utc(i64::try_from(n).unwrap_or(i64::MAX))),
        Ty::Oct => node.value(crate::formats::util::val::oct(n, 64)),
        Ty::Size => node
            .value(Value::UInt {
                value: n,
                bits: 64,
                radix: Radix::Dec,
            })
            .summary(crate::formats::util::fmt::size(n)),
        Ty::Match => node.value(crate::formats::util::val::flagsv(n, 32, DEP_MATCH)),
        _ => node.value(Value::UInt {
            value: n,
            bits: 64,
            radix: Radix::Dec,
        }),
    })
}

/// Expands an array or object: one node per slot.
async fn walk(cx: Cx, (ctx, v, ty, path): Walk) -> Result<()> {
    let adb = ctx.adb;
    let Some((start, n)) = slots(&cx, adb, v).await? else {
        return Ok(());
    };
    let mut i = 0u64;
    while i < n {
        let take = n.saturating_sub(i).min(SLOT_WINDOW);
        let window = cx
            .read(adb.sub_exact(
                start.saturating_add(i.saturating_mul(4)),
                take.saturating_mul(4),
            )?)
            .await?;
        for (j, chunk) in window.as_chunks::<4>().0.iter().enumerate() {
            let index = i.saturating_add(to_u64(j));
            let s = u32::from_le_bytes(*chunk);
            let slot_span = adb.sub(start.saturating_add(index.saturating_mul(4)), 4);
            let (label, child_ty): (std::borrow::Cow<'static, str>, Option<Ty>) = match ty {
                Ty::Arr(item) => (format!("[{index}]").into(), Some(*item)),
                Ty::Obj(o) => match o.fields.get(usize::try_from(index).unwrap_or(usize::MAX)) {
                    Some((name, t)) => ((*name).into(), Some(*t)),
                    None => (format!("slot {}", index.saturating_add(1)).into(), None),
                },
                _ => (format!("[{index}]").into(), None),
            };
            // Absent fields of an object are null slots.
            if s == 0 && matches!(ty, Ty::Obj(_)) {
                continue;
            }
            let node = match child_ty {
                Some(t) => value_node(&cx, ctx, label, s, t, path.clone()).await?,
                None => Node::new(label).value(Value::UInt {
                    value: s.into(),
                    bits: 32,
                    radix: Radix::Hex,
                }),
            };
            let node = if node.span.is_none() {
                node.span(slot_span)
            } else {
                node
            };
            cx.push(node).await;
        }
        i = i.saturating_add(take);
    }
    Ok(())
}

/// "name version" of the package (or the index description).
async fn describe(cx: &Cx, adb: Span, schema: u32) -> Result<Option<String>> {
    let Some(root) = u32_le(&cx.read(adb.sub(0, 8)).await?, 4) else {
        return Ok(None);
    };
    match schema {
        0x676b_6370 => {
            let Some(info) = slot(cx, adb, root, 1).await? else {
                return Ok(None);
            };
            let s = object_summary(cx, adb, info, &PKGINFO).await?;
            if s == PKGINFO.name {
                return Ok(None);
            }
            let arch = match slot(cx, adb, info, 5).await? {
                Some(a) => text_of(cx, adb, a).await?,
                None => None,
            };
            Ok(Some(match arch {
                Some(a) => format!("{s} ({a})"),
                None => s,
            }))
        }
        0x7864_6e69 => {
            let n = match slot(cx, adb, root, 2).await? {
                Some(p) => slots(cx, adb, p).await?.map_or(0, |(_, n)| n),
                None => 0,
            };
            let d = match slot(cx, adb, root, 1).await? {
                Some(d) => text_of(cx, adb, d).await?,
                None => None,
            };
            Ok(Some(match d {
                Some(d) => format!("\"{d}\", {}", plural(n, "package")),
                None => plural(n, "package"),
            }))
        }
        _ => Ok(None),
    }
}

async fn sig_block(cx: Cx, block: Block) -> Result<()> {
    cx.emit(header_node(block));
    let body = block.body;
    cx.emit(struct_node(
        "Signature",
        body,
        LE,
        body.len,
        |f: &mut Fields<'_>, &len: &u64| {
            let ver = f.u8("sign_ver").desc("Signature format version").emit()?;
            f.u8("hash_alg")
                .enumeration(HASH_ALG)
                .desc("Digest of the ADB block that was signed")
                .emit()?;
            if ver == 0 {
                f.bytes("id", 16)
                    .desc("Identifies the signing key (derived from its public key)")
                    .emit()?;
                f.bytes("sig", len.saturating_sub(18)).emit()?;
            }
            Ok(())
        },
    ));
    Ok(())
}

/// A DATA block: the file's indexes, resolved to its path when the
/// package's metadata is at hand, and its content.
async fn data_block(
    cx: &Cx,
    input: Input,
    block: Block,
    adb: Option<Span>,
    schema: u32,
) -> Result<Node> {
    let idx = cx.read(block.body.sub(0, 8)).await?;
    let dir = u32_le(&idx, 0).unwrap_or(0);
    let file = u32_le(&idx, 4).unwrap_or(0);
    let path = match adb {
        Some(adb) if schema == 0x676b_6370 => resolve(cx, adb, dir, file).await.unwrap_or(None),
        _ => None,
    };
    let name = match &path {
        Some(p) => format!("DATA block: {p}"),
        None => format!("DATA block: path {dir}, file {file}"),
    };
    let size = block.body.len.saturating_sub(8);
    Ok(Node::new(name)
        .span(block.span)
        .summary(format!("{size} bytes"))
        .lazy(data_contents, (input, block)))
}

async fn resolve(cx: &Cx, adb: Span, dir: u32, file: u32) -> Result<Option<String>> {
    let Some(root) = u32_le(&cx.read(adb.sub(0, 8)).await?, 4) else {
        return Ok(None);
    };
    let Some(paths) = slot(cx, adb, root, 2).await? else {
        return Ok(None);
    };
    let Some(d) = slot(cx, adb, paths, dir.into()).await? else {
        return Ok(None);
    };
    let dname = match slot(cx, adb, d, 1).await? {
        Some(n) => text_of(cx, adb, n).await?.unwrap_or_default(),
        None => String::new(),
    };
    let Some(files) = slot(cx, adb, d, 3).await? else {
        return Ok(None);
    };
    let Some(f) = slot(cx, adb, files, file.into()).await? else {
        return Ok(None);
    };
    let Some(fname) = (match slot(cx, adb, f, 1).await? {
        Some(n) => text_of(cx, adb, n).await?,
        None => None,
    }) else {
        return Ok(None);
    };
    Ok(Some(if dname.is_empty() {
        fname
    } else {
        format!("{dname}/{fname}")
    }))
}

async fn data_contents(cx: Cx, (input, block): (Input, Block)) -> Result<()> {
    cx.emit(header_node(block));
    let body = block.body;
    cx.emit(struct_node(
        "File index",
        body.sub(0, 8),
        LE,
        (),
        |f: &mut Fields<'_>, _: &()| {
            f.u32("path_idx")
                .desc("1-based index of the directory in the package's paths")
                .emit()?;
            f.u32("file_idx")
                .desc("1-based index of the file in that directory's files")
                .emit()?;
            Ok(())
        },
    ));
    let data = body.sub(8, body.len.saturating_sub(8));
    cx.emit(embedded("Content", input.nested(data)).summary(format!("{} bytes", data.len)));
    Ok(())
}
