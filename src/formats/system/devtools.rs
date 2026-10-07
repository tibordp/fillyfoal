//! Developer and infrastructure artifacts: compiler and linker outputs,
//! version-control bundles, package archives and storage-engine files.

use crate::bytes::{to_u64, u16_le, u32_be, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Path, Record, emit_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::{Codec, Head, Input, Probe, content, embedded};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

// ---------------------------------------------------------------------------
// Precompiled headers: GCC and Clang

declare_format!(pub GCC_PCH = "gcc-pch", "GCC precompiled header", ["gch"], "application/x-gcc-pch",
    Probe::Magic(&[(0, b"gpch")]), gcc_pch);

async fn gcc_pch(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 8)).await?;
    let version = String::from_utf8_lossy(head.get(4..8).unwrap_or_default()).into_owned();
    let language = match head.get(4) {
        Some(b'C') => "C",
        Some(b'+') => "C++",
        Some(b'o') => "Objective-C",
        Some(b'O') => "Objective-C++",
        _ => "unknown language",
    };
    cx.emit(Node::new("Magic").span(file.sub(0, 4)));
    cx.emit(
        Node::new("Language and version")
            .span(file.sub(4, 4))
            .value(text(version.clone())),
    );
    cx.emit(Node::new("Compiler state").span(file.tail(8)));
    cx.annotate(format!(
        "GCC precompiled header ({language}, format {})",
        version.get(1..).unwrap_or_default()
    ));
    Ok(())
}

declare_format!(pub CLANG_PCH = "clang-ast", "Clang precompiled header / module (AST file)", ["pch", "pcm", "ast"], "application/x-clang-ast",
    Probe::Magic(&[(0, b"CPCH")]), clang_ast);

async fn clang_ast(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Magic").span(file.sub(0, 4)));
    cx.emit(Node::new("LLVM bitstream").span(file.tail(4)));
    // The control block holds the producer string; look for it in the head.
    let head = cx.read_avail(file.sub(0, 4096)).await?;
    let producer = head.windows(5).position(|w| w == b"clang").map(|at| {
        String::from_utf8_lossy(head.get(at..at.saturating_add(48)).unwrap_or_default())
            .split('\0')
            .next()
            .unwrap_or_default()
            .to_owned()
    });
    cx.annotate(match producer {
        Some(p) => format!("Clang AST file ({p})"),
        None => "Clang AST file".to_owned(),
    });
    Ok(())
}

// ---------------------------------------------------------------------------
// Windows compiled resources (.res)

declare_format!(pub WIN_RES = "win-res", "Windows compiled resources", ["res"], "application/x-ms-res",
    Probe::Magic(&[(0, b"\0\0\0\0\x20\0\0\0\xff\xff\0\0\xff\xff\0\0")]), win_res);

const RES_TYPES: EnumTable = crate::formats::executable::pe::tables::RESOURCE_TYPE;

/// A resource type or name: 0xFFFF + ordinal, or a NUL-terminated UTF-16
/// string. Returns the label, the ordinal and the offset after it.
fn res_id(data: &[u8], at: usize) -> (String, Option<u16>, usize) {
    if u16_le(data, at) == Some(0xffff) {
        let id = u16_le(data, at.saturating_add(2)).unwrap_or(0);
        return (format!("#{id}"), Some(id), at.saturating_add(4));
    }
    let (s, used, _) = crate::text::utf16z(data.get(at..).unwrap_or_default(), LE);
    (s, None, at.saturating_add(used))
}

const RES_MEMORY_FLAGS: crate::value::FlagTable = &[
    crate::value::flag(0x0010, "MOVEABLE"),
    crate::value::flag(0x0020, "PURE"),
    crate::value::flag(0x0040, "PRELOAD"),
    crate::value::flag(0x1000, "DISCARDABLE"),
];

/// One `RESOURCEHEADER` and the resource data after it.
#[derive(Clone, Copy)]
struct ResEntry {
    input: Input,
    header: Span,
    data: Span,
    kind: Option<u16>,
    name: Option<u16>,
}

async fn win_res(cx: Cx, input: Input) -> Result<()> {
    use crate::formats::executable::pe::resource;
    use crate::formats::util::lcid;
    let file = input.span;
    let (mut pos, mut count) = cx.resume::<(u64, u32)>().unwrap_or((0, 0));
    while pos.saturating_add(32) <= file.len {
        let head = cx.read(file.sub(pos, 8)).await?;
        let data_size = u64::from(u32_le(&head, 0).unwrap_or(0));
        let header_size = u64::from(u32_le(&head, 4).unwrap_or(0));
        if header_size < 32 {
            cx.diag(
                Diagnostic::malformed(format!("resource header size {header_size}"))
                    .at(file.sub(pos, 8)),
            );
            break;
        }
        let header_span = file.sub(pos, header_size);
        let header = cx.read_avail(header_span).await?;
        // TYPE and NAME follow each other directly; the fixed fields after
        // them are DWORD-aligned.
        let (kind_label, kind, after) = res_id(&header, 8);
        let (name_label, name, after) = res_id(&header, after);
        let fields_at = after.next_multiple_of(4);
        let language = u16_le(&header, fields_at.saturating_add(6)).unwrap_or(0);
        let data = file.sub(pos.saturating_add(header_size), data_size);
        let at = (pos, count);
        cx.mark(move || at);
        if data_size == 0 && pos == 0 && kind == Some(0) && name == Some(0) {
            cx.push(
                Node::new("Empty entry")
                    .span(header_span)
                    .summary("marks a 32-bit resource file"),
            )
            .await;
        } else {
            count = count.saturating_add(1);
            let entry = ResEntry {
                input,
                header: header_span,
                data,
                kind,
                name,
            };
            let content =
                resource::content(&cx, input, data, kind.map(u32::from), name.map(u32::from)).await;
            let kind_label = kind
                .and_then(|id| lookup(RES_TYPES, id.into()))
                .map_or(kind_label, str::to_owned);
            let mut summary = content
                .summary
                .clone()
                .unwrap_or_else(|| format!("{data_size:#x} bytes"));
            summary.push_str(&format!(", language {}", lcid::describe(language.into())));
            cx.push(
                Node::new(format!("{kind_label} {name_label}"))
                    .span(file.sub(pos, header_size.saturating_add(data_size)))
                    .summary(summary)
                    .lazy(res_entry, entry),
            )
            .await;
        }
        pos = pos
            .saturating_add(header_size)
            .saturating_add(data_size)
            .next_multiple_of(4);
    }
    cx.annotate(format!("Win32 resources, {count} entries"));
    Ok(())
}

async fn res_entry(cx: Cx, e: ResEntry) -> Result<()> {
    use crate::formats::executable::pe::resource;
    cx.emit(
        Node::new("Header")
            .span(e.header)
            .lazy(res_header, e.header),
    );
    let mut content = resource::content(
        &cx,
        e.input,
        e.data,
        e.kind.map(u32::from),
        e.name.map(u32::from),
    )
    .await;
    let wanted = cx
        .read_avail(e.header.sub(0, 4))
        .await
        .ok()
        .and_then(|h| u32_le(&h, 0))
        .map_or(0, u64::from);
    if e.data.len < wanted {
        content = content.diag(Diagnostic::truncated(
            Span::new(e.data.source, e.data.offset, wanted),
            e.data.len,
        ));
    }
    cx.emit(content);
    Ok(())
}

async fn res_header(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u32("DataSize").hex().emit()?;
    f.u32("HeaderSize").hex().emit()?;
    let ids = [("TYPE", true), ("NAME", false)];
    for (label, is_type) in ids {
        let at = crate::bytes::to_usize(f.pos());
        let (name_text, ordinal, end) = res_id(&block.data, at);
        let len = to_u64(end.saturating_sub(at));
        let mut node = Node::new(label).span(f.peek_span(len));
        node = match ordinal {
            Some(id) if is_type => node
                .value(Value::Enum {
                    raw: id.into(),
                    bits: 16,
                    name: lookup(RES_TYPES, id.into()),
                })
                .desc("0xFFFF, then an ordinal"),
            Some(id) => node
                .value(crate::formats::util::lines::uint(id.into()))
                .desc("0xFFFF, then an ordinal"),
            None => node
                .value(text(name_text))
                .desc("NUL-terminated UTF-16 name"),
        };
        f.node(node);
        f.skip(len);
    }
    let aligned = f.pos().next_multiple_of(4);
    if aligned > f.pos() {
        f.bytes("Padding", aligned.saturating_sub(f.pos())).emit()?;
    }
    f.u32("DataVersion").emit()?;
    f.u16("MemoryFlags").flags(RES_MEMORY_FLAGS).emit()?;
    f.u16("LanguageId")
        .with(
            |&v, node| match crate::formats::util::lcid::name(v.into()) {
                Some(n) => node.summary(n),
                None => node,
            },
        )
        .hex()
        .emit()?;
    f.u32("Version").emit()?;
    f.u32("Characteristics").hex().emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// MSVC incremental linker database, COM type libraries

declare_format!(pub ILK = "ilk", "MSVC incremental linker database", ["ilk"], "application/x-ms-ilk",
    Probe::Magic(&[(0, b"Microsoft Linker Database")]), ilk);

async fn ilk(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 64)).await?;
    let end = head.iter().position(|&b| b == b'\n').unwrap_or(25);
    cx.emit(
        Node::new("Signature")
            .span(file.sub(0, to_u64(end)))
            .value(text(String::from_utf8_lossy(
                head.get(..end).unwrap_or_default(),
            ))),
    );
    cx.emit(Node::new("Database").span(file.tail(to_u64(end))));
    cx.annotate("MSVC incremental link state");
    Ok(())
}

declare_format!(pub TYPELIB = "typelib", "COM type library", ["tlb", "olb"], "application/x-ms-typelib",
    Probe::Magic(&[(0, b"MSFT"), (0, b"SLTG")]), typelib);

record! {
    pub struct MsftHeader {
        magic: ascii[4] "Magic",
        version: u32 "Format version" .hex(),
        guid_offset: i32 "Library GUID offset",
        lcid: u32 "Locale ID" .hex(),
        lcid2: u32 "Locale ID 2" .hex(),
        var_flags: u32 "Flags" .hex(),
        version_number: u32 "Library version" .hex(),
        flags: u32 "Library flags" .hex(),
        type_infos: u32 "Type infos",
        help_string: i32 "Help string offset",
        help_context: u32 "Help context",
        help_string_context: u32 "Help string context",
        names: u32 "Name table entries",
        name_chars: u32 "Name table characters",
        name_offset: i32 "Library name offset",
        help_file: i32 "Help file offset",
        custom_data: i32 "Custom data offset",
        _reserved: u32 "Reserved",
        _reserved2: u32 "Reserved",
        dispatch: i32 "IDispatch href",
        imports: u32 "Import infos",
    }
}

async fn typelib(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    if cx.read(file.sub(0, 4)).await? == b"SLTG" {
        cx.emit(Node::new("Magic").span(file.sub(0, 4)));
        cx.annotate("COM type library (SLTG format)");
        return Ok(());
    }
    let h: MsftHeader = emit_record(&cx, file.sub(0, MsftHeader::SIZE), LE).await?;
    cx.annotate(format!(
        "COM type library (MSFT) v{}.{}, {} type infos",
        h.version_number & 0xffff,
        h.version_number >> 16,
        h.type_infos
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Nix archives (NAR)

fn nar_probe(h: &Head<'_>) -> bool {
    h.at(0, b"\x0d\0\0\0\0\0\0\0nix-archive-1")
}

declare_format!(pub NAR = "nix-nar", "Nix archive (NAR)", ["nar"], "application/x-nix-nar",
    Probe::Custom(nar_probe), nar);

/// A NAR string: u64 length, bytes, padding to 8.
async fn nar_string(cur: &mut Cursor<'_>) -> Result<(Vec<u8>, Span)> {
    let len = cur.u64().await?;
    if len > cur.remaining() {
        return Err(Diagnostic::malformed("string longer than the archive").at(cur.span(8)));
    }
    let span = cur.span(len);
    let bytes = if len <= 4096 {
        cur.bytes(len).await?
    } else {
        cur.skip(len);
        Vec::new()
    };
    cur.seek(cur.pos().next_multiple_of(8));
    Ok((bytes, span))
}

async fn nar(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(
        Node::new("Magic")
            .span(file.sub(0, 24))
            .value(text("nix-archive-1")),
    );
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(24);
    let node = nar_node(&cx, input, &mut cur, String::new(), Path::new()).await?;
    cx.emit(node);
    cx.annotate("Nix archive");
    Ok(())
}

type NodeFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<Node>> + Send + 'a>>;

/// Recursion goes through a boxed future with an explicit `Send` bound, so
/// the compiler does not have to infer it from the (recursive) body.
fn nar_node_boxed<'a>(
    cx: &'a Cx,
    input: Input,
    cur: &'a mut Cursor<'_>,
    name: String,
    path: Path,
) -> NodeFuture<'a> {
    Box::pin(nar_node(cx, input, cur, name, path))
}

/// Parses one `( type ... )` node starting at the cursor. Directory entries
/// are parsed eagerly to find their extents but expanded lazily.
async fn nar_node(
    cx: &Cx,
    input: Input,
    cur: &mut Cursor<'_>,
    name: String,
    path: Path,
) -> Result<Node> {
    let start = cur.pos();
    let open = nar_string(cur).await?.0;
    let type_key = nar_string(cur).await?.0;
    let kind = nar_string(cur).await?.0;
    if open != b"(" || type_key != b"type" {
        return Err(Diagnostic::malformed("expected a NAR node").at(cur.since(start)));
    }
    let node = match kind.as_slice() {
        b"regular" => {
            let mut key = nar_string(cur).await?.0;
            let mut executable = false;
            if key == b"executable" {
                executable = true;
                nar_string(cur).await?;
                key = nar_string(cur).await?.0;
            }
            if key != b"contents" {
                return Err(Diagnostic::malformed("expected contents"));
            }
            let (_, data) = nar_string(cur).await?;
            nar_string(cur).await?; // ")"
            embedded(name, input.nested(data)).summary(format!(
                "{} bytes{}",
                data.len,
                if executable { ", executable" } else { "" }
            ))
        }
        b"symlink" => {
            nar_string(cur).await?; // "target"
            let (target, _) = nar_string(cur).await?;
            nar_string(cur).await?;
            Node::new(name).summary(format!("→ {}", String::from_utf8_lossy(&target)))
        }
        b"directory" => {
            let entries_start = cur.pos();
            let mut count = 0u32;
            let child_path = path.enter(start, 256)?;
            loop {
                cx.checkpoint().await;
                let (token, _) = nar_string(cur).await?;
                if token == b")" {
                    break;
                }
                if token != b"entry" {
                    return Err(Diagnostic::malformed("expected entry"));
                }
                nar_string(cur).await?; // "("
                nar_string(cur).await?; // "name"
                nar_string(cur).await?;
                nar_string(cur).await?; // "node"
                nar_node_boxed(cx, input, cur, String::new(), child_path.clone()).await?;
                nar_string(cur).await?; // ")"
                count = count.saturating_add(1);
            }
            let entries = input
                .span
                .sub(entries_start, cur.pos().saturating_sub(entries_start));
            Node::new(format!("{name}/"))
                .summary(format!("{count} entries"))
                .lazy(
                    crate::expander!(self::nar_dir: (Input, Span, Path)),
                    (input, entries, child_path),
                )
        }
        _ => {
            return Err(Diagnostic::unsupported(format!(
                "node type {}",
                String::from_utf8_lossy(&kind)
            )));
        }
    };
    Ok(node.target(cur.since(start)))
}

async fn nar_dir(cx: Cx, (input, entries, path): (Input, Span, Path)) -> Result<()> {
    let mut cur = Cursor::new(&cx, input.span, LE);
    cur.seek(entries.offset.saturating_sub(input.span.offset));
    while cur.pos() < entries.end().saturating_sub(input.span.offset) {
        let (token, _) = nar_string(&mut cur).await?;
        if token != b"entry" {
            break;
        }
        nar_string(&mut cur).await?;
        nar_string(&mut cur).await?;
        let (name, _) = nar_string(&mut cur).await?;
        nar_string(&mut cur).await?;
        let node = nar_node_boxed(
            &cx,
            input,
            &mut cur,
            String::from_utf8_lossy(&name).into_owned(),
            path.clone(),
        )
        .await?;
        nar_string(&mut cur).await?;
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Git and Mercurial bundles, Subversion dumps

declare_format!(pub GIT_BUNDLE = "git-bundle", "Git bundle", ["bundle"], "application/x-git-bundle",
    Probe::Magic(&[(0, b"# v2 git bundle\n"), (0, b"# v3 git bundle\n")]), git_bundle);

async fn git_bundle(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 1 << 20)).await?;
    let end = head
        .windows(2)
        .position(|w| w == b"\n\n")
        .ok_or_else(|| Diagnostic::malformed("no end of bundle header"))?;
    let header = String::from_utf8_lossy(head.get(..end).unwrap_or_default()).into_owned();
    let mut pos = 0u64;
    let (mut refs, mut prereqs) = (0u32, 0u32);
    for line in header.lines() {
        let len = to_u64(line.len()).saturating_add(1);
        let span = file.sub(pos, len);
        if line.starts_with('#') {
            cx.emit(Node::new("Signature").span(span).value(text(line)));
        } else if let Some(rest) = line.strip_prefix('-') {
            prereqs = prereqs.saturating_add(1);
            cx.emit(Node::new("Prerequisite").span(span).value(text(rest)));
        } else if let Some(cap) = line.strip_prefix('@') {
            cx.emit(Node::new("Capability").span(span).value(text(cap)));
        } else if let Some((sha, name)) = line.split_once(' ') {
            refs = refs.saturating_add(1);
            cx.emit(Node::new(name.to_owned()).span(span).value(text(sha)));
        }
        pos = pos.saturating_add(len);
    }
    let pack = file.tail(to_u64(end).saturating_add(2));
    cx.emit(embedded("Pack", input.nested(pack)).summary(format!("{} bytes", pack.len)));
    cx.annotate(format!("git bundle, {refs} refs, {prereqs} prerequisites"));
    Ok(())
}

declare_format!(pub HG_BUNDLE = "hg-bundle", "Mercurial bundle", ["hg", "bundle"], "application/x-mercurial-bundle",
    Probe::Magic(&[(0, b"HG10UN"), (0, b"HG10GZ"), (0, b"HG10BZ"), (0, b"HG20")]), hg_bundle);

async fn hg_bundle(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 6)).await?;
    let magic = String::from_utf8_lossy(&head).into_owned();
    cx.emit(
        Node::new("Header")
            .span(file.sub(0, if magic.starts_with("HG20") { 4 } else { 6 }))
            .value(text(magic.clone())),
    );
    if magic.starts_with("HG20") {
        let mut cur = Cursor::new(&cx, file, BE);
        cur.seek(4);
        let params_len = cur.u32().await?;
        let params = String::from_utf8_lossy(&cur.bytes(params_len.into()).await?).into_owned();
        cx.emit(
            Node::new("Stream parameters")
                .span(file.sub(4, 4u64.saturating_add(params_len.into())))
                .value(text(params.clone())),
        );
        let compressed = params.contains("Compression=") && !params.contains("Compression=UN");
        let mut parts = 0u32;
        if !compressed {
            while cur.remaining() >= 4 {
                let start = cur.pos();
                let header_len = cur.u32().await?;
                if header_len == 0 {
                    break;
                }
                let header = cur.bytes(header_len.into()).await?;
                let type_len = usize::from(header.first().copied().unwrap_or(0));
                let kind = String::from_utf8_lossy(
                    header
                        .get(1..1usize.saturating_add(type_len))
                        .unwrap_or_default(),
                )
                .into_owned();
                // Payload chunks until a zero-length chunk.
                loop {
                    let n = cur.u32().await? as i32;
                    if n <= 0 {
                        break;
                    }
                    cur.skip(n.unsigned_abs().into());
                }
                parts = parts.saturating_add(1);
                cx.push(Node::new(kind).span(cur.since(start))).await;
            }
        } else {
            let payload = file.tail(cur.pos());
            let codec = params
                .split(' ')
                .find_map(|p| p.strip_prefix("Compression="))
                .and_then(|c| match c {
                    "GZ" => Some(Codec::Zlib),
                    "BZ" => Some(Codec::Bzip2),
                    "ZS" => Some(Codec::Zstd),
                    _ => None,
                });
            cx.emit(match codec {
                Some(codec) => content("Compressed payload", input, payload, codec, None),
                None => Node::new("Compressed payload").span(payload),
            });
        }
        cx.annotate(format!("Mercurial bundle2, {parts} parts ({params})"));
        return Ok(());
    }
    let body = file.tail(6);
    match &magic[4..] {
        "GZ" => cx.emit(content(
            "Changegroup (zlib)",
            input,
            body,
            Codec::Zlib,
            None,
        )),
        // The bzip2 stream's own "BZ" magic doubles as the end of ours.
        "BZ" => cx.emit(content(
            "Changegroup (bzip2)",
            input,
            file.tail(4),
            Codec::Bzip2,
            None,
        )),
        _ => cx.emit(Node::new("Changegroup").span(body)),
    }
    cx.annotate(format!("Mercurial bundle ({magic})"));
    Ok(())
}

declare_format!(pub SVN_DUMP = "svn-dump", "Subversion repository dump", ["dump", "svndump"], "application/x-svn-dump",
    Probe::Magic(&[(0, b"SVN-fs-dump-format-version: ")]), svn_dump);

/// Reads RFC 822-style headers at `pos`; returns them and the position after
/// the blank line.
async fn svn_headers(cx: &Cx, file: Span, pos: u64) -> Result<(Vec<(String, String)>, u64)> {
    let block = cx.read_avail(file.sub(pos, 8192)).await?;
    let end = block
        .windows(2)
        .position(|w| w == b"\n\n")
        .map_or(block.len(), |p| p.saturating_add(2));
    let text = String::from_utf8_lossy(block.get(..end).unwrap_or_default()).into_owned();
    let headers = text
        .lines()
        .filter_map(|l| {
            l.split_once(": ")
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
        })
        .collect();
    Ok((headers, pos.saturating_add(to_u64(end))))
}

async fn svn_dump(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut pos = 0u64;
    let mut revisions = 0u32;
    let mut version = String::new();
    while pos < file.len {
        // Skip blank lines between records.
        let peek = cx.read_avail(file.sub(pos, 1)).await?;
        if peek == b"\n" {
            pos = pos.saturating_add(1);
            continue;
        }
        let (headers, after) = svn_headers(&cx, file, pos).await?;
        if headers.is_empty() {
            break;
        }
        let get = |k: &str| headers.iter().find(|(h, _)| h == k).map(|(_, v)| v.clone());
        let content_len: u64 = get("Content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let record = file.sub(pos, after.saturating_sub(pos).saturating_add(content_len));
        let node = if let Some(v) = get("SVN-fs-dump-format-version") {
            version = v.clone();
            Node::new("Format version").value(text(v))
        } else if let Some(uuid) = get("UUID") {
            Node::new("Repository UUID").value(text(uuid))
        } else if let Some(rev) = get("Revision-number") {
            revisions = revisions.saturating_add(1);
            Node::new(format!("Revision {rev}"))
        } else if let Some(path) = get("Node-path") {
            Node::new(format!("  {path}")).summary(format!(
                "{} {}",
                get("Node-action").unwrap_or_default(),
                get("Node-kind").unwrap_or_default()
            ))
        } else {
            Node::new("Record")
        };
        cx.push(node.span(record)).await;
        if after <= pos {
            break;
        }
        pos = after.saturating_add(content_len);
    }
    cx.annotate(format!("Subversion dump v{version}, {revisions} revisions"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Storage engines: DuckDB, LMDB, bbolt, Prometheus TSDB, InfluxDB TSM, Lucene

fn duckdb_probe(h: &Head<'_>) -> bool {
    h.at(8, b"DUCK")
}

declare_format!(pub DUCKDB = "duckdb", "DuckDB database", ["duckdb", "db"], "application/x-duckdb",
    Probe::Custom(duckdb_probe), duckdb);

async fn duckdb(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 4096)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u64("Checksum").hex().emit()?;
    f.ascii("Magic", 4).emit()?;
    let version = f.u64("Storage version").emit()?;
    f.u64("Flags").hex().emit()?;
    cx.emit(Node::new("Database headers").span(file.sub(4096, 8192)));
    cx.emit(Node::new("Blocks").span(file.tail(12288)));
    cx.annotate(format!("DuckDB database, storage version {version}"));
    Ok(())
}

fn lmdb_probe(h: &Head<'_>) -> bool {
    u32_le(h.data, 16) == Some(0xbeef_c0de)
}

declare_format!(pub LMDB = "lmdb", "LMDB database", ["mdb"], "application/x-lmdb",
    Probe::Custom(lmdb_probe), lmdb);

record! {
    pub struct LmdbMeta {
        page: u64 "Page number",
        _pad: u16 "Padding",
        flags: u16 "Page flags" .hex(),
        _bounds: u32 "Bounds",
        magic: u32 "Magic" .hex(),
        version: u32 "Version",
        address: u64 "Fixed map address" .hex(),
        map_size: u64 "Map size",
    }
}

async fn lmdb(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let meta: LmdbMeta = emit_record(&cx, file.sub(0, LmdbMeta::SIZE), LE).await?;
    // Two meta pages; the second sits one page in (page size from the OS,
    // usually 4096).
    let txn_at = 16u64 + 24 + 2 * 48 + 8;
    let txn = crate::bytes::u64_le(&cx.read_avail(file.sub(txn_at, 8)).await?, 0).unwrap_or(0);
    cx.emit(
        Node::new("Last transaction")
            .span(file.sub(txn_at, 8))
            .value(Value::UInt {
                value: txn,
                bits: 64,
                radix: crate::value::Radix::Dec,
            }),
    );
    cx.emit(Node::new("Pages").span(file.tail(8192)));
    cx.annotate(format!(
        "LMDB v{}, map size {} bytes, txn {txn}",
        meta.version, meta.map_size
    ));
    Ok(())
}

fn bolt_probe(h: &Head<'_>) -> bool {
    u32_le(h.data, 16) == Some(0xed0c_daed)
}

declare_format!(pub BOLT = "bbolt", "BoltDB / bbolt database", ["db", "bolt"], "application/x-bolt",
    Probe::Custom(bolt_probe), bolt);

async fn bolt(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 80)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u64("Page ID").emit()?;
    f.u16("Flags").hex().emit()?;
    f.u16("Count").emit()?;
    f.u32("Overflow").emit()?;
    f.u32("Magic").hex().emit()?;
    let version = f.u32("Version").emit()?;
    let page_size = f.u32("Page size").emit()?;
    f.u32("Flags").hex().emit()?;
    f.u64("Root bucket page").emit()?;
    f.u64("Root bucket sequence").emit()?;
    f.u64("Freelist page").emit()?;
    let pages = f.u64("High water mark (pages)").emit()?;
    let txid = f.u64("Transaction ID").emit()?;
    cx.annotate(format!(
        "bbolt v{version}, {pages} pages of {page_size} bytes, txid {txid}"
    ));
    Ok(())
}

declare_format!(pub PROM_CHUNKS = "prometheus-chunks", "Prometheus TSDB chunk segment", [], "application/x-prometheus-tsdb",
    Probe::Magic(&[(0, b"\x85\xbd\x40\xdd")]), prom_chunks);
declare_format!(pub PROM_INDEX = "prometheus-index", "Prometheus TSDB block index", [], "application/x-prometheus-tsdb",
    Probe::Magic(&[(0, b"\xba\xaa\xd7\x00")]), prom_index);

async fn prom_chunks(cx: Cx, input: Input) -> Result<()> {
    let head = cx.read(input.span.sub(0, 8)).await?;
    cx.emit(
        Node::new("Header")
            .span(input.span.sub(0, 8))
            .summary(format!(
                "format version {}",
                head.get(4).copied().unwrap_or(0)
            )),
    );
    cx.emit(Node::new("Chunks").span(input.span.tail(8)));
    cx.annotate("Prometheus chunk segment");
    Ok(())
}

async fn prom_index(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 5)).await?;
    cx.emit(Node::new("Header").span(file.sub(0, 5)).summary(format!(
        "format version {}",
        head.get(4).copied().unwrap_or(0)
    )));
    // The table of contents is the last 52 bytes: six u64 offsets + CRC.
    let toc_span = file.tail(file.len.saturating_sub(52));
    let toc = cx.read(toc_span).await?;
    for (i, name) in [
        "Symbol table",
        "Series",
        "Label indices",
        "Label offset table",
        "Postings",
        "Postings offset table",
    ]
    .iter()
    .enumerate()
    {
        let offset = crate::bytes::u64_be(&toc, i.saturating_mul(8)).unwrap_or(0);
        cx.emit(
            Node::new(*name)
                .span(file.sub(offset, 0))
                .value(Value::UInt {
                    value: offset,
                    bits: 64,
                    radix: crate::value::Radix::Hex,
                }),
        );
    }
    cx.emit(Node::new("Table of contents").span(toc_span));
    cx.annotate("Prometheus TSDB index");
    Ok(())
}

declare_format!(pub INFLUX_TSM = "influxdb-tsm", "InfluxDB TSM file", ["tsm"], "application/x-influxdb-tsm",
    Probe::Magic(&[(0, b"\x16\xd1\x16\xd1")]), influx_tsm);

async fn influx_tsm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 5)).await?;
    let index = crate::bytes::u64_be(&cx.read(file.sub(file.len.saturating_sub(8), 8)).await?, 0)
        .unwrap_or(0);
    cx.emit(
        Node::new("Header")
            .span(file.sub(0, 5))
            .summary(format!("version {}", head.get(4).copied().unwrap_or(0))),
    );
    cx.emit(Node::new("Blocks").span(file.sub(5, index.saturating_sub(5))));
    cx.emit(
        Node::new("Index").span(file.sub(index, file.len.saturating_sub(8).saturating_sub(index))),
    );
    cx.emit(Node::new("Footer").span(file.tail(file.len.saturating_sub(8))));
    cx.annotate(format!(
        "InfluxDB TSM v{}, index at {index:#x}",
        head.get(4).copied().unwrap_or(0)
    ));
    Ok(())
}

declare_format!(pub LUCENE = "lucene", "Apache Lucene index file", ["cfs", "cfe", "si", "doc", "tim", "tip", "fdt", "fdx", "nvd", "nvm", "dvd", "dvm", "pos", "fnm"], "application/x-lucene",
    Probe::Magic(&[(0, b"\x3f\xd7\x6c\x17")]), lucene);

async fn lucene(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, BE);
    cur.skip(4);
    // Codec name: a VInt length (one byte here) and UTF-8 bytes.
    let len = cur.u8().await?;
    let codec = String::from_utf8_lossy(&cur.bytes(len.into()).await?).into_owned();
    let version = cur.u32().await?;
    cx.emit(
        Node::new("Codec header")
            .span(file.sub(0, cur.pos()))
            .value(text(codec.clone()))
            .summary(format!("version {version}")),
    );
    let footer = file.tail(file.len.saturating_sub(16));
    let tail = cx.read_avail(footer).await?;
    let footer_ok = u32_be(&tail, 0) == Some(0xc028_93e8);
    let mut body = Node::new("Body").span(file.sub(
        cur.pos(),
        file.len.saturating_sub(cur.pos()).saturating_sub(16),
    ));
    if !footer_ok {
        body = body.diag(Diagnostic::warning("no codec footer"));
    }
    cx.emit(body);
    if footer_ok {
        cx.emit(Node::new("Codec footer").span(footer).summary(format!(
            "CRC {:#x}",
            crate::bytes::u64_be(&tail, 8).unwrap_or(0)
        )));
    }
    cx.annotate(format!("Lucene {codec} v{version}"));
    Ok(())
}
