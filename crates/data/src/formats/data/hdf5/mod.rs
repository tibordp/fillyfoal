//! HDF5: a superblock, then a graph of objects (groups, datasets, named
//! datatypes), each an object header of messages.
//!
//! Groups name their members through a symbol table (a version 1 B-tree
//! of symbol table nodes, names in a local heap), through link messages, or
//! densely through a fractal heap indexed by version 2 B-trees; attributes
//! are messages or live in a fractal heap the same way. Datasets are
//! compact, contiguous or chunked; chunks are indexed by a version 1
//! B-tree, or (newer files) by a single address, an implicit layout, a
//! fixed array, an extensible array or a version 2 B-tree, and pass
//! through a filter pipeline (deflate chunks are decoded, shuffling is
//! undone). Variable-length values live in global heap collections.
//!
//! Objects are expanded lazily; every object node carries the addresses of
//! the objects above it, so hard-link cycles end instead of recursing, and
//! B-tree and continuation walks keep visited sets. MATLAB 7.3 MAT-files are
//! HDF5 files with a 512-byte user block and NetCDF-4 files are HDF5 with
//! netCDF conventions (`_NCProperties`, dimension scales); both are
//! dissected here. Structures follow the HDF5 File Format Specification
//! version 3; checked against files written by h5py and netCDF4-python.

mod btree;
mod data;
mod datatype;
mod heap;
mod message;
mod util;

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag};

use crate::formats::util::val::hex;
use datatype::Ty;
use message::{Dense, Info, Layout, Link, Space, Target};
use util::{File, FileRef, Rd, checksum_node, emit_all, group, shape};

const SIGNATURE: &[u8] = b"\x89HDF\r\n\x1a\n";
/// Objects followed below one another.
const MAX_DEPTH: usize = 48;
/// Bytes of a dense link or attribute read.
const MAX_HEAP_OBJECT: u64 = 1 << 20;

pub static FORMAT: Format = Format {
    name: "hdf5",
    title: "HDF5 data",
    extensions: &["h5", "hdf5", "he5", "nc4", "nc"],
    mime: "application/x-hdf5",
    probe: Probe::Custom(|h| superblock_offset(h).is_some() && !is_mat73(h)),
    dissect: crate::expander!(dissect: Input),
};

pub static MAT73: Format = Format {
    name: "mat73",
    title: "MATLAB 7.3 MAT-file (HDF5)",
    extensions: &["mat"],
    mime: "application/x-matlab-data",
    probe: Probe::Custom(is_mat73),
    dissect: crate::expander!(dissect: Input),
};

fn is_mat73(h: &Head<'_>) -> bool {
    h.starts_with(b"MATLAB 7.3 MAT-file") && h.at(512, SIGNATURE)
}

/// The superblock is at 0 or at a power of two from 512 on.
fn superblock_offset(h: &Head<'_>) -> Option<usize> {
    std::iter::once(0usize)
        .chain((9..16).map(|s| 1usize << s))
        .find(|&o| h.at(o, SIGNATURE))
}

const CONSISTENCY: FlagTable = &[
    flag(0x1, "open for writing"),
    flag(0x4, "open for SWMR writing"),
];

const SUPERBLOCK_VERSIONS: EnumTable = &[
    (0, "HDF5 1.0"),
    (1, "HDF5 1.4 (non-default B-tree K)"),
    (2, "HDF5 1.8"),
    (3, "HDF5 1.10 (SWMR)"),
];

// ---------------------------------------------------------------------------
// The superblock

/// What the superblock says.
#[derive(Default)]
struct Sb {
    version: u8,
    o: usize,
    l: usize,
    base: u64,
    eof: u64,
    driver: u64,
    ext: u64,
    root: u64,
    cache: Option<(u64, u64)>,
    /// B-tree K values: group leaf, group internal, indexed storage.
    k: [u64; 3],
}

fn superblock_fields(rd: &mut Rd<'_>, sb: &mut Sb) -> Option<()> {
    rd.bytes("Signature", 8)?;
    sb.version = u8::try_from(rd.en("Version", 1, SUPERBLOCK_VERSIONS)?).unwrap_or(0);
    if sb.version <= 1 {
        rd.num("Free-space storage version", 1)?;
        rd.num("Root group symbol table entry version", 1)?;
        rd.reserved(1)?;
        rd.num("Shared header message format version", 1)?;
    }
    sb.o = usize::try_from(rd.num("Size of offsets", 1)?).unwrap_or(8);
    sb.l = usize::try_from(rd.num("Size of lengths", 1)?).unwrap_or(8);
    if !matches!(sb.o, 2 | 4 | 8) || !matches!(sb.l, 2 | 4 | 8) {
        return None;
    }
    rd.o = sb.o;
    rd.l = sb.l;
    if sb.version <= 1 {
        rd.reserved(1)?;
        sb.k[0] = rd.num("Group leaf node K", 2)?;
        sb.k[1] = rd.num("Group internal node K", 2)?;
        rd.flags("File consistency flags", 4, CONSISTENCY)?;
        if sb.version == 1 {
            sb.k[2] = rd.num("Indexed storage internal node K", 2)?;
            rd.reserved(2)?;
        }
        sb.base = rd.addr("Base address")?;
        rd.addr("Free-space info address")?;
        sb.eof = rd.addr("End of file address")?;
        sb.driver = rd.addr("Driver information block address")?;
        let start = rd.pos;
        let mut sub = rd.fork();
        let root = btree::entry_fields(&mut sub, None);
        rd.join("Root group symbol table entry", start, sub);
        sb.root = root?;
        // Cache type 1: the root group's B-tree and heap in the scratch pad.
        let cache_at = start.saturating_add(sb.l).saturating_add(sb.o);
        if util::uint(rd.data, cache_at, 4) == Some(1) {
            let at = cache_at.saturating_add(8);
            if let (Some(b), Some(h)) = (
                util::uint(rd.data, at, sb.o),
                util::uint(rd.data, at.saturating_add(sb.o), sb.o),
            ) {
                sb.cache = Some((b, h));
            }
        }
    } else {
        rd.flags("File consistency flags", 1, CONSISTENCY)?;
        sb.base = rd.addr("Base address")?;
        sb.ext = rd.addr("Superblock extension address")?;
        sb.eof = rd.addr("End of file address")?;
        sb.root = rd.addr("Root group object header address")?;
    }
    Some(())
}

/// A MATLAB 7.3 header, or the text at the start of another user block.
fn user_block(data: &[u8], span: Span) -> Vec<Node> {
    let mut out = Vec::new();
    if data.starts_with(b"MATLAB") && span.len >= 128 {
        let text = crate::text::until_nul(data.get(..116).unwrap_or_default())
            .trim_end()
            .to_owned();
        out.push(
            Node::new("Text")
                .span(span.sub(0, 116))
                .value(Value::Text(text)),
        );
        out.push(
            Node::new("Subsystem data offset")
                .span(span.sub(116, 8))
                .value(hex(util::uint(data, 116, 8).unwrap_or(0), 64)),
        );
        out.push(
            Node::new("Version")
                .span(span.sub(124, 2))
                .value(hex(util::uint(data, 124, 2).unwrap_or(0), 64)),
        );
        out.push(
            Node::new("Endian indicator")
                .span(span.sub(126, 2))
                .value(Value::Text(
                    String::from_utf8_lossy(data.get(126..128).unwrap_or_default()).into_owned(),
                )),
        );
        out.push(Node::new("Padding").span(span.tail(128)));
    } else {
        let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
        let text = String::from_utf8_lossy(data.get(..end).unwrap_or_default()).into_owned();
        out.push(
            Node::new("Text")
                .span(span.sub(0, to_u64(end)))
                .value(Value::Text(text)),
        );
        if to_u64(end) < span.len {
            out.push(Node::new("Padding").span(span.tail(to_u64(end))));
        }
    }
    out
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 0x10000)).await?;
    let probe = Head {
        data: &head,
        tail: &[],
        len: file.len,
        len_known: true,
    };
    let sb = to_u64(
        superblock_offset(&probe)
            .ok_or_else(|| Diagnostic::malformed("no HDF5 signature").at(file.sub(0, 8)))?,
    );
    let matlab = sb == 512 && head.starts_with(b"MATLAB 7.3");
    if sb > 0 {
        let span = file.sub(0, sb);
        let data = head.get(..to_usize(sb)).unwrap_or_default();
        let text = crate::text::until_nul(data.get(..116).unwrap_or(data))
            .trim_end()
            .to_owned();
        cx.emit(
            group("User block", user_block(data, span))
                .span(span)
                .summary(text),
        );
    }
    let sb_span = file.sub(sb, 128);
    let data = cx.read_avail(sb_span).await?;
    let mut rd = Rd {
        data: &data,
        span: sb_span,
        pos: 0,
        out: Vec::new(),
        o: 8,
        l: 8,
    };
    // The library's defaults, for superblocks that do not record them.
    let mut info = Sb {
        k: [4, 16, 32],
        ..Sb::default()
    };
    let ok = superblock_fields(&mut rd, &mut info);
    let end = rd.pos;
    if ok.is_none() {
        rd.finish(None);
        cx.emit(group("Superblock", rd.out).span(sb_span.sub(0, to_u64(end))));
        return Err(
            Diagnostic::malformed("superblock truncated or with invalid field sizes")
                .at(sb_span.sub(0, to_u64(end))),
        );
    }
    let base = if util::undefined(info.base, info.o) {
        sb
    } else {
        info.base.max(sb).min(file.len)
    };
    let hdf = Arc::new(File {
        input,
        k: info.k,
        base,
        o: info.o,
        l: info.l,
    });
    let mut fields = rd.out;
    let mut sb_len = end;
    if info.version >= 2
        && let Some(n) = checksum_node(&cx, &data, sb_span, end).await
    {
        fields.push(n);
        sb_len = end.saturating_add(4);
    }
    if info.version <= 1 && !hdf.undef(info.driver) {
        fields.push(
            Node::new("Driver information block")
                .target(hdf.at(info.driver, 16))
                .lazy(driver_block, (hdf.clone(), info.driver)),
        );
    }
    if let Some((btree, heap)) = info.cache {
        let heap_info = heap::local_heap(&cx, &hdf, heap).await.ok();
        fields.push(
            btree::v1_node(&hdf, btree, btree::V1Kind::Group(heap_info))
                .summary("cached in the root entry"),
        );
        fields.push(heap::local_heap_node(&hdf, heap).summary("cached in the root entry"));
    }
    let mut sb_node = group("Superblock", fields)
        .span(file.sub(sb, to_u64(sb_len)))
        .summary(format!(
            "version {}, {}-byte offsets, {}-byte lengths",
            info.version, info.o, info.l
        ));
    // The library writes the end of file as an absolute position (user
    // block included); accept one relative to the base too.
    if !util::undefined(info.eof, info.o)
        && info.eof != file.len
        && info.eof.saturating_add(base) != file.len
    {
        sb_node = sb_node.diag(Diagnostic::warning(format!(
            "the file is {} bytes; the superblock says {}",
            file.len, info.eof
        )));
    }
    cx.emit(sb_node);
    if info.version >= 2 && !hdf.undef(info.ext) {
        cx.emit(object_node(
            &hdf,
            "Superblock extension".to_owned(),
            info.ext,
            &[],
        ));
    }
    // The root group, and what its attributes say about the file.
    let root = obj(&cx, &hdf, info.root).await;
    let mut root_node = object_node(&hdf, "Root group".to_owned(), info.root, &[]);
    let mut kind = if matlab {
        "MATLAB 7.3 MAT-file (HDF5, ".to_owned()
    } else {
        "HDF5 (".to_owned()
    };
    kind = format!("{kind}superblock v{})", info.version);
    match &root {
        Ok(o) => {
            root_node = root_node.summary(describe(o));
            if let Some(props) = &o.nc_props {
                kind = format!(
                    "NetCDF-4{}, {kind}, {props}",
                    if o.nc_classic { " classic model" } else { "" }
                );
            }
            cx.annotate(format!("{kind}, root {}", describe(o)));
        }
        Err(e) => {
            root_node = root_node.diag(e.clone());
            cx.annotate(kind);
        }
    }
    cx.emit(root_node);
    Ok(())
}

async fn driver_block(cx: Cx, (file, addr): (FileRef, u64)) -> Result<()> {
    let head = cx.read(file.exact(addr, 16)?).await?;
    let size = util::uint(&head, 4, 4).unwrap_or(0);
    let span = file.exact(addr, size.saturating_add(16))?;
    let data = cx.read(span).await?;
    let mut rd = Rd::new(&file, &data, span);
    let ok = driver_fields(&mut rd, size);
    rd.finish(ok);
    for n in rd.out {
        cx.emit(n);
    }
    Ok(())
}

fn driver_fields(rd: &mut Rd<'_>, size: u64) -> Option<()> {
    rd.num("Version", 1)?;
    rd.reserved(3)?;
    rd.num("Driver information size", 4)?;
    let id = rd.text("Driver identification", 8)?;
    match id.as_str() {
        "NCSAmult" => rd.note("multi driver"),
        "NCSAfami" => rd.note("family driver"),
        _ => {}
    }
    rd.bytes("Driver information", to_usize(size))?;
    Some(())
}

// ---------------------------------------------------------------------------
// Objects

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Group,
    Dataset,
    Datatype,
    Other,
}

/// What an object header says, decoded once per object.
struct Obj {
    header: Arc<message::Header>,
    kind: Kind,
    ty: Option<Arc<Ty>>,
    space: Option<Space>,
    layout: Option<Layout>,
    filters: Vec<message::Filter>,
    links: Vec<(Link, Span)>,
    link_info: Option<Dense>,
    symtab: Option<(u64, u64)>,
    attr_info: Option<Dense>,
    attrs: usize,
    /// Members of a group, where cheap to know.
    count: Option<u64>,
    comment: Option<String>,
    /// netCDF-4 conventions seen in the attributes.
    nc_props: Option<String>,
    nc_classic: bool,
    scale: bool,
    dim_only: bool,
}

/// Decodes the object header at `addr` (cached).
async fn obj(cx: &Cx, file: &FileRef, addr: u64) -> Result<Arc<Obj>> {
    let key = file.at(addr, 1);
    if let Some(o) = cx.cached::<Obj>(key, "hdf5-object") {
        return Ok(o);
    }
    let header = message::read(cx, file, addr).await?;
    let mut o = Obj {
        header: header.clone(),
        kind: Kind::Other,
        ty: None,
        space: None,
        layout: None,
        filters: Vec::new(),
        links: Vec::new(),
        link_info: None,
        symtab: None,
        attr_info: None,
        attrs: 0,
        count: None,
        comment: None,
        nc_props: None,
        nc_classic: false,
        scale: false,
        dim_only: false,
    };
    let mut ctx = message::Ctx::default();
    for m in &header.msgs {
        cx.checkpoint().await;
        let body = header.body(m);
        let span = header.body_span(m);
        let mut rd = Rd::new(file, body, span);
        let (info, _) = message::decode(&mut rd, m.kind, m.flags, &ctx);
        match info {
            Info::Type(t) => {
                ctx.ty = Some(t.clone());
                o.ty = Some(Arc::new(t));
            }
            Info::Shared(Some(at)) if m.kind == 0x03 => {
                if let Some(t) = committed_type(cx, file, at).await {
                    ctx.ty = Some(t.clone());
                    o.ty = Some(Arc::new(t));
                }
            }
            Info::Space(s) => o.space = Some(s),
            Info::Layout(l) => o.layout = Some(l),
            Info::Filters(f) => o.filters = f,
            Info::Link(l) => o.links.push((l, m.whole)),
            Info::LinkStore(d) => o.link_info = Some(d),
            Info::SymTab { btree, heap } => o.symtab = Some((btree, heap)),
            Info::AttrStore(d) => o.attr_info = Some(d),
            Info::Comment(c) => o.comment = Some(c),
            Info::Attr(a) => {
                o.attrs = o.attrs.saturating_add(1);
                conventions(&mut o, &a, body, span);
            }
            _ => {}
        }
    }
    o.kind = if o.layout.is_some() {
        Kind::Dataset
    } else if o.symtab.is_some() || o.link_info.is_some() || !o.links.is_empty() {
        Kind::Group
    } else if o.ty.is_some() && o.space.is_none() {
        Kind::Datatype
    } else {
        Kind::Other
    };
    if o.kind == Kind::Group {
        o.count = match o.link_info {
            Some(d) if !file.undef(d.heap) => {
                heap::frheap(cx, file, d.heap).await.ok().map(|h| h.objects)
            }
            _ if o.symtab.is_none() => Some(to_u64(o.links.len())),
            _ => None,
        };
    }
    let o = Arc::new(o);
    cx.cache(key, "hdf5-object", o.clone());
    Ok(o)
}

/// The datatype of a committed (named) datatype object.
async fn committed_type(cx: &Cx, file: &FileRef, addr: u64) -> Option<Ty> {
    let h = message::read(cx, file, addr).await.ok()?;
    let m = h.find(0x03).find(|m| m.flags & 0x02 == 0)?;
    let mut rd = Rd::new(file, h.body(m), h.body_span(m));
    datatype::parse(&mut rd, 0)
}

/// Notes the netCDF-4 conventions an attribute signals.
fn conventions(o: &mut Obj, a: &message::Attr, body: &[u8], span: Span) {
    let text = || {
        let Some(Ty::Str { pad, .. }) = &a.ty else {
            return None;
        };
        let at = to_usize(a.data.offset.saturating_sub(span.offset));
        let bytes = body.get(at..at.saturating_add(to_usize(a.data.len)))?;
        Some(datatype::fixed_string(bytes, *pad))
    };
    match a.name.as_str() {
        "_NCProperties" => o.nc_props = Some(text().unwrap_or_default()),
        "_nc3_strict" => o.nc_classic = true,
        "CLASS" => o.scale |= text().as_deref() == Some("DIMENSION_SCALE"),
        "NAME" => {
            o.dim_only |= text().is_some_and(|t| {
                t.starts_with("This is a netCDF dimension but not a netCDF variable")
            });
        }
        _ => {}
    }
}

/// A one-line description of an object.
fn describe(o: &Obj) -> String {
    match o.kind {
        Kind::Group => {
            let mut s = "group".to_owned();
            if let Some(n) = o.count {
                s = format!("{s}, {n} member{}", if n == 1 { "" } else { "s" });
            }
            s
        }
        Kind::Dataset => {
            let mut s = format!(
                "dataset, {} {}",
                o.ty.as_ref()
                    .map_or_else(|| "?".to_owned(), |t| t.describe()),
                o.space
                    .as_ref()
                    .map_or_else(|| "?".to_owned(), Space::describe)
            );
            match &o.layout {
                Some(Layout::Compact { .. }) => s.push_str(", compact"),
                Some(Layout::Contiguous { .. }) => s.push_str(", contiguous"),
                Some(Layout::Chunked { dims, .. }) => {
                    s = format!("{s}, chunked {}", shape(dims));
                }
                Some(Layout::Virtual { .. }) => s.push_str(", virtual"),
                _ => {}
            }
            if !o.filters.is_empty() {
                let names: Vec<String> = o.filters.iter().map(message::Filter::label).collect();
                s = format!("{s}, {}", names.join(" → "));
            }
            if o.dim_only {
                s.push_str(", netCDF dimension without a variable");
            } else if o.scale {
                s.push_str(", dimension scale");
            }
            s
        }
        Kind::Datatype => format!(
            "named datatype, {}",
            o.ty.as_ref()
                .map_or_else(|| "?".to_owned(), |t| t.describe())
        ),
        Kind::Other => format!("object, {} messages", o.header.msgs.len()),
    }
}

#[derive(Clone)]
struct ObjState {
    file: FileRef,
    addr: u64,
    path: Arc<Vec<u64>>,
}

/// A node that expands into the object at `addr`.
fn object_node(file: &FileRef, name: String, addr: u64, path: &[u64]) -> Node {
    let node = Node::new(name).value(hex(addr, 64));
    if file.undef(addr) {
        return node.summary("undefined address");
    }
    let node = node.target(file.at(addr, 4));
    if path.contains(&addr) {
        return node.summary("already open above (a hard-link cycle)");
    }
    if path.len() >= MAX_DEPTH {
        return node.diag(Diagnostic::limit(format!(
            "objects nested deeper than {MAX_DEPTH}"
        )));
    }
    let mut path = path.to_vec();
    path.push(addr);
    node.lazy(
        crate::expander!(self::object: ObjState),
        ObjState {
            file: file.clone(),
            addr,
            path: Arc::new(path),
        },
    )
}

async fn object(cx: Cx, st: ObjState) -> Result<()> {
    let file = &st.file;
    let o = obj(&cx, file, st.addr).await?;
    for p in &o.header.problems {
        cx.diag(p.clone());
    }
    cx.annotate(describe(&o));
    let h = &o.header;
    let first = h.blocks.first().map(|b| b.span);
    let mut header = Node::new("Object header")
        .summary(format!(
            "version {}, {} messages{}",
            h.version,
            h.msgs.len(),
            if h.blocks.len() > 1 {
                format!(", {} blocks", h.blocks.len())
            } else {
                String::new()
            }
        ))
        .lazy(header_expand, st.clone());
    if let Some(span) = first {
        header = header.span(span);
    }
    cx.emit(header);
    if let Some(c) = &o.comment {
        cx.emit(Node::new("Comment").value(Value::Text(c.clone())));
    }
    let dense_attrs = o.attr_info.filter(|d| !file.undef(d.heap));
    if o.attrs > 0 || dense_attrs.is_some() {
        let mut node = Node::new("Attributes").lazy(attributes, st.clone());
        node = match dense_attrs {
            None => node.summary(format!("{}", o.attrs)),
            Some(d) => match heap::frheap(&cx, file, d.heap).await {
                Ok(h) => node.summary(format!("{}", h.objects.saturating_add(to_u64(o.attrs)))),
                Err(_) => node.summary("stored densely"),
            },
        };
        cx.emit(node);
    }
    if o.kind == Kind::Dataset
        && let Some(layout) = &o.layout
    {
        let d = Arc::new(data::Dset {
            file: file.clone(),
            ty: o.ty.clone(),
            space: o.space.clone().unwrap_or_default(),
            layout: layout.clone(),
            filters: o.filters.clone(),
            path: st.path.clone(),
        });
        if let Some(node) = data::data_node(&d) {
            cx.emit(node);
        }
    }
    if o.kind == Kind::Group {
        members(&cx, &st, &o).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The object header, message by message

fn prefix_fields(rd: &mut Rd<'_>, h: &message::Header) -> Option<()> {
    if h.version == 1 {
        rd.num("Version", 1)?;
        rd.reserved(1)?;
        rd.num("Number of messages", 2)?;
        rd.num("Object reference count", 4)?;
        rd.num("Object header size", 4)?;
        rd.reserved(4)?;
        return Some(());
    }
    rd.sig(4)?;
    rd.num("Version", 1)?;
    let flags = rd.flags("Flags", 1, message::HEADER_FLAGS)?;
    if flags & 0x20 != 0 {
        for name in [
            "Access time",
            "Modification time",
            "Change time",
            "Birth time",
        ] {
            rd.val(name, 4, |v| Value::Timestamp {
                unix_seconds: i64::try_from(v).unwrap_or(0),
            })?;
        }
    }
    if flags & 0x10 != 0 {
        rd.num("Maximum compact attributes", 2)?;
        rd.num("Minimum dense attributes", 2)?;
    }
    rd.num("Size of chunk #0", 1usize << (flags & 3))?;
    Some(())
}

async fn header_expand(cx: Cx, st: ObjState) -> Result<()> {
    let file = &st.file;
    let o = obj(&cx, file, st.addr).await?;
    let h = &o.header;
    let ctx = message::Ctx {
        ty: o.ty.as_deref().cloned(),
    };
    for (bi, blk) in h.blocks.iter().enumerate() {
        if bi == 0 {
            let mut rd = Rd::new(file, &blk.data, blk.span);
            let ok = prefix_fields(&mut rd, h);
            rd.finish(ok);
            for n in rd.out {
                cx.emit(n);
            }
        } else {
            let mut node = Node::new(format!("Continuation block at {:#x}", blk.span.offset))
                .span(blk.span.sub(0, to_u64(blk.first)));
            if blk.v2 {
                node = node.value(Value::Text(
                    String::from_utf8_lossy(blk.data.get(..4).unwrap_or_default()).into_owned(),
                ));
            } else {
                node = node.summary("messages continue here");
            }
            cx.push(node).await;
        }
        let mut last = blk.first;
        for m in h.msgs.iter().filter(|m| m.block == bi) {
            last = last.max(m.at.saturating_add(m.len));
            let node = message_node(&cx, &st, h, m, &ctx).await;
            cx.push(node).await;
        }
        if blk.v2 {
            if blk.end > last {
                cx.push(
                    Node::new("Gap")
                        .span(
                            blk.span
                                .sub(to_u64(last), to_u64(blk.end.saturating_sub(last))),
                        )
                        .summary("too small for a message"),
                )
                .await;
            }
            if let Some(n) = checksum_node(&cx, &blk.data, blk.span, blk.end).await {
                cx.push(n).await;
            }
        }
    }
    Ok(())
}

/// A header message: its header fields, its decoded body, and the
/// structures it points to.
async fn message_node(
    cx: &Cx,
    st: &ObjState,
    h: &message::Header,
    m: &message::Msg,
    ctx: &message::Ctx,
) -> Node {
    let file = &st.file;
    let mut rd = Rd::new(file, h.body(m), h.body_span(m));
    let (info, summary) = message::decode(&mut rd, m.kind, m.flags, ctx);
    let mut children = message::header_fields(h, m);
    children.extend(rd.out);
    children.extend(structures(cx, st, &info).await);
    let name = crate::value::lookup(message::MESSAGES, m.kind.into())
        .map_or_else(|| format!("Message {:#x}", m.kind), str::to_owned);
    let mut node = group(name, children).span(m.whole);
    if let Some(s) = summary {
        node = node.summary(s);
    }
    if let Some(t) = message::target(file, &info) {
        node = node.target(t);
    }
    node
}

/// Nodes for the structures a message points to.
async fn structures(cx: &Cx, st: &ObjState, info: &Info) -> Vec<Node> {
    let file = &st.file;
    let mut out = Vec::new();
    match info {
        Info::SymTab { btree, heap } => {
            let heap_info = heap::local_heap(cx, file, *heap).await.ok();
            out.push(btree::v1_node(
                file,
                *btree,
                btree::V1Kind::Group(heap_info),
            ));
            out.push(heap::local_heap_node(file, *heap));
        }
        Info::LinkStore(d) | Info::AttrStore(d) => {
            if !file.undef(d.heap) {
                out.push(heap::frheap_node(file, d.heap));
                out.push(btree::v2_node(file, d.names, "Name index", None));
                if let Some(order) = d.order.filter(|&a| !file.undef(a)) {
                    out.push(btree::v2_node(file, order, "Creation order index", None));
                }
            }
        }
        Info::Layout(Layout::Chunked {
            index, addr, dims, ..
        }) if !file.undef(*addr) => {
            let rank = dims.len();
            match index {
                message::ChunkIndex::BtreeV1 => out.push(btree::v1_node(
                    file,
                    *addr,
                    btree::V1Kind::Chunk(rank.saturating_add(1)),
                )),
                message::ChunkIndex::Fixed => out.push(btree::fa_node(file, *addr)),
                message::ChunkIndex::Extensible => out.push(btree::ea_node(file, *addr)),
                message::ChunkIndex::BtreeV2 => {
                    out.push(btree::v2_node(file, *addr, "Chunk index", Some(rank)));
                }
                _ => {}
            }
        }
        Info::Layout(Layout::Virtual { heap, .. }) => out.push(heap::gcol_node(file, *heap)),
        Info::Attr(a) => {
            // The values are listed under the object's "Attributes".
            out.push(Node::new("Data").span(a.data).summary(format!(
                "{}; see Attributes",
                crate::formats::util::fmt::size(a.data.len)
            )));
        }
        Info::Shared(Some(addr)) => {
            out.push(object_node(
                file,
                "Shared message source".to_owned(),
                *addr,
                &st.path,
            ));
        }
        Info::SharedTable(addr, n) if !file.undef(*addr) => {
            out.push(
                Node::new("Shared message table")
                    .target(file.at(*addr, 4))
                    .lazy(smtb, (file.clone(), *addr, *n)),
            );
        }
        Info::FileSpace(addrs) => {
            for &a in addrs {
                out.push(heap::fsm_node(file, a));
            }
        }
        Info::External { heap } => out.push(heap::local_heap_node(file, *heap)),
        _ => {}
    }
    out
}

// ---------------------------------------------------------------------------
// Attributes

/// The value of an attribute (when small) for its node.
async fn attribute_node(cx: &Cx, st: &ObjState, info: Info, fields: Vec<Node>, span: Span) -> Node {
    let Info::Attr(a) = info else {
        return group("Attribute", fields).span(span);
    };
    let mut children = fields;
    let mut node = Node::new(a.name.clone()).span(span);
    let ty = match (&a.ty, a.ty_ref) {
        (Some(t), _) => Some(t.clone()),
        (None, Some(at)) => committed_type(cx, &st.file, at).await,
        _ => None,
    };
    match ty {
        Some(ty) => {
            let block = data::Block {
                file: st.file.clone(),
                ty: Arc::new(ty.clone()),
                span: a.data,
                shape: Arc::new(a.space.dims.clone()),
                origin: Arc::new(Vec::new()),
                extent: Arc::new(Vec::new()),
                path: st.path.clone(),
            };
            if let Some(v) = data::preview(cx, &block).await {
                node = node.value(v);
            }
            node = node.summary(if a.space.kind == 0 {
                ty.describe()
            } else {
                format!("{} {}", ty.describe(), a.space.describe())
            });
            children.push(data::values_node("Data", block));
        }
        None => node = node.summary("datatype not decoded"),
    }
    node.lazy(emit_all, Arc::new(children))
}

async fn attributes(cx: Cx, st: ObjState) -> Result<()> {
    let file = &st.file;
    let o = obj(&cx, file, st.addr).await?;
    let h = &o.header;
    let ctx = message::Ctx::default();
    for m in h.find(0x0c) {
        let mut rd = Rd::new(file, h.body(m), h.body_span(m));
        let (info, _) = message::decode(&mut rd, m.kind, m.flags, &ctx);
        let mut fields = message::header_fields(h, m);
        fields.extend(rd.out);
        let node = attribute_node(&cx, &st, info, fields, m.whole).await;
        cx.push(node).await;
    }
    let Some(d) = o.attr_info.filter(|d| !file.undef(d.heap)) else {
        return Ok(());
    };
    let fh = heap::frheap(&cx, file, d.heap).await?;
    let index = d.order.filter(|&a| !file.undef(a)).unwrap_or(d.names);
    let mut it = btree::V2Iter::new(&cx, file, index).await?;
    while let Some(r) = it.next(&cx).await? {
        let id = r.data.get(..8).unwrap_or_default();
        let node = match heap::heap_object(&cx, file, &fh, id, r.span.sub(0, 8)).await {
            Ok(span) => {
                let bytes = cx.read(span.sub(0, MAX_HEAP_OBJECT)).await?;
                let mut rd = Rd::new(file, &bytes, span);
                let (info, _) = message::decode(&mut rd, 0x0c, 0, &ctx);
                attribute_node(&cx, &st, info, rd.out, span).await
            }
            Err(e) => Node::new("Attribute").span(r.span).diag(e),
        };
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Group members

async fn link_node(cx: &Cx, st: &ObjState, link: &Link, span: Span) -> Node {
    let file = &st.file;
    match &link.target {
        Target::Hard(addr) => {
            let mut node = object_node(file, link.name.clone(), *addr, &st.path).span(span);
            if node.has_children() {
                match obj(cx, file, *addr).await {
                    Ok(o) => node = node.summary(describe(&o)),
                    Err(e) => node = node.diag(e),
                }
            }
            node
        }
        Target::Soft(path) => Node::new(link.name.clone())
            .span(span)
            .value(Value::Text(path.clone()))
            .summary("soft link"),
        Target::External { file: f, path } => Node::new(link.name.clone())
            .span(span)
            .value(Value::Text(format!("{f}:{path}")))
            .summary("external link"),
        Target::User(t) => Node::new(link.name.clone())
            .span(span)
            .summary(format!("user-defined link type {t}")),
    }
}

async fn members(cx: &Cx, st: &ObjState, o: &Obj) -> Result<()> {
    let file = &st.file;
    if let Some((btree, heap)) = o.symtab {
        symtab_members(cx, st, btree, heap).await?;
    }
    for (link, span) in &o.links {
        let node = link_node(cx, st, link, *span).await;
        cx.push(node).await;
    }
    let Some(d) = o.link_info.filter(|d| !file.undef(d.heap)) else {
        return Ok(());
    };
    let fh = heap::frheap(cx, file, d.heap).await?;
    let index = d.order.filter(|&a| !file.undef(a)).unwrap_or(d.names);
    let mut it = btree::V2Iter::new(cx, file, index).await?;
    let skip = if it.hdr.kind == 6 { 8usize } else { 4 };
    let ctx = message::Ctx::default();
    while let Some(r) = it.next(cx).await? {
        let id = r.data.get(skip..).unwrap_or_default();
        let id_span = r.span.sub(to_u64(skip), to_u64(id.len()));
        let node = match heap::heap_object(cx, file, &fh, id, id_span).await {
            Ok(span) => {
                let bytes = cx.read(span.sub(0, MAX_HEAP_OBJECT)).await?;
                let mut rd = Rd::new(file, &bytes, span);
                match message::decode(&mut rd, 0x06, 0, &ctx) {
                    (Info::Link(l), _) => link_node(cx, st, &l, span).await,
                    _ => group("Link", rd.out).span(span),
                }
            }
            Err(e) => Node::new("Link").span(r.span).diag(e),
        };
        cx.push(node).await;
    }
    Ok(())
}

async fn symtab_members(cx: &Cx, st: &ObjState, btree: u64, heap: u64) -> Result<()> {
    let file = &st.file;
    let lh = heap::local_heap(cx, file, heap).await?;
    let mut it = btree::V1Iter::new(file, btree, file.l);
    let entry = btree::entry_len(file);
    while let Some(e) = it.next(cx).await? {
        let head = cx.read(file.exact(e.child, 8)?).await?;
        if !head.starts_with(b"SNOD") {
            cx.diag(
                Diagnostic::malformed("symbol table node signature missing")
                    .at(file.at(e.child, 4)),
            );
            continue;
        }
        let n = usize::from(crate::bytes::u16_le(&head, 6).unwrap_or(0));
        let span = file.exact(e.child.saturating_add(8), to_u64(n.saturating_mul(entry)))?;
        let data = cx.read(span).await?;
        for i in 0..n {
            let at = i.saturating_mul(entry);
            let espan = span.sub(to_u64(at), to_u64(entry));
            let (o, l) = (file.o, file.l);
            let name_off = util::uint(&data, at, l).unwrap_or(0);
            let addr = util::uint(&data, at.saturating_add(l), o).unwrap_or(u64::MAX);
            let cache = util::uint(&data, at.saturating_add(l).saturating_add(o), 4).unwrap_or(0);
            let name = match heap::local_name(cx, file, &lh, name_off).await {
                Ok((s, _)) => s,
                Err(_) => format!("<entry {i}>"),
            };
            let node = if cache == 2 {
                let value_off = util::uint(
                    &data,
                    at.saturating_add(l).saturating_add(o).saturating_add(8),
                    4,
                )
                .unwrap_or(0);
                let target = heap::local_name(cx, file, &lh, value_off)
                    .await
                    .map(|(s, _)| s)
                    .unwrap_or_default();
                Node::new(name)
                    .span(espan)
                    .value(Value::Text(target))
                    .summary("soft link")
            } else {
                let link = Link {
                    name,
                    target: Target::Hard(addr),
                };
                link_node(cx, st, &link, espan).await
            };
            cx.push(node).await;
        }
    }
    for p in it.problems {
        cx.diag(p);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Shared object header message table

const SHARED_TYPES: FlagTable = &[
    flag(1 << 1, "dataspace"),
    flag(1 << 3, "datatype"),
    flag(1 << 5, "fill value"),
    flag(1 << 11, "filter pipeline"),
    flag(1 << 12, "attribute"),
];

async fn smtb(cx: Cx, (file, addr, n): (FileRef, u64, u8)) -> Result<()> {
    let entry = 14usize.saturating_add(file.o.saturating_mul(2));
    let len = 4usize
        .saturating_add(entry.saturating_mul(usize::from(n)))
        .saturating_add(4);
    let span = file.exact(addr, to_u64(len))?;
    let data = cx.read(span).await?;
    if !data.starts_with(b"SMTB") {
        return Err(
            Diagnostic::malformed("shared message table signature missing").at(span.sub(0, 4)),
        );
    }
    let mut rd = Rd::new(&file, &data, span);
    rd.sig(4);
    let mut lists = Vec::new();
    for i in 0..n {
        let start = rd.pos;
        let mut sub = rd.fork();
        let ok = smtb_index(&mut sub);
        rd.join(format!("Index {i}"), start, sub);
        let Some((kind, index, heap)) = ok else {
            break;
        };
        if !file.undef(index) {
            lists.push(if kind == 1 {
                btree::v2_node(&file, index, "Index B-tree", None)
            } else {
                Node::new("Index list").target(file.at(index, 4))
            });
        }
        if !file.undef(heap) {
            lists.push(heap::frheap_node(&file, heap));
        }
    }
    let at = rd.pos;
    for n in rd.out {
        cx.emit(n);
    }
    if let Some(n) = checksum_node(&cx, &data, span, at).await {
        cx.emit(n);
    }
    for n in lists {
        cx.push(n).await;
    }
    Ok(())
}

fn smtb_index(rd: &mut Rd<'_>) -> Option<(u64, u64, u64)> {
    rd.num("Version", 1)?;
    let kind = rd.en("Index type", 1, &[(0, "list"), (1, "v2 B-tree")])?;
    rd.flags("Message types", 2, SHARED_TYPES)?;
    rd.num("Minimum message size", 4)?;
    rd.num("List cutoff", 2)?;
    rd.num("B-tree cutoff", 2)?;
    rd.num("Number of messages", 2)?;
    let index = rd.addr("Index address")?;
    let heap = rd.addr("Fractal heap address")?;
    Some((kind, index, heap))
}
