//! Object headers (versions 1 and 2, with continuation blocks) and the
//! header messages in them.

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Radix, Value, field, flag, lookup};

use super::datatype::{self, Ty};
use super::util::{File, Rd, shape, uint, undefined};

/// Continuation blocks followed per object header.
const MAX_BLOCKS: usize = 1 << 12;

pub const MESSAGES: EnumTable = &[
    (0x00, "NIL"),
    (0x01, "Dataspace"),
    (0x02, "Link Info"),
    (0x03, "Datatype"),
    (0x04, "Fill Value (old)"),
    (0x05, "Fill Value"),
    (0x06, "Link"),
    (0x07, "External Data Files"),
    (0x08, "Data Layout"),
    (0x09, "Bogus"),
    (0x0a, "Group Info"),
    (0x0b, "Filter Pipeline"),
    (0x0c, "Attribute"),
    (0x0d, "Object Comment"),
    (0x0e, "Object Modification Time (old)"),
    (0x0f, "Shared Message Table"),
    (0x10, "Object Header Continuation"),
    (0x11, "Symbol Table"),
    (0x12, "Object Modification Time"),
    (0x13, "B-tree 'K' Values"),
    (0x14, "Driver Info"),
    (0x15, "Attribute Info"),
    (0x16, "Object Reference Count"),
    (0x17, "File Space Info"),
];

const MESSAGE_FLAGS: FlagTable = &[
    flag(0x01, "constant"),
    flag(0x02, "shared"),
    flag(0x04, "not shareable"),
    flag(0x08, "fail if unknown and writing"),
    flag(0x10, "mark if unknown"),
    flag(0x20, "unknown and modified"),
    flag(0x40, "shareable"),
    flag(0x80, "fail if unknown"),
];

pub const HEADER_FLAGS: FlagTable = &[
    field(0x03, 0x00, "chunk #0 size in 1 byte"),
    field(0x03, 0x01, "chunk #0 size in 2 bytes"),
    field(0x03, 0x02, "chunk #0 size in 4 bytes"),
    field(0x03, 0x03, "chunk #0 size in 8 bytes"),
    flag(0x04, "attribute creation order tracked"),
    flag(0x08, "attribute creation order indexed"),
    flag(0x10, "attribute storage phase change values stored"),
    flag(0x20, "times stored"),
];

pub const FILTERS: EnumTable = &[
    (1, "deflate"),
    (2, "shuffle"),
    (3, "fletcher32"),
    (4, "szip"),
    (5, "nbit"),
    (6, "scaleoffset"),
    (305, "LZO"),
    (307, "bzip2"),
    (32000, "LZF"),
    (32001, "Blosc"),
    (32002, "MAFISC"),
    (32003, "Snappy"),
    (32004, "LZ4"),
    (32005, "APAX"),
    (32006, "CBF"),
    (32007, "JPEG-XR"),
    (32008, "bitshuffle"),
    (32009, "SPDP"),
    (32010, "LPC-Rice"),
    (32011, "CCSDS-123"),
    (32012, "JPEG-LS"),
    (32013, "zfp"),
    (32014, "fpzip"),
    (32015, "Zstandard"),
    (32016, "B³D"),
    (32017, "SZ"),
    (32018, "FCIDECOMP"),
    (32019, "JPEG"),
    (32020, "VBZ"),
    (32021, "FAPEC"),
    (32022, "BitGroom"),
    (32023, "Granular BitRound"),
    (32024, "SZ3"),
    (32025, "Delta-Rice"),
    (32026, "Blosc2"),
    (32027, "FLAC"),
];

const LAYOUT_CLASSES: EnumTable = &[
    (0, "compact"),
    (1, "contiguous"),
    (2, "chunked"),
    (3, "virtual"),
];

pub const CHUNK_INDEXES: EnumTable = &[
    (1, "single chunk"),
    (2, "implicit"),
    (3, "fixed array"),
    (4, "extensible array"),
    (5, "version 2 B-tree"),
];

const LINK_TYPES: EnumTable = &[(0, "hard"), (1, "soft"), (64, "external")];
const CHARSETS: EnumTable = &[(0, "ASCII"), (1, "UTF-8")];
const ALLOC_TIMES: EnumTable = &[
    (0, "default"),
    (1, "early"),
    (2, "late"),
    (3, "incremental"),
];
const FILL_TIMES: EnumTable = &[(0, "on allocation"), (1, "never"), (2, "if set")];

/// One message of an object header.
#[derive(Clone, Debug)]
pub struct Msg {
    pub kind: u16,
    pub flags: u8,
    /// The message including its header.
    pub whole: Span,
    /// Which block it is in, and where its body is in that block's bytes.
    pub block: usize,
    pub at: usize,
    pub len: usize,
}

/// One block of an object header: chunk #0 (with the prefix) or a
/// continuation block.
#[derive(Clone, Debug)]
pub struct Blk {
    pub span: Span,
    pub data: Arc<Vec<u8>>,
    /// Where messages start and end within `data`.
    pub first: usize,
    pub end: usize,
    /// Version 2 blocks have a signature (continuations) and a checksum.
    pub v2: bool,
}

/// An object header, read in full.
#[derive(Debug)]
pub struct Header {
    pub version: u8,
    /// Version 2 header flags.
    pub flags: u8,
    pub blocks: Vec<Blk>,
    pub msgs: Vec<Msg>,
    pub problems: Vec<Diagnostic>,
}

impl Header {
    /// The body of a message.
    pub fn body(&self, m: &Msg) -> &[u8] {
        self.blocks
            .get(m.block)
            .and_then(|b| b.data.get(m.at..m.at.saturating_add(m.len)))
            .unwrap_or_default()
    }

    /// The span of a message's body.
    pub fn body_span(&self, m: &Msg) -> Span {
        self.blocks
            .get(m.block)
            .map_or(m.whole, |b| b.span.sub(to_u64(m.at), to_u64(m.len)))
    }

    pub fn find(&self, kind: u16) -> impl Iterator<Item = &Msg> {
        self.msgs.iter().filter(move |m| m.kind == kind)
    }
}

/// Reads the object header at `addr` (cached per file position).
pub async fn read(cx: &Cx, file: &File, addr: u64) -> Result<Arc<Header>> {
    let key = file.at(addr, 1);
    if let Some(h) = cx.cached::<Header>(key, "hdf5-object-header") {
        return Ok(h);
    }
    let h = Arc::new(read_uncached(cx, file, addr).await?);
    cx.cache(key, "hdf5-object-header", h.clone());
    Ok(h)
}

async fn read_uncached(cx: &Cx, file: &File, addr: u64) -> Result<Header> {
    let head = cx.read_avail(file.at(addr, 64)).await?;
    let mut blocks = Vec::new();
    let mut pending: Vec<(u64, u64)> = Vec::new();
    let version;
    let mut flags = 0u8;
    if head.starts_with(b"OHDR") {
        version = head.get(4).copied().unwrap_or(0);
        flags = head.get(5).copied().unwrap_or(0);
        let mut at = 6usize;
        if flags & 0x20 != 0 {
            at = at.saturating_add(16);
        }
        if flags & 0x10 != 0 {
            at = at.saturating_add(4);
        }
        let width = 1usize << (flags & 3);
        let size = uint(&head, at, width).ok_or_else(|| {
            Diagnostic::truncated(
                file.at(addr, to_u64(at.saturating_add(width))),
                to_u64(head.len()),
            )
        })?;
        let first = at.saturating_add(width);
        let total = to_u64(first).saturating_add(size).saturating_add(4);
        let span = file.exact(addr, total)?;
        let data = cx.read(span).await?;
        blocks.push(Blk {
            span,
            first,
            end: first.saturating_add(to_usize(size)),
            data: Arc::new(data),
            v2: true,
        });
    } else {
        version = head.first().copied().unwrap_or(0);
        if version != 1 {
            return Err(Diagnostic::malformed(format!(
                "not an object header (version {version}, no OHDR signature)"
            ))
            .at(file.at(addr, 4)));
        }
        let size = u64::from(crate::bytes::u32_le(&head, 8).unwrap_or(0));
        let span = file.exact(addr, size.saturating_add(16))?;
        let data = cx.read(span).await?;
        blocks.push(Blk {
            span,
            first: 16,
            end: data.len(),
            data: Arc::new(data),
            v2: false,
        });
    }
    let v2 = version != 1;
    let mut msgs = Vec::new();
    let mut problems = Vec::new();
    let mut seen = BTreeSet::new();
    let mut index = 0usize;
    loop {
        // Load the next continuation block, if any.
        if index >= blocks.len() {
            let Some((at, len)) = pending.pop() else {
                break;
            };
            if !seen.insert(at) || blocks.len() >= MAX_BLOCKS {
                problems.push(Diagnostic::malformed(format!(
                    "continuation block at {at:#x} repeats or there are too many"
                )));
                continue;
            }
            let span = match file.exact(at, len) {
                Ok(s) => s,
                Err(e) => {
                    problems.push(e);
                    continue;
                }
            };
            let data = match cx.read(span).await {
                Ok(d) => d,
                Err(e) => {
                    problems.push(e);
                    continue;
                }
            };
            let (first, end) = if v2 {
                if !data.starts_with(b"OCHK") {
                    problems.push(
                        Diagnostic::malformed("continuation block without OCHK signature")
                            .at(span.sub(0, 4)),
                    );
                }
                (4, data.len().saturating_sub(4))
            } else {
                (0, data.len())
            };
            blocks.push(Blk {
                span,
                first,
                end,
                data: Arc::new(data),
                v2,
            });
        }
        let Some(blk) = blocks.get(index) else {
            break;
        };
        let data = blk.data.clone();
        let (first, end, span) = (blk.first, blk.end.min(data.len()), blk.span);
        let mut found = Vec::new();
        let mut pos = first;
        while pos < end {
            cx.checkpoint().await;
            let header = if v2 {
                if flags & 0x04 != 0 { 6 } else { 4 }
            } else {
                8
            };
            if pos.saturating_add(header) > end {
                break;
            }
            let (kind, len, mflags) = if v2 {
                (
                    u16::from(data.get(pos).copied().unwrap_or(0)),
                    u16_le(&data, pos.saturating_add(1)).unwrap_or(0),
                    data.get(pos.saturating_add(3)).copied().unwrap_or(0),
                )
            } else {
                (
                    u16_le(&data, pos).unwrap_or(0),
                    u16_le(&data, pos.saturating_add(2)).unwrap_or(0),
                    data.get(pos.saturating_add(4)).copied().unwrap_or(0),
                )
            };
            let at = pos.saturating_add(header);
            let mut len = usize::from(len);
            if at.saturating_add(len) > end {
                problems.push(
                    Diagnostic::malformed(format!("message of type {kind:#x} overruns its block"))
                        .at(span.sub(to_u64(pos), to_u64(header))),
                );
                len = end.saturating_sub(at);
            }
            if kind == 0x10
                && let (Some(a), Some(l)) = (
                    uint(&data, at, file.o),
                    uint(&data, at.saturating_add(file.o), file.l),
                )
            {
                found.push((a, l));
            }
            msgs.push(Msg {
                kind,
                flags: mflags,
                whole: span.sub(to_u64(pos), to_u64(header.saturating_add(len))),
                block: index,
                at,
                len,
            });
            pos = at.saturating_add(len);
            if !v2 {
                pos = pos.checked_next_multiple_of(8).unwrap_or(usize::MAX);
            }
        }
        // Continuations are followed in the order they appear.
        pending.extend(found.into_iter().rev());
        index = index.saturating_add(1);
    }
    Ok(Header {
        version,
        flags,
        blocks,
        msgs,
        problems,
    })
}

// ---------------------------------------------------------------------------
// Decoded message contents

#[derive(Clone, Debug, Default)]
pub struct Space {
    /// 0 scalar, 1 simple, 2 null.
    pub kind: u8,
    pub dims: Vec<u64>,
    pub max: Option<Vec<u64>>,
}

impl Space {
    /// Number of elements.
    pub fn count(&self) -> u64 {
        match self.kind {
            2 => 0,
            _ => self.dims.iter().fold(1u64, |a, &d| a.saturating_mul(d)),
        }
    }

    pub fn describe(&self) -> String {
        match self.kind {
            0 => "scalar".to_owned(),
            2 => "null (no data)".to_owned(),
            _ => {
                let mut s = format!("[{}]", shape(&self.dims));
                if let Some(max) = &self.max
                    && max != &self.dims
                {
                    let m: Vec<String> = max
                        .iter()
                        .map(|&d| {
                            if d == u64::MAX {
                                "∞".to_owned()
                            } else {
                                d.to_string()
                            }
                        })
                        .collect();
                    s = format!("{s} (max {})", m.join("×"));
                }
                s
            }
        }
    }
}

#[derive(Clone, Debug)]
pub enum ChunkIndex {
    /// Version 1 B-tree (layout versions 1–3).
    BtreeV1,
    Single {
        filtered: Option<(u64, u32)>,
    },
    Implicit,
    Fixed,
    Extensible,
    BtreeV2,
}

#[derive(Clone, Debug)]
pub enum Layout {
    Compact {
        data: Span,
    },
    Contiguous {
        addr: u64,
        size: Option<u64>,
    },
    Chunked {
        /// Chunk dimensions (without the element-size dimension).
        dims: Vec<u64>,
        elem: u64,
        index: ChunkIndex,
        addr: u64,
    },
    Virtual {
        heap: u64,
        index: u32,
    },
    Other,
}

#[derive(Clone, Debug)]
pub struct Filter {
    pub id: u16,
    pub name: Option<String>,
    pub flags: u16,
    pub values: Vec<u32>,
}

impl Filter {
    pub fn label(&self) -> String {
        match lookup(FILTERS, self.id.into()) {
            Some(n) => n.to_owned(),
            None => self
                .name
                .clone()
                .unwrap_or_else(|| format!("filter {}", self.id)),
        }
    }
}

#[derive(Clone, Debug)]
pub enum Target {
    Hard(u64),
    Soft(String),
    External { file: String, path: String },
    User(u8),
}

#[derive(Clone, Debug)]
pub struct Link {
    pub name: String,
    pub target: Target,
}

/// Where a group keeps dense links or an object dense attributes.
#[derive(Clone, Copy, Debug)]
pub struct Dense {
    pub heap: u64,
    pub names: u64,
    pub order: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct Attr {
    pub name: String,
    pub ty: Option<Ty>,
    /// The address of a committed datatype, when the type is shared.
    pub ty_ref: Option<u64>,
    pub space: Space,
    pub data: Span,
}

#[derive(Clone, Debug)]
pub enum Info {
    None,
    Space(Space),
    Type(Ty),
    Layout(Layout),
    Filters(Vec<Filter>),
    Link(Link),
    LinkStore(Dense),
    AttrStore(Dense),
    Attr(Attr),
    SymTab {
        btree: u64,
        heap: u64,
    },
    /// A shared message stored elsewhere: in another object header.
    Shared(Option<u64>),
    Comment(String),
    External {
        heap: u64,
    },
    SharedTable(u64, u8),
    FileSpace(Vec<u64>),
    Cont {
        addr: u64,
        len: u64,
    },
}

/// What a message decoder may need from elsewhere in the header.
#[derive(Clone, Default)]
pub struct Ctx {
    /// The object's datatype (for fill values and compact data).
    pub ty: Option<Ty>,
}

fn field_node(
    rd: &mut Rd<'_>,
    name: String,
    n: usize,
    value: impl FnOnce(u64) -> Value,
) -> Option<u64> {
    let (v, span) = rd.take(n)?;
    rd.push(Node::new(name).span(span).value(value(v)));
    Some(v)
}

/// A shared message reference (the body of a message flagged shared).
fn shared_ref(rd: &mut Rd<'_>) -> Option<Option<u64>> {
    const SHARED_V3: EnumTable = &[
        (0, "not shared"),
        (1, "in the shared message heap"),
        (2, "in another object header (committed)"),
        (3, "in this object header"),
    ];
    const SHARED_V1: EnumTable = &[(0, "in another object header (committed)")];
    let version = rd.num("Version", 1)?;
    let kind = rd.en("Type", 1, if version >= 3 { SHARED_V3 } else { SHARED_V1 })?;
    if version == 1 {
        rd.reserved(6)?;
    }
    if version >= 3 && kind == 1 {
        rd.bytes("Heap ID", 8)?;
        return Some(None);
    }
    let addr = rd.addr("Object header address")?;
    Some(Some(addr))
}

pub fn dataspace(rd: &mut Rd<'_>) -> Option<Space> {
    let version = rd.num("Version", 1)?;
    let rank = rd.num("Dimensionality", 1)?;
    let flags = rd.flags(
        "Flags",
        1,
        &[
            flag(1, "maximum dimensions present"),
            flag(2, "permutation indices present"),
        ],
    )?;
    let kind = if version >= 2 {
        u8::try_from(rd.en("Type", 1, &[(0, "scalar"), (1, "simple"), (2, "null")])?).unwrap_or(1)
    } else {
        rd.reserved(5)?;
        u8::from(rank != 0)
    };
    let l = rd.l;
    let mut dims = Vec::new();
    for i in 0..rank {
        dims.push(field_node(
            rd,
            format!("Dimension {i} size"),
            l,
            super::util::dec,
        )?);
    }
    let mut max = None;
    if flags & 1 != 0 {
        let mut m = Vec::new();
        for i in 0..rank {
            let v = field_node(rd, format!("Dimension {i} maximum"), l, super::util::dec)?;
            if undefined(v, l) {
                rd.note("unlimited");
                m.push(u64::MAX);
            } else {
                m.push(v);
            }
        }
        max = Some(m);
    }
    if version == 1 && flags & 2 != 0 {
        for i in 0..rank {
            field_node(
                rd,
                format!("Dimension {i} permutation"),
                l,
                super::util::dec,
            )?;
        }
    }
    Some(Space { kind, dims, max })
}

fn dense_info(rd: &mut Rd<'_>, attrs: bool) -> Option<Dense> {
    rd.num("Version", 1)?;
    let flags = rd.flags(
        "Flags",
        1,
        &[
            flag(1, "creation order tracked"),
            flag(2, "creation order indexed"),
        ],
    )?;
    if flags & 1 != 0 {
        rd.num("Maximum creation index", if attrs { 2 } else { 8 })?;
    }
    let heap = rd.addr("Fractal heap address")?;
    let names = rd.addr("Name index v2 B-tree address")?;
    let order = if flags & 2 != 0 {
        Some(rd.addr("Creation order index v2 B-tree address")?)
    } else {
        None
    };
    Some(Dense { heap, names, order })
}

fn link(rd: &mut Rd<'_>) -> Option<Link> {
    rd.num("Version", 1)?;
    let flags = rd.flags(
        "Flags",
        1,
        &[
            field(0x03, 0x00, "name length in 1 byte"),
            field(0x03, 0x01, "name length in 2 bytes"),
            field(0x03, 0x02, "name length in 4 bytes"),
            field(0x03, 0x03, "name length in 8 bytes"),
            flag(0x04, "creation order present"),
            flag(0x08, "link type present"),
            flag(0x10, "character set present"),
        ],
    )?;
    let kind = if flags & 0x08 != 0 {
        rd.en("Link type", 1, LINK_TYPES)?
    } else {
        0
    };
    if flags & 0x04 != 0 {
        rd.num("Creation order", 8)?;
    }
    if flags & 0x10 != 0 {
        rd.en("Character set", 1, CHARSETS)?;
    }
    let width = 1usize << (flags & 3);
    let len = rd.num("Name length", width)?;
    let (bytes, span) = rd.slice(to_usize(len))?;
    let name = String::from_utf8_lossy(bytes).into_owned();
    rd.push(
        Node::new("Name")
            .span(span)
            .value(Value::Text(name.clone())),
    );
    let target = match kind {
        0 => Target::Hard(rd.addr("Object header address")?),
        1 => {
            let n = rd.num("Value length", 2)?;
            Target::Soft(rd.text("Target path", to_usize(n))?)
        }
        64 => {
            let n = to_usize(rd.num("Value length", 2)?);
            let start = rd.pos;
            rd.val("Version and flags", 1, |v| Value::UInt {
                value: v,
                bits: 8,
                radix: Radix::Hex,
            })?;
            let file = rd.cstr("File name", 1)?;
            let path = rd.cstr("Object path", 1)?;
            rd.rest("Padding", start.saturating_add(n));
            Target::External { file, path }
        }
        other => {
            let n = rd.num("Value length", 2)?;
            rd.bytes("Value", to_usize(n))?;
            Target::User(u8::try_from(other).unwrap_or(u8::MAX))
        }
    };
    Some(Link { name, target })
}

fn layout(rd: &mut Rd<'_>) -> Option<Layout> {
    let version = rd.num("Version", 1)?;
    if version < 3 {
        let rank = rd.num("Dimensionality", 1)?;
        let class = rd.en("Layout class", 1, LAYOUT_CLASSES)?;
        rd.reserved(5)?;
        let addr = if class != 0 {
            rd.addr("Data address")?
        } else {
            u64::MAX
        };
        let mut dims = Vec::new();
        for i in 0..rank {
            dims.push(field_node(
                rd,
                format!("Dimension {i} size"),
                4,
                super::util::dec,
            )?);
        }
        return Some(match class {
            0 => {
                let n = rd.num("Compact data size", 4)?;
                let (_, span) = rd.slice(to_usize(n))?;
                rd.push(Node::new("Compact data").span(span));
                Layout::Compact { data: span }
            }
            1 => Layout::Contiguous { addr, size: None },
            _ => {
                let elem = dims.pop().unwrap_or(1);
                Layout::Chunked {
                    dims,
                    elem,
                    index: ChunkIndex::BtreeV1,
                    addr,
                }
            }
        });
    }
    let class = rd.en("Layout class", 1, LAYOUT_CLASSES)?;
    Some(match class {
        0 => {
            let n = rd.num("Size", 2)?;
            let (_, span) = rd.slice(to_usize(n))?;
            rd.push(Node::new("Compact data").span(span));
            Layout::Compact { data: span }
        }
        1 => {
            let addr = rd.addr("Address")?;
            let size = rd.length("Size")?;
            Layout::Contiguous {
                addr,
                size: Some(size),
            }
        }
        2 if version == 3 => {
            let rank = rd.num("Dimensionality", 1)?;
            let addr = rd.addr("B-tree address")?;
            let mut dims = Vec::new();
            for i in 0..rank {
                dims.push(field_node(
                    rd,
                    format!("Dimension {i} size"),
                    4,
                    super::util::dec,
                )?);
            }
            if let Some(last) = rd.last() {
                last.summary = Some("element size".to_owned());
            }
            let elem = dims.pop().unwrap_or(1);
            Layout::Chunked {
                dims,
                elem,
                index: ChunkIndex::BtreeV1,
                addr,
            }
        }
        2 => {
            let flags = rd.flags(
                "Flags",
                1,
                &[
                    flag(1, "do not filter partial edge chunks"),
                    flag(2, "single index with filter"),
                ],
            )?;
            let flags = u8::try_from(flags).unwrap_or(0);
            let rank = rd.num("Dimensionality", 1)?;
            let width = to_usize(rd.num("Dimension size encoded length", 1)?);
            let mut dims = Vec::new();
            for i in 0..rank {
                dims.push(field_node(
                    rd,
                    format!("Dimension {i} size"),
                    width,
                    super::util::dec,
                )?);
            }
            if let Some(last) = rd.last() {
                last.summary = Some("element size".to_owned());
            }
            let elem = dims.pop().unwrap_or(1);
            let kind = rd.en("Chunk indexing type", 1, CHUNK_INDEXES)?;
            let index = match kind {
                1 => ChunkIndex::Single {
                    filtered: if flags & 2 != 0 {
                        let size = rd.length("Size of filtered chunk")?;
                        let mask = rd.hexn("Filter mask", 4)?;
                        Some((size, u32::try_from(mask).unwrap_or(0)))
                    } else {
                        None
                    },
                },
                2 => ChunkIndex::Implicit,
                3 => {
                    rd.num("Page bits", 1)?;
                    ChunkIndex::Fixed
                }
                4 => {
                    for name in [
                        "Maximum bits",
                        "Index elements",
                        "Minimum pointers",
                        "Minimum elements",
                        "Page bits",
                    ] {
                        rd.num(name, 1)?;
                    }
                    ChunkIndex::Extensible
                }
                5 => {
                    rd.num("Node size", 4)?;
                    rd.num("Split percent", 1)?;
                    rd.num("Merge percent", 1)?;
                    ChunkIndex::BtreeV2
                }
                _ => return Some(Layout::Other),
            };
            let addr = rd.addr("Index address")?;
            Layout::Chunked {
                dims,
                elem,
                index,
                addr,
            }
        }
        3 => {
            let heap = rd.addr("Global heap collection address")?;
            let index = rd.num("Global heap object index", 4)?;
            Layout::Virtual {
                heap,
                index: u32::try_from(index).unwrap_or(0),
            }
        }
        _ => Layout::Other,
    })
}

fn filters(rd: &mut Rd<'_>) -> Option<Vec<Filter>> {
    let version = rd.num("Version", 1)?;
    let n = rd.num("Number of filters", 1)?;
    if version == 1 {
        rd.reserved(6)?;
    }
    let mut out = Vec::new();
    for _ in 0..n {
        let start = rd.pos;
        let mut sub = rd.fork();
        let f = filter(&mut sub, version);
        let label = f
            .as_ref()
            .map_or_else(|| "Filter".to_owned(), Filter::label);
        let summary = f.as_ref().map(|f| {
            let values: Vec<String> = f.values.iter().map(u32::to_string).collect();
            format!(
                "{}{}",
                if f.flags & 1 != 0 {
                    "optional"
                } else {
                    "mandatory"
                },
                if values.is_empty() {
                    String::new()
                } else {
                    format!(", parameters {}", values.join(", "))
                }
            )
        });
        rd.join(label, start, sub);
        if let (Some(s), Some(last)) = (summary, rd.last()) {
            last.summary = Some(s);
        }
        out.push(f?);
    }
    Some(out)
}

fn filter(rd: &mut Rd<'_>, version: u64) -> Option<Filter> {
    let id = u16::try_from(rd.en("Filter ID", 2, FILTERS)?).unwrap_or(0);
    let name_len = if version == 1 || id >= 256 {
        rd.num("Name length", 2)?
    } else {
        0
    };
    let flags = u16::try_from(rd.flags("Flags", 2, &[flag(1, "optional")])?).unwrap_or(0);
    let nvalues = rd.num("Number of client data values", 2)?;
    let name = if name_len > 0 {
        let (bytes, span) = rd.slice(to_usize(name_len))?;
        let text = crate::text::until_nul(bytes);
        rd.push(
            Node::new("Name")
                .span(span)
                .value(Value::Text(text.clone())),
        );
        Some(text)
    } else {
        None
    };
    // What the client data of the predefined filters mean.
    let meanings: &[&str] = match id {
        1 => &["compression level"],
        2 => &["element size"],
        4 => &[
            "options mask",
            "pixels per block",
            "bits per pixel",
            "pixels per scanline",
        ],
        6 => &["scale type", "scale factor", "number of elements", "class"],
        _ => &[],
    };
    let mut values = Vec::new();
    for i in 0..nvalues {
        let v = field_node(rd, format!("Client data {i}"), 4, super::util::dec)?;
        if let Some(m) = meanings.get(to_usize(i)) {
            rd.note(*m);
        }
        values.push(u32::try_from(v).unwrap_or(0));
    }
    if version == 1 && nvalues % 2 == 1 {
        rd.reserved(4)?;
    }
    Some(Filter {
        id,
        name,
        flags,
        values,
    })
}

fn attribute(rd: &mut Rd<'_>, ctx: &Ctx) -> Option<Attr> {
    let _ = ctx;
    let version = rd.num("Version", 1)?;
    let flags = if version == 1 {
        rd.reserved(1)?;
        0
    } else {
        rd.flags(
            "Flags",
            1,
            &[flag(1, "datatype shared"), flag(2, "dataspace shared")],
        )?
    };
    let name_len = to_usize(rd.num("Name size", 2)?);
    let type_len = to_usize(rd.num("Datatype size", 2)?);
    let space_len = to_usize(rd.num("Dataspace size", 2)?);
    if version >= 3 {
        rd.en("Name character set", 1, CHARSETS)?;
    }
    let pad = |n: usize| {
        if version == 1 {
            n.checked_next_multiple_of(8).unwrap_or(n)
        } else {
            n
        }
    };
    let (bytes, span) = rd.slice(pad(name_len))?;
    let name = crate::text::until_nul(bytes.get(..name_len).unwrap_or(bytes));
    rd.push(
        Node::new("Name")
            .span(span)
            .value(Value::Text(name.clone())),
    );
    // Datatype.
    let start = rd.pos;
    let mut sub = rd.fork();
    sub.data = sub
        .data
        .get(..start.saturating_add(type_len))
        .unwrap_or(sub.data);
    let (mut ty, mut ty_ref) = (None, None);
    if flags & 1 != 0 {
        ty_ref = shared_ref(&mut sub).flatten();
    } else {
        ty = datatype::parse(&mut sub, 0);
    }
    let summary = ty.as_ref().map(Ty::describe);
    pad_to(&mut sub, start.saturating_add(pad(type_len)));
    rd.join("Datatype", start, sub);
    if let (Some(s), Some(last)) = (summary, rd.last()) {
        last.summary = Some(s);
    }
    // Dataspace.
    let start = rd.pos;
    let mut sub = rd.fork();
    sub.data = sub
        .data
        .get(..start.saturating_add(space_len))
        .unwrap_or(sub.data);
    let space = if flags & 2 != 0 {
        shared_ref(&mut sub);
        None
    } else {
        dataspace(&mut sub)
    };
    let summary = space.as_ref().map(Space::describe);
    pad_to(&mut sub, start.saturating_add(pad(space_len)));
    rd.join("Dataspace", start, sub);
    if let (Some(s), Some(last)) = (summary, rd.last()) {
        last.summary = Some(s);
    }
    // Neither a datatype nor a reference to one: the message is cut short.
    if ty.is_none() && ty_ref.is_none() {
        return None;
    }
    let space = space.unwrap_or_default();
    let elem = ty.as_ref().map_or(0, |t| u64::from(t.size()));
    let want = space.count().saturating_mul(elem);
    let left = to_u64(rd.left());
    let len = if ty.is_some() { want.min(left) } else { left };
    let data = rd.sp(rd.pos, to_usize(len));
    rd.skip(to_usize(len));
    Some(Attr {
        name,
        ty,
        ty_ref,
        space,
        data,
    })
}

/// Decodes a message body, rendering its fields into `rd`. Returns what
/// the message says, and a one-line summary.
pub fn decode(rd: &mut Rd<'_>, kind: u16, flags: u8, ctx: &Ctx) -> (Info, Option<String>) {
    let mut summary = None;
    let info = if flags & 0x02 != 0 && kind != 0x10 {
        let r = shared_ref(rd);
        rd.finish(r.map(|_| ()));
        summary = Some("shared message".to_owned());
        Info::Shared(r.flatten())
    } else {
        let r = body(rd, kind, ctx, &mut summary);
        rd.finish(r.as_ref().map(|_| ()));
        r.unwrap_or(Info::None)
    };
    (info, summary)
}

fn body(rd: &mut Rd<'_>, kind: u16, ctx: &Ctx, summary: &mut Option<String>) -> Option<Info> {
    Some(match kind {
        0x00 => {
            let n = rd.left();
            if n > 0 {
                rd.bytes("Padding", n)?;
            }
            *summary = Some(format!("{n} bytes of free space"));
            Info::None
        }
        0x01 => {
            let s = dataspace(rd)?;
            *summary = Some(s.describe());
            Info::Space(s)
        }
        0x02 => {
            let d = dense_info(rd, false)?;
            *summary = Some(if undefined(d.heap, rd.o) {
                "links stored in the object header".to_owned()
            } else {
                "links stored densely (fractal heap)".to_owned()
            });
            Info::LinkStore(d)
        }
        0x03 => {
            let t = datatype::parse(rd, 0)?;
            *summary = Some(t.describe());
            Info::Type(t)
        }
        0x04 => {
            let n = rd.num("Size", 4)?;
            fill_value(rd, n, ctx)?;
            Info::None
        }
        0x05 => {
            let version = rd.num("Version", 1)?;
            let defined = if version < 3 {
                rd.en("Space allocation time", 1, ALLOC_TIMES)?;
                rd.en("Fill value write time", 1, FILL_TIMES)?;
                let d = rd.num("Fill value defined", 1)?;
                version == 1 || d != 0
            } else {
                let (v, span) = rd.take(1)?;
                let alloc = lookup(ALLOC_TIMES, v & 3).unwrap_or("?");
                let write = lookup(FILL_TIMES, (v >> 2) & 3).unwrap_or("?");
                rd.push(
                    Node::new("Flags")
                        .span(span)
                        .value(Value::UInt {
                            value: v,
                            bits: 8,
                            radix: Radix::Hex,
                        })
                        .summary(format!(
                            "allocation {alloc}, write {write}{}{}",
                            if v & 0x10 != 0 { ", undefined" } else { "" },
                            if v & 0x20 != 0 { ", defined" } else { "" }
                        )),
                );
                v & 0x20 != 0
            };
            if defined {
                let n = rd.num("Size", 4)?;
                let v = fill_value(rd, n, ctx)?;
                *summary = Some(v.map_or_else(
                    || "no fill value stored".to_owned(),
                    |v| format!("fill value {v}"),
                ));
            } else {
                *summary = Some("default fill value".to_owned());
            }
            Info::None
        }
        0x06 => {
            let l = link(rd)?;
            *summary = Some(match &l.target {
                Target::Hard(a) => format!("{} → {a:#x}", l.name),
                Target::Soft(p) => format!("{} → {p} (soft)", l.name),
                Target::External { file, path } => format!("{} → {file}:{path} (external)", l.name),
                Target::User(t) => format!("{} (user-defined link type {t})", l.name),
            });
            Info::Link(l)
        }
        0x07 => {
            rd.num("Version", 1)?;
            rd.reserved(3)?;
            rd.num("Allocated slots", 2)?;
            let used = rd.num("Used slots", 2)?;
            let heap = rd.addr("Local heap address")?;
            for i in 0..used {
                let start = rd.pos;
                let mut sub = rd.fork();
                let ok = external_slot(&mut sub);
                rd.join(format!("Slot {i}"), start, sub);
                ok?;
            }
            *summary = Some(format!("{used} files"));
            Info::External { heap }
        }
        0x08 => {
            let l = layout(rd)?;
            *summary = Some(match &l {
                Layout::Compact { data } => format!("compact, {} bytes", data.len),
                Layout::Contiguous { addr, size } if undefined(*addr, rd.o) => {
                    format!(
                        "contiguous, not allocated{}",
                        size.map_or_else(String::new, |s| format!(", {s} bytes"))
                    )
                }
                Layout::Contiguous { addr, size } => format!(
                    "contiguous at {addr:#x}{}",
                    size.map_or_else(String::new, |s| format!(", {s} bytes"))
                ),
                Layout::Chunked { dims, index, .. } => format!(
                    "chunked {}, {}",
                    shape(dims),
                    match index {
                        ChunkIndex::BtreeV1 => "version 1 B-tree",
                        ChunkIndex::Single { .. } => "single chunk",
                        ChunkIndex::Implicit => "implicit index",
                        ChunkIndex::Fixed => "fixed array",
                        ChunkIndex::Extensible => "extensible array",
                        ChunkIndex::BtreeV2 => "version 2 B-tree",
                    }
                ),
                Layout::Virtual { .. } => "virtual".to_owned(),
                Layout::Other => "unknown layout".to_owned(),
            });
            Info::Layout(l)
        }
        0x09 => {
            rd.hexn("Bogus value", 4)?;
            Info::None
        }
        0x0a => {
            rd.num("Version", 1)?;
            let flags = rd.flags(
                "Flags",
                1,
                &[
                    flag(1, "link phase change values stored"),
                    flag(2, "estimated entry information stored"),
                ],
            )?;
            if flags & 1 != 0 {
                rd.num("Maximum compact links", 2)?;
                rd.num("Minimum dense links", 2)?;
            }
            if flags & 2 != 0 {
                rd.num("Estimated number of entries", 2)?;
                rd.num("Estimated link name length", 2)?;
            }
            Info::None
        }
        0x0b => {
            let f = filters(rd)?;
            let names: Vec<String> = f.iter().map(Filter::label).collect();
            *summary = Some(names.join(" → "));
            Info::Filters(f)
        }
        0x0c => {
            let a = attribute(rd, ctx)?;
            *summary = Some(format!(
                "{}: {}{}",
                a.name,
                a.ty.as_ref().map_or_else(
                    || {
                        if a.ty_ref.is_some() {
                            "committed type".to_owned()
                        } else {
                            "datatype not decoded".to_owned()
                        }
                    },
                    Ty::describe,
                ),
                if a.space.kind == 0 {
                    String::new()
                } else {
                    format!(" {}", a.space.describe())
                }
            ));
            Info::Attr(a)
        }
        0x0d => {
            let s = rd.cstr("Comment", 1)?;
            *summary = Some(s.clone());
            Info::Comment(s)
        }
        0x0e => {
            let (bytes, span) = rd.slice(14)?;
            let t = String::from_utf8_lossy(bytes).into_owned();
            let get = |a: usize, b: usize| t.get(a..b).unwrap_or("??");
            let text = format!(
                "{}-{}-{} {}:{}:{} UTC",
                get(0, 4),
                get(4, 6),
                get(6, 8),
                get(8, 10),
                get(10, 12),
                get(12, 14)
            );
            rd.push(
                Node::new("Time")
                    .span(span)
                    .value(Value::Text(text.clone())),
            );
            rd.reserved(2)?;
            *summary = Some(text);
            Info::None
        }
        0x0f => {
            rd.num("Version", 1)?;
            let addr = rd.addr("Shared message table address")?;
            let n = u8::try_from(rd.num("Number of indices", 1)?).unwrap_or(0);
            Info::SharedTable(addr, n)
        }
        0x10 => {
            let addr = rd.addr("Offset")?;
            let len = rd.length("Length")?;
            *summary = Some(format!("{len} bytes at {addr:#x}"));
            Info::Cont { addr, len }
        }
        0x11 => {
            let btree = rd.addr("v1 B-tree address")?;
            let heap = rd.addr("Local heap address")?;
            Info::SymTab { btree, heap }
        }
        0x12 => {
            rd.num("Version", 1)?;
            rd.reserved(3)?;
            let t = rd.val("Seconds since the epoch", 4, |v| Value::Timestamp {
                unix_seconds: i64::try_from(v).unwrap_or(0),
            })?;
            let t = i64::try_from(t).unwrap_or(0);
            *summary = Some(crate::render::value(&Value::Timestamp { unix_seconds: t }));
            Info::None
        }
        0x13 => {
            rd.num("Version", 1)?;
            rd.num("Indexed storage internal node K", 2)?;
            rd.num("Group internal node K", 2)?;
            rd.num("Group leaf node K", 2)?;
            Info::None
        }
        0x14 => {
            rd.num("Version", 1)?;
            let id = rd.text("Driver identification", 8)?;
            let n = rd.num("Driver information size", 2)?;
            rd.bytes("Driver information", to_usize(n))?;
            *summary = Some(id);
            Info::None
        }
        0x15 => {
            let d = dense_info(rd, true)?;
            *summary = Some(if undefined(d.heap, rd.o) {
                "attributes stored in the object header".to_owned()
            } else {
                "attributes stored densely (fractal heap)".to_owned()
            });
            Info::AttrStore(d)
        }
        0x16 => {
            rd.num("Version", 1)?;
            let n = rd.num("Reference count", 4)?;
            *summary = Some(format!("{n} links"));
            Info::None
        }
        0x17 => {
            let version = rd.num("Version", 1)?;
            let strategy = rd.num("Strategy", 1)?;
            let mut addrs = Vec::new();
            if version == 0 {
                rd.length("Threshold")?;
                if strategy == 1 {
                    for _ in 0..6 {
                        addrs.push(rd.addr("Free-space manager address")?);
                    }
                }
            } else {
                let persist = rd.num("Persisting free space", 1)?;
                rd.length("Free-space section threshold")?;
                rd.length("File space page size")?;
                rd.num("Page-end metadata threshold", 2)?;
                rd.addr("End of allocated space before free-space managers")?;
                if persist != 0 {
                    for _ in 0..12 {
                        addrs.push(rd.addr("Free-space manager address")?);
                    }
                }
            }
            addrs.retain(|&a| !undefined(a, rd.o));
            Info::FileSpace(addrs)
        }
        _ => {
            let n = rd.left();
            if n > 0 {
                rd.bytes("Data", n)?;
            }
            Info::None
        }
    })
}

/// Moves a reader that decoded a field of known size to its end, showing
/// what the decoder left (alignment padding, unknown trailing bytes).
fn pad_to(rd: &mut Rd<'_>, end: usize) {
    if end > rd.pos {
        let span = rd.sp(rd.pos, end.saturating_sub(rd.pos));
        if span.len > 0 {
            rd.push(Node::new("Padding").span(span));
        }
    }
    rd.pos = end;
}

fn external_slot(rd: &mut Rd<'_>) -> Option<()> {
    rd.length("Name offset in heap")?;
    rd.length("Offset in external file")?;
    rd.length("Data size")?;
    Some(())
}

/// A fill value of `n` bytes; rendered with the object's datatype if known.
fn fill_value(rd: &mut Rd<'_>, n: u64, ctx: &Ctx) -> Option<Option<String>> {
    if n == 0 {
        return Some(None);
    }
    let (bytes, span) = rd.slice(to_usize(n))?;
    let (value, text) = match &ctx.ty {
        Some(ty) if u64::from(ty.size()) == n => (
            datatype::value(ty, bytes),
            Some(datatype::format(ty, bytes)),
        ),
        _ => (Value::Bytes(bytes.iter().take(64).copied().collect()), None),
    };
    rd.push(Node::new("Fill value").span(span).value(value));
    Some(text)
}

/// The fields of a message's header.
pub fn header_fields(h: &Header, m: &Msg) -> Vec<Node> {
    let mut out = Vec::new();
    let whole = m.whole;
    let v2 = h.version != 1;
    let hex = |v: u64, bits: u8| Value::UInt {
        value: v,
        bits,
        radix: Radix::Hex,
    };
    let enum_type = Value::Enum {
        raw: m.kind.into(),
        bits: if v2 { 8 } else { 16 },
        name: lookup(MESSAGES, m.kind.into()),
    };
    let size = to_u64(m.len);
    let (decoded_flags, unknown) = crate::value::decode_flags(MESSAGE_FLAGS, m.flags.into());
    let flags = Value::Flags {
        raw: m.flags.into(),
        bits: 8,
        set: decoded_flags,
        unknown,
    };
    if v2 {
        out.push(Node::new("Type").span(whole.sub(0, 1)).value(enum_type));
        out.push(
            Node::new("Size")
                .span(whole.sub(1, 2))
                .value(super::util::dec(size)),
        );
        out.push(Node::new("Flags").span(whole.sub(3, 1)).value(flags));
        if h.flags & 0x04 != 0 {
            let raw = h
                .blocks
                .get(m.block)
                .and_then(|b| u16_le(&b.data, m.at.saturating_sub(2)))
                .unwrap_or(0);
            out.push(
                Node::new("Creation order")
                    .span(whole.sub(4, 2))
                    .value(super::util::dec(raw.into())),
            );
        }
    } else {
        out.push(Node::new("Type").span(whole.sub(0, 2)).value(enum_type));
        out.push(
            Node::new("Size")
                .span(whole.sub(2, 2))
                .value(super::util::dec(size)),
        );
        out.push(Node::new("Flags").span(whole.sub(4, 1)).value(flags));
        let raw = h
            .blocks
            .get(m.block)
            .and_then(|b| uint(&b.data, m.at.saturating_sub(3), 3))
            .unwrap_or(0);
        out.push(
            Node::new("Reserved")
                .span(whole.sub(5, 3))
                .value(hex(raw, 24)),
        );
    }
    out
}

/// The address a message points at, for its node's target.
pub fn target(file: &File, info: &Info) -> Option<Span> {
    let at = |a: u64, n: u64| (!file.undef(a)).then(|| file.at(a, n));
    match info {
        Info::Cont { addr, len } => at(*addr, *len),
        Info::Layout(Layout::Contiguous { addr, size }) => at(*addr, size.unwrap_or(0)),
        Info::Layout(Layout::Chunked { addr, .. }) => at(*addr, 4),
        Info::SymTab { btree, .. } => at(*btree, 4),
        Info::LinkStore(d) | Info::AttrStore(d) => at(d.heap, 4),
        Info::Link(Link {
            target: Target::Hard(a),
            ..
        }) => at(*a, 4),
        Info::Shared(Some(a)) => at(*a, 4),
        _ => None,
    }
}
