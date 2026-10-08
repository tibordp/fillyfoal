//! HDF5: the superblock, then a graph of object headers. Groups link to
//! their members either through link messages (newer files) or through a
//! symbol table: a version 1 B-tree of symbol table nodes whose names live
//! in a local heap.
//!
//! Objects are expanded lazily; every object node carries the addresses of
//! the objects above it, so hard-link cycles end instead of recursing, and
//! B-tree and continuation walks keep visited sets. MATLAB 7.3 MAT-files are
//! HDF5 files with a 512-byte user block and are dissected the same way.

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_le, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value, lookup};

const SIGNATURE: &[u8] = b"\x89HDF\r\n\x1a\n";
/// Objects followed below one another.
const MAX_DEPTH: usize = 48;
/// B-tree levels and continuation blocks followed.
const MAX_NODES: usize = 1 << 16;

pub static FORMAT: Format = Format {
    name: "hdf5",
    title: "HDF5 data",
    extensions: &["h5", "hdf5", "he5", "nc4"],
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

const MESSAGES: EnumTable = &[
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

const CLASSES: EnumTable = &[
    (0, "fixed-point"),
    (1, "floating-point"),
    (2, "time"),
    (3, "string"),
    (4, "bitfield"),
    (5, "opaque"),
    (6, "compound"),
    (7, "reference"),
    (8, "enum"),
    (9, "variable-length"),
    (10, "array"),
];

/// What every expansion needs: the file, the base address and field sizes.
struct File {
    input: Input,
    base: u64,
    offsets: usize,
    lengths: usize,
}

type FileRef = Arc<File>;

impl File {
    fn at(&self, addr: u64, len: u64) -> Span {
        self.input.span.sub(self.base.saturating_add(addr), len)
    }
}

/// A little-endian unsigned integer of `n` bytes.
fn uint(data: &[u8], at: usize, n: usize) -> Option<u64> {
    let bytes = data.get(at..at.checked_add(n)?)?;
    Some(
        bytes
            .iter()
            .rev()
            .fold(0u64, |acc, &b| acc << 8 | u64::from(b)),
    )
}

fn undefined(addr: u64, n: usize) -> bool {
    n >= 8 && addr == u64::MAX || n < 8 && addr == (1u64 << (n.saturating_mul(8))).saturating_sub(1)
}

fn addr_value(addr: u64) -> Value {
    Value::UInt {
        value: addr,
        bits: 64,
        radix: Radix::Hex,
    }
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
    if sb > 0 {
        let text = crate::text::until_nul(head.get(..to_usize(sb).min(116)).unwrap_or_default())
            .trim_end()
            .to_owned();
        cx.emit(
            Node::new("User block")
                .span(file.sub(0, sb))
                .value(Value::Text(text)),
        );
    }
    let data = cx
        .read(file.sub(sb, 128))
        .await
        .or_else(|_| Ok::<_, Diagnostic>(head.get(to_usize(sb)..).unwrap_or_default().to_vec()))?;
    let version = data.get(8).copied().unwrap_or(0);
    let sb_span = file.sub(sb, 128);
    let mut fields = Vec::new();
    let mut emit = |name: &'static str, at: usize, len: usize, value: Value| {
        fields.push(
            Node::new(name)
                .span(sb_span.sub(to_u64(at), to_u64(len)))
                .value(value),
        );
    };
    let uintv = |v: u64| Value::UInt {
        value: v,
        bits: 64,
        radix: Radix::Dec,
    };
    emit("Signature", 0, 8, Value::Bytes(SIGNATURE.to_vec()));
    emit("Version", 8, 1, uintv(version.into()));
    let (offsets, lengths, root, eof, base);
    let mut end;
    if version <= 1 {
        offsets = usize::from(data.get(13).copied().unwrap_or(8));
        lengths = usize::from(data.get(14).copied().unwrap_or(8));
        emit(
            "Free-space storage version",
            9,
            1,
            uintv(data.get(9).copied().unwrap_or(0).into()),
        );
        emit(
            "Root group symbol table version",
            10,
            1,
            uintv(data.get(10).copied().unwrap_or(0).into()),
        );
        emit(
            "Shared header message version",
            12,
            1,
            uintv(data.get(12).copied().unwrap_or(0).into()),
        );
        emit("Size of offsets", 13, 1, uintv(to_u64(offsets)));
        emit("Size of lengths", 14, 1, uintv(to_u64(lengths)));
        emit(
            "Group leaf node K",
            16,
            2,
            uintv(u16_le(&data, 16).unwrap_or(0).into()),
        );
        emit(
            "Group internal node K",
            18,
            2,
            uintv(u16_le(&data, 18).unwrap_or(0).into()),
        );
        emit(
            "File consistency flags",
            20,
            4,
            Value::UInt {
                value: u32_le(&data, 20).unwrap_or(0).into(),
                bits: 32,
                radix: Radix::Hex,
            },
        );
        end = if version == 1 { 28 } else { 24 };
        if version == 1 {
            emit(
                "Indexed storage internal node K",
                24,
                2,
                uintv(u16_le(&data, 24).unwrap_or(0).into()),
            );
        }
        if !matches!(offsets, 2 | 4 | 8) || !matches!(lengths, 2 | 4 | 8) {
            for n in fields {
                cx.emit(n);
            }
            return Err(
                Diagnostic::malformed("invalid size of offsets or lengths").at(sb_span.sub(13, 2))
            );
        }
        let mut addr = |name: &'static str, end: &mut usize| {
            let v = uint(&data, *end, offsets).unwrap_or(u64::MAX);
            emit(name, *end, offsets, addr_value(v));
            *end = end.saturating_add(offsets);
            v
        };
        base = addr("Base address", &mut end);
        addr("Free-space info address", &mut end);
        eof = addr("End of file address", &mut end);
        addr("Driver info address", &mut end);
        // Root group symbol table entry.
        let entry = end;
        root = uint(&data, entry.saturating_add(offsets), offsets).unwrap_or(u64::MAX);
        let entry_len = offsets.saturating_mul(2).saturating_add(24);
        fields.push(
            Node::new("Root group symbol table entry")
                .span(sb_span.sub(to_u64(entry), to_u64(entry_len)))
                .value(addr_value(root))
                .summary("object header address"),
        );
        end = entry.saturating_add(entry_len);
    } else {
        offsets = usize::from(data.get(9).copied().unwrap_or(8));
        lengths = usize::from(data.get(10).copied().unwrap_or(8));
        emit("Size of offsets", 9, 1, uintv(to_u64(offsets)));
        emit("Size of lengths", 10, 1, uintv(to_u64(lengths)));
        emit(
            "File consistency flags",
            11,
            1,
            uintv(data.get(11).copied().unwrap_or(0).into()),
        );
        if !matches!(offsets, 2 | 4 | 8) || !matches!(lengths, 2 | 4 | 8) {
            for n in fields {
                cx.emit(n);
            }
            return Err(
                Diagnostic::malformed("invalid size of offsets or lengths").at(sb_span.sub(9, 2))
            );
        }
        end = 12;
        let mut addr = |name: &'static str, end: &mut usize| {
            let v = uint(&data, *end, offsets).unwrap_or(u64::MAX);
            emit(name, *end, offsets, addr_value(v));
            *end = end.saturating_add(offsets);
            v
        };
        base = addr("Base address", &mut end);
        addr("Superblock extension address", &mut end);
        eof = addr("End of file address", &mut end);
        root = addr("Root group object header address", &mut end);
        emit(
            "Checksum",
            end,
            4,
            Value::UInt {
                value: u32_le(&data, end).unwrap_or(0).into(),
                bits: 32,
                radix: Radix::Hex,
            },
        );
        end = end.saturating_add(4);
    }
    let mut sb_node = Node::new("Superblock").span(file.sub(sb, to_u64(end)));
    sb_node = sb_node.summary(format!("version {version}"));
    cx.emit(sb_node.lazy(emit_all, Arc::new(fields)));
    // Addresses are relative to the base address (normally the superblock).
    let hdf = Arc::new(File {
        input,
        base: if undefined(base, offsets) {
            sb
        } else {
            base.max(sb).min(file.len)
        },
        offsets,
        lengths,
    });
    cx.annotate(format!(
        "{} superblock v{version}, {} bytes declared",
        if sb == 512 && head.starts_with(b"MATLAB 7.3") {
            "MATLAB 7.3 MAT-file, HDF5"
        } else {
            "HDF5"
        },
        eof
    ));
    cx.emit(object_node(&hdf, "Root group".to_owned(), root, &[]));
    Ok(())
}

async fn emit_all(cx: Cx, nodes: Arc<Vec<Node>>) -> Result<()> {
    for n in nodes.iter() {
        cx.emit(n.clone());
    }
    Ok(())
}

#[derive(Clone)]
struct ObjState {
    file: FileRef,
    addr: u64,
    path: Arc<Vec<u64>>,
}

/// A node that expands into the object header at `addr`.
fn object_node(file: &FileRef, name: String, addr: u64, path: &[u64]) -> Node {
    let node = Node::new(name).value(addr_value(addr));
    if undefined(addr, file.offsets) {
        return node.summary("undefined address");
    }
    let node = node.target(file.at(addr, 16));
    if path.contains(&addr) {
        return node.summary("already open above (hard-link cycle)");
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

/// One header message: its type, data span, and the bytes of its data.
struct Message {
    kind: u16,
    whole: Span,
    data: Span,
}

/// Reads the messages of an object header (v1 or v2), following
/// continuation blocks.
async fn messages(cx: &Cx, file: &File, addr: u64) -> Result<(u8, Vec<Message>)> {
    let head = cx.read(file.at(addr, 16)).await?;
    let mut out = Vec::new();
    let mut blocks: Vec<(u64, u64, bool)> = Vec::new();
    let version;
    let mut v2_flags = 0u8;
    if head.starts_with(b"OHDR") {
        version = head.get(4).copied().unwrap_or(0);
        v2_flags = head.get(5).copied().unwrap_or(0);
        let mut at = 6u64;
        if v2_flags & 0x20 != 0 {
            at = at.saturating_add(16);
        }
        if v2_flags & 0x10 != 0 {
            at = at.saturating_add(4);
        }
        let width = 1usize << (v2_flags & 3);
        let size_bytes = cx
            .read(file.at(addr.saturating_add(at), to_u64(width)))
            .await?;
        let size = uint(&size_bytes, 0, width).unwrap_or(0);
        blocks.push((
            addr.saturating_add(at).saturating_add(to_u64(width)),
            size,
            true,
        ));
    } else {
        version = head.first().copied().unwrap_or(0);
        if version != 1 {
            return Err(
                Diagnostic::malformed(format!("unknown object header version {version}"))
                    .at(file.at(addr, 1)),
            );
        }
        let size = u64::from(u32_le(&head, 8).unwrap_or(0));
        blocks.push((addr.saturating_add(16), size, false));
    }
    let mut seen = BTreeSet::new();
    let mut i = 0usize;
    while let Some(&(start, size, v2)) = blocks.get(i) {
        i = i.saturating_add(1);
        if !seen.insert(start) || blocks.len() > MAX_NODES {
            cx.diag(Diagnostic::malformed("object header continuation loops"));
            break;
        }
        let block = file.at(start, size);
        let data = cx.read(block).await?;
        let mut pos = 0usize;
        // v2 continuation blocks start with "OCHK"; v2 blocks end with a checksum.
        if v2 && data.starts_with(b"OCHK") {
            pos = 4;
        }
        let end = if v2 {
            data.len().saturating_sub(4)
        } else {
            data.len()
        };
        while pos < end {
            cx.checkpoint().await;
            let (kind, len, header) = if v2 {
                let kind = u16::from(data.get(pos).copied().unwrap_or(0));
                let len = u16_le(&data, pos.saturating_add(1)).unwrap_or(0);
                let header = if v2_flags & 0x04 != 0 { 6 } else { 4 };
                (kind, len, header)
            } else {
                (
                    u16_le(&data, pos).unwrap_or(0),
                    u16_le(&data, pos.saturating_add(2)).unwrap_or(0),
                    8,
                )
            };
            if v2 && pos.saturating_add(header) > end {
                break;
            }
            let whole = block.sub(to_u64(pos), to_u64(header.saturating_add(usize::from(len))));
            let body = block.sub(to_u64(pos.saturating_add(header)), u64::from(len));
            if kind == 0x10 {
                let bytes = data.get(pos.saturating_add(header)..).unwrap_or_default();
                if let (Some(off), Some(l)) = (
                    uint(bytes, 0, file.offsets),
                    uint(bytes, file.offsets, file.lengths),
                ) {
                    blocks.push((off, l, v2));
                }
            }
            out.push(Message {
                kind,
                whole,
                data: body,
            });
            pos = pos.saturating_add(header).saturating_add(usize::from(len));
            if !v2 {
                pos = pos.checked_next_multiple_of(8).unwrap_or(usize::MAX);
            }
        }
    }
    Ok((version, out))
}

async fn object(cx: Cx, state: ObjState) -> Result<()> {
    let file = &state.file;
    let (version, list) = messages(&cx, file, state.addr).await?;
    let mut kind = "object";
    for m in &list {
        match m.kind {
            0x11 | 0x06 | 0x02 => kind = "group",
            0x08 if kind == "object" => kind = "dataset",
            _ => {}
        }
    }
    cx.annotate(format!(
        "{kind}, object header v{version}, {} messages",
        list.len()
    ));
    for m in list {
        let node = message(&cx, &state, &m).await?;
        cx.push(node).await;
    }
    Ok(())
}

async fn message(cx: &Cx, state: &ObjState, m: &Message) -> Result<Node> {
    let file = &state.file;
    let name = lookup(MESSAGES, m.kind.into())
        .map_or_else(|| format!("Message {:#x}", m.kind), str::to_owned);
    let node = Node::new(name).span(m.whole);
    let data = cx.read_avail(m.data.sub(0, 4096)).await?;
    let (o, l) = (file.offsets, file.lengths);
    let at = |i: usize| data.get(i).copied().unwrap_or(0);
    Ok(match m.kind {
        0x01 => {
            let version = at(0);
            let rank = usize::from(at(1));
            let start: usize = if version == 1 { 8 } else { 4 };
            let dims: Vec<String> = (0..rank)
                .filter_map(|i| uint(&data, start.saturating_add(i.saturating_mul(l)), l))
                .map(|d| d.to_string())
                .collect();
            node.summary(if rank == 0 {
                "scalar".to_owned()
            } else {
                format!("[{}]", dims.join("×"))
            })
        }
        0x03 => {
            let class = at(0) & 0x0f;
            let size = u32_le(&data, 4).unwrap_or(0);
            node.summary(format!(
                "{}, {size} bytes",
                lookup(CLASSES, class.into()).unwrap_or("unknown class")
            ))
        }
        0x06 => {
            let flags = at(1);
            let mut pos = 2usize;
            let mut link_type = 0u8;
            if flags & 0x08 != 0 {
                link_type = at(pos);
                pos = pos.saturating_add(1);
            }
            if flags & 0x04 != 0 {
                pos = pos.saturating_add(8);
            }
            if flags & 0x10 != 0 {
                pos = pos.saturating_add(1);
            }
            let width = 1usize << (flags & 3);
            let len = to_usize(uint(&data, pos, width).unwrap_or(0));
            pos = pos.saturating_add(width);
            let name =
                String::from_utf8_lossy(data.get(pos..pos.saturating_add(len)).unwrap_or_default())
                    .into_owned();
            pos = pos.saturating_add(len);
            match link_type {
                0 => {
                    let addr = uint(&data, pos, o).unwrap_or(u64::MAX);
                    object_node(file, name, addr, &state.path).span(m.whole)
                }
                1 => node.value(Value::Text(name)).summary("soft link"),
                _ => node.value(Value::Text(name)).summary("external link"),
            }
        }
        0x08 => {
            let version = at(0);
            match (version, at(1)) {
                (3 | 4, 1) => {
                    let addr = uint(&data, 2, o).unwrap_or(u64::MAX);
                    let size = uint(&data, 2usize.saturating_add(o), l).unwrap_or(0);
                    let node = node
                        .summary(format!("contiguous, {size} bytes"))
                        .value(addr_value(addr));
                    if undefined(addr, o) {
                        node
                    } else {
                        node.target(file.at(addr, size))
                    }
                }
                (3 | 4, 0) => node.summary("compact"),
                (3 | 4, 2) => node.summary("chunked"),
                _ => node.summary(format!("version {version}")),
            }
        }
        0x0c => {
            let version = at(0);
            let name_len = usize::from(u16_le(&data, 2).unwrap_or(0));
            let start: usize = if version == 3 { 9 } else { 8 };
            let name = String::from_utf8_lossy(
                data.get(start..start.saturating_add(name_len))
                    .unwrap_or_default(),
            )
            .trim_end_matches('\0')
            .to_owned();
            node.value(Value::Text(name))
        }
        0x0d => node.value(Value::Text(crate::text::until_nul(&data))),
        0x10 => {
            let addr = uint(&data, 0, o).unwrap_or(0);
            let len = uint(&data, o, l).unwrap_or(0);
            node.value(addr_value(addr))
                .summary(format!("{len} bytes"))
                .target(file.at(addr, len))
        }
        0x11 => {
            let btree = uint(&data, 0, o).unwrap_or(u64::MAX);
            let heap = uint(&data, o, o).unwrap_or(u64::MAX);
            node.summary(format!("B-tree at {btree:#x}, heap at {heap:#x}"))
                .lazy(members, (state.clone(), btree, heap))
        }
        0x12 => match u32_le(&data, 4) {
            Some(t) => node.value(Value::Timestamp {
                unix_seconds: t.into(),
            }),
            None => node,
        },
        _ => node.summary(format!("{} bytes", m.data.len)),
    })
}

/// The members of a version 1 group: a walk of the group B-tree, whose
/// leaves point at symbol table nodes.
async fn members(cx: Cx, (state, btree, heap): (ObjState, u64, u64)) -> Result<()> {
    let file = &state.file;
    let (o, l) = (file.offsets, file.lengths);
    // The local heap holding the names.
    let heap_head = cx
        .read(file.at(
            heap,
            to_u64(8usize.saturating_add(l.saturating_mul(2)).saturating_add(o)),
        ))
        .await?;
    if !heap_head.starts_with(b"HEAP") {
        return Err(Diagnostic::malformed("local heap signature missing").at(file.at(heap, 4)));
    }
    let heap_data = uint(&heap_head, 8usize.saturating_add(l.saturating_mul(2)), o).unwrap_or(0);
    let mut stack = vec![(btree, 0u32)];
    let mut seen = BTreeSet::new();
    while let Some((node, depth)) = stack.pop() {
        cx.checkpoint().await;
        if !seen.insert(node) || seen.len() > MAX_NODES || depth > 64 {
            cx.diag(Diagnostic::malformed(format!(
                "group B-tree revisits {node:#x}"
            )));
            continue;
        }
        let head = cx.read(file.at(node, 8)).await?;
        if head.starts_with(b"SNOD") {
            let count = usize::from(u16_le(&head, 6).unwrap_or(0));
            let entry = o.saturating_mul(2).saturating_add(24);
            let entries = cx
                .read(file.at(node.saturating_add(8), to_u64(count.saturating_mul(entry))))
                .await?;
            for i in 0..count {
                let at = i.saturating_mul(entry);
                let name_off = uint(&entries, at, o).unwrap_or(0);
                let addr = uint(&entries, at.saturating_add(o), o).unwrap_or(u64::MAX);
                let (name, _) = cx
                    .cstr(file.at(heap_data.saturating_add(name_off), 1024))
                    .await
                    .unwrap_or_else(|_| (format!("<entry {i}>"), file.at(0, 0)));
                let span = file.at(
                    node.saturating_add(8).saturating_add(to_u64(at)),
                    to_u64(entry),
                );
                cx.push(object_node(file, name, addr, &state.path).span(span))
                    .await;
            }
            continue;
        }
        if !head.starts_with(b"TREE") {
            cx.diag(Diagnostic::malformed(format!(
                "expected a B-tree or symbol node at {node:#x}"
            )));
            continue;
        }
        let entries = usize::from(u16_le(&head, 6).unwrap_or(0));
        // Keys (heap offsets, size of lengths) alternate with children.
        let body_at = node
            .saturating_add(8)
            .saturating_add(to_u64(o.saturating_mul(2)));
        let len = entries
            .saturating_mul(l.saturating_add(o))
            .saturating_add(l);
        let body = cx.read(file.at(body_at, to_u64(len))).await?;
        let mut children = Vec::new();
        for i in 0..entries {
            let at = l.saturating_add(i.saturating_mul(l.saturating_add(o)));
            if let Some(child) = uint(&body, at, o) {
                children.push((child, depth.saturating_add(1)));
            }
        }
        stack.extend(children.into_iter().rev());
    }
    Ok(())
}
