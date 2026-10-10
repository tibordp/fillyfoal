//! Heaps: local heaps (group member names), global heap collections
//! (variable-length data), fractal heaps (dense links and attributes) and
//! the free-space managers that track their free space.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::fmt;
use crate::node::Node;
use crate::span::Span;
use crate::value::{FlagTable, Radix, Value, flag};

use super::util::{File, FileRef, Rd, checksum_node, group, limit_enc_size, log2, uint, undefined};

/// Largest metadata block read whole (heap data segments, collections).
const MAX_BLOCK: u64 = 4 << 20;
/// Objects indexed per global heap collection.
const MAX_OBJECTS: usize = 1 << 16;
/// Indirect blocks followed down a fractal heap.
const MAX_LEVELS: u32 = 32;

fn lazy_at(name: &'static str, file: &FileRef, addr: u64, f: fn(&FileRef, u64) -> Node) -> Node {
    if file.undef(addr) {
        Node::new(name).summary("undefined address")
    } else {
        f(file, addr).target(file.at(addr, 4))
    }
}

fn emit_rd(cx: &Cx, out: Vec<Node>) {
    for n in out {
        cx.emit(n);
    }
}

// ---------------------------------------------------------------------------
// Local heaps

#[derive(Clone, Copy, Debug)]
pub struct LocalHeap {
    pub data: u64,
    pub size: u64,
    pub free: u64,
}

fn local_header_len(file: &File) -> u64 {
    to_u64(
        8usize
            .saturating_add(file.l.saturating_mul(2))
            .saturating_add(file.o),
    )
}

pub async fn local_heap(cx: &Cx, file: &File, addr: u64) -> Result<LocalHeap> {
    let head = cx.read(file.exact(addr, local_header_len(file))?).await?;
    if !head.starts_with(b"HEAP") {
        return Err(Diagnostic::malformed("local heap signature missing").at(file.at(addr, 4)));
    }
    Ok(LocalHeap {
        size: uint(&head, 8, file.l).unwrap_or(0),
        free: uint(&head, 8usize.saturating_add(file.l), file.l).unwrap_or(u64::MAX),
        data: uint(
            &head,
            8usize.saturating_add(file.l.saturating_mul(2)),
            file.o,
        )
        .unwrap_or(u64::MAX),
    })
}

/// The NUL-terminated string at `offset` in a local heap's data segment.
pub async fn local_name(
    cx: &Cx,
    file: &File,
    heap: &LocalHeap,
    offset: u64,
) -> Result<(String, Span)> {
    let left = heap.size.saturating_sub(offset).min(64 * 1024);
    cx.cstr(file.at(heap.data.saturating_add(offset), left))
        .await
}

pub fn local_heap_node(file: &FileRef, addr: u64) -> Node {
    lazy_at("Local heap", file, addr, |file, addr| {
        Node::new("Local heap").lazy(local_heap_expand, (file.clone(), addr))
    })
}

fn local_fields(rd: &mut Rd<'_>) -> Option<()> {
    rd.sig(4)?;
    rd.num("Version", 1)?;
    rd.reserved(3)?;
    rd.length("Data segment size")?;
    let l = rd.l;
    let free = rd.num("Offset to head of free list", l)?;
    if undefined(free, l) {
        rd.note("no free blocks");
    }
    rd.addr("Data segment address")?;
    Some(())
}

async fn local_heap_expand(cx: Cx, (file, addr): (FileRef, u64)) -> Result<()> {
    let span = file.at(addr, local_header_len(&file));
    let data = cx.read_avail(span).await?;
    let mut rd = Rd::new(&file, &data, span);
    let ok = local_fields(&mut rd);
    rd.finish(ok);
    emit_rd(&cx, rd.out);
    let heap = local_heap(&cx, &file, addr).await?;
    if !file.undef(heap.data) {
        cx.emit(
            Node::new("Data segment")
                .span(file.at(heap.data, heap.size))
                .summary(fmt::size(heap.size))
                .lazy(data_segment, (file.clone(), heap)),
        );
    }
    Ok(())
}

/// The strings and free blocks of a local heap's data segment.
async fn data_segment(cx: Cx, (file, heap): (FileRef, LocalHeap)) -> Result<()> {
    let span = file.exact(heap.data, heap.size.min(MAX_BLOCK))?;
    let data = cx.read(span).await?;
    // The free list: (offset, size) pairs, in address order.
    let mut free = Vec::new();
    let mut at = heap.free;
    while !undefined(at, file.l) && free.len() < 4096 {
        let pos = to_usize(at);
        let (Some(next), Some(size)) = (
            uint(&data, pos, file.l),
            uint(&data, pos.saturating_add(file.l), file.l),
        ) else {
            break;
        };
        free.push((at, size));
        // A well-formed free list is in increasing address order.
        if next <= at {
            break;
        }
        at = next;
    }
    free.sort_unstable();
    let mut next_free = 0usize;
    let mut pos = 0usize;
    while pos < data.len() {
        let here = to_u64(pos);
        while free.get(next_free).is_some_and(|&(o, _)| o < here) {
            next_free = next_free.saturating_add(1);
        }
        if let Some(&(o, size)) = free.get(next_free)
            && o == here
        {
            let n = to_usize(size).max(1);
            let mut sub = Rd::new(&file, &data, span);
            sub.pos = pos;
            sub.length("Offset of next free block");
            sub.length("Size");
            cx.push(
                group("Free block", sub.out)
                    .span(span.sub(here, to_u64(n)))
                    .summary(fmt::size(size)),
            )
            .await;
            pos = pos.saturating_add(n);
            continue;
        }
        let rest = data.get(pos..).unwrap_or_default();
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        let total = end
            .saturating_add(1)
            .checked_next_multiple_of(8)
            .unwrap_or(rest.len())
            .min(rest.len())
            .max(1);
        let text = String::from_utf8_lossy(rest.get(..end).unwrap_or_default()).into_owned();
        cx.push(
            Node::new(format!("Offset {here}"))
                .span(span.sub(here, to_u64(total)))
                .value(Value::Text(text)),
        )
        .await;
        pos = pos.saturating_add(total);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Global heap collections

#[derive(Clone, Copy, Debug)]
pub struct GcolObj {
    pub index: u16,
    /// Position of the object's header, relative to the collection.
    pub at: u64,
    pub size: u64,
}

#[derive(Debug)]
pub struct Gcol {
    pub span: Span,
    pub objects: Vec<GcolObj>,
}

/// Reads and indexes a global heap collection (cached).
pub async fn gcol(cx: &Cx, file: &File, addr: u64) -> Result<Arc<Gcol>> {
    let key = file.at(addr, 1);
    if let Some(g) = cx.cached::<Gcol>(key, "hdf5-global-heap") {
        return Ok(g);
    }
    let hdr = 8usize.saturating_add(file.l);
    let head = cx.read(file.exact(addr, to_u64(hdr))?).await?;
    if !head.starts_with(b"GCOL") {
        return Err(Diagnostic::malformed("global heap signature missing").at(file.at(addr, 4)));
    }
    let size = uint(&head, 8, file.l).unwrap_or(0);
    let span = file.at(addr, size.min(MAX_BLOCK));
    let data = cx.read(span).await?;
    let mut objects = Vec::new();
    let mut pos = hdr;
    while pos.saturating_add(hdr) <= data.len() && objects.len() < MAX_OBJECTS {
        if objects.len() % 256 == 255 {
            cx.checkpoint().await;
        }
        let index = crate::bytes::u16_le(&data, pos).unwrap_or(0);
        let osize = uint(&data, pos.saturating_add(8), file.l).unwrap_or(0);
        objects.push(GcolObj {
            index,
            at: to_u64(pos),
            size: osize,
        });
        if index == 0 {
            break;
        }
        let total = to_usize(osize)
            .checked_next_multiple_of(8)
            .unwrap_or(usize::MAX)
            .saturating_add(hdr);
        pos = pos.saturating_add(total);
    }
    let g = Arc::new(Gcol { span, objects });
    cx.cache(key, "hdf5-global-heap", g.clone());
    Ok(g)
}

/// The data of object `index` in the collection at `addr`.
pub async fn gheap_object(cx: &Cx, file: &File, addr: u64, index: u32) -> Result<Span> {
    let g = gcol(cx, file, addr).await?;
    let hdr = to_u64(8usize.saturating_add(file.l));
    g.objects
        .iter()
        .find(|o| u32::from(o.index) == index && index != 0)
        .map(|o| g.span.sub(o.at.saturating_add(hdr), o.size))
        .ok_or_else(|| {
            Diagnostic::malformed(format!("global heap object {index} not found"))
                .at(g.span.sub(0, 4))
        })
}

pub fn gcol_node(file: &FileRef, addr: u64) -> Node {
    lazy_at("Global heap collection", file, addr, |file, addr| {
        Node::new(format!("Global heap collection at {addr:#x}"))
            .lazy(gcol_expand, (file.clone(), addr))
    })
}

fn gcol_fields(rd: &mut Rd<'_>) -> Option<()> {
    rd.sig(4)?;
    rd.num("Version", 1)?;
    rd.reserved(3)?;
    rd.length("Collection size")?;
    Some(())
}

async fn gcol_expand(cx: Cx, (file, addr): (FileRef, u64)) -> Result<()> {
    let g = gcol(&cx, &file, addr).await?;
    let data = cx.read(g.span).await?;
    let mut rd = Rd::new(&file, &data, g.span);
    let ok = gcol_fields(&mut rd);
    rd.finish(ok);
    emit_rd(&cx, rd.out);
    for o in &g.objects {
        let mut rd = Rd::new(&file, &data, g.span);
        rd.pos = to_usize(o.at);
        let ok = gcol_object(&mut rd, o.index);
        rd.finish(ok);
        let span = g.span.sub(o.at, to_u64(rd.pos).saturating_sub(o.at));
        let name = if o.index == 0 {
            "Free space".to_owned()
        } else {
            format!("Object {}", o.index)
        };
        cx.push(group(name, rd.out).span(span).summary(fmt::size(o.size)))
            .await;
    }
    Ok(())
}

fn gcol_object(rd: &mut Rd<'_>, index: u16) -> Option<()> {
    rd.num("Heap object index", 2)?;
    if index == 0 {
        rd.reserved(6)?;
        rd.length("Free space size")?;
        let n = rd.left();
        if n > 0 {
            let (_, span) = rd.slice(n)?;
            rd.push(Node::new("Free space").span(span));
        }
        return Some(());
    }
    rd.num("Reference count", 2)?;
    rd.reserved(4)?;
    let size = rd.length("Object size")?;
    let n = to_usize(size);
    let (bytes, span) = rd.slice(n)?;
    let mut node = Node::new("Object data").span(span);
    if !bytes.is_empty() && crate::text::looks_like_text(bytes) {
        node = node.value(Value::Text(String::from_utf8_lossy(bytes).into_owned()));
    } else {
        node = node.value(Value::Bytes(bytes.iter().take(64).copied().collect()));
    }
    rd.push(node);
    let pad = n.checked_next_multiple_of(8).unwrap_or(n).saturating_sub(n);
    if pad > 0 && rd.has(pad) {
        rd.reserved(pad)?;
    }
    Some(())
}

// ---------------------------------------------------------------------------
// Fractal heaps

#[derive(Clone, Debug)]
pub struct FrHeap {
    pub id_len: u16,
    pub filter_len: u16,
    pub flags: u8,
    pub huge_bt: u64,
    pub width: u16,
    pub start: u64,
    pub root: u64,
    pub rows: u16,
    pub objects: u64,
    /// Bytes of the heap offset and length in managed object IDs.
    pub off_size: usize,
    pub len_size: usize,
    /// Rows of direct blocks an indirect block can have.
    pub max_dblock_rows: u32,
}

impl FrHeap {
    /// The size of the blocks in row `r` of the doubling table.
    fn row_size(&self, r: u32) -> u64 {
        if r == 0 {
            self.start
        } else {
            self.start
                .checked_shl(r.saturating_sub(1))
                .unwrap_or(u64::MAX)
        }
    }

    /// Size of a direct block entry in an indirect block.
    fn dentry(&self, o: usize, l: usize) -> usize {
        if self.filter_len > 0 {
            o.saturating_add(l).saturating_add(4)
        } else {
            o
        }
    }

    /// Rows of an indirect block whose blocks span `size` bytes.
    fn rows_for(&self, size: u64) -> u32 {
        let first = log2(self.start).saturating_add(log2(self.width.into()));
        log2(size).saturating_sub(first).saturating_add(1)
    }

    fn iblock_header(&self, o: usize) -> usize {
        5usize.saturating_add(o).saturating_add(self.off_size)
    }

    fn dblock_header(&self, o: usize) -> usize {
        self.iblock_header(o)
            .saturating_add(if self.flags & 2 != 0 { 4 } else { 0 })
    }
}

/// The size of a fractal heap header without I/O filter fields.
fn frheap_len(file: &File) -> usize {
    let (o, l) = (file.o, file.l);
    14usize
        .saturating_add(l.saturating_mul(12))
        .saturating_add(o.saturating_mul(3))
        .saturating_add(12)
}

/// Reads a fractal heap header (cached).
pub async fn frheap(cx: &Cx, file: &File, addr: u64) -> Result<Arc<FrHeap>> {
    let key = file.at(addr, 1);
    if let Some(h) = cx.cached::<FrHeap>(key, "hdf5-fractal-heap") {
        return Ok(h);
    }
    let span = file.exact(addr, to_u64(frheap_len(file)))?;
    let d = cx.read(span).await?;
    if !d.starts_with(b"FRHP") {
        return Err(Diagnostic::malformed("fractal heap signature missing").at(file.at(addr, 4)));
    }
    let (o, l) = (file.o, file.l);
    let u = |at: usize, n: usize| uint(&d, at, n).unwrap_or(0);
    let id_len = u16::try_from(u(5, 2)).unwrap_or(0);
    let filter_len = u16::try_from(u(7, 2)).unwrap_or(0);
    let flags = u8::try_from(u(9, 1)).unwrap_or(0);
    let max_man = u(10, 4);
    let mut p = 14usize.saturating_add(l);
    let huge_bt = u(p, o);
    // Skip the huge-object B-tree, free space, free-space manager, managed
    // space, allocated space and the allocation iterator.
    p = p
        .saturating_add(o)
        .saturating_add(l)
        .saturating_add(o)
        .saturating_add(l.saturating_mul(3));
    let objects = u(p, l);
    p = p.saturating_add(l.saturating_mul(5));
    let width = u16::try_from(u(p, 2)).unwrap_or(0);
    p = p.saturating_add(2);
    let start = u(p, l);
    let max_direct = u(p.saturating_add(l), l);
    p = p.saturating_add(l.saturating_mul(2));
    let max_bits = u(p, 2);
    let root = u(p.saturating_add(4), o);
    let rows = u16::try_from(u(p.saturating_add(4).saturating_add(o), 2)).unwrap_or(0);
    let off_size = to_usize(max_bits.saturating_add(7) / 8);
    let len_size =
        to_usize(u64::from(log2(max_direct)).saturating_add(7) / 8).min(limit_enc_size(max_man));
    let max_dblock_rows = log2(max_direct)
        .saturating_sub(log2(start))
        .saturating_add(2);
    let h = Arc::new(FrHeap {
        id_len,
        filter_len,
        flags,
        huge_bt,
        width,
        start,
        root,
        rows,
        objects,
        off_size,
        len_size,
        max_dblock_rows,
    });
    cx.cache(key, "hdf5-fractal-heap", h.clone());
    Ok(h)
}

/// Where the object a heap ID refers to lives: in the file, or inside
/// the ID itself (tiny objects).
pub async fn heap_object(
    cx: &Cx,
    file: &File,
    heap: &FrHeap,
    id: &[u8],
    id_span: Span,
) -> Result<Span> {
    let b0 = id.first().copied().unwrap_or(0);
    if b0 >> 6 != 0 {
        return Err(Diagnostic::unsupported(format!("heap ID version {}", b0 >> 6)).at(id_span));
    }
    match (b0 >> 4) & 3 {
        0 => {
            let off = uint(id, 1, heap.off_size).unwrap_or(0);
            let len = uint(id, 1usize.saturating_add(heap.off_size), heap.len_size).unwrap_or(0);
            managed_object(cx, file, heap, off, len).await
        }
        2 => {
            let (len, at) = if heap.id_len <= 18 {
                (u64::from(b0 & 0x0f).saturating_add(1), 1u64)
            } else {
                let hi = u64::from(b0 & 0x0f);
                let lo = u64::from(id.get(1).copied().unwrap_or(0));
                ((hi << 8 | lo).saturating_add(1), 2)
            };
            Ok(id_span.sub(at, len))
        }
        1 if heap.filter_len == 0
            && id.len() >= 1usize.saturating_add(file.o).saturating_add(file.l) =>
        {
            let addr = uint(id, 1, file.o).unwrap_or(0);
            let len = uint(id, 1usize.saturating_add(file.o), file.l).unwrap_or(0);
            file.exact(addr, len)
        }
        1 => Err(Diagnostic::unsupported("huge object stored through a B-tree").at(id_span)),
        _ => Err(Diagnostic::malformed("unknown heap ID type").at(id_span)),
    }
}

/// The span of the managed object at heap offset `off`.
async fn managed_object(cx: &Cx, file: &File, heap: &FrHeap, off: u64, len: u64) -> Result<Span> {
    if heap.rows == 0 {
        if off.saturating_add(len) > heap.start {
            return Err(Diagnostic::malformed(format!(
                "heap object at {off:#x} lies outside the root block"
            )));
        }
        return file.exact(heap.root.saturating_add(off), len);
    }
    let (o, l) = (file.o, file.l);
    let mut block = heap.root;
    let mut block_off = 0u64;
    let mut rows = u32::from(heap.rows);
    let width = u64::from(heap.width);
    let first_row = heap.start.saturating_mul(width).max(1);
    for _ in 0..MAX_LEVELS {
        let rel = off.saturating_sub(block_off);
        let (row, row_start) = if rel < first_row {
            (0u32, 0u64)
        } else {
            let r = log2(rel.checked_div(first_row).unwrap_or(0)).saturating_add(1);
            (
                r,
                first_row
                    .checked_shl(r.saturating_sub(1))
                    .unwrap_or(u64::MAX),
            )
        };
        if row >= rows {
            break;
        }
        let size = heap.row_size(row).max(1);
        let col = rel.saturating_sub(row_start).checked_div(size).unwrap_or(0);
        let child_off = block_off
            .saturating_add(row_start)
            .saturating_add(col.saturating_mul(size));
        let header = to_u64(heap.iblock_header(o));
        let dentry = to_u64(heap.dentry(o, l));
        let ndirect = u64::from(rows.min(heap.max_dblock_rows)).saturating_mul(width);
        let at = if row < heap.max_dblock_rows {
            let entry = u64::from(row).saturating_mul(width).saturating_add(col);
            header.saturating_add(entry.saturating_mul(dentry))
        } else {
            let entry = u64::from(row.saturating_sub(heap.max_dblock_rows))
                .saturating_mul(width)
                .saturating_add(col);
            header
                .saturating_add(ndirect.saturating_mul(dentry))
                .saturating_add(entry.saturating_mul(to_u64(o)))
        };
        let raw = cx
            .read(file.exact(block.saturating_add(at), to_u64(o))?)
            .await?;
        let addr = uint(&raw, 0, o).unwrap_or(u64::MAX);
        if file.undef(addr) {
            break;
        }
        if row < heap.max_dblock_rows {
            if off.saturating_add(len) > child_off.saturating_add(size) {
                break;
            }
            return file.exact(addr.saturating_add(off.saturating_sub(child_off)), len);
        }
        block = addr;
        block_off = child_off;
        rows = heap.rows_for(size);
    }
    Err(Diagnostic::malformed(format!(
        "heap offset {off:#x} is not in an allocated block"
    )))
}

const HEAP_FLAGS: FlagTable = &[
    flag(1, "huge object IDs wrapped"),
    flag(2, "direct blocks checksummed"),
];

pub fn frheap_node(file: &FileRef, addr: u64) -> Node {
    lazy_at("Fractal heap", file, addr, |file, addr| {
        Node::new("Fractal heap").lazy(frheap_expand, (file.clone(), addr))
    })
}

/// The header fields; returns the free-space manager's address.
fn frheap_fields(rd: &mut Rd<'_>, filter_len: u16) -> Option<u64> {
    rd.sig(4)?;
    rd.num("Version", 1)?;
    rd.num("Heap ID length", 2)?;
    rd.num("I/O filters' encoded length", 2)?;
    rd.flags("Flags", 1, HEAP_FLAGS)?;
    rd.num("Maximum size of managed objects", 4)?;
    rd.length("Next huge object ID")?;
    rd.addr("Huge objects v2 B-tree address")?;
    rd.length("Free space in managed blocks")?;
    let fsm = rd.addr("Free-space manager address")?;
    rd.length("Managed space")?;
    rd.length("Allocated managed space")?;
    rd.length("Direct block allocation iterator offset")?;
    rd.length("Managed objects")?;
    rd.length("Size of huge objects")?;
    rd.length("Huge objects")?;
    rd.length("Size of tiny objects")?;
    rd.length("Tiny objects")?;
    rd.num("Table width", 2)?;
    rd.length("Starting block size")?;
    rd.length("Maximum direct block size")?;
    rd.num("Maximum heap size", 2)?;
    rd.note("bits of heap address space");
    rd.num("Starting rows in root indirect block", 2)?;
    rd.addr("Root block address")?;
    let rows = rd.num("Rows in root indirect block", 2)?;
    if rows == 0 {
        rd.note("the root is a direct block");
    }
    if filter_len > 0 {
        rd.length("Size of filtered root direct block")?;
        rd.hexn("I/O filter mask", 4)?;
        rd.bytes("I/O filter information", filter_len.into())?;
    }
    Some(fsm)
}

async fn frheap_expand(cx: Cx, (file, addr): (FileRef, u64)) -> Result<()> {
    let heap = frheap(&cx, &file, addr).await?;
    let filtered = if heap.filter_len > 0 {
        to_u64(file.l)
            .saturating_add(4)
            .saturating_add(heap.filter_len.into())
    } else {
        0
    };
    let span = file.at(addr, to_u64(frheap_len(&file)).saturating_add(filtered));
    let data = cx.read(span).await?;
    let mut rd = Rd::new(&file, &data, span);
    let fsm = frheap_fields(&mut rd, heap.filter_len);
    rd.finish(fsm.map(|_| ()));
    let at = rd.pos;
    emit_rd(&cx, rd.out);
    if let Some(n) = checksum_node(&cx, &data, span, at).await {
        cx.emit(n);
    }
    if let Some(fsm) = fsm.filter(|&a| !file.undef(a)) {
        cx.emit(fsm_node(&file, fsm));
    }
    if !file.undef(heap.huge_bt) {
        cx.emit(super::btree::v2_node(
            &file,
            heap.huge_bt,
            "Huge objects B-tree",
            None,
        ));
    }
    if !file.undef(heap.root) {
        cx.emit(if heap.rows == 0 {
            dblock_node(&file, heap.clone(), heap.root, heap.start)
        } else {
            iblock_node(&file, heap.clone(), heap.root, u32::from(heap.rows), 0)
        });
    }
    Ok(())
}

fn dblock_node(file: &FileRef, heap: Arc<FrHeap>, addr: u64, size: u64) -> Node {
    Node::new(format!("Direct block at {addr:#x}"))
        .span(file.at(addr, size))
        .summary(fmt::size(size))
        .lazy(dblock_expand, (file.clone(), heap, addr, size))
}

fn dblock_fields(rd: &mut Rd<'_>, off_size: usize) -> Option<()> {
    rd.sig(4)?;
    rd.num("Version", 1)?;
    rd.addr("Heap header address")?;
    rd.num("Block offset", off_size)?;
    Some(())
}

async fn dblock_expand(
    cx: Cx,
    (file, heap, addr, size): (FileRef, Arc<FrHeap>, u64, u64),
) -> Result<()> {
    let hlen = heap.dblock_header(file.o);
    let span = file.at(addr, size.min(MAX_BLOCK));
    let data = cx.read_avail(span).await?;
    let mut rd = Rd::new(&file, &data, span);
    let ok = dblock_fields(&mut rd, heap.off_size);
    rd.finish(ok);
    let at = rd.pos;
    emit_rd(&cx, rd.out);
    if heap.flags & 2 != 0 && to_u64(data.len()) == size {
        // The checksum covers the whole block, with its own field zeroed.
        let mut copy = data.clone();
        if let Some(field) = copy.get_mut(at..at.saturating_add(4)) {
            field.fill(0);
        }
        let stored = u32_le(&data, at).unwrap_or(0);
        let computed = super::util::lookup3(&cx, &copy).await;
        let node = Node::new("Checksum")
            .span(span.sub(to_u64(at), 4))
            .value(Value::UInt {
                value: stored.into(),
                bits: 32,
                radix: Radix::Hex,
            });
        cx.emit(if stored == computed {
            node.summary("lookup3 over the block, valid")
        } else {
            node.diag(Diagnostic::warning(format!(
                "checksum mismatch: computed {computed:#010x}"
            )))
        });
    }
    let body = span.tail(to_u64(hlen));
    cx.emit(Node::new("Objects").span(body).summary(format!(
        "{}, found through their heap IDs",
        fmt::size(body.len)
    )));
    Ok(())
}

fn iblock_node(file: &FileRef, heap: Arc<FrHeap>, addr: u64, rows: u32, depth: u32) -> Node {
    Node::new(format!("Indirect block at {addr:#x}"))
        .summary(format!("{rows} rows"))
        .target(file.at(addr, 4))
        .lazy(
            crate::expander!(self::iblock_expand: (FileRef, Arc<FrHeap>, u64, u32, u32)),
            (file.clone(), heap, addr, rows, depth),
        )
}

async fn iblock_expand(
    cx: Cx,
    (file, heap, addr, rows, depth): (FileRef, Arc<FrHeap>, u64, u32, u32),
) -> Result<()> {
    let (o, l) = (file.o, file.l);
    let width = usize::from(heap.width);
    let direct_rows = rows.min(heap.max_dblock_rows);
    let ndirect = to_usize(direct_rows.into()).saturating_mul(width);
    let nindirect = to_usize(rows.saturating_sub(direct_rows).into()).saturating_mul(width);
    let len = heap
        .iblock_header(o)
        .saturating_add(ndirect.saturating_mul(heap.dentry(o, l)))
        .saturating_add(nindirect.saturating_mul(o))
        .saturating_add(4);
    let span = file.exact(addr, to_u64(len))?;
    let data = cx.read(span).await?;
    let mut rd = Rd::new(&file, &data, span);
    let ok = dblock_fields(&mut rd, heap.off_size);
    rd.finish(ok);
    let mut children = Vec::new();
    for i in 0..ndirect.saturating_add(nindirect) {
        if i % 64 == 63 {
            cx.checkpoint().await;
        }
        let row = u32::try_from(i.checked_div(width).unwrap_or(0)).unwrap_or(u32::MAX);
        let start = rd.pos;
        let mut sub = rd.fork();
        let Some(child) = sub.addr("Address") else {
            break;
        };
        if i < ndirect && heap.filter_len > 0 {
            sub.length("Filtered size");
            sub.hexn("Filter mask", 4);
        }
        let name = if i < ndirect {
            format!("Direct block entry {i}")
        } else {
            format!("Indirect block entry {}", i.saturating_sub(ndirect))
        };
        rd.join(name, start, sub);
        if file.undef(child) {
            continue;
        }
        let size = heap.row_size(row);
        if i < ndirect {
            children.push(dblock_node(&file, heap.clone(), child, size));
        } else if depth < MAX_LEVELS {
            children.push(iblock_node(
                &file,
                heap.clone(),
                child,
                heap.rows_for(size),
                depth.saturating_add(1),
            ));
        }
    }
    let at = rd.pos;
    emit_rd(&cx, rd.out);
    if let Some(n) = checksum_node(&cx, &data, span, at).await {
        cx.emit(n);
    }
    for c in children {
        cx.push(c).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Free-space managers

pub fn fsm_node(file: &FileRef, addr: u64) -> Node {
    lazy_at("Free-space manager", file, addr, |file, addr| {
        Node::new("Free-space manager").lazy(fsm_expand, (file.clone(), addr))
    })
}

/// What the section list needs from the manager's header.
#[derive(Clone, Copy, Default)]
struct Fsm {
    serial: u64,
    bits: u64,
    max: u64,
    list: u64,
    used: u64,
}

fn fsm_fields(rd: &mut Rd<'_>) -> Option<Fsm> {
    rd.sig(4)?;
    rd.num("Version", 1)?;
    rd.en("Client", 1, &[(0, "fractal heap"), (1, "file")])?;
    rd.length("Total space tracked")?;
    rd.length("Total sections")?;
    let serial = rd.length("Serialized sections")?;
    rd.length("Ghost sections")?;
    rd.num("Section classes", 2)?;
    rd.num("Shrink percent", 2)?;
    rd.num("Expand percent", 2)?;
    let bits = rd.num("Size of address space", 2)?;
    rd.note("bits");
    let max = rd.length("Maximum section size")?;
    let list = rd.addr("Section list address")?;
    let used = rd.length("Section list size used")?;
    rd.length("Section list size allocated")?;
    Some(Fsm {
        serial,
        bits,
        max,
        list,
        used,
    })
}

async fn fsm_expand(cx: Cx, (file, addr): (FileRef, u64)) -> Result<()> {
    let (o, l) = (file.o, file.l);
    let len = 14usize
        .saturating_add(l.saturating_mul(7))
        .saturating_add(o)
        .saturating_add(4);
    let span = file.exact(addr, to_u64(len))?;
    let data = cx.read(span).await?;
    if !data.starts_with(b"FSHD") {
        return Err(
            Diagnostic::malformed("free-space manager signature missing").at(span.sub(0, 4)),
        );
    }
    let mut rd = Rd::new(&file, &data, span);
    let fsm = fsm_fields(&mut rd);
    rd.finish(fsm.map(|_| ()));
    let at = rd.pos;
    emit_rd(&cx, rd.out);
    if let Some(n) = checksum_node(&cx, &data, span, at).await {
        cx.emit(n);
    }
    if let Some(f) = fsm
        && !file.undef(f.list)
        && f.used >= 4
    {
        cx.emit(
            Node::new("Section list")
                .span(file.at(f.list, f.used))
                .lazy(
                    sections,
                    (file.clone(), f.list, f.used, f.serial, f.bits, f.max),
                ),
        );
    }
    Ok(())
}

fn section_fields(rd: &mut Rd<'_>) -> Option<()> {
    rd.sig(4)?;
    rd.num("Version", 1)?;
    rd.addr("Free-space manager address")?;
    Some(())
}

async fn sections(
    cx: Cx,
    (file, addr, used, serial, bits, max): (FileRef, u64, u64, u64, u64, u64),
) -> Result<()> {
    let span = file.exact(addr, used.min(MAX_BLOCK))?;
    let data = cx.read(span).await?;
    let end = data.len().saturating_sub(4);
    let mut rd = Rd::new(&file, &data, span);
    let ok = section_fields(&mut rd);
    rd.finish(ok);
    let count_size = limit_enc_size(serial);
    let len_size = limit_enc_size(max);
    let off_size = to_usize(bits.saturating_add(7) / 8);
    let mut seen = 0u64;
    while seen < serial && rd.pos < end {
        cx.checkpoint().await;
        let start = rd.pos;
        let mut sub = rd.fork();
        let Some(n) = sub.num("Sections of this size", count_size) else {
            break;
        };
        let Some(size) = sub.num("Section size", len_size) else {
            break;
        };
        let mut i = 0u64;
        while i < n && sub.pos < end {
            if sub.num("Section offset", off_size).is_none()
                || sub.num("Section class", 1).is_none()
            {
                break;
            }
            i = i.saturating_add(1);
            if i.is_multiple_of(256) {
                cx.checkpoint().await;
            }
        }
        seen = seen.saturating_add(n.max(1));
        rd.join(format!("{n} sections of {size} bytes"), start, sub);
        if rd.pos == start {
            break;
        }
    }
    rd.rest("Unused", end);
    emit_rd(&cx, rd.out);
    if let Some(n) = checksum_node(&cx, &data, span, end).await {
        cx.emit(n);
    }
    Ok(())
}
