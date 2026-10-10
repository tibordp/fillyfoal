//! ext extended attributes: in the inode after its extra fields, and in a
//! block of their own (shared by inodes with the same attributes). Both
//! are a list of entries growing up and values growing down.

use crate::bytes::{align_up, to_u64, to_usize, u16_le, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Fields, struct_node};
use crate::formats::disk::acl::{self, NAME_INDEXES};
use crate::formats::disk::size;
use crate::node::Node;
use crate::span::Span;
use crate::value::{Value, lookup};

use super::inode::Inode;
use super::{FsRef, LE, csum32};

const MAGIC: u32 = 0xea02_0000;

struct Entry {
    /// Offset of the entry in the area.
    off: usize,
    len: usize,
    index: u8,
    name: Vec<u8>,
    value_offs: u64,
    value_inum: u32,
    value_size: u64,
}

/// The entries starting at `start` (up to the 4-byte zero terminator) and
/// the offset just past the terminator.
fn entries(data: &[u8], start: usize) -> (Vec<Entry>, usize, Option<Diagnostic>) {
    let mut out = Vec::new();
    let mut at = start;
    loop {
        match u32_le(data, at) {
            None => {
                return (
                    out,
                    at,
                    Some(Diagnostic::malformed("attribute list is not terminated")),
                );
            }
            Some(0) => return (out, at.saturating_add(4), None),
            Some(_) => {}
        }
        let name_len = usize::from(data.get(at).copied().unwrap_or(0));
        let len = to_usize(align_up(to_u64(16usize.saturating_add(name_len)), 4));
        let Some(name) =
            data.get(at.saturating_add(16)..at.saturating_add(16).saturating_add(name_len))
        else {
            return (
                out,
                at,
                Some(Diagnostic::malformed("attribute entry runs past its area")),
            );
        };
        out.push(Entry {
            off: at,
            len,
            index: data.get(at.saturating_add(1)).copied().unwrap_or(0),
            name: name.to_vec(),
            value_offs: u16_le(data, at.saturating_add(2)).unwrap_or(0).into(),
            value_inum: u32_le(data, at.saturating_add(4)).unwrap_or(0),
            value_size: u32_le(data, at.saturating_add(8)).unwrap_or(0).into(),
        });
        at = at.saturating_add(len);
    }
}

fn full_name(index: u8, name: &[u8]) -> String {
    format!(
        "{}{}",
        lookup(NAME_INDEXES, index.into()).unwrap_or("[unknown index]."),
        String::from_utf8_lossy(name)
    )
}

/// ext4's on-disk POSIX ACL (`ext4_acl_header`), `getfacl` short form.
fn acl_text(value: &[u8]) -> Option<String> {
    if u32_le(value, 0)? != 1 {
        return None;
    }
    let mut out = Vec::new();
    let mut at = 4usize;
    while at < value.len() {
        let tag = u16_le(value, at)?;
        let perm = u16_le(value, at.checked_add(2)?)?;
        let tag = u32::from(tag);
        // Short entries (no id) for the owner, owning group, mask and other.
        let (id, len) = match tag {
            0x02 | 0x08 => (u32_le(value, at.checked_add(4)?)?, 8),
            0x01 | 0x04 | 0x10 | 0x20 => (0, 4),
            _ => return None,
        };
        out.push(acl::entry(tag, id, perm));
        at = at.checked_add(len)?;
    }
    Some(out.join(", "))
}

fn value_node(name: String, span: Span, index: u8, value: &[u8]) -> Node {
    let node = Node::new(name).span(span);
    if matches!(index, 2 | 3)
        && let Some(acl) = acl_text(value)
    {
        return node
            .value(Value::Bytes(value.to_vec()))
            .summary(format!("POSIX ACL: {acl}"));
    }
    let trimmed = value.strip_suffix(&[0]).unwrap_or(value);
    if !value.is_empty() && crate::text::looks_like_text(trimmed) {
        node.value(Value::Text(String::from_utf8_lossy(trimmed).into_owned()))
    } else {
        node.value(Value::Bytes(value.to_vec()))
    }
}

fn entry_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    let name_len = f.u8("Name length").emit()?;
    f.u8("Name index").enumeration(NAME_INDEXES).emit()?;
    f.u16("Value offset").emit()?;
    f.u32("Value inode")
        .desc("With EA_INODE, the inode holding a large value; 0 when the value is here")
        .emit()?;
    f.u32("Value size").emit()?;
    f.u32("Hash").hex().emit()?;
    f.bytes("Name", name_len.into())
        .with(|b, n| n.value(Value::Text(String::from_utf8_lossy(b).into_owned())))
        .emit()?;
    let rest = f.remaining();
    if rest > 0 {
        f.bytes("Padding", rest).emit()?;
    }
    Ok(())
}

/// Emits an attribute area's entries and values. `base` is the offset
/// values are relative to, `start` where the entries begin (both relative
/// to the cursor's block); the cursor ends at the end of the area.
fn area(f: &mut Fields<'_>, base: usize, start: usize) {
    let data: &[u8] = &f.block().data;
    let (list, end, problem) = entries(data, start);
    let area_end = data.len();
    for e in &list {
        f.seek(to_u64(e.off));
        let what = if e.value_inum != 0 {
            format!("value in inode {}", e.value_inum)
        } else {
            size(e.value_size)
        };
        f.node(
            struct_node(
                full_name(e.index, &e.name),
                f.peek_span(to_u64(e.len)),
                LE,
                (),
                entry_layout,
            )
            .summary(what),
        );
    }
    if let Some(d) = problem {
        f.seek(to_u64(end));
        f.node(Node::new("Malformed entry").span(f.peek_span(0)).diag(d));
        f.seek(to_u64(area_end));
        return;
    }
    f.seek(to_u64(end.saturating_sub(4)));
    f.node(
        Node::new("End of entries")
            .span(f.peek_span(4))
            .value(Value::UInt {
                value: 0,
                bits: 32,
                radix: crate::value::Radix::Hex,
            }),
    );
    let mut lowest = area_end;
    let mut values: Vec<(usize, Node)> = Vec::new();
    for e in &list {
        if e.value_inum != 0 {
            continue;
        }
        let at = base.saturating_add(to_usize(e.value_offs));
        let value = data
            .get(at..at.saturating_add(to_usize(e.value_size)))
            .unwrap_or_default();
        f.seek(to_u64(at));
        let span = f.peek_span(e.value_size);
        lowest = lowest.min(at);
        values.push((
            at,
            value_node(
                format!("Value of {}", full_name(e.index, &e.name)),
                span,
                e.index,
                value,
            ),
        ));
    }
    if lowest > end {
        f.seek(to_u64(end));
        f.node(
            Node::new("Free space")
                .span(f.peek_span(to_u64(lowest.saturating_sub(end))))
                .summary(size(to_u64(lowest.saturating_sub(end)))),
        );
    }
    values.sort_by_key(|(at, _)| *at);
    for (_, node) in values {
        f.node(node);
    }
    f.seek(to_u64(area_end));
}

/// The in-inode attribute area, if the cursor (after the extra fields) is
/// at its magic.
pub(super) fn ibody_layout(f: &mut Fields<'_>) -> Result<()> {
    if f.remaining() < 4 || u32_le(&f.block().data, to_usize(f.pos())) != Some(MAGIC) {
        return Ok(());
    }
    f.u32("Extended attribute magic").hex().emit()?;
    let start = to_usize(f.pos());
    area(f, start, start);
    Ok(())
}

/// The value of the `system.data` attribute (the rest of inline data).
pub(super) fn inline_data_value(inode: &Inode) -> Option<Span> {
    let magic_at = to_usize(128u64.saturating_add(inode.extra_isize()));
    if u32_le(&inode.raw, magic_at)? != MAGIC {
        return None;
    }
    let start = magic_at.checked_add(4)?;
    let (list, _, _) = entries(&inode.raw, start);
    let e = list.iter().find(|e| e.index == 7 && e.name == b"data")?;
    Some(
        inode
            .span
            .sub(to_u64(start).saturating_add(e.value_offs), e.value_size),
    )
}

#[derive(Clone, Copy, Debug)]
struct BlockCtx {
    computed: Option<u32>,
}

fn block_layout(f: &mut Fields<'_>, ctx: &BlockCtx) -> Result<()> {
    f.u32("Magic").hex().emit()?;
    f.u32("Reference count")
        .desc("Inodes sharing this block")
        .emit()?;
    f.u32("Blocks").emit()?;
    f.u32("Hash").hex().emit()?;
    f.u32("Checksum")
        .hex()
        .with(|&v, n| match ctx.computed {
            Some(c) if c == v => n.summary("valid"),
            Some(c) => n.diag(Diagnostic::warning(format!("mismatch: computed {c:#010x}"))),
            None => n,
        })
        .emit()?;
    f.bytes("Reserved", 12).emit()?;
    area(f, 0, 32);
    Ok(())
}

/// An extended attribute block.
pub(super) async fn block_view(cx: Cx, (fs, block): (FsRef, u64)) -> Result<()> {
    let span = fs.block_span(block);
    let data = cx.read(span).await?;
    if u32_le(&data, 0) != Some(MAGIC) {
        return Err(Diagnostic::malformed("bad extended attribute block magic").at(span.sub(0, 4)));
    }
    let computed = fs.csum.map(|seed| {
        csum32(
            seed,
            &[
                &block.to_le_bytes(),
                data.get(..0x10).unwrap_or_default(),
                &[0; 4],
                data.get(0x14..).unwrap_or_default(),
            ],
        )
    });
    let block_data = crate::cx::Block { span, data };
    let ctx = BlockCtx { computed };
    block_layout(&mut Fields::emitting(&cx, &block_data, LE), &ctx)?;
    Ok(())
}
