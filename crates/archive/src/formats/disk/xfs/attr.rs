//! XFS extended attributes: short-form (in the inode's attribute fork),
//! leaf blocks, DA B+tree node blocks and remote value blocks.

use crate::bytes::{to_u64, to_usize, u16_be, u32_be, u64_be};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Fields, struct_node};
use crate::formats::disk::name_field;
use crate::formats::disk::{PieceList, size, uuid_value};
use crate::node::Node;
use crate::span::Span;
use crate::value::{FlagTable, Value, flag};

use super::inode::{Dinode, Ext, extents, logical_span};
use super::{BE, Fs, FsRef, HdrCtx, crc, crc_field, lsn_summary, rest_unused};

/// Attribute blocks visited for one inode.
const MAX_ATTR_BLOCKS: u64 = 1 << 16;

const ATTR_FLAGS: FlagTable = &[
    flag(0x01, "LOCAL"),
    flag(0x02, "ROOT"),
    flag(0x04, "SECURE"),
    flag(0x08, "PARENT"),
    flag(0x80, "INCOMPLETE"),
];

/// An attribute's name with its namespace.
fn attr_name(flags: u8, name: &[u8]) -> String {
    let name = String::from_utf8_lossy(name);
    if flags & 0x08 != 0 {
        format!("parent pointer \"{name}\"")
    } else if flags & 0x02 != 0 {
        format!("trusted.{name}")
    } else if flags & 0x04 != 0 {
        format!("security.{name}")
    } else {
        format!("user.{name}")
    }
}

/// A POSIX ACL as XFS stores it (`xfs_acl`), in `getfacl` short form.
fn acl_text(value: &[u8]) -> Option<String> {
    let count = to_usize(u32_be(value, 0)?.into());
    let entries = value.get(4..)?.as_chunks::<12>().0;
    if entries.len() < count {
        return None;
    }
    let mut out = Vec::new();
    for e in entries.iter().take(count) {
        let tag = u32_be(e, 0)?;
        let id = u32_be(e, 4)?;
        let perm = u16_be(e, 8)?;
        let who = match tag {
            0x01 => "user::".to_owned(),
            0x02 => format!("user:{id}:"),
            0x04 => "group::".to_owned(),
            0x08 => format!("group:{id}:"),
            0x10 => "mask::".to_owned(),
            0x20 => "other::".to_owned(),
            _ => format!("tag {tag:#x}:"),
        };
        let bit = |b: u16, c: char| if perm & b != 0 { c } else { '-' };
        out.push(format!(
            "{who}{}{}{}",
            bit(4, 'r'),
            bit(2, 'w'),
            bit(1, 'x')
        ));
    }
    Some(out.join(", "))
}

/// A node for an attribute value.
fn value_node(name: &'static str, span: Span, flags: u8, attr: &[u8], value: &[u8]) -> Node {
    let node = Node::new(name).span(span);
    if flags & 0x02 != 0
        && (attr == b"SGI_ACL_FILE" || attr == b"SGI_ACL_DEFAULT")
        && let Some(text) = acl_text(value)
    {
        return node.value(Value::Bytes(value.to_vec())).summary(format!(
            "POSIX {} ACL: {text}",
            if attr == b"SGI_ACL_FILE" {
                "access"
            } else {
                "default"
            }
        ));
    }
    if flags & 0x08 != 0 && value.len() == 12 {
        return node.value(Value::Bytes(value.to_vec())).summary(format!(
            "parent directory inode {}, generation {}",
            u64_be(value, 0).unwrap_or(0),
            u32_be(value, 8).unwrap_or(0)
        ));
    }
    let trimmed = value.strip_suffix(&[0]).unwrap_or(value);
    if crate::text::looks_like_text(trimmed) {
        node.value(Value::Text(String::from_utf8_lossy(trimmed).into_owned()))
    } else {
        node.value(Value::Bytes(value.to_vec()))
    }
}

/// The bytes of the next `len` bytes of the cursor's block.
fn ahead<'a>(f: &Fields<'a>, len: u64) -> &'a [u8] {
    let data: &'a [u8] = &f.block().data;
    let pos = to_usize(f.pos());
    data.get(pos..pos.saturating_add(to_usize(len)))
        .unwrap_or_default()
}

fn sf_entry_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    let namelen = f.u8("Name length").emit()?;
    let valuelen = f.u8("Value length").emit()?;
    let flags = f.u8("Flags").hex().flags(ATTR_FLAGS).emit()?;
    let name = name_field(f, namelen.into())?;
    let len = u64::from(valuelen);
    let value = ahead(f, len);
    f.node(value_node("Value", f.peek_span(len), flags, &name, value));
    f.skip(len);
    Ok(())
}

/// A short-form attribute list in the attribute fork.
pub(super) fn sf_layout(f: &mut Fields<'_>, _fs: &FsRef) -> Result<()> {
    let data: &[u8] = &f.block().data;
    let start = to_usize(f.pos());
    f.u16("Total size").emit()?;
    let count = f.u8("Entries").emit()?;
    f.u8("Padding").emit()?;
    let mut at = start.saturating_add(4);
    for _ in 0..count {
        let namelen = usize::from(data.get(at).copied().unwrap_or(0));
        let valuelen = usize::from(data.get(at.saturating_add(1)).copied().unwrap_or(0));
        let flags = data.get(at.saturating_add(2)).copied().unwrap_or(0);
        let name_at = at.saturating_add(3);
        let len = 3usize.saturating_add(namelen).saturating_add(valuelen);
        if data.len() < at.saturating_add(len) {
            f.node(
                Node::new("Malformed entry")
                    .span(f.peek_span(0))
                    .diag(Diagnostic::malformed("attribute entry runs past the fork")),
            );
            break;
        }
        let name = data
            .get(name_at..name_at.saturating_add(namelen))
            .unwrap_or_default();
        let value = data
            .get(name_at.saturating_add(namelen)..at.saturating_add(len))
            .unwrap_or_default();
        f.seek(to_u64(at));
        let probe = value_node("Value", f.peek_span(0), flags, name, value);
        let summary = probe.summary.clone().unwrap_or_else(|| match &probe.value {
            Some(Value::Text(t)) => format!("\"{}\"", t.chars().take(60).collect::<String>()),
            _ => format!("{valuelen} bytes"),
        });
        f.node(
            struct_node(
                attr_name(flags, name),
                f.peek_span(to_u64(len)),
                BE,
                (),
                sf_entry_layout,
            )
            .summary(summary),
        );
        f.skip(to_u64(len));
        at = at.saturating_add(len);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Attribute blocks

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AttrKind {
    Leaf,
    Node,
    Remote,
    Data,
}

fn attr_kind(fs: &Fs, data: &[u8]) -> AttrKind {
    match u16_be(data, 8) {
        Some(0xfbee | 0x3bee) => AttrKind::Leaf,
        Some(0xfebe | 0x3ebe) => AttrKind::Node,
        _ if fs.v5 && data.get(..4) == Some(b"XARM".as_slice()) => AttrKind::Remote,
        _ => AttrKind::Data,
    }
}

/// Every mapped block of the attribute fork, in logical order.
async fn attr_blocks(cx: &Cx, exts: &[Ext]) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    'outer: for e in exts {
        for i in 0..e.count {
            if to_u64(out.len()) >= MAX_ATTR_BLOCKS {
                break 'outer;
            }
            if out.len().is_multiple_of(256) {
                cx.checkpoint().await;
            }
            out.push((e.off.saturating_add(i), e.fsb.saturating_add(i)));
        }
    }
    out
}

/// Lists the attribute fork's blocks with their structure.
pub(super) async fn blocks(cx: Cx, (fs, ino): (FsRef, u64)) -> Result<()> {
    let di = Dinode::read(&cx, &fs, ino).await?;
    let (exts, problem) = extents(&cx, &fs, &di, true).await?;
    if let Some(d) = problem {
        cx.diag(d);
    }
    for (lblk, fsb) in attr_blocks(&cx, &exts).await {
        if !fs.fsb_valid(fsb) {
            cx.push(
                Node::new(format!("Block {lblk}"))
                    .diag(Diagnostic::malformed("block outside the filesystem")),
            )
            .await;
            continue;
        }
        let span = fs.fsb_span(fsb, 1);
        let data = cx.read_avail(span).await?;
        let kind = attr_kind(&fs, &data);
        let info: usize = if fs.v5 { 56 } else { 12 };
        let summary = match kind {
            AttrKind::Leaf => format!("leaf, {} entries", u16_be(&data, info).unwrap_or(0)),
            AttrKind::Node => format!(
                "DA B+tree node, level {}, {} children",
                u16_be(&data, info.saturating_add(2)).unwrap_or(0),
                u16_be(&data, info).unwrap_or(0)
            ),
            AttrKind::Remote => format!(
                "remote value, {} bytes at value offset {}",
                u32_be(&data, 8).unwrap_or(0),
                u32_be(&data, 4).unwrap_or(0)
            ),
            AttrKind::Data => "remote value data".to_owned(),
        };
        cx.push(
            Node::new(format!("Block {lblk}"))
                .span(span)
                .summary(summary)
                .lazy(attr_block, (fs.clone(), span)),
        )
        .await;
    }
    Ok(())
}

fn leaf_header_layout(f: &mut Fields<'_>, ctx: &HdrCtx) -> Result<()> {
    f.u32("Next block").emit()?;
    f.u32("Previous block").emit()?;
    f.u16("Magic").hex().emit()?;
    f.u16("Padding").emit()?;
    if ctx.v5 {
        crc_field(f, ctx.crc)?;
        f.u64("Disk address (512-byte units)").hex().emit()?;
        f.u64("LSN").hex().with(lsn_summary).emit()?;
        f.bytes("UUID", 16).with(uuid_value).emit()?;
        f.u64("Owner (inode)").emit()?;
    }
    f.u16("Entries").emit()?;
    f.u16("Bytes used").emit()?;
    f.u16("First used")
        .desc("Offset of the lowest name/value; 0 means 65536 on v5")
        .emit()?;
    f.u8("Holes").emit()?;
    f.u8("Padding").emit()?;
    for (base, len) in [
        ("Free map 0: offset", "Free map 0: size"),
        ("Free map 1: offset", "Free map 1: size"),
        ("Free map 2: offset", "Free map 2: size"),
    ] {
        f.u16(base).emit()?;
        f.u16(len).emit()?;
    }
    if ctx.v5 {
        f.u32("Padding").emit()?;
    }
    Ok(())
}

fn entry_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Hash").hex().emit()?;
    f.u16("Name offset").emit()?;
    f.u8("Flags").hex().flags(ATTR_FLAGS).emit()?;
    f.u8("Padding").emit()?;
    Ok(())
}

fn local_name_layout(f: &mut Fields<'_>, flags: &u8) -> Result<()> {
    let valuelen = f.u16("Value length").emit()?;
    let namelen = f.u8("Name length").emit()?;
    let name = name_field(f, namelen.into())?;
    let len = u64::from(valuelen);
    let value = ahead(f, len);
    f.node(value_node("Value", f.peek_span(len), *flags, &name, value));
    f.skip(len);
    rest_unused(f, "Padding");
    Ok(())
}

fn remote_name_layout(f: &mut Fields<'_>, _: &u8) -> Result<()> {
    f.u32("Value block")
        .desc("Logical block of the attribute fork where the value starts")
        .emit()?;
    f.u32("Value length").emit()?;
    let namelen = f.u8("Name length").emit()?;
    name_field(f, namelen.into())?;
    rest_unused(f, "Padding");
    Ok(())
}

/// One leaf entry: (entry index, flags, name offset, name/value length,
/// name, value or (value block, value length)).
struct LeafEnt {
    flags: u8,
    nameidx: u64,
    len: u64,
    name: Vec<u8>,
    local: Option<(u64, u64)>,
    remote: Option<(u64, u64)>,
}

fn leaf_entries(fs: &Fs, data: &[u8]) -> Vec<LeafEnt> {
    let hdr: usize = if fs.v5 { 80 } else { 32 };
    let info: usize = if fs.v5 { 56 } else { 12 };
    let count = usize::from(u16_be(data, info).unwrap_or(0));
    let mut out = Vec::new();
    for i in 0..count {
        let at = hdr.saturating_add(i.saturating_mul(8));
        let (Some(nameidx), Some(&flags)) = (
            u16_be(data, at.saturating_add(4)),
            data.get(at.saturating_add(6)),
        ) else {
            break;
        };
        let n = usize::from(nameidx);
        let ent = if flags & 0x01 != 0 {
            let valuelen = usize::from(u16_be(data, n).unwrap_or(0));
            let namelen = usize::from(data.get(n.saturating_add(2)).copied().unwrap_or(0));
            let name_at = n.saturating_add(3);
            LeafEnt {
                flags,
                nameidx: nameidx.into(),
                len: to_u64(3usize.saturating_add(namelen).saturating_add(valuelen))
                    .next_multiple_of(4),
                name: data
                    .get(name_at..name_at.saturating_add(namelen))
                    .unwrap_or_default()
                    .to_vec(),
                local: Some((to_u64(name_at.saturating_add(namelen)), to_u64(valuelen))),
                remote: None,
            }
        } else {
            let namelen = usize::from(data.get(n.saturating_add(8)).copied().unwrap_or(0));
            let name_at = n.saturating_add(9);
            LeafEnt {
                flags,
                nameidx: nameidx.into(),
                len: to_u64(9usize.saturating_add(namelen)).next_multiple_of(4),
                name: data
                    .get(name_at..name_at.saturating_add(namelen))
                    .unwrap_or_default()
                    .to_vec(),
                local: None,
                remote: Some((
                    u64::from(u32_be(data, n).unwrap_or(0)),
                    u64::from(u32_be(data, n.saturating_add(4)).unwrap_or(0)),
                )),
            }
        };
        out.push(ent);
    }
    out
}

fn remote_header_layout(f: &mut Fields<'_>, ctx: &HdrCtx) -> Result<()> {
    f.ascii("Magic", 4).emit()?;
    f.u32("Offset in value").emit()?;
    let bytes = f.u32("Bytes in this block").emit()?;
    crc_field(f, ctx.crc)?;
    f.bytes("UUID", 16).with(uuid_value).emit()?;
    f.u64("Owner (inode)").emit()?;
    f.u64("Disk address (512-byte units)").hex().emit()?;
    f.u64("LSN").hex().with(lsn_summary).emit()?;
    let len = u64::from(bytes).min(f.remaining());
    f.node(
        Node::new("Value data")
            .span(f.peek_span(len))
            .summary(size(len)),
    );
    f.skip(len);
    rest_unused(f, "Unused");
    Ok(())
}

/// Shows one attribute block.
async fn attr_block(cx: Cx, (fs, span): (FsRef, Span)) -> Result<()> {
    let data = cx.read(span).await?;
    let len = to_u64(data.len());
    match attr_kind(&fs, &data) {
        AttrKind::Node => super::dir::da_node(&cx, &fs, span, &data),
        AttrKind::Remote => cx.emit(struct_node(
            "Remote value block",
            span,
            BE,
            HdrCtx {
                v5: true,
                crc: crc(&data, 12),
            },
            remote_header_layout,
        )),
        AttrKind::Data => cx.emit(Node::new("Value data").span(span).summary(size(span.len))),
        AttrKind::Leaf => {
            let hdr: u64 = if fs.v5 { 80 } else { 32 };
            cx.emit(struct_node(
                "Header",
                span.sub(0, hdr),
                BE,
                HdrCtx {
                    v5: fs.v5,
                    crc: if fs.v5 { crc(&data, 12) } else { None },
                },
                leaf_header_layout,
            ));
            let entries = leaf_entries(&fs, &data);
            let table_end = hdr.saturating_add(to_u64(entries.len()).saturating_mul(8));
            for (i, e) in entries.iter().enumerate() {
                cx.push(
                    struct_node(
                        format!("Entry {i}"),
                        span.sub(hdr.saturating_add(to_u64(i).saturating_mul(8)), 8),
                        BE,
                        (),
                        entry_layout,
                    )
                    .summary(format!(
                        "{} at offset {}",
                        attr_name(e.flags, &e.name),
                        e.nameidx
                    )),
                )
                .await;
            }
            let mut lowest = len;
            for e in &entries {
                lowest = lowest.min(e.nameidx);
                let espan = span.sub(e.nameidx, e.len);
                let name = attr_name(e.flags, &e.name);
                let node = if let Some((vat, vlen)) = e.local {
                    let value = data
                        .get(to_usize(vat)..to_usize(vat.saturating_add(vlen)))
                        .unwrap_or_default();
                    let probe = value_node("Value", espan, e.flags, &e.name, value);
                    let summary = probe
                        .summary
                        .clone()
                        .unwrap_or_else(|| format!("{vlen} bytes"));
                    struct_node(name, espan, BE, e.flags, local_name_layout).summary(summary)
                } else {
                    let (blk, vlen) = e.remote.unwrap_or_default();
                    struct_node(name, espan, BE, e.flags, remote_name_layout)
                        .summary(format!("{vlen} bytes in block {blk}"))
                };
                cx.push(node).await;
            }
            if lowest > table_end {
                cx.emit(
                    Node::new("Free space")
                        .span(span.sub(table_end, lowest.saturating_sub(table_end)))
                        .summary(size(lowest.saturating_sub(table_end))),
                );
            }
        }
    }
    Ok(())
}

/// The value of a remote attribute, assembled from its blocks.
async fn remote_value(
    cx: &Cx,
    fs: &Fs,
    exts: &[Ext],
    anchor: Span,
    blk: u64,
    len: u64,
) -> Result<Span> {
    let per = if fs.v5 {
        fs.block.saturating_sub(56)
    } else {
        fs.block
    };
    let mut list = PieceList::new(anchor);
    let mut left = len.min(1 << 16);
    let mut b = blk;
    while left > 0 && per > 0 {
        let Some(span) = logical_span(cx, fs, exts, b, 1, "xfs-attr-block").await? else {
            return Err(Diagnostic::malformed(format!(
                "remote value block {b} is not mapped"
            )));
        };
        let take = left.min(per);
        list.data(if fs.v5 {
            span.sub(56, take)
        } else {
            span.sub(0, take)
        });
        left = left.saturating_sub(take);
        b = b.saturating_add(1);
    }
    list.finish(cx, "xfs-attr-value").await
}

/// Lists an inode's attributes (name and value) from its leaf blocks.
pub(super) async fn list(cx: Cx, (fs, ino): (FsRef, u64)) -> Result<()> {
    let di = Dinode::read(&cx, &fs, ino).await?;
    let (exts, problem) = extents(&cx, &fs, &di, true).await?;
    if let Some(d) = problem {
        cx.diag(d);
    }
    for (_, fsb) in attr_blocks(&cx, &exts).await {
        if !fs.fsb_valid(fsb) {
            continue;
        }
        let span = fs.fsb_span(fsb, 1);
        let data = cx.read_avail(span).await?;
        if attr_kind(&fs, &data) != AttrKind::Leaf {
            continue;
        }
        for e in leaf_entries(&fs, &data) {
            let name = attr_name(e.flags, &e.name);
            let espan = span.sub(e.nameidx, e.len);
            let node = if let Some((vat, vlen)) = e.local {
                let value = data
                    .get(to_usize(vat)..to_usize(vat.saturating_add(vlen)))
                    .unwrap_or_default();
                let mut n = value_node("Value", span.sub(vat, vlen), e.flags, &e.name, value);
                n.name = name.into();
                n
            } else {
                let (blk, vlen) = e.remote.unwrap_or_default();
                match remote_value(&cx, &fs, &exts, espan, blk, vlen).await {
                    Ok(vspan) => {
                        let value = cx.read_avail(vspan).await?;
                        let mut n = value_node("Value", vspan, e.flags, &e.name, &value);
                        n.name = name.into();
                        n.summary(format!("{} (remote)", size(vlen)))
                    }
                    Err(d) => Node::new(name).span(espan).diag(d),
                }
            };
            cx.push(node).await;
        }
    }
    Ok(())
}
