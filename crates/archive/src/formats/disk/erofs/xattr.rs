//! EROFS extended attributes: an inode's inline area (a header, the ids of
//! shared xattrs, then inline entries), the shared xattr area and the long
//! name prefix table.

use std::sync::Arc;

use crate::bytes::{align_up, to_u64, to_usize, u16_le, u32_le};
use crate::cx::Cx;
use crate::error::Result;
use crate::fields::{Fields, struct_node};
use crate::formats::disk::acl::{NAME_INDEXES, xattr_v2};
use crate::node::Node;
use crate::span::Span;
use crate::value::{Radix, Value, lookup};

use super::{Fs, FsRef, Ino, LE};

/// The prefix a name index stands for (a long prefix if bit 7 is set).
fn prefix(fs: &Fs, index: u8) -> String {
    if index & 0x80 != 0 {
        return match fs.prefixes.get(usize::from(index & 0x7f)) {
            Some((base, infix)) => format!(
                "{}{}",
                lookup(NAME_INDEXES, (*base).into()).unwrap_or(""),
                String::from_utf8_lossy(infix)
            ),
            None => format!("[long prefix {}]", index & 0x7f),
        };
    }
    lookup(NAME_INDEXES, index.into()).map_or_else(|| format!("[index {index}]"), str::to_owned)
}

/// A short description of an xattr value.
fn value_summary(index: u8, value: &[u8]) -> String {
    if matches!(index, 2 | 3)
        && let Some(acl) = xattr_v2(value)
    {
        return format!("POSIX ACL: {acl}");
    }
    let trimmed = value.strip_suffix(&[0]).unwrap_or(value);
    if crate::text::looks_like_text(trimmed) {
        let text: String = String::from_utf8_lossy(trimmed).chars().take(60).collect();
        format!("\"{text}\"")
    } else {
        format!("{} bytes", value.len())
    }
}

/// One entry: (name index, name, value, entry length).
fn entry_at(data: &[u8], at: usize) -> Option<(u8, Vec<u8>, Vec<u8>, usize)> {
    let name_len = usize::from(*data.get(at)?);
    let index = *data.get(at.checked_add(1)?)?;
    let value_len = usize::from(u16_le(data, at.checked_add(2)?)?);
    let name_at = at.checked_add(4)?;
    let value_at = name_at.checked_add(name_len)?;
    let end = value_at.checked_add(value_len)?;
    let name = data.get(name_at..value_at)?.to_vec();
    let value = data.get(value_at..end)?.to_vec();
    let len = to_usize(align_up(to_u64(end.checked_sub(at)?), 4));
    Some((index, name, value, len))
}

#[derive(Clone)]
struct EntryCtx {
    fs: FsRef,
}

fn entry_layout(f: &mut Fields<'_>, ctx: &EntryCtx) -> Result<()> {
    let name_len = f.u8("Name length").emit()?;
    let index = f
        .u8("Name index")
        .with(|&v, n| n.summary(prefix(&ctx.fs, v)))
        .desc("The name's prefix: a standard namespace, or (bit 7) a long prefix from the table")
        .emit()?;
    let value_len = f.u16("Value size").emit()?;
    f.bytes("Name", name_len.into())
        .with(|b, n| n.value(Value::Text(String::from_utf8_lossy(b).into_owned())))
        .emit()?;
    let len = u64::from(value_len);
    let data: &[u8] = &f.block().data;
    let pos = to_usize(f.pos());
    let value = data
        .get(pos..pos.saturating_add(to_usize(len)))
        .unwrap_or_default();
    let trimmed = value.strip_suffix(&[0]).unwrap_or(value);
    let node = Node::new("Value").span(f.peek_span(len));
    let node = if crate::text::looks_like_text(trimmed) {
        node.value(Value::Text(String::from_utf8_lossy(trimmed).into_owned()))
    } else {
        node.value(Value::Bytes(value.to_vec()))
            .summary(value_summary(index, value))
    };
    f.node(node);
    f.skip(len);
    let rest = f.remaining();
    if rest > 0 {
        f.bytes("Padding", rest).emit()?;
    }
    Ok(())
}

fn header_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Name filter")
        .hex()
        .desc("Bloom filter of the names present: a set bit means no name hashes to it (XATTR_FILTER)")
        .emit()?;
    f.u8("Shared xattrs").emit()?;
    f.bytes("Reserved", 7).emit()?;
    Ok(())
}

/// Shows an inode's inline xattr area.
pub(super) async fn view(cx: Cx, (fs, nid): (FsRef, u64)) -> Result<()> {
    let ino = Ino::read(&cx, &fs, nid).await?;
    let span = fs
        .vol
        .sub(ino.off.saturating_add(ino.core_len()), ino.xattr_len());
    let data = cx.read(span).await?;
    cx.emit(struct_node(
        "Header",
        span.sub(0, 12),
        LE,
        (),
        header_layout,
    ));
    let shared = usize::from(data.get(4).copied().unwrap_or(0));
    for i in 0..shared {
        let at = 12usize.saturating_add(i.saturating_mul(4));
        let Some(id) = u32_le(&data, at) else { break };
        let entry_off = fs.xattr.saturating_add(u64::from(id).saturating_mul(4));
        let head = cx.read_avail(fs.vol.sub(entry_off, 4)).await?;
        let name_len = u64::from(head.first().copied().unwrap_or(0));
        let value_len = u64::from(u16_le(&head, 2).unwrap_or(0));
        let elen = align_up(4u64.saturating_add(name_len).saturating_add(value_len), 4);
        let espan = fs.vol.sub(entry_off, elen);
        let raw = cx.read_avail(espan).await?;
        let summary = match entry_at(&raw, 0) {
            Some((index, name, value, _)) => format!(
                "{}{} = {}",
                prefix(&fs, index),
                String::from_utf8_lossy(&name),
                value_summary(index, &value)
            ),
            None => "truncated".to_owned(),
        };
        cx.push(
            Node::new(format!("Shared xattr {i}"))
                .span(span.sub(to_u64(at), 4))
                .value(Value::UInt {
                    value: id.into(),
                    bits: 32,
                    radix: Radix::Dec,
                })
                .summary(summary)
                .target(espan)
                .lazy(shared_entry, (fs.clone(), espan)),
        )
        .await;
    }
    let mut at = 12usize.saturating_add(shared.saturating_mul(4));
    while at.saturating_add(4) <= data.len() {
        let Some((index, name, value, len)) = entry_at(&data, at) else {
            cx.diag(
                crate::error::Diagnostic::malformed("xattr entry runs past the inline area")
                    .at(span.tail(to_u64(at))),
            );
            break;
        };
        cx.push(
            struct_node(
                format!("{}{}", prefix(&fs, index), String::from_utf8_lossy(&name)),
                span.sub(to_u64(at), to_u64(len)),
                LE,
                EntryCtx { fs: fs.clone() },
                entry_layout,
            )
            .summary(value_summary(index, &value)),
        )
        .await;
        at = at.saturating_add(len.max(4));
    }
    Ok(())
}

async fn shared_entry(cx: Cx, (fs, span): (FsRef, Span)) -> Result<()> {
    cx.emit(struct_node(
        "Shared entry",
        span,
        LE,
        EntryCtx { fs: fs.clone() },
        entry_layout,
    ));
    Ok(())
}

fn prefix_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("Length").emit()?;
    f.u8("Base name index").enumeration(NAME_INDEXES).emit()?;
    let rest = f.remaining();
    f.bytes("Infix", rest)
        .with(|b, n| n.value(Value::Text(String::from_utf8_lossy(b).into_owned())))
        .emit()?;
    Ok(())
}

/// The long xattr name prefix table.
pub(super) async fn prefix_table(cx: Cx, (fs, spans): (FsRef, Arc<Vec<Span>>)) -> Result<()> {
    for (i, span) in spans.iter().enumerate() {
        let name = fs
            .prefixes
            .get(i)
            .map(|(base, infix)| {
                format!(
                    "{}{}",
                    lookup(NAME_INDEXES, (*base).into()).unwrap_or(""),
                    String::from_utf8_lossy(infix)
                )
            })
            .unwrap_or_default();
        cx.push(
            struct_node(format!("Prefix {i}"), *span, LE, (), prefix_layout)
                .summary(format!("\"{name}\"")),
        )
        .await;
    }
    Ok(())
}
