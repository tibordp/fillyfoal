//! .NET manifest resources: the blobs in the CLR header's resources
//! directory (each a 32-bit length and the data, 8-byte aligned), named by
//! the `ManifestResource` metadata table. If the metadata cannot be read,
//! the blobs are listed by walking the directory, without names.

use super::Pe;
use super::metadata::{IMPLEMENTATION, decode_coded, load, table_name};
use crate::bytes::u32_le;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::embedded;
use crate::node::Node;
use crate::span::Span;
use crate::value::{Radix, Value};

const MANIFEST_RESOURCE: usize = 0x28;

/// One resource blob: its length prefix and data.
/// Returns the prefix, the data and the whole entry.
async fn blob(cx: &Cx, res: Span, offset: u64) -> Result<(Span, Span, Span)> {
    let prefix = res.sub_exact(offset, 4)?;
    let len = cx.read(prefix).await?;
    let len = u64::from(u32_le(&len, 0).unwrap_or(0));
    Ok((
        prefix,
        res.sub(offset.saturating_add(4), len),
        res.sub(offset, len.saturating_add(4)),
    ))
}

async fn resource(cx: Cx, (pe, prefix, data): (Pe, Span, Span)) -> Result<()> {
    cx.emit(Node::new("Length").span(prefix).value(Value::UInt {
        value: data.len,
        bits: 32,
        radix: Radix::Dec,
    }));
    cx.emit(embedded("Data", pe.input.nested(data)));
    Ok(())
}

pub(super) async fn resources(cx: Cx, (pe, root, res): (Pe, Span, Span)) -> Result<()> {
    match load(&cx, root).await {
        Ok(md) if md.valid & (1u64 << MANIFEST_RESOURCE) != 0 => {
            for row in 1..=md.row_count(MANIFEST_RESOURCE) {
                let Some(data) = md.row(&cx, MANIFEST_RESOURCE, row).await else {
                    break;
                };
                let offset = md.cell(MANIFEST_RESOURCE, &data, 0);
                let flags = md.cell(MANIFEST_RESOURCE, &data, 1);
                let name = md.string(&cx, md.cell(MANIFEST_RESOURCE, &data, 2)).await;
                let implementation = md.cell(MANIFEST_RESOURCE, &data, 3);
                let visibility = match flags & 7 {
                    1 => "public",
                    2 => "private",
                    _ => "unknown visibility",
                };
                if implementation != 0 {
                    // Lives in another file or assembly.
                    let target = match decode_coded(IMPLEMENTATION, implementation) {
                        Some((t, r)) => format!("{} #{r}", table_name(t)),
                        None => format!("{implementation:#x}"),
                    };
                    cx.push(Node::new(name).summary(format!("{visibility}, in {target}")))
                        .await;
                    continue;
                }
                let node = match blob(&cx, res, offset.into()).await {
                    Ok((prefix, span, whole)) => Node::new(name)
                        .span(whole)
                        .summary(format!("{visibility}, {} bytes", span.len))
                        .lazy(resource, (pe.clone(), prefix, span)),
                    Err(e) => Node::new(name).diag(e),
                };
                cx.push(node).await;
            }
        }
        other => {
            if let Err(e) = other {
                cx.diag(Diagnostic::note(format!(
                    "resource names unavailable ({}); listed in directory order",
                    e.message
                )));
            }
            let mut at = 0u64;
            let mut i = 0u32;
            while at.saturating_add(4) <= res.len {
                let (prefix, span, whole) = blob(&cx, res, at).await?;
                cx.progress_in(res, span.end());
                cx.push(
                    Node::new(format!("Resource {i}"))
                        .span(whole)
                        .summary(format!("{} bytes", span.len))
                        .lazy(resource, (pe.clone(), prefix, span)),
                )
                .await;
                at = at
                    .saturating_add(4)
                    .saturating_add(span.len)
                    .next_multiple_of(8);
                i = i.saturating_add(1);
            }
        }
    }
    Ok(())
}
