//! Tracker modules: ProTracker-style MOD, Scream Tracker 3 (S3M),
//! FastTracker 2 (XM) and Impulse Tracker (IT).
//!
//! Each format has a header, an order list, and tables of samples,
//! instruments and patterns, either stored back to back (MOD, XM) or
//! reached through pointer tables (S3M, IT). The helpers here list such
//! tables lazily.

pub mod it;
pub mod more;
pub mod protracker;
pub mod s3m;
pub mod xm;

use crate::bytes::{to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::Result;
use crate::fields::Endian;
use crate::formats::util::sound::Describe;
use crate::node::{Count, Node};
use crate::span::Span;

/// "C-4" style note names (0 = C-0).
pub fn note_name(n: u8) -> String {
    const NAMES: [&str; 12] = [
        "C-", "C#", "D-", "D#", "E-", "F-", "F#", "G-", "G#", "A-", "A#", "B-",
    ];
    let name = NAMES.get(usize::from(n % 12)).copied().unwrap_or("?");
    format!("{name}{}", n / 12)
}

/// The order list as text: "0 1 2 1 …", with markers shown as `+++`
/// (skip) and `---` (end).
pub fn orders(list: &[u8]) -> String {
    // Unused entries at the end are end markers (255).
    let used = list
        .iter()
        .rposition(|&o| o != 255)
        .map_or(0, |p| p.saturating_add(1));
    let list = list.get(..used).unwrap_or_default();
    let mut out: Vec<String> = Vec::new();
    for &o in list.iter().take(64) {
        out.push(match o {
            254 => "+++".to_owned(),
            255 => "---".to_owned(),
            n => n.to_string(),
        });
    }
    if list.len() > 64 {
        out.push("…".to_owned());
    }
    out.join(" ")
}

/// A node for an order list at `span`.
pub async fn order_node(cx: &Cx, span: Span) -> Result<Node> {
    let list = cx.read_avail(span).await?;
    Ok(Node::new("Orders")
        .span(span)
        .summary(format!("{} entries", list.len()))
        .value(crate::formats::util::sound::text(orders(&list))))
}

/// How a pointer table addresses its targets.
#[derive(Clone, Copy, Debug)]
pub struct Pointers {
    /// The pointer array.
    pub table: Span,
    /// 2 (S3M paragraphs) or 4 (IT byte offsets).
    pub width: u8,
    /// What a pointer is multiplied by (16 for S3M, 1 for IT).
    pub scale: u64,
}

/// A lazy node listing records of type `R` reached through `pointers`,
/// relative to `file`.
pub fn pointed<R: Record>(
    name: &'static str,
    file: Span,
    pointers: Pointers,
    item: &'static str,
    describe: Option<Describe<R>>,
) -> Node {
    let count = pointers
        .table
        .len
        .checked_div(pointers.width.into())
        .unwrap_or(0);
    Node::new(name)
        .span(pointers.table)
        .summary(format!("{count} entries"))
        .lazy(expand_pointed::<R>, (file, pointers, item, describe))
}

type PointedState<R> = (Span, Pointers, &'static str, Option<Describe<R>>);

async fn expand_pointed<R: Record>(
    cx: Cx,
    (file, pointers, item, describe): PointedState<R>,
) -> Result<()> {
    let table = cx.read(pointers.table).await?;
    let width = usize::from(pointers.width.max(1));
    cx.set_count(Count::Exact(to_u64(
        table.len().checked_div(width).unwrap_or(0),
    )));
    let mut index = 0u64;
    let mut at = 0usize;
    while at.saturating_add(width) <= table.len() {
        let ptr = if width == 2 {
            u64::from(u16_le(&table, at).unwrap_or(0))
        } else {
            u64::from(u32_le(&table, at).unwrap_or(0))
        };
        let label = format!("{item} {}", index.saturating_add(1));
        if ptr == 0 {
            cx.push(Node::new(label).summary("empty")).await;
        } else {
            let span = file.sub(ptr.saturating_mul(pointers.scale), R::SIZE);
            let mut node = R::node(label, span, Endian::Little);
            if let Some(describe) = describe
                && let Ok((r, _)) = Cursor::new(&cx, span, Endian::Little).record::<R>().await
            {
                node = node.summary(describe(&r));
            }
            cx.push(node).await;
        }
        at = at.saturating_add(width);
        index = index.saturating_add(1);
    }
    Ok(())
}

/// "name" or "(unnamed)".
pub fn named(s: &str) -> String {
    let t = s.trim();
    if t.is_empty() {
        "(unnamed)".to_owned()
    } else {
        t.to_owned()
    }
}
