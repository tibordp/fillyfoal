//! MAPI property names, types and values.

use std::sync::Arc;

use super::ltp::{self, NodeRef, Raw};
use super::ndb::{self, Pst};
use crate::bytes::{to_u64, to_usize, u16_le, u32_le};
use crate::cx::Cx;
use crate::error::Result;
use crate::fields::Endian;
use crate::formats::util::mapi::{self, Named};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

pub use crate::formats::util::mapi::{ATTACH_METHOD, TYPES};

/// The name-to-ID map ([MS-PST] 2.4.7), indexed by `prop_id - 0x8000`.
pub type NameMap = Vec<Option<Named>>;

/// Most named properties resolved (the map can be large).
const MAX_NAMED: usize = 0x8000;

pub async fn name_map(cx: &Cx, pst: &Pst) -> Arc<NameMap> {
    let key = pst.file().sub(0, 0);
    if let Some(found) = cx.cached::<NameMap>(key, "pst-nameid") {
        return found;
    }
    let map = Arc::new(load_name_map(cx, pst).await.unwrap_or_default());
    cx.cache(key, "pst-nameid", map.clone());
    map
}

async fn load_name_map(cx: &Cx, pst: &Pst) -> Result<NameMap> {
    let Some(entry) = ndb::find_node(cx, pst, 0x61).await? else {
        return Ok(Vec::new());
    };
    let node = NodeRef {
        nid: entry.nid,
        data: entry.data,
        sub: entry.sub,
    };
    let pc = ltp::pc(cx, pst, node).await?;
    let mut streams: [Option<Span>; 3] = [None, None, None];
    for p in &pc.props {
        let slot = match p.id {
            0x0002 => 0,
            0x0003 => 1,
            0x0004 => 2,
            _ => continue,
        };
        if let Raw::Data(span) = ltp::prop_value(cx, pst, &pc.heap, p).await?
            && let Some(s) = streams.get_mut(slot)
        {
            *s = Some(span);
        }
    }
    let [Some(guids), Some(entries), strings] = streams else {
        return Ok(Vec::new());
    };
    let guids = cx.read(guids.sub(0, 0x10000)).await?;
    let entries = cx
        .read(entries.sub(0, to_u64(MAX_NAMED).saturating_mul(8)))
        .await?;
    let strings = match strings {
        Some(s) => cx.read(s.sub(0, 0x100000)).await?,
        None => Vec::new(),
    };
    let mut map: NameMap = Vec::new();
    for e in entries.as_chunks::<8>().0 {
        // Each entry may decode a string of up to the whole string stream.
        cx.checkpoint().await;
        let value = u32_le(e, 0).unwrap_or(0);
        let flags = u16_le(e, 4).unwrap_or(0);
        let index = usize::from(u16_le(e, 6).unwrap_or(0));
        let set = mapi::set_label(flags >> 1, &guids);
        let id = if flags & 1 == 0 {
            Ok(value)
        } else {
            Err(mapi::name_string(&strings, value).unwrap_or_default())
        };
        let named = Named { set, id };
        if index < MAX_NAMED {
            if map.len() <= index {
                map.resize(index.saturating_add(1), None);
            }
            if let Some(slot) = map.get_mut(index) {
                *slot = Some(named);
            }
        }
    }
    Ok(map)
}

/// The display name of a property ID.
pub fn name(id: u16, names: &NameMap) -> String {
    mapi::property_name(id, names)
}

/// Text values are shown up to this many bytes.
pub const MAX_TEXT: u64 = 0x1000;
/// Binary values are shown inline up to this many bytes.
const MAX_INLINE_BINARY: u64 = 64;

/// Decodes a string property's bytes.
pub fn text(ty: u16, data: &[u8]) -> String {
    let s = if ty & 0x0fff == 0x001f {
        crate::text::utf16(data, Endian::Little)
    } else {
        crate::text::latin1(data)
    };
    s.trim_end_matches('\0').to_owned()
}

/// A property value as a node (named by the caller), with typed value and
/// span; large text and binary values get a child to dissect them.
pub fn value_node(pst: &Pst, mut node: Node, id: u16, ty: u16, raw: &[u8], span: Span) -> Node {
    node = node.span(span);
    let (value, summary) = scalar(id, ty, raw);
    if let Some(v) = value {
        node = node.value(v);
    }
    if let Some(s) = summary {
        node = node.summary(s);
    }
    match ty {
        0x001e | 0x001f => {
            if span.len > MAX_TEXT {
                node = node.summary(format!("first 4 KiB of {} bytes", span.len));
            }
        }
        0x0102 | 0x000d if span.len > MAX_INLINE_BINARY => {
            node = node
                .summary(format!("{} bytes", span.len))
                .lazy(crate::formats::dissect_or_data, pst.input.nested(span));
        }
        _ => {}
    }
    node
}

/// Typed value and summary of a scalar property (`raw` holds its bytes,
/// at most [`MAX_TEXT`] of them for variable-size types).
pub fn scalar(id: u16, ty: u16, raw: &[u8]) -> (Option<Value>, Option<String>) {
    let value = match ty {
        t if mapi::is_fixed(t) => return mapi::fixed_scalar(id, t, raw),
        0x0048 => match mapi::guid(raw, 0) {
            Some(g) => Value::Guid(g),
            None => return (None, None),
        },
        0x001e | 0x001f => Value::Text(text(ty, raw)),
        0x0102 | 0x000d => {
            if to_u64(raw.len()) <= MAX_INLINE_BINARY {
                Value::Bytes(raw.to_vec())
            } else {
                return (None, None);
            }
        }
        t if t & 0x1000 != 0 => return (None, Some(multi(t, raw))),
        _ => return (None, Some(format!("{} bytes", raw.len()))),
    };
    (Some(value), None)
}

/// A multi-valued property, as a one-line summary.
fn multi(ty: u16, raw: &[u8]) -> String {
    let count = to_usize(u32_le(raw, 0).unwrap_or(0).into());
    let base = ty & 0x0fff;
    if let Some(size) = ltp::fixed_size(base) {
        // Fixed-size elements are stored back to back, without a count.
        let size = to_usize(size).max(1);
        let n = raw.len().checked_div(size).unwrap_or(0);
        let shown: Vec<String> = raw
            .chunks_exact(size)
            .take(16)
            .map(|c| {
                scalar(0, base, c)
                    .0
                    .map_or_else(String::new, |v| crate::render::value(&v))
            })
            .collect();
        return format!("{n} values: {}", shown.join(", "));
    }
    let mut items = Vec::new();
    for i in 0..count.min(16) {
        let at = |k: usize| u32_le(raw, 4usize.saturating_add(k.saturating_mul(4)));
        let Some(start) = at(i) else { break };
        let end = if i.saturating_add(1) < count {
            at(i.saturating_add(1)).unwrap_or(0)
        } else {
            raw.len() as u32
        };
        let item = raw
            .get(to_usize(start.into())..to_usize(end.into()))
            .unwrap_or_default();
        items.push(match base {
            0x001e | 0x001f => format!("{:?}", text(base, item)),
            _ => format!("{} bytes", item.len()),
        });
    }
    format!("{count} values: {}", items.join(", "))
}

/// Reads a property's bytes (inline or from the heap or a subnode), up
/// to [`MAX_TEXT`].
pub async fn read_raw(cx: &Cx, raw: &Raw) -> Result<(Vec<u8>, Span)> {
    match *raw {
        Raw::Inline(v, span) => Ok((v.to_le_bytes().to_vec(), span)),
        Raw::Data(span) => Ok((cx.read_avail(span.sub(0, MAX_TEXT)).await?, span)),
    }
}
