//! Minecraft NBT (named binary tag) data.

use crate::bytes::{u16_be, u32_be};
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::formats::util::val::text;
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

// ---------------------------------------------------------------------------
// Minecraft NBT (uncompressed; gzipped NBT reaches here through gzip)

fn nbt_probe(h: &Head<'_>) -> bool {
    let Some(len) = u16_be(h.data, 1) else {
        return false;
    };
    let len = usize::from(len);
    h.data.first() == Some(&10)
        && len <= 64
        && h.data
            .get(3..3usize.saturating_add(len))
            .is_some_and(|n| n.iter().all(|b| b.is_ascii_graphic() || *b == b' '))
        && h.data
            .get(3usize.saturating_add(len))
            .is_some_and(|&t| (1..=12).contains(&t))
}

declare_format!(pub NBT = "nbt", "Minecraft NBT", ["nbt", "dat", "schematic", "schem", "litematic"], "application/x-minecraft-nbt",
    Probe::Custom(nbt_probe), nbt);

const NBT_TYPES: &[&str] = &[
    "End",
    "Byte",
    "Short",
    "Int",
    "Long",
    "Float",
    "Double",
    "Byte array",
    "String",
    "List",
    "Compound",
    "Int array",
    "Long array",
];

fn nbt_type(t: u8) -> &'static str {
    NBT_TYPES.get(usize::from(t)).copied().unwrap_or("?")
}

async fn read_exact(cx: &Cx, region: Span, at: u64, n: u64) -> Result<Vec<u8>> {
    cx.read(region.sub_exact(at, n)?).await
}

async fn be_int(cx: &Cx, region: Span, at: u64, n: u64) -> Result<u64> {
    let b = read_exact(cx, region, at, n).await?;
    Ok(b.iter()
        .fold(0u64, |acc, &x| acc.wrapping_shl(8) | u64::from(x)))
}

/// Length of a payload of type `t` at `pos` (iterative, so hostile nesting
/// cannot overflow the stack).
async fn nbt_skip(cx: &Cx, region: Span, start: u64, t: u8) -> Result<u64> {
    enum Frame {
        Compound,
        List(u8, u64),
    }
    let mut pos = start;
    let mut stack: Vec<Frame> = Vec::new();
    let mut pending = Some(t);
    loop {
        if let Some(t) = pending.take() {
            let fixed = |t: u8| match t {
                1 => Some(1u64),
                2 => Some(2),
                3 | 5 => Some(4),
                4 | 6 => Some(8),
                _ => None,
            };
            if let Some(n) = fixed(t) {
                pos = pos.saturating_add(n);
            } else {
                match t {
                    7 | 11 | 12 => {
                        let n = be_int(cx, region, pos, 4).await? & 0x7fff_ffff;
                        let unit = match t {
                            7 => 1,
                            11 => 4,
                            _ => 8,
                        };
                        pos = pos.saturating_add(4).saturating_add(n.saturating_mul(unit));
                    }
                    8 => {
                        let n = be_int(cx, region, pos, 2).await?;
                        pos = pos.saturating_add(2).saturating_add(n);
                    }
                    9 => {
                        let et = u8::try_from(be_int(cx, region, pos, 1).await?).unwrap_or(0);
                        let n = be_int(cx, region, pos.saturating_add(1), 4).await? & 0x7fff_ffff;
                        pos = pos.saturating_add(5);
                        if let Some(size) = fixed(et) {
                            pos = pos.saturating_add(n.saturating_mul(size));
                        } else if n > 0 {
                            stack.push(Frame::List(et, n));
                        }
                    }
                    10 => stack.push(Frame::Compound),
                    _ => {
                        return Err(Diagnostic::malformed(format!("unknown tag type {t}"))
                            .at(region.sub(pos, 1)));
                    }
                }
            }
            if pos > region.len {
                return Err(Diagnostic::malformed("tag runs past the end of the data")
                    .at(region.sub(start, 1)));
            }
        }
        if stack.len() > 512 {
            return Err(Diagnostic::limit("NBT nested deeper than 512").at(region.sub(start, 1)));
        }
        match stack.last_mut() {
            None => return Ok(pos.saturating_sub(start)),
            Some(Frame::List(et, n)) => {
                if *n == 0 {
                    stack.pop();
                } else {
                    *n = n.saturating_sub(1);
                    pending = Some(*et);
                }
            }
            Some(Frame::Compound) => {
                let t = u8::try_from(be_int(cx, region, pos, 1).await?).unwrap_or(0);
                pos = pos.saturating_add(1);
                if t == 0 {
                    stack.pop();
                } else {
                    let n = be_int(cx, region, pos, 2).await?;
                    pos = pos.saturating_add(2).saturating_add(n);
                    pending = Some(t);
                }
            }
        }
    }
}

/// A node for a payload of type `t` occupying `span` (within `region`).
async fn nbt_value(
    cx: &Cx,
    region: Span,
    name: String,
    header: u64,
    at: u64,
    t: u8,
) -> Result<Node> {
    let len = nbt_skip(cx, region, at, t).await?;
    let span = region.sub(at.saturating_sub(header), len.saturating_add(header));
    let payload = region.sub(at, len);
    let node = Node::new(name).span(span);
    let b = cx.read(payload.sub(0, 8)).await?;
    let int = |n: usize| -> i64 {
        let v = b
            .get(..n)
            .unwrap_or_default()
            .iter()
            .fold(0u64, |acc, &x| acc.wrapping_shl(8) | u64::from(x));
        let shift = 64u32.saturating_sub(u32::try_from(n).unwrap_or(0).saturating_mul(8));
        i64::from_ne_bytes(v.wrapping_shl(shift).to_ne_bytes()).wrapping_shr(shift)
    };
    Ok(match t {
        1 => node.value(Value::Int {
            value: int(1),
            bits: 8,
        }),
        2 => node.value(Value::Int {
            value: int(2),
            bits: 16,
        }),
        3 => node.value(Value::Int {
            value: int(4),
            bits: 32,
        }),
        4 => node.value(Value::Int {
            value: int(8),
            bits: 64,
        }),
        5 => node.value(Value::Float(
            f32::from_bits(u32_be(&b, 0).unwrap_or(0)).into(),
        )),
        6 => node.value(Value::Float(f64::from_bits(u64::from_be_bytes(
            b.get(..8).and_then(|s| s.try_into().ok()).unwrap_or([0; 8]),
        )))),
        8 => {
            let s = cx.read(payload.tail(2).sub(0, 256)).await?;
            node.value(text(String::from_utf8_lossy(&s).into_owned()))
        }
        7 | 11 | 12 => node.summary(format!("{} × {}", nbt_type(t), int(4))),
        9 => node
            .summary(format!(
                "List of {} {}",
                u32_be(&b, 1).unwrap_or(0) & 0x7fff_ffff,
                nbt_type(b.first().copied().unwrap_or(0))
            ))
            .lazy(
                crate::expander!(nbt_list: (Span, u8)),
                (payload, b.first().copied().unwrap_or(0)),
            ),
        10 => node.lazy(crate::expander!(nbt_compound: Span), payload),
        _ => node,
    })
}

async fn nbt_compound(cx: Cx, region: Span) -> Result<()> {
    let mut pos = 0u64;
    loop {
        let t = u8::try_from(be_int(&cx, region, pos, 1).await?).unwrap_or(0);
        if t == 0 {
            break;
        }
        let n = be_int(&cx, region, pos.saturating_add(1), 2).await?;
        let name =
            String::from_utf8_lossy(&read_exact(&cx, region, pos.saturating_add(3), n).await?)
                .into_owned();
        let at = pos.saturating_add(3).saturating_add(n);
        let node = nbt_value(&cx, region, name, at.saturating_sub(pos), at, t).await?;
        let end = node
            .span
            .map_or(at, |s| s.end().saturating_sub(region.offset));
        cx.push(node).await;
        pos = end.max(at);
    }
    Ok(())
}

async fn nbt_list(cx: Cx, (region, et): (Span, u8)) -> Result<()> {
    let n = be_int(&cx, region, 1, 4).await? & 0x7fff_ffff;
    let mut pos = 5u64;
    for i in 0..n {
        let node = nbt_value(&cx, region, format!("[{i}]"), 0, pos, et).await?;
        let end = node
            .span
            .map_or(pos, |s| s.end().saturating_sub(region.offset));
        cx.push(node).await;
        if end <= pos {
            break;
        }
        pos = end;
    }
    Ok(())
}

async fn nbt(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let n = be_int(&cx, file, 1, 2).await?;
    let name = String::from_utf8_lossy(&read_exact(&cx, file, 3, n).await?).into_owned();
    let at = 3u64.saturating_add(n);
    let len = nbt_skip(&cx, file, at, 10).await?;
    let payload = file.sub(at, len);
    cx.annotate(format!("NBT compound {name:?}, {len} bytes"));
    nbt_compound(cx, payload).await
}
