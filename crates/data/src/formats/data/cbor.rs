//! CBOR (RFC 8949) data marked with the self-describe tag 55799
//! (`d9 d9 f7`), the only way CBOR announces itself.
//!
//! Every item starts with a head: major type (3 bits), additional
//! information (5 bits) and an optional argument. Containers record their
//! member count (or are indefinite and end with a break byte), but not their
//! byte length, so finding the end of an item means scanning it. Members are
//! decoded only when a container is expanded.

use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::datakit::{ByteReader, hex};
use crate::formats::util::floats::f16;
use crate::formats::util::fmt::clip;
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

const MAX_DEPTH: usize = 256;
const MAX_TEXT: u64 = 0x1000;
/// Remaining-member marker for indefinite-length containers.
const INDEFINITE: u64 = u64::MAX;

pub static FORMAT: Format = Format {
    name: "cbor",
    title: "CBOR data (self-described)",
    extensions: &["cbor"],
    mime: "application/cbor",
    probe: Probe::Magic(&[(0, b"\xd9\xd9\xf7")]),
    dissect: crate::expander!(dissect: Input),
};

const TAGS: EnumTable = &[
    (0, "date/time string"),
    (1, "epoch date/time"),
    (2, "unsigned bignum"),
    (3, "negative bignum"),
    (4, "decimal fraction"),
    (5, "bigfloat"),
    (16, "COSE_Encrypt0"),
    (17, "COSE_Mac0"),
    (18, "COSE_Sign1"),
    (21, "expected base64url"),
    (22, "expected base64"),
    (23, "expected base16"),
    (24, "encoded CBOR data item"),
    (32, "URI"),
    (33, "base64url"),
    (34, "base64"),
    (35, "regular expression"),
    (36, "MIME message"),
    (37, "binary UUID"),
    (61, "CBOR Web Token"),
    (96, "COSE_Encrypt"),
    (97, "COSE_Mac"),
    (98, "COSE_Sign"),
    (100, "days since epoch"),
    (258, "set"),
    (259, "map with object keys"),
    (1004, "full date string"),
    (55799, "self-described CBOR"),
    (55800, "CBOR sequence"),
];

#[derive(Clone, Copy, Debug)]
struct Head {
    major: u8,
    info: u8,
    arg: u64,
    len: u64,
    indefinite: bool,
}

async fn head(r: &mut ByteReader<'_>, at: u64) -> Result<Head> {
    let ib = r.byte(at).await?;
    let (major, info) = (ib >> 5, ib & 0x1f);
    let (arg, len, indefinite) = match info {
        0..=23 => (u64::from(info), 1, false),
        24..=27 => {
            let size = 1u64 << (info.saturating_sub(24));
            (
                r.be(at.saturating_add(1), size).await?,
                size.saturating_add(1),
                false,
            )
        }
        31 if matches!(major, 2..=5 | 7) => (0, 1, true),
        _ => {
            return Err(Diagnostic::malformed(format!(
                "reserved additional information {info} in {ib:#04x}"
            ))
            .at(r.span(at, 1)));
        }
    };
    if major == 7 && indefinite {
        return Err(Diagnostic::malformed("unexpected break").at(r.span(at, 1)));
    }
    Ok(Head {
        major,
        info,
        arg,
        len,
        indefinite,
    })
}

/// The end of the item starting at `at` (scanning nested items).
async fn end_of(r: &mut ByteReader<'_>, at: u64) -> Result<u64> {
    let mut stack: Vec<u64> = vec![1];
    let mut pos = at;
    loop {
        while stack.last() == Some(&0) {
            stack.pop();
        }
        let Some(top) = stack.last_mut() else {
            return Ok(pos);
        };
        r.cx().checkpoint().await;
        if *top == INDEFINITE && r.byte(pos).await? == 0xff {
            stack.pop();
            pos = pos.saturating_add(1);
            continue;
        }
        if *top != INDEFINITE {
            *top = top.saturating_sub(1);
        }
        let h = head(r, pos).await?;
        pos = pos.saturating_add(h.len);
        let nested = match (h.major, h.indefinite) {
            (2..=5, true) => INDEFINITE,
            (2 | 3, false) => {
                pos = pos.saturating_add(h.arg);
                if pos > r.region().len {
                    return Err(Diagnostic::truncated(
                        r.span(pos.saturating_sub(h.arg), h.arg),
                        r.region().len.saturating_sub(pos.saturating_sub(h.arg)),
                    ));
                }
                0
            }
            (4, false) => h.arg,
            (5, false) => h.arg.saturating_mul(2),
            (6, _) => 1,
            _ => 0,
        };
        if nested > 0 {
            if stack.len() >= MAX_DEPTH {
                return Err(
                    Diagnostic::limit(format!("items nested deeper than {MAX_DEPTH}"))
                        .at(r.span(pos, 1)),
                );
            }
            stack.push(nested);
        }
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let mut r = ByteReader::new(&cx, input.span);
    let mut pos = 0u64;
    let mut index = 0u64;
    while pos < input.span.len {
        let end = end_of(&mut r, pos).await?;
        let mut node = item_node(&mut r, pos, end, format!("Item {index}")).await?;
        if index == 0 {
            // Describe what the self-describe tag wraps.
            let mut h = head(&mut r, pos).await?;
            if h.major == 6 && h.arg == 55799 {
                h = head(&mut r, pos.saturating_add(h.len)).await?;
            }
            cx.annotate(format!("CBOR, top-level {}", describe(&h)));
            node = node.desc("First item of the CBOR sequence");
        }
        cx.progress(end, input.span.len);
        cx.push(node).await;
        pos = end;
        index = index.saturating_add(1);
    }
    Ok(())
}

fn describe(h: &Head) -> String {
    let count = |what: &str| {
        if h.indefinite {
            format!("{what} (indefinite)")
        } else {
            format!("{what} ({})", h.arg)
        }
    };
    match h.major {
        0 | 1 => "integer".to_owned(),
        2 => "byte string".to_owned(),
        3 => "text string".to_owned(),
        4 => count("array"),
        5 => count("map"),
        6 => format!("tag {}", h.arg),
        _ => "simple value".to_owned(),
    }
}

/// A node for the item at `start..end`.
async fn item_node(r: &mut ByteReader<'_>, start: u64, end: u64, name: String) -> Result<Node> {
    let h = head(r, start).await?;
    let span = r.span(start, end.saturating_sub(start));
    let node = Node::new(name).span(span);
    let body = start.saturating_add(h.len);
    let walk = (r.region(), start);
    Ok(match (h.major, h.indefinite) {
        (0, _) => node.value(Value::UInt {
            value: h.arg,
            bits: 64,
            radix: crate::value::Radix::Dec,
        }),
        (1, _) => match i64::try_from(h.arg) {
            Ok(v) => node.value(Value::Int {
                value: v.saturating_neg().saturating_sub(1),
                bits: 64,
            }),
            Err(_) => node.value(Value::Text(format!("-1 - {}", h.arg))),
        },
        (2, false) => {
            let data = r.bytes(body, h.arg.min(32)).await?;
            node.value(Value::Bytes(data))
                .summary(format!("byte string, {} bytes", h.arg))
        }
        (3, false) => {
            let data = r.bytes(body, h.arg.min(MAX_TEXT)).await?;
            let text = String::from_utf8_lossy(&data).into_owned();
            let node = node.value(Value::Text(text));
            if h.arg > MAX_TEXT {
                node.summary(format!("text, {} bytes (truncated)", h.arg))
            } else {
                node
            }
        }
        (2 | 3, true) => node
            .summary(format!(
                "indefinite {} string",
                if h.major == 2 { "byte" } else { "text" }
            ))
            .lazy(crate::expander!(self::members: (Span, u64)), walk),
        (4, _) => node
            .summary(if h.indefinite {
                "array (indefinite)".to_owned()
            } else {
                format!("array ({})", h.arg)
            })
            .lazy(crate::expander!(self::members: (Span, u64)), walk),
        (5, _) => node
            .summary(if h.indefinite {
                "map (indefinite)".to_owned()
            } else {
                format!("map ({})", h.arg)
            })
            .lazy(crate::expander!(self::members: (Span, u64)), walk),
        (6, _) => {
            let name = lookup(TAGS, h.arg);
            let mut node = node.value(Value::Enum {
                raw: h.arg,
                bits: 64,
                name,
            });
            // Epoch times are shown directly.
            if h.arg == 1 {
                let inner = head(r, body).await?;
                if inner.major == 0 {
                    node = node.summary(crate::render::value(&Value::Timestamp {
                        unix_seconds: i64::try_from(inner.arg).unwrap_or(i64::MAX),
                    }));
                }
            }
            node.lazy(crate::expander!(self::members: (Span, u64)), walk)
        }
        (7, _) => match h.info {
            20 => node.value(Value::Bool(false)),
            21 => node.value(Value::Bool(true)),
            22 => node.value(Value::Text("null".into())),
            23 => node.value(Value::Text("undefined".into())),
            25 => node.value(Value::Float(f16(u16::try_from(h.arg).unwrap_or(0)))),
            26 => node.value(Value::Float(f64::from(f32::from_bits(
                u32::try_from(h.arg).unwrap_or(0),
            )))),
            27 => node.value(Value::Float(f64::from_bits(h.arg))),
            _ => node.value(hex(h.arg, 8)).summary("simple value"),
        },
        _ => node.diag(Diagnostic::malformed("unknown major type")),
    })
}

/// Short text for a map key.
async fn key_name(r: &mut ByteReader<'_>, at: u64) -> Result<String> {
    let h = head(r, at).await?;
    Ok(match (h.major, h.indefinite) {
        (0, _) => h.arg.to_string(),
        (1, _) => format!("-{}", h.arg.saturating_add(1)),
        (3, false) => {
            let data = r.bytes(at.saturating_add(h.len), h.arg.min(80)).await?;
            clip(&String::from_utf8_lossy(&data), 80)
        }
        _ => String::new(),
    })
}

async fn members(cx: Cx, (region, start): (Span, u64)) -> Result<()> {
    let mut r = ByteReader::new(&cx, region);
    let h = head(&mut r, start).await?;
    let (count, pairs) = match (h.major, h.indefinite) {
        (_, true) => (INDEFINITE, h.major == 5),
        (4, false) => (h.arg, false),
        (5, false) => (h.arg, true),
        (6, _) => (1, false),
        _ => (0, false),
    };
    if count != INDEFINITE {
        cx.set_count(Count::Exact(count));
    }
    let mut pos = start.saturating_add(h.len);
    let mut index = 0u64;
    while index < count {
        if count == INDEFINITE && r.byte(pos).await? == 0xff {
            break;
        }
        let node = if pairs {
            let key_end = end_of(&mut r, pos).await?;
            let value_end = end_of(&mut r, key_end).await?;
            let key = key_name(&mut r, pos).await?;
            let name = if key.is_empty() {
                format!("key #{index}")
            } else {
                key
            };
            let node = item_node(&mut r, key_end, value_end, name).await?;
            pos = value_end;
            node
        } else {
            let end = end_of(&mut r, pos).await?;
            let name = if h.major == 6 {
                "Content".to_owned()
            } else {
                format!("[{index}]")
            };
            let node = item_node(&mut r, pos, end, name).await?;
            pos = end;
            node
        };
        cx.push(node).await;
        index = index.saturating_add(1);
    }
    Ok(())
}
