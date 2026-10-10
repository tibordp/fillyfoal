//! MATLAB Level 5 MAT-files: a 128-byte header, then tagged data elements.
//! Arrays (`miMATRIX`) nest; `miCOMPRESSED` elements are inflated on demand.

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::binutil::get;
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Radix, Value, flag, lookup};

/// Arrays nested inside cells and structs.
const MAX_DEPTH: u32 = 32;

pub static FORMAT: Format = Format {
    name: "mat",
    title: "MATLAB MAT-file (Level 5)",
    extensions: &["mat"],
    mime: "application/x-matlab-data",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    h.starts_with(b"MATLAB 5.0 MAT-file")
        || (h.starts_with(b"MATLAB ") && matches!(h.data.get(126..128), Some(b"IM" | b"MI")))
            && !h.starts_with(b"MATLAB 7.3")
}

const TYPES: EnumTable = &[
    (1, "miINT8"),
    (2, "miUINT8"),
    (3, "miINT16"),
    (4, "miUINT16"),
    (5, "miINT32"),
    (6, "miUINT32"),
    (7, "miSINGLE"),
    (9, "miDOUBLE"),
    (12, "miINT64"),
    (13, "miUINT64"),
    (14, "miMATRIX"),
    (15, "miCOMPRESSED"),
    (16, "miUTF8"),
    (17, "miUTF16"),
    (18, "miUTF32"),
];

const CLASSES: EnumTable = &[
    (1, "cell"),
    (2, "struct"),
    (3, "object"),
    (4, "char"),
    (5, "sparse"),
    (6, "double"),
    (7, "single"),
    (8, "int8"),
    (9, "uint8"),
    (10, "int16"),
    (11, "uint16"),
    (12, "int32"),
    (13, "uint32"),
    (14, "int64"),
    (15, "uint64"),
    (16, "function"),
    (17, "opaque"),
];

const ARRAY_FLAGS: FlagTable = &[
    flag(0x08, "complex"),
    flag(0x04, "global"),
    flag(0x02, "logical"),
];

#[derive(Clone, Copy)]
struct Level {
    input: Input,
    span: Span,
    endian: Endian,
    depth: u32,
    /// Inside a miMATRIX: sub-elements are named by position.
    matrix: Option<u8>,
}

/// An element tag: type, size, header length, and whether it is the small
/// (4-byte data) form.
fn tag(data: &[u8], endian: Endian) -> Option<(u32, u64, u64)> {
    let first = get::<u32>(data, 0, endian)?;
    if first >> 16 != 0 {
        // Small data element: size in the upper half, data in the next 4.
        return Some((first & 0xffff, u64::from(first >> 16), 4));
    }
    Some((first, u64::from(get::<u32>(data, 4, endian)?), 8))
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 128)).await?;
    let text = String::from_utf8_lossy(head.get(..116).unwrap_or_default())
        .trim_end_matches(['\0', ' '])
        .to_owned();
    let endian = if head.get(126..128) == Some(b"MI") {
        Endian::Big
    } else {
        Endian::Little
    };
    cx.emit(
        Node::new("Description")
            .span(file.sub(0, 116))
            .value(Value::Text(text.clone())),
    );
    cx.emit(
        Node::new("Subsystem data offset")
            .span(file.sub(116, 8))
            .value(Value::Bytes(
                head.get(116..124).unwrap_or_default().to_vec(),
            )),
    );
    let version = head.get(124..126).map_or(0, |v| match endian {
        Endian::Little => u16::from_le_bytes([
            v.first().copied().unwrap_or(0),
            v.get(1).copied().unwrap_or(0),
        ]),
        Endian::Big => u16::from_be_bytes([
            v.first().copied().unwrap_or(0),
            v.get(1).copied().unwrap_or(0),
        ]),
    });
    cx.emit(
        Node::new("Version")
            .span(file.sub(124, 2))
            .value(Value::UInt {
                value: version.into(),
                bits: 16,
                radix: Radix::Hex,
            }),
    );
    cx.emit(
        Node::new("Endian indicator")
            .span(file.sub(126, 2))
            .value(Value::Text(
                String::from_utf8_lossy(head.get(126..128).unwrap_or_default()).into_owned(),
            ))
            .summary(if endian == Endian::Little {
                "little-endian"
            } else {
                "big-endian"
            }),
    );
    cx.annotate(text.split(',').next().unwrap_or("MAT-file").to_owned());
    elements(
        cx,
        Level {
            input,
            span: file.tail(128),
            endian,
            depth: 0,
            matrix: None,
        },
    )
    .await
}

/// Names of a matrix's sub-elements, by class and position.
fn matrix_part(class: u8, index: usize) -> &'static str {
    match (class, index) {
        (_, 0) => "Array flags",
        (_, 1) => "Dimensions",
        (_, 2) => "Array name",
        (1, _) => "Cell",
        (2, 3) => "Field name length",
        (2, 4) => "Field names",
        (2, _) => "Field",
        (3, 3) => "Class name",
        (3, 4) => "Field name length",
        (3, 5) => "Field names",
        (3, _) => "Field",
        (5, 3) => "Row indices (ir)",
        (5, 4) => "Column indices (jc)",
        (5, 5) => "Real part",
        (5, _) => "Imaginary part",
        (_, 3) => "Real part",
        _ => "Imaginary part",
    }
}

async fn elements(cx: Cx, level: Level) -> Result<()> {
    let mut pos = 0u64;
    let mut index = 0usize;
    let class = level.matrix.unwrap_or(0);
    while pos < level.span.len {
        let head = cx.read_avail(level.span.sub(pos, 8)).await?;
        let Some((kind, size, header)) = tag(&head, level.endian) else {
            cx.push(Node::new("Trailing data").span(level.span.tail(pos)))
                .await;
            break;
        };
        let padded = if header == 4 {
            4
        } else {
            size.checked_next_multiple_of(8).unwrap_or(u64::MAX)
        };
        let whole = level.span.sub(pos, header.saturating_add(padded));
        let data = level.span.sub(pos.saturating_add(header), size);
        let name = match level.matrix {
            Some(_) => matrix_part(class, index).to_owned(),
            None => lookup(TYPES, kind.into())
                .map_or_else(|| format!("Element type {kind}"), str::to_owned),
        };
        let mut node = Node::new(name).span(whole);
        if data.len < size {
            node = node.diag(Diagnostic::truncated(
                Span::new(data.source, data.offset, size),
                data.len,
            ));
        }
        node = element(&cx, &level, node, kind, data).await?;
        cx.progress_in(level.span, whole.end());
        cx.push(node).await;
        pos = pos
            .saturating_add(header.saturating_add(padded))
            .max(pos.saturating_add(1));
        index = index.saturating_add(1);
    }
    Ok(())
}

fn type_size(kind: u32) -> usize {
    match kind {
        1 | 2 | 16 => 1,
        3 | 4 | 17 => 2,
        5 | 6 | 7 | 18 => 4,
        _ => 8,
    }
}

fn number(kind: u32, c: &[u8], endian: Endian) -> String {
    macro_rules! num {
        ($t:ty) => {{
            let Ok(b) = <[u8; std::mem::size_of::<$t>()]>::try_from(c) else {
                return String::new();
            };
            match endian {
                Endian::Little => <$t>::from_le_bytes(b).to_string(),
                Endian::Big => <$t>::from_be_bytes(b).to_string(),
            }
        }};
    }
    match kind {
        1 => num!(i8),
        2 => num!(u8),
        3 => num!(i16),
        4 => num!(u16),
        5 => num!(i32),
        6 => num!(u32),
        7 => num!(f32),
        9 => num!(f64),
        12 => num!(i64),
        _ => num!(u64),
    }
}

async fn element(cx: &Cx, level: &Level, node: Node, kind: u32, data: Span) -> Result<Node> {
    let typed = node.summary(format!(
        "{}, {} bytes",
        lookup(TYPES, kind.into()).unwrap_or("unknown type"),
        data.len
    ));
    match kind {
        14 => {
            let head = cx.read_avail(data.sub(0, 256)).await?;
            let (summary, class) = matrix_summary(&head, level.endian);
            let node = typed.summary(summary);
            if level.depth >= MAX_DEPTH {
                return Ok(node.diag(Diagnostic::limit("arrays nested too deeply")));
            }
            Ok(node.lazy(
                crate::expander!(self::elements: Level),
                Level {
                    span: data,
                    depth: level.depth.saturating_add(1),
                    matrix: Some(class),
                    ..*level
                },
            ))
        }
        15 => {
            if level.depth >= MAX_DEPTH {
                return Ok(typed.diag(Diagnostic::limit("compressed elements nested too deeply")));
            }
            Ok(typed.lazy(
                crate::expander!(self::inflate: Level),
                Level {
                    span: data,
                    ..*level
                },
            ))
        }
        16..=18 => {
            let text = cx.read_avail(data.sub(0, 4096)).await?;
            let text = match kind {
                16 => String::from_utf8_lossy(&text).into_owned(),
                17 => crate::text::utf16(&text, level.endian),
                _ => text
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .filter_map(|c| get::<u32>(c, 0, level.endian).and_then(char::from_u32))
                    .collect(),
            };
            Ok(typed.value(Value::Text(text)))
        }
        6 if typed.name == "Array flags" => {
            let raw = cx.read_avail(data.sub(0, 4)).await?;
            let flags = get::<u32>(&raw, 0, level.endian).unwrap_or(0);
            let class = flags & 0xff;
            let (set, _) = crate::value::decode_flags(ARRAY_FLAGS, u64::from(flags >> 8 & 0xff));
            let node = typed.value(Value::Enum {
                raw: class.into(),
                bits: 8,
                name: lookup(CLASSES, class.into()),
            });
            Ok(if set.is_empty() {
                node
            } else {
                node.summary(set.join(", "))
            })
        }
        1 | 2 if level.matrix.is_some() => {
            // Names: NUL-padded fixed-length strings.
            let text = cx.read_avail(data.sub(0, 4096)).await?;
            let names: Vec<String> = text
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect();
            Ok(typed.value(Value::Text(names.join(", "))))
        }
        _ => {
            let size = type_size(kind);
            let bytes = cx
                .read_avail(data.sub(0, to_u64(size.saturating_mul(16))))
                .await?;
            let shown: Vec<String> = bytes
                .chunks_exact(size.max(1))
                .map(|c| number(kind, c, level.endian))
                .collect();
            let count = data.len.checked_div(to_u64(size)).unwrap_or(0);
            let more = if count > 16 { " …" } else { "" };
            Ok(typed.value(Value::Text(format!("[{}{more}]", shown.join(", ")))))
        }
    }
}

/// `double [3×4] "x"` from the start of a matrix's content.
fn matrix_summary(data: &[u8], endian: Endian) -> (String, u8) {
    let mut parts = Vec::new();
    let mut at = 0usize;
    let mut class = 0u8;
    let mut flags = 0u32;
    for i in 0..3 {
        let Some((kind, size, header)) = tag(data.get(at..).unwrap_or_default(), endian) else {
            break;
        };
        let start = at.saturating_add(to_usize(header));
        let body = data
            .get(start..start.saturating_add(to_usize(size)))
            .unwrap_or_default();
        match i {
            0 => {
                flags = get::<u32>(body, 0, endian).unwrap_or(0);
                class = (flags & 0xff) as u8;
            }
            1 => {
                let dims: Vec<String> = body
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .filter_map(|c| get::<u32>(c, 0, endian).map(|d| d.to_string()))
                    .collect();
                parts.push(format!("[{}]", dims.join("×")));
            }
            _ => {
                if kind == 1 || kind == 2 {
                    parts.push(format!("{:?}", String::from_utf8_lossy(body)));
                }
            }
        }
        let padded = if header == 4 {
            4
        } else {
            size.checked_next_multiple_of(8).unwrap_or(u64::MAX)
        };
        at = at.saturating_add(to_usize(header.saturating_add(padded)));
    }
    let (set, _) = crate::value::decode_flags(ARRAY_FLAGS, u64::from(flags >> 8 & 0xff));
    let mut out = lookup(CLASSES, class.into())
        .unwrap_or("unknown class")
        .to_owned();
    for f in set {
        out = format!("{f} {out}");
    }
    (format!("{out} {}", parts.join(" ")), class)
}

async fn inflate(cx: Cx, level: Level) -> Result<()> {
    let decoded = crate::codec::inflate_span(&cx, level.span, true, None).await?;
    cx.annotate(format!("{:#x} bytes decompressed", decoded.span.len));
    if let Some(e) = decoded.error {
        cx.diag(e);
    }
    elements(
        cx,
        Level {
            input: level.input.nested(decoded.span),
            span: decoded.span,
            depth: level.depth.saturating_add(1),
            matrix: None,
            endian: level.endian,
        },
    )
    .await
}
