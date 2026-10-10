//! AppleSingle and AppleDouble (`._name` files that macOS writes on
//! foreign file systems).
//!
//! A header lists entries by ID: data and resource forks, real name,
//! dates, Finder info, ... In AppleDouble files written by macOS, the
//! Finder info entry is followed by an `ATTR` block with extended
//! attributes, which is decoded too.

use crate::bytes::{to_u64, u16_be, u32_be};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::civil::EPOCH_2000;
use crate::formats::util::fmt::{fourcc, size};
use crate::formats::{Codec, Format, Input, Probe, content, embedded};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

const BE: Endian = Endian::Big;

pub static APPLESINGLE: Format = Format {
    name: "applesingle",
    title: "AppleSingle encoded file",
    extensions: &["as"],
    mime: "application/applefile",
    probe: Probe::Magic(&[(0, b"\x00\x05\x16\x00")]),
    dissect: crate::expander!(dissect: Input),
};

pub static APPLEDOUBLE: Format = Format {
    name: "appledouble",
    title: "AppleDouble header file",
    extensions: &[],
    mime: "multipart/appledouble",
    probe: Probe::Magic(&[(0, b"\x00\x05\x16\x07")]),
    dissect: crate::expander!(dissect: Input),
};

const ENTRY_IDS: EnumTable = &[
    (1, "Data fork"),
    (2, "Resource fork"),
    (3, "Real name"),
    (4, "Comment"),
    (5, "Icon (black and white)"),
    (6, "Icon (colour)"),
    (8, "File dates"),
    (9, "Finder info"),
    (10, "Macintosh file info"),
    (11, "ProDOS file info"),
    (12, "MS-DOS file info"),
    (13, "AFP short name"),
    (14, "AFP file info"),
    (15, "AFP directory ID"),
];

const FINDER_FLAGS: FlagTable = &[
    flag(0x0001, "isOnDesk"),
    flag(0x0040, "isShared"),
    flag(0x0080, "hasNoINITs"),
    flag(0x0100, "hasBeenInited"),
    flag(0x0400, "hasCustomIcon"),
    flag(0x0800, "isStationery"),
    flag(0x1000, "nameLocked"),
    flag(0x2000, "hasBundle"),
    flag(0x4000, "isInvisible"),
    flag(0x8000, "isAlias"),
];

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub_exact(0, 26)?).await?;
    let double = u32_be(&head, 0) == Some(0x0005_1607);
    let count = u16_be(&head, 24).unwrap_or(0);
    let header = file.sub(0, 26u64.saturating_add(u64::from(count).saturating_mul(12)));
    let block = cx.block(header).await?;
    let mut entries = Vec::new();
    {
        let mut f = Fields::emitting(&cx, &block, BE);
        f.u32("Magic").hex().emit()?;
        f.u32("Version").hex().emit()?;
        f.bytes("Filler", 16).emit()?;
        f.u16("Number of entries").emit()?;
        for _ in 0..count {
            let at = f.pos();
            let (Ok(id), Ok(offset), Ok(len)) = (f.u32("").get(), f.u32("").get(), f.u32("").get())
            else {
                break;
            };
            entries.push((header.sub(at, 12), id, offset, len));
        }
    }
    let mut name = None;
    for &(_, id, offset, len) in &entries {
        if id == 3 {
            let bytes = cx
                .read_avail(file.sub(offset.into(), u64::from(len).min(1024)))
                .await?;
            name = Some(String::from_utf8_lossy(&bytes).into_owned());
        }
    }
    let ids: Vec<String> = entries
        .iter()
        .map(|(_, id, _, _)| {
            lookup(ENTRY_IDS, (*id).into()).map_or_else(|| format!("#{id}"), |s| s.to_lowercase())
        })
        .collect();
    let mut summary = format!(
        "{}, {}",
        if double { "AppleDouble" } else { "AppleSingle" },
        ids.join(", ")
    );
    if let Some(n) = name {
        summary = format!("{summary}, {n:?}");
    }
    cx.annotate(summary);
    cx.set_count(Count::Exact(to_u64(entries.len()).saturating_add(4)));
    for (desc, id, offset, len) in entries {
        let span = file.sub(offset.into(), len.into());
        let label =
            lookup(ENTRY_IDS, id.into()).map_or_else(|| format!("Entry {id}"), str::to_owned);
        let mut node = match id {
            1 | 2 => content(label, input, span, Codec::Stored, None),
            _ => Node::new(label)
                .span(span)
                .lazy(entry, (input, desc, span, id)),
        };
        node = node.summary(format!("{} bytes", len)).target(desc);
        if span.len < u64::from(len) {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, len.into()),
                span.len,
            ));
        }
        cx.push(node).await;
    }
    Ok(())
}

fn date(v: i32) -> Value {
    Value::Timestamp {
        unix_seconds: i64::from(v).saturating_add(EPOCH_2000),
    }
}

async fn entry(cx: Cx, (input, desc, span, id): (Input, Span, Span, u32)) -> Result<()> {
    let header = cx.block(desc).await?;
    {
        let mut f = Fields::emitting(&cx, &header, BE);
        f.u32("Entry ID").emit()?;
        f.u32("Offset").hex().emit()?;
        f.u32("Length").emit()?;
    }
    let block = cx.block(span.sub(0, 0x10000)).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    match id {
        3 | 4 | 13 => {
            let n = f.remaining();
            f.ascii("Text", n).emit()?;
        }
        8 => {
            for name in ["Created", "Modified", "Backed up", "Accessed"] {
                f.int::<i32>(name).with(|&v, n| n.value(date(v))).emit()?;
            }
        }
        9 => {
            f.bytes("File type", 4)
                .with(|b, n| n.value(Value::Text(fourcc(b))))
                .emit()?;
            f.bytes("Creator", 4)
                .with(|b, n| n.value(Value::Text(fourcc(b))))
                .emit()?;
            f.u16("Finder flags").flags(FINDER_FLAGS).emit()?;
            f.int::<i16>("Location v").emit()?;
            f.int::<i16>("Location h").emit()?;
            f.u16("Folder").emit()?;
            f.bytes("Extended Finder info", 16).emit()?;
            if span.len > 34 {
                let data = cx.read_avail(span.sub(32, 0x10000)).await?;
                if data.get(2..6) == Some(b"ATTR") {
                    cx.emit(
                        Node::new("Extended attributes")
                            .span(span.tail(32))
                            .lazy(attributes, (input, span.tail(32))),
                    );
                }
            }
        }
        10 => {
            f.int::<i32>("Created")
                .with(|&v, n| n.value(date(v)))
                .emit()?;
            f.int::<i32>("Modified")
                .with(|&v, n| n.value(date(v)))
                .emit()?;
            f.int::<i32>("Backed up")
                .with(|&v, n| n.value(date(v)))
                .emit()?;
            f.u32("Attributes").hex().emit()?;
        }
        12 => {
            f.u16("Modification date (DOS)").hex().emit()?;
            f.u16("Modification time (DOS)").hex().emit()?;
            f.u16("Attributes").hex().emit()?;
        }
        _ => {
            let n = f.remaining();
            f.node(Node::new("Data").span(span).summary(format!("{n} bytes")));
        }
    }
    Ok(())
}

/// The `ATTR` header after the Finder info (offsets relative to the file).
async fn attributes(cx: Cx, (input, at): (Input, Span)) -> Result<()> {
    let file = input.span;
    let block = cx.block(at.sub(0, 38)).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.u16("Padding").emit()?;
    f.ascii("Magic", 4).emit()?;
    f.u32("Debug tag").hex().emit()?;
    f.u32("Total size").emit()?;
    f.u32("Data start").hex().emit()?;
    f.u32("Data length").emit()?;
    f.bytes("Reserved", 12).emit()?;
    f.u16("Flags").hex().emit()?;
    let count = f.u16("Number of attributes").emit()?;
    let mut pos = 38u64;
    for _ in 0..count {
        let head = cx.read(at.sub_exact(pos, 11)?).await?;
        let offset = u32_be(&head, 0).unwrap_or(0);
        let len = u32_be(&head, 4).unwrap_or(0);
        let name_len = u64::from(head.get(10).copied().unwrap_or(0));
        let name = crate::text::until_nul(
            &cx.read(at.sub_exact(pos.saturating_add(11), name_len)?)
                .await?,
        );
        let entry_len = 11u64
            .saturating_add(name_len)
            .checked_next_multiple_of(4)
            .unwrap_or(u64::MAX);
        let value = file.sub(offset.into(), len.into());
        let preview = cx.read_avail(value.sub(0, 64)).await?;
        let mut node = Node::new(name.clone())
            .span(at.sub(pos, entry_len))
            .target(value)
            .summary(size(len.into()));
        node = if preview.starts_with(b"bplist00") {
            embedded(name, input.nested(value)).summary(size(len.into()))
        } else if crate::text::looks_like_text(&preview) {
            node.value(Value::Text(String::from_utf8_lossy(&preview).into_owned()))
        } else {
            node.value(Value::Bytes(preview.get(..32).unwrap_or(&preview).to_vec()))
        };
        cx.push(node).await;
        pos = pos.saturating_add(entry_len);
    }
    Ok(())
}
