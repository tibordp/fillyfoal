//! Linux ROM filesystem (romfs): a read-only tree of 16-byte-aligned file
//! headers, each linking to the next entry of its directory.

use std::collections::HashSet;
use std::sync::Arc;

use crate::bytes::u32_be;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::{align, content_node, size};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value};

const BE: Endian = Endian::Big;
/// Entries per directory and nesting followed.
const MAX_ENTRIES: usize = 1 << 16;
const MAX_DEPTH: usize = 64;

pub static FORMAT: Format = Format {
    name: "romfs",
    title: "Linux ROM filesystem",
    extensions: &["romfs", "img"],
    mime: "application/x-romfs",
    probe: Probe::Magic(&[(0, b"-rom1fs-")]),
    dissect: crate::expander!(dissect: Input),
};

const TYPES: EnumTable = &[
    (0, "hard link"),
    (1, "directory"),
    (2, "regular file"),
    (3, "symbolic link"),
    (4, "block device"),
    (5, "character device"),
    (6, "socket"),
    (7, "FIFO"),
];

record! {
    pub struct Header {
        magic: ascii[8] "Magic",
        size: u32 "Filesystem size" .with(|&v, n| n.summary(size(v.into()))),
        checksum: u32 "Checksum" .hex(),
    }
}

record! {
    pub struct FileHeader {
        next: u32 "Next entry / type" .hex() .with(|&v, n| n.summary(format!(
            "next at {:#x}, {}{}",
            v & !0xf,
            crate::value::lookup(TYPES, (v & 7).into()).unwrap_or("?"),
            if v & 8 != 0 { ", executable" } else { "" }
        ))),
        spec: u32 "Type-specific info" .hex(),
        size: u32 "Size",
        checksum: u32 "Checksum" .hex(),
    }
}

/// A NUL-terminated name padded to 16 bytes at `at`; returns it and the
/// offset after the padding.
async fn name_at(cx: &Cx, fs: Span, at: u64) -> Result<(String, u64)> {
    let (name, span) = cx.cstr(fs.sub(at, 1024)).await?;
    Ok((name, align(at.saturating_add(span.len), 16)))
}

/// Sum of the first 512 bytes (or the whole image) as big-endian words.
fn checksum(data: &[u8]) -> u32 {
    data.as_chunks::<4>().0.iter().fold(0u32, |s, w| s.wrapping_add(u32::from_be_bytes(*w)))
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let fs = input.span;
    let h = parse(&cx, fs.sub(0, Header::SIZE), BE, &(), Header::layout).await?;
    let (volume, first) = name_at(&cx, fs, 16).await?;
    let mut node = Header::node("Header", fs.sub(0, 16), BE);
    let head = cx.read_avail(fs.sub(0, u64::from(h.size).min(512))).await?;
    if checksum(&head) != 0 {
        node = node.diag(Diagnostic::warning("header checksum mismatch"));
    }
    cx.emit(node);
    cx.emit(Node::new("Volume name").span(fs.sub(16, first.saturating_sub(16))).value(Value::Text(volume.clone())));
    cx.annotate(format!("romfs \"{volume}\", {}", size(h.size.into())));
    cx.emit(
        Node::new("Root directory")
            .lazy(crate::expander!(self::directory: (Input, u64, Arc<Vec<u64>>)), (input, first, Arc::new(Vec::new()))),
    );
    Ok(())
}

async fn directory(cx: Cx, (input, first, ancestors): (Input, u64, Arc<Vec<u64>>)) -> Result<()> {
    let fs = input.span;
    let mut at = first;
    let mut seen = HashSet::new();
    let mut ancestors = (*ancestors).clone();
    ancestors.push(first);
    let ancestors = Arc::new(ancestors);
    while at != 0 {
        if !seen.insert(at) || seen.len() > MAX_ENTRIES {
            cx.diag(Diagnostic::malformed(format!("entry chain loops at {at:#x}")));
            break;
        }
        let raw = cx.read(fs.sub(at, 16)).await?;
        let next = u32_be(&raw, 0).unwrap_or(0);
        let spec = u64::from(u32_be(&raw, 4).unwrap_or(0));
        let len = u64::from(u32_be(&raw, 8).unwrap_or(0));
        let kind = next & 7;
        let (name, data_at) = name_at(&cx, fs, at.saturating_add(16)).await?;
        let header = fs.sub(at, data_at.saturating_sub(at));
        let node = Node::new(name.clone()).span(header).summary(format!(
            "{}{}",
            crate::value::lookup(TYPES, kind.into()).unwrap_or("?"),
            if kind == 2 { format!(", {}", size(len)) } else { String::new() }
        ));
        let node = match kind {
            1 if name == "." || name == ".." => None,
            1 if ancestors.contains(&spec) || ancestors.len() > MAX_DEPTH => {
                Some(node.diag(Diagnostic::malformed("directory contains itself; not followed")))
            }
            1 => Some(node.lazy(
                crate::expander!(self::directory: (Input, u64, Arc<Vec<u64>>)),
                (input, spec, ancestors.clone()),
            )),
            _ => Some(node.lazy(entry, (input, at, fs.sub(data_at, len), kind))),
        };
        if let Some(node) = node {
            cx.push(node).await;
        } else {
            cx.checkpoint().await;
        }
        at = u64::from(next & !0xf);
    }
    Ok(())
}

async fn entry(cx: Cx, (input, at, data, kind): (Input, u64, Span, u32)) -> Result<()> {
    cx.emit(FileHeader::node("File header", input.span.sub(at, 16), BE));
    match kind {
        2 => cx.emit(content_node(&input, data)),
        3 => {
            let target = String::from_utf8_lossy(&cx.read_avail(data).await?).into_owned();
            cx.emit(Node::new("Target").span(data).value(Value::Text(target)));
        }
        _ => {}
    }
    Ok(())
}
