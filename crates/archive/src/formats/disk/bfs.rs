//! SCO UnixWare Boot File System (BFS): one flat directory of contiguous
//! files, as used for `/stand` partitions.

use crate::bytes::{to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::{content_node, size, unix_mode, unix_time};
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value};

const LE: Endian = Endian::Little;
const BLOCK: u64 = 512;
const ROOT: u16 = 2;
const INODE: u64 = 64;

pub static FORMAT: Format = Format {
    name: "bfs",
    title: "SCO boot filesystem (BFS)",
    extensions: &["img", "bfs"],
    mime: "application/x-bfs",
    probe: Probe::Magic(&[(0, b"\xce\xfa\xad\x1b")]),
    dissect: crate::expander!(dissect: Input),
};

record! {
    pub struct Superblock {
        magic: u32 "Magic" .hex(),
        start: u32 "Data start" .hex(),
        end: u32 "Last byte" .hex(),
        from: u32 "Compaction from" .hex(),
        to: u32 "Compaction to" .hex(),
        bfrom: u32 "Backup from" .hex(),
        bto: u32 "Backup to" .hex(),
        fs_name: bytes[6] "Filesystem name" .with(|b, n| n.value(crate::formats::disk::text(b))),
        volume: bytes[6] "Volume name" .with(|b, n| n.value(crate::formats::disk::text(b))),
    }
}

const TYPES: EnumTable = &[(1, "regular file"), (2, "directory")];

record! {
    pub struct Inode {
        ino: u16 "Inode number",
        _unused: u16 "Unused",
        first_block: u32 "First block",
        last_block: u32 "Last block",
        last_byte: u32 "Last byte offset" .hex(),
        kind: u32 "Type" .enumeration(TYPES),
        mode: u32 "Mode" .with(|&m, n| n.summary(unix_mode(m))),
        uid: u32 "Owner",
        gid: u32 "Group",
        links: u32 "Links",
        atime: u32 "Accessed" .with(unix_time),
        mtime: u32 "Modified" .with(unix_time),
        ctime: u32 "Changed" .with(unix_time),
    }
}

/// The span of the data of inode `ino`, and its type.
async fn inode_data(cx: &Cx, vol: Span, ino: u16, inodes_end: u64) -> Result<(Span, Span, u32)> {
    let at = BLOCK.saturating_add(u64::from(ino.saturating_sub(ROOT)).saturating_mul(INODE));
    if at.saturating_add(INODE) > inodes_end {
        return Err(Diagnostic::malformed(format!(
            "inode {ino} is outside the inode table"
        )));
    }
    let span = vol.sub(at, INODE);
    let raw = cx.read(span).await?;
    let first = u64::from(u32_le(&raw, 4).unwrap_or(0));
    let last = u64::from(u32_le(&raw, 12).unwrap_or(0));
    let start = first.saturating_mul(BLOCK);
    let len = if first == 0 {
        0
    } else {
        last.saturating_add(1).saturating_sub(start)
    };
    Ok((span, vol.sub(start, len), u32_le(&raw, 16).unwrap_or(0)))
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let vol = input.span;
    let sb = parse(
        &cx,
        vol.sub(0, Superblock::SIZE),
        LE,
        &(),
        Superblock::layout,
    )
    .await?;
    cx.emit(Superblock::node("Superblock", vol.sub(0, BLOCK), LE));
    let inodes_end = u64::from(sb.start);
    let count = inodes_end.saturating_sub(BLOCK) / INODE;
    cx.annotate(format!(
        "BFS filesystem \"{}\", {}, {count} inodes",
        crate::text::until_nul(&sb.volume),
        size(u64::from(sb.end).saturating_add(1))
    ));
    cx.emit(
        Node::new("Inode table")
            .span(vol.sub(BLOCK, inodes_end.saturating_sub(BLOCK)))
            .summary(format!("{count} inodes")),
    );
    let (root, dir, _) = inode_data(&cx, vol, ROOT, inodes_end).await?;
    cx.emit(Inode::node("Root inode", root, LE));
    let data = cx.read_avail(dir).await?;
    let entries: Vec<(u16, String, u64)> = data
        .as_chunks::<16>()
        .0
        .iter()
        .enumerate()
        .map(|(i, e)| {
            (
                u16_le(e, 0).unwrap_or(0),
                crate::text::until_nul(e.get(2..).unwrap_or_default()),
                to_u64(i),
            )
        })
        .filter(|(ino, name, _)| *ino != 0 && name != "." && name != "..")
        .collect();
    cx.emit(
        Node::new("Root directory")
            .span(dir)
            .summary(format!("{} files", entries.len()))
            .lazy(directory, (input, inodes_end, dir)),
    );
    Ok(())
}

async fn directory(cx: Cx, (input, inodes_end, dir): (Input, u64, Span)) -> Result<()> {
    let vol = input.span;
    let data = cx.read_avail(dir).await?;
    cx.set_count(Count::Unknown);
    for (i, e) in data.as_chunks::<16>().0.iter().enumerate() {
        let ino = u16_le(e, 0).unwrap_or(0);
        let name = crate::text::until_nul(e.get(2..).unwrap_or_default());
        if ino == 0 || name == "." || name == ".." {
            cx.checkpoint().await;
            continue;
        }
        let entry = dir.sub(to_u64(i).saturating_mul(16), 16);
        let node = match inode_data(&cx, vol, ino, inodes_end).await {
            Ok((inode, data, kind)) => Node::new(name)
                .span(entry)
                .summary(format!("{}, inode {ino}", size(data.len)))
                .lazy(file, (input, inode, data, kind)),
            Err(e) => Node::new(name).span(entry).diag(e),
        };
        cx.push(node).await;
    }
    Ok(())
}

async fn file(cx: Cx, (input, inode, data, kind): (Input, Span, Span, u32)) -> Result<()> {
    cx.emit(Inode::node("Inode", inode, LE));
    if kind == 2 {
        cx.emit(
            Node::new("Directory data")
                .span(data)
                .value(Value::Text("directory".into())),
        );
    } else {
        cx.emit(content_node(&input, data));
    }
    Ok(())
}
