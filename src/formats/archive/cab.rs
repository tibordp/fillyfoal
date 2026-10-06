//! Microsoft Cabinet (`.cab`) files.
//!
//! A header (`MSCF`), folder entries, file entries, then per folder a chain
//! of data blocks. Files are byte ranges of their folder's uncompressed
//! stream. A folder's stream is its data blocks through its codec (stored,
//! MSZIP, Quantum or LZX; see [`crate::codec::cab`]), decoded lazily as far
//! as reads reach; files in a single stored block map straight back to the
//! cabinet's bytes.

use std::sync::Arc;

use crate::bytes::{u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::arcutil::{count, emit_nodes, hex, human_size, text, uint, unsupported};
use crate::codec::cab::Folder;
use crate::formats::{Codec, Format, Input, Probe, dissect_or_data, embedded};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag};

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "cab",
    title: "Microsoft Cabinet",
    extensions: &["cab", "msu"],
    mime: "application/vnd.ms-cab-compressed",
    probe: Probe::Custom(|h| h.starts_with(b"MSCF\0\0\0\0") && h.at(25, b"\x01")),
    dissect: crate::expander!(dissect: Input),
};

const FLAGS: FlagTable = &[
    flag(0x1, "PREV_CABINET"),
    flag(0x2, "NEXT_CABINET"),
    flag(0x4, "RESERVE_PRESENT"),
];

const COMPRESSION: EnumTable = &[(0, "none"), (1, "MSZIP"), (2, "Quantum"), (3, "LZX")];

const ATTRIBUTES: FlagTable = &[
    flag(0x01, "READONLY"),
    flag(0x02, "HIDDEN"),
    flag(0x04, "SYSTEM"),
    flag(0x20, "ARCHIVE"),
    flag(0x40, "EXECUTE"),
    flag(0x80, "NAME_IS_UTF"),
];

record! {
    pub struct Header {
        signature: ascii[4] "Signature",
        reserved1: u32 "Reserved",
        size: u32 "Cabinet size" .with(|&s, n| n.summary(human_size(s.into()))),
        reserved2: u32 "Reserved",
        files_offset: u32 "First file entry offset" .hex(),
        reserved3: u32 "Reserved",
        minor: u8 "Minor version",
        major: u8 "Major version",
        folders: u16 "Folders",
        files: u16 "Files",
        flags: u16 "Flags" .flags(FLAGS),
        set_id: u16 "Set ID",
        index: u16 "Cabinet index",
    }
}

fn compression_name(kind: u16) -> String {
    match crate::value::lookup(COMPRESSION, u64::from(kind & 0x0f)) {
        Some(n @ ("LZX" | "Quantum")) => format!("{n} (window 2^{})", (kind >> 8) & 0x1f),
        Some(n) => n.to_owned(),
        None => format!("method {kind:#06x}"),
    }
}

/// Layout facts shared by the expanders.
#[derive(Clone, Copy, Debug)]
struct Layout {
    file: Span,
    folders_at: u64,
    folder_size: u64,
    data_reserve: u64,
    folders: u16,
    files: u16,
    files_at: u64,
}

#[derive(Clone, Copy, Debug)]
struct FolderInfo {
    data_at: u64,
    blocks: u16,
    kind: u16,
}

async fn folder_info(cx: &Cx, l: &Layout, i: u16) -> Result<FolderInfo> {
    let at = l
        .folders_at
        .saturating_add(u64::from(i).saturating_mul(l.folder_size));
    let b = cx.read(l.file.sub(at, 8)).await?;
    Ok(FolderInfo {
        data_at: u32_le(&b, 0).unwrap_or(0).into(),
        blocks: u16_le(&b, 4).unwrap_or(0),
        kind: u16_le(&b, 6).unwrap_or(0),
    })
}

/// The folder's codec, if its compression method is known.
fn folder_codec(l: &Layout, f: &FolderInfo) -> Option<Codec> {
    (f.kind & 0x0f <= 3).then(|| {
        Codec::CabFolder(Folder {
            kind: f.kind,
            data_reserve: u8::try_from(l.data_reserve).unwrap_or(u8::MAX),
        })
    })
}

/// The folder's data blocks (headers included) and its unpacked size.
async fn folder_data(cx: &Cx, l: &Layout, f: &FolderInfo) -> Result<(Span, u64)> {
    let mut cur = Cursor::new(cx, l.file, LE);
    cur.seek(f.data_at);
    let mut total = 0u64;
    for _ in 0..f.blocks {
        cur.skip(4);
        let packed = cur.u16().await?;
        let unpacked = cur.u16().await?;
        cur.skip(l.data_reserve.saturating_add(packed.into()));
        total = total.saturating_add(unpacked.into());
        cx.checkpoint().await;
    }
    Ok((cur.since(f.data_at), total))
}

/// The folder's uncompressed stream, decoded on demand. Its length is the
/// one the data blocks claim (whether or not decoding fails earlier, which
/// shows up as short reads), so the result does not depend on what was
/// decoded before.
async fn folder_stream(cx: &Cx, l: &Layout, f: &FolderInfo) -> Result<Span> {
    let codec = folder_codec(l, f).ok_or_else(|| Diagnostic::unsupported(compression_name(f.kind)))?;
    let (data, total) = folder_data(cx, l, f).await?;
    let stream = cx.decode_lazy(data, &codec, total)?;
    Ok(Span::new(stream.source, 0, total))
}

async fn folder_content(cx: Cx, (input, l, f): (Input, Layout, FolderInfo)) -> Result<()> {
    let stream = folder_stream(&cx, &l, &f).await?;
    cx.annotate(format!("{:#x} bytes, decoded on demand", stream.len));
    dissect_or_data(cx, input.nested(stream)).await
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let (h, _) = cur.record::<Header>().await?;
    let mut folder_reserve = 0u64;
    let mut data_reserve = 0u64;
    if h.flags & 0x4 != 0 {
        let header_reserve = cur.u16().await?;
        folder_reserve = cur.u8().await?.into();
        data_reserve = cur.u8().await?.into();
        cur.skip(header_reserve.into());
    }
    for (bit, n) in [(0x1u16, 2), (0x2, 2)] {
        if h.flags & bit != 0 {
            for _ in 0..n {
                cur.cstr(256).await?;
            }
        }
    }
    let header_span = cur.since(0);
    cx.emit(
        struct_node("Header", header_span, LE, (), header_layout)
            .summary(format!("version {}.{}", h.major, h.minor)),
    );
    let layout = Layout {
        file,
        folders_at: cur.pos(),
        folder_size: 8u64.saturating_add(folder_reserve),
        data_reserve,
        folders: h.folders,
        files: h.files,
        files_at: h.files_offset.into(),
    };
    let folders_span = file.sub(
        layout.folders_at,
        u64::from(h.folders).saturating_mul(layout.folder_size),
    );
    cx.emit(
        Node::new("Folders")
            .span(folders_span)
            .summary(count(h.folders.into(), "folder", "folders"))
            .lazy(folders, (input, layout)),
    );
    cx.emit(
        Node::new("Files")
            .span(file.tail(layout.files_at))
            .summary(count(h.files.into(), "file", "files"))
            .lazy(files, (input, layout)),
    );
    let mut methods = Vec::new();
    for i in 0..h.folders.min(64) {
        let f = folder_info(&cx, &layout, i).await?;
        let name = compression_name(f.kind);
        if !methods.contains(&name) {
            methods.push(name);
        }
    }
    cx.annotate(format!(
        "Microsoft Cabinet, {}, {}, {}",
        count(h.files.into(), "file", "files"),
        count(h.folders.into(), "folder", "folders"),
        methods.join(", ")
    ));
    Ok(())
}

fn header_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    let h = Header::read(f)?;
    if h.flags & 0x4 != 0 {
        let header_reserve = f.u16("Header reserve size").emit()?;
        f.u8("Folder reserve size").emit()?;
        f.u8("Data reserve size").emit()?;
        f.bytes("Header reserve", header_reserve.into()).emit()?;
    }
    if h.flags & 0x1 != 0 {
        f.cstr("Previous cabinet").emit()?;
        f.cstr("Previous disk").emit()?;
    }
    if h.flags & 0x2 != 0 {
        f.cstr("Next cabinet").emit()?;
        f.cstr("Next disk").emit()?;
    }
    Ok(())
}

async fn folders(cx: Cx, (input, l): (Input, Layout)) -> Result<()> {
    cx.set_count(Count::Exact(l.folders.into()));
    for i in 0..l.folders {
        let at = l
            .folders_at
            .saturating_add(u64::from(i).saturating_mul(l.folder_size));
        let span = l.file.sub(at, l.folder_size);
        let f = folder_info(&cx, &l, i).await?;
        let mut fields = vec![
            Node::new("First data block offset")
                .span(span.sub(0, 4))
                .value(hex(f.data_at))
                .target(l.file.sub(f.data_at, 0)),
            Node::new("Data blocks")
                .span(span.sub(4, 2))
                .value(uint(f.blocks.into())),
            Node::new("Compression")
                .span(span.sub(6, 2))
                .value(Value::Enum {
                    raw: f.kind.into(),
                    bits: 16,
                    name: crate::value::lookup(COMPRESSION, u64::from(f.kind & 0x0f)),
                })
                .summary(compression_name(f.kind)),
            Node::new("Data")
                .span(l.file.tail(f.data_at))
                .summary(count(f.blocks.into(), "block", "blocks"))
                .lazy(data_blocks, (input, l, f)),
        ];
        if f.kind & 0x0f != 0 {
            fields.push(match folder_codec(&l, &f) {
                Some(_) => Node::new("Uncompressed stream")
                    .span(l.file.tail(f.data_at))
                    .lazy(folder_content, (input, l, f)),
                None => unsupported("Uncompressed stream", l.file.tail(f.data_at), &compression_name(f.kind)),
            });
        }
        cx.push(
            Node::new(format!("Folder {i}"))
                .span(span)
                .summary(format!(
                    "{}, {}",
                    compression_name(f.kind),
                    count(f.blocks.into(), "data block", "data blocks")
                ))
                .lazy(emit_nodes, Arc::new(fields)),
        )
        .await;
    }
    Ok(())
}

async fn data_blocks(cx: Cx, (input, l, f): (Input, Layout, FolderInfo)) -> Result<()> {
    cx.set_count(Count::Exact(f.blocks.into()));
    let mut cur = Cursor::new(&cx, l.file, LE);
    cur.seek(f.data_at);
    let mut uncompressed_at = 0u64;
    for i in 0..f.blocks {
        let start = cur.pos();
        let csum = cur.u32().await?;
        let packed = cur.u16().await?;
        let unpacked = cur.u16().await?;
        cur.skip(l.data_reserve);
        let data = cur.span(packed.into());
        cur.skip(packed.into());
        let span = cur.since(start);
        let mut checksum = Node::new("Checksum")
            .span(span.sub(0, 4))
            .value(hex(csum.into()));
        if csum == 0 {
            checksum = checksum.summary("not used");
        }
        let mut fields = vec![
            checksum,
            Node::new("Packed size")
                .span(span.sub(4, 2))
                .value(uint(packed.into())),
            Node::new("Unpacked size")
                .span(span.sub(6, 2))
                .value(uint(unpacked.into())),
        ];
        fields.push(match f.kind & 0x0f {
            0 => embedded("Data", input.nested(data)),
            1 => {
                let magic = cx.read_avail(data.sub(0, 2)).await?;
                if magic == b"CK" {
                    Node::new("Data").span(data).summary("MSZIP: 'CK' + deflate")
                } else {
                    Node::new("Data")
                        .span(data)
                        .diag(Diagnostic::malformed("MSZIP block without 'CK' signature"))
                }
            }
            2 | 3 => Node::new("Data")
                .span(data)
                .summary(format!("{}, decoded with the folder", compression_name(f.kind))),
            _ => unsupported("Data", data, &compression_name(f.kind)),
        });
        cx.push(crate::formats::util::arcutil::check_len(
            Node::new(format!("Block {i}"))
                .span(span)
                .summary(format!(
                    "{} → {}, at {uncompressed_at:#x} in the folder",
                    human_size(packed.into()),
                    human_size(unpacked.into())
                ))
                .lazy(emit_nodes, Arc::new(fields)),
            data,
            packed.into(),
        ))
        .await;
        uncompressed_at = uncompressed_at.saturating_add(unpacked.into());
    }
    Ok(())
}

async fn files(cx: Cx, (input, l): (Input, Layout)) -> Result<()> {
    cx.set_count(Count::Exact(l.files.into()));
    let mut cur = Cursor::new(&cx, l.file, LE);
    cur.seek(l.files_at);
    for _ in 0..l.files {
        let start = cur.pos();
        let size = cur.u32().await?;
        let offset = cur.u32().await?;
        let folder = cur.u16().await?;
        cur.skip(6);
        let (name, _) = cur.cstr(1024).await?;
        let span = cur.since(start);
        cx.push(
            Node::new(name)
                .span(span)
                .summary(human_size(size.into()))
                .lazy(file_entry, (input, l, span, size, offset, folder)),
        )
        .await;
    }
    Ok(())
}

async fn file_entry(
    cx: Cx,
    (input, l, span, size, offset, folder): (Input, Layout, Span, u32, u32, u16),
) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u32("Size")
        .with(|&s, n| n.summary(human_size(s.into())))
        .emit()?;
    f.u32("Offset in folder").hex().emit()?;
    f.u16("Folder")
        .with(|&i, n| match i {
            0xfffd => n.summary("continued from the previous cabinet"),
            0xfffe => n.summary("continued to the next cabinet"),
            0xffff => n.summary("continued both ways"),
            _ => n,
        })
        .emit()?;
    let date = f.u16("Date").hex().get()?;
    let time = f.u16("Time").hex().get()?;
    let at = span.sub(10, 4);
    f.node(
        Node::new("Modification time (DOS)")
            .span(at)
            .value(text(crate::text::dos_datetime(date, time))),
    );
    f.u16("Attributes").flags(ATTRIBUTES).emit()?;
    f.cstr("Name").emit()?;
    if folder >= l.folders || size == 0 {
        return Ok(());
    }
    let fo = folder_info(&cx, &l, folder).await?;
    let want_start = u64::from(offset);
    let want_end = want_start.saturating_add(size.into());
    // Find the data block holding the file's start.
    let mut cur = Cursor::new(&cx, l.file, LE);
    cur.seek(fo.data_at);
    let mut uncompressed_at = 0u64;
    for i in 0..fo.blocks {
        cur.skip(4);
        let packed = cur.u16().await?;
        let unpacked = cur.u16().await?;
        cur.skip(l.data_reserve);
        let data = cur.span(packed.into());
        cur.skip(packed.into());
        let end = uncompressed_at.saturating_add(unpacked.into());
        if want_start < end {
            if fo.kind & 0x0f == 0 && want_end <= end {
                // Within one stored block: the cabinet's own bytes.
                let s = data.sub(want_start.saturating_sub(uncompressed_at), size.into());
                cx.emit(embedded("Content", input.nested(s)).summary(human_size(size.into())));
                return Ok(());
            }
            cx.emit(Node::new("Location").span(data).summary(format!(
                "{}, starts in data block {i} of folder {folder}",
                compression_name(fo.kind)
            )));
            break;
        }
        uncompressed_at = end;
        cx.checkpoint().await;
    }
    if folder_codec(&l, &fo).is_none() {
        cx.emit(unsupported("Content", span, &compression_name(fo.kind)));
        return Ok(());
    }
    let stream = folder_stream(&cx, &l, &fo).await?;
    if want_end > stream.len {
        cx.diag(Diagnostic::malformed("file lies beyond its folder's data"));
        return Ok(());
    }
    cx.emit(
        embedded("Content", input.nested(stream.sub(want_start, size.into())))
            .summary(format!("{}, {}", compression_name(fo.kind), human_size(size.into()))),
    );
    Ok(())
}
