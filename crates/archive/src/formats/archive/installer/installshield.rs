//! InstallShield archives: InstallShield 3 `.z` archives and the cabinets
//! of InstallShield 5 and later (`data1.hdr`, `data1.cab`, ...).
//!
//! **`.z`** (InstallShield 3): a 255-byte header (signature `13 5D 65 8C`,
//! the file count at 0x0c, the archive size at 0x12, the offset of the
//! directory table at 0x29 and the directory count at 0x31), the files'
//! data, each a PKWARE DCL implode stream, and at the end the directory
//! entries (file count, entry size, name length, name) followed by the file
//! entries (directory index, sizes, data offset, DOS date and time, entry
//! size, name). From memory of the i3comp/STIX documentation of the
//! format; unknown header and entry bytes are shown raw.
//!
//! **Cabinets**: a 20-byte common header (`ISc(`, version, volume info, the
//! offset and size of the cabinet descriptor). The header file (`.hdr`, or
//! a `.cab` that carries it) has the descriptor: the file table's offset,
//! sizes, the directory and file counts, and the offsets of the file group
//! and component lists. The file table starts with the directory name
//! offsets, then (version 5) the file descriptor offsets; version 6 and
//! later keep fixed-size (0x57-byte) descriptors after the table. File
//! descriptors give the name, directory, flags (split, obfuscated,
//! compressed, invalid), sizes, data offset and MD5. Volumes (`.cab`) have a
//! volume header after the common header (data offset, first and last file
//! with their offsets and sizes). Compressed files are a run of chunks,
//! each a 16-bit length and a raw DEFLATE stream; obfuscated files are
//! XOR-scrambled first. From memory of unshield's reader; checked only
//! against our synthetic fixtures (InstallShield needs Windows).

use std::sync::Arc;

use crate::bytes::{to_u64, u16_le, u32_le, u64_le};
use crate::codec::{Codec, decode_span, read_all};
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::arcutil::emit_nodes;
use crate::formats::util::fmt::count;
use crate::formats::util::val::{hex, text, uint};
use crate::formats::{Input, Probe, dissect_or_data};
use crate::node::{Count, Node};
use crate::span::{Origin, Span};
use crate::value::{FlagTable, Value, flag};

use crate::formats::util::fmt::size;

const LE: Endian = Endian::Little;

// ---------------------------------------------------------------------------
// InstallShield 3 `.z`

declare_format!(pub ISZ = "installshield-z", "InstallShield 3 archive (.Z)", ["z"], "application/x-installshield-z",
    Probe::Magic(&[(0, b"\x13\x5d\x65\x8c")]), isz);

const Z_HEADER: u64 = 0xff;
/// A file entry's fixed part, before the name.
const Z_FILE: usize = 0x1e;
const Z_DIR: usize = 6;

/// A directory of a `.z` archive.
#[derive(Clone, Debug)]
struct ZDir {
    at: u64,
    len: u64,
    files: u16,
    name: String,
}

/// A file of a `.z` archive.
#[derive(Clone, Debug)]
struct ZFile {
    at: u64,
    len: u64,
    dir: u16,
    size: u32,
    packed: u32,
    offset: u32,
    date: u16,
    time: u16,
    name: String,
}

struct ZArchive {
    dirs: Vec<ZDir>,
    files: Vec<ZFile>,
    /// Where (and why) reading the tables stopped early.
    problem: Option<Diagnostic>,
}

/// Reads the directory and file tables (they follow each other).
async fn z_tables(cx: &Cx, file: Span, dirs_at: u64, ndirs: u16, nfiles: u16) -> Result<ZArchive> {
    let tables = file.tail(dirs_at);
    let data = cx
        .read_avail(tables.sub(0, cx.limits().max_read.min(1 << 22)))
        .await?;
    let mut out = ZArchive {
        dirs: Vec::new(),
        files: Vec::new(),
        problem: None,
    };
    let mut pos = 0usize;
    for _ in 0..ndirs {
        let (Some(files), Some(len), Some(name_len)) = (
            u16_le(&data, pos),
            u16_le(&data, pos.saturating_add(2)),
            u16_le(&data, pos.saturating_add(4)),
        ) else {
            out.problem = Some(Diagnostic::truncated(tables.tail(to_u64(pos)), 0));
            return Ok(out);
        };
        let name_end = pos.saturating_add(Z_DIR).saturating_add(name_len.into());
        if usize::from(len) < Z_DIR.saturating_add(name_len.into()) || name_end > data.len() {
            out.problem =
                Some(Diagnostic::malformed("bad directory entry").at(tables.sub(to_u64(pos), 6)));
            return Ok(out);
        }
        let name = crate::text::latin1(
            data.get(pos.saturating_add(Z_DIR)..name_end)
                .unwrap_or_default(),
        );
        out.dirs.push(ZDir {
            at: dirs_at.saturating_add(to_u64(pos)),
            len: len.into(),
            files,
            name,
        });
        pos = pos.saturating_add(len.into());
    }
    for _ in 0..nfiles {
        let fixed = data.get(pos..pos.saturating_add(Z_FILE));
        let Some(fixed) = fixed else {
            out.problem = Some(Diagnostic::truncated(tables.tail(to_u64(pos)), 0));
            return Ok(out);
        };
        let len = u16_le(fixed, 0x17).unwrap_or(0);
        let name_len = fixed.get(0x1d).copied().unwrap_or(0);
        let name_end = pos.saturating_add(Z_FILE).saturating_add(name_len.into());
        if usize::from(len) < Z_FILE.saturating_add(name_len.into()) || name_end > data.len() {
            out.problem = Some(
                Diagnostic::malformed("bad file entry").at(tables.sub(to_u64(pos), to_u64(Z_FILE))),
            );
            return Ok(out);
        }
        out.files.push(ZFile {
            at: dirs_at.saturating_add(to_u64(pos)),
            len: len.into(),
            dir: u16_le(fixed, 1).unwrap_or(0),
            size: u32_le(fixed, 3).unwrap_or(0),
            packed: u32_le(fixed, 7).unwrap_or(0),
            offset: u32_le(fixed, 0x0b).unwrap_or(0),
            date: u16_le(fixed, 0x0f).unwrap_or(0),
            time: u16_le(fixed, 0x11).unwrap_or(0),
            name: crate::text::latin1(
                data.get(pos.saturating_add(Z_FILE)..name_end)
                    .unwrap_or_default(),
            ),
        });
        pos = pos.saturating_add(len.into());
        cx.checkpoint().await;
    }
    Ok(out)
}

async fn isz(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, Z_HEADER)).await?;
    let nfiles = u16_le(&head, 0x0c).unwrap_or(0);
    let total = u32_le(&head, 0x12).unwrap_or(0);
    let dirs_at = u64::from(u32_le(&head, 0x29).unwrap_or(0));
    let ndirs = u16_le(&head, 0x31).unwrap_or(0);
    cx.emit(struct_node(
        "Header",
        file.sub(0, Z_HEADER),
        LE,
        (),
        z_header,
    ));
    let summary = format!(
        "InstallShield 3 archive, {}, {}",
        count(nfiles, "file", "files"),
        count(ndirs, "directory", "directories")
    );
    if dirs_at < Z_HEADER || dirs_at > file.len {
        cx.annotate(summary);
        return Err(Diagnostic::malformed("directory table outside the archive"));
    }
    cx.emit(
        Node::new("File data")
            .span(file.sub(Z_HEADER, dirs_at.saturating_sub(Z_HEADER)))
            .summary(size(dirs_at.saturating_sub(Z_HEADER))),
    );
    let archive = Arc::new(z_tables(&cx, file, dirs_at, ndirs, nfiles).await?);
    let dir_end = archive
        .dirs
        .last()
        .map_or(dirs_at, |d| d.at.saturating_add(d.len));
    cx.emit(
        Node::new("Directories")
            .span(file.sub(dirs_at, dir_end.saturating_sub(dirs_at)))
            .summary(count(
                to_u64(archive.dirs.len()),
                "directory",
                "directories",
            ))
            .lazy(z_dirs, (file, archive.clone())),
    );
    let mut files = Node::new("Files")
        .span(file.tail(dir_end))
        .summary(count(to_u64(archive.files.len()), "file", "files"))
        .lazy(z_files, (input, archive.clone()));
    if let Some(e) = &archive.problem {
        files = files.diag(e.clone());
    }
    cx.emit(files);
    let mut summary = summary;
    if total != 0 && u64::from(total) != file.len {
        summary.push_str(&format!(", {} expected", size(total.into())));
    }
    cx.annotate(summary);
    Ok(())
}

fn z_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Signature").hex().emit()?;
    f.bytes("Unknown", 8).emit()?;
    f.u16("Files").emit()?;
    f.u32("Unknown").hex().emit()?;
    f.u32("Archive size").emit()?;
    f.bytes("Unknown", 0x13).emit()?;
    f.u32("Directory table offset").hex().emit()?;
    f.u32("Unknown").hex().emit()?;
    f.u16("Directories").emit()?;
    f.bytes("Unknown", Z_HEADER.saturating_sub(0x33)).emit()?;
    Ok(())
}

async fn z_dirs(cx: Cx, (file, a): (Span, Arc<ZArchive>)) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(a.dirs.len())));
    for (i, d) in a.dirs.iter().enumerate() {
        let span = file.sub(d.at, d.len);
        let fields = vec![
            Node::new("Files")
                .span(span.sub(0, 2))
                .value(uint(d.files, 64)),
            Node::new("Entry size")
                .span(span.sub(2, 2))
                .value(uint(d.len, 64)),
            Node::new("Name length").span(span.sub(4, 2)),
            Node::new("Name")
                .span(span.sub(6, to_u64(d.name.len())))
                .value(text(d.name.clone())),
        ];
        let name = if d.name.is_empty() {
            format!("Directory {i} (root)")
        } else {
            format!("Directory {i}: {}", d.name)
        };
        cx.push(
            Node::new(name)
                .span(span)
                .summary(count(d.files, "file", "files"))
                .lazy(emit_nodes, Arc::new(fields)),
        )
        .await;
    }
    Ok(())
}

async fn z_files(cx: Cx, (input, a): (Input, Arc<ZArchive>)) -> Result<()> {
    let file = input.span;
    cx.set_count(Count::Exact(to_u64(a.files.len())));
    let first = cx.resume::<usize>().unwrap_or(0);
    for (i, f) in a.files.iter().enumerate().skip(first) {
        cx.mark(move || i);
        let dir = a
            .dirs
            .get(usize::from(f.dir))
            .map(|d| d.name.as_str())
            .unwrap_or("");
        let path = if dir.is_empty() {
            f.name.clone()
        } else {
            format!("{dir}\\{}", f.name)
        };
        let span = file.sub(f.at, f.len);
        let data = file.sub(f.offset.into(), f.packed.into());
        let fields = vec![
            Node::new("Directory")
                .span(span.sub(1, 2))
                .value(uint(f.dir, 64)),
            Node::new("Size")
                .span(span.sub(3, 4))
                .value(uint(f.size, 64)),
            Node::new("Compressed size")
                .span(span.sub(7, 4))
                .value(uint(f.packed, 64)),
            Node::new("Data offset")
                .span(span.sub(0x0b, 4))
                .value(hex(f.offset, 64))
                .target(data),
            Node::new("Modification time (DOS)")
                .span(span.sub(0x0f, 4))
                .value(text(crate::text::dos_datetime(f.date, f.time))),
            Node::new("Unknown").span(span.sub(0x13, 4)),
            Node::new("Entry size")
                .span(span.sub(0x17, 2))
                .value(uint(f.len, 64)),
            Node::new("Unknown").span(span.sub(0x19, 4)),
            Node::new("Name length").span(span.sub(0x1d, 1)),
            Node::new("Name")
                .span(span.sub(0x1e, to_u64(f.name.len())))
                .value(text(f.name.clone())),
            crate::formats::content(
                "Content",
                input,
                data,
                Codec::DclImplode,
                Some(f.size.into()),
            ),
        ];
        cx.push(
            Node::new(path)
                .span(data)
                .summary(format!(
                    "{} → {}",
                    size(f.packed.into()),
                    size(f.size.into())
                ))
                .lazy(emit_nodes, Arc::new(fields)),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// InstallShield cabinets

declare_format!(pub ISCAB = "installshield-cab", "InstallShield cabinet", ["cab", "hdr"], "application/x-installshield-cab",
    Probe::Magic(&[(0, b"ISc(")]), iscab);

const COMMON: u64 = 20;
const MAX_GROUPS: u64 = 71;
const DESCRIPTOR: u64 = 0x15a + MAX_GROUPS * 4;
const V6_FILE: u64 = 0x57;

const FILE_FLAGS: FlagTable = &[
    flag(1, "SPLIT"),
    flag(2, "OBFUSCATED"),
    flag(4, "COMPRESSED"),
    flag(8, "INVALID"),
];
const SPLIT: u16 = 1;
const OBFUSCATED: u16 = 2;
const COMPRESSED: u16 = 4;
const INVALID: u16 = 8;

/// The InstallShield major version from the common header's version
/// field; layouts before 6 are version 5's.
fn major(version: u32) -> u32 {
    let m = match version >> 24 {
        1 => (version >> 12) & 0xf,
        2 | 4 => (version & 0xffff) / 100,
        _ => 0,
    };
    m.max(5)
}

/// What the descriptor says.
#[derive(Clone, Copy, Debug)]
struct Cab {
    file: Span,
    major: u32,
    /// The descriptor's offset (everything else is relative to it).
    desc: u64,
    table: u64,
    table2: u64,
    dirs: u32,
    files: u32,
    /// The volume's data, if this file is a volume (`.cab`).
    volume: Option<(u64, u32, u32)>,
}

impl Cab {
    fn at(&self, offset: u64) -> Span {
        self.file.tail(self.desc.saturating_add(offset))
    }
}

/// A file descriptor.
#[derive(Clone, Debug)]
struct IsFile {
    span: Span,
    name: u32,
    dir: u32,
    flags: u16,
    size: u64,
    packed: u64,
    data: u64,
    md5: Vec<u8>,
}

async fn string(cx: &Cx, cab: &Cab, offset: u64) -> String {
    match cx.cstr(cab.at(offset).sub(0, 1024)).await {
        Ok((s, _)) => s,
        Err(_) => String::new(),
    }
}

async fn descriptor_word(cx: &Cx, cab: &Cab, offset: u64) -> Result<u32> {
    let b = cx.read(cab.at(offset).sub(0, 4)).await?;
    Ok(u32_le(&b, 0).unwrap_or(0))
}

async fn iscab(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, COMMON)).await?;
    let version = u32_le(&head, 4).unwrap_or(0);
    let desc = u64::from(u32_le(&head, 12).unwrap_or(0));
    let desc_size = u64::from(u32_le(&head, 16).unwrap_or(0));
    let major = major(version);
    cx.emit(struct_node(
        "Common header",
        file.sub(0, COMMON),
        LE,
        major,
        common_header,
    ));
    // A volume header follows unless the descriptor does (a .hdr file).
    let vol_len = if major == 5 { 40 } else { 64 };
    let vol = cx.read_avail(file.sub(COMMON, vol_len)).await?;
    let data_offset = u32_le(&vol, 0).unwrap_or(0);
    let volume = (data_offset != 0 && desc != COMMON).then(|| {
        let first = u32_le(&vol, 8).unwrap_or(0);
        let last = u32_le(&vol, 12).unwrap_or(0);
        (u64::from(data_offset), first, last)
    });
    if volume.is_some() {
        cx.emit(struct_node(
            "Volume header",
            file.sub(COMMON, vol_len),
            LE,
            major,
            volume_header,
        ));
    }
    let mut summary = format!("InstallShield {major} cabinet");
    if desc == 0 {
        summary.push_str(if volume.is_some() {
            " volume (data only; the file list is in the .hdr)"
        } else {
            ""
        });
        cx.annotate(summary);
        return Ok(());
    }
    let d = file.sub(desc, desc_size.max(DESCRIPTOR));
    cx.emit(struct_node("Cabinet descriptor", d, LE, (), cab_descriptor));
    let mut cab = Cab {
        file,
        major,
        desc,
        table: 0,
        table2: 0,
        dirs: 0,
        files: 0,
        volume,
    };
    cab.table = descriptor_word(&cx, &cab, 0x0c).await?.into();
    cab.dirs = descriptor_word(&cx, &cab, 0x1c).await?;
    cab.files = descriptor_word(&cx, &cab, 0x28).await?;
    cab.table2 = descriptor_word(&cx, &cab, 0x2c).await?.into();
    // Each directory takes a table slot, each file a slot or a descriptor.
    let room = file.len.saturating_sub(desc);
    let cap = |n: u32, each: u64| {
        u32::try_from(u64::from(n).min(room.checked_div(each).unwrap_or(0))).unwrap_or(0)
    };
    cab.dirs = cap(cab.dirs, 4);
    cab.files = cap(cab.files, if major == 5 { 4 } else { V6_FILE });
    cx.emit(
        Node::new("Directories")
            .span(
                cab.at(cab.table)
                    .sub(0, u64::from(cab.dirs).saturating_mul(4)),
            )
            .summary(count(cab.dirs, "directory", "directories"))
            .lazy(directories, cab),
    );
    cx.emit(
        Node::new("Files")
            .summary(count(cab.files, "file", "files"))
            .lazy(files, (input, cab)),
    );
    cx.emit(
        Node::new("File groups")
            .span(d.sub(0x3e, MAX_GROUPS.saturating_mul(4)))
            .lazy(groups, (cab, false)),
    );
    cx.emit(
        Node::new("Components")
            .span(d.sub(0x15a, MAX_GROUPS.saturating_mul(4)))
            .lazy(groups, (cab, true)),
    );
    summary.push_str(&format!(
        ", {}, {}",
        count(cab.files, "file", "files"),
        count(cab.dirs, "directory", "directories")
    ));
    if volume.is_none() {
        summary.push_str(" (header only)");
    }
    cx.annotate(summary);
    Ok(())
}

fn common_header(f: &mut Fields<'_>, major: &u32) -> Result<()> {
    f.ascii("Signature", 4).emit()?;
    f.u32("Version")
        .hex()
        .with(|_, n| n.summary(format!("InstallShield {major}")))
        .emit()?;
    f.u32("Volume info").hex().emit()?;
    f.u32("Cabinet descriptor offset").hex().emit()?;
    f.u32("Cabinet descriptor size").emit()?;
    Ok(())
}

fn volume_header(f: &mut Fields<'_>, major: &u32) -> Result<()> {
    f.u32("Data offset").hex().emit()?;
    f.u32("Unknown").hex().emit()?;
    f.u32("First file").emit()?;
    f.u32("Last file").emit()?;
    let wide = *major > 5;
    for name in [
        "First file offset",
        "First file size",
        "First file compressed size",
        "Last file offset",
        "Last file size",
        "Last file compressed size",
    ] {
        f.u32(name).emit()?;
        if wide {
            f.u32("High part").emit()?;
        }
    }
    Ok(())
}

fn cab_descriptor(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.bytes("Unknown", 0x0c).emit()?;
    f.u32("File table offset").hex().emit()?;
    f.u32("Unknown").hex().emit()?;
    f.u32("File table size").emit()?;
    f.u32("File table size 2").emit()?;
    f.u32("Directories").emit()?;
    f.bytes("Unknown", 8).emit()?;
    f.u32("Files").emit()?;
    f.u32("File table offset 2").hex().emit()?;
    f.bytes("Unknown", 0x0e).emit()?;
    f.bytes("File group offsets", MAX_GROUPS.saturating_mul(4))
        .emit()?;
    f.bytes("Component offsets", MAX_GROUPS.saturating_mul(4))
        .emit()?;
    Ok(())
}

async fn directory_name(cx: &Cx, cab: &Cab, index: u32) -> String {
    if index >= cab.dirs {
        return String::new();
    }
    match descriptor_word(
        cx,
        cab,
        cab.table.saturating_add(u64::from(index).saturating_mul(4)),
    )
    .await
    {
        Ok(off) => string(cx, cab, cab.table.saturating_add(off.into())).await,
        Err(_) => String::new(),
    }
}

async fn directories(cx: Cx, cab: Cab) -> Result<()> {
    cx.set_count(Count::Exact(cab.dirs.into()));
    let first = cx.resume::<u32>().unwrap_or(0);
    for i in first..cab.dirs {
        cx.mark(move || i);
        let entry = cab
            .at(cab.table.saturating_add(u64::from(i).saturating_mul(4)))
            .sub(0, 4);
        let off = descriptor_word(
            &cx,
            &cab,
            cab.table.saturating_add(u64::from(i).saturating_mul(4)),
        )
        .await?;
        let name = string(&cx, &cab, cab.table.saturating_add(off.into())).await;
        cx.push(
            Node::new(format!("Directory {i}"))
                .span(entry)
                .value(text(name))
                .target(cab.at(cab.table.saturating_add(off.into())).sub(0, 1)),
        )
        .await;
    }
    Ok(())
}

async fn descriptor(cx: &Cx, cab: &Cab, index: u32) -> Result<IsFile> {
    if cab.major == 5 {
        let slot = cab
            .table
            .saturating_add(u64::from(cab.dirs.saturating_add(index)).saturating_mul(4));
        let off = descriptor_word(cx, cab, slot).await?;
        let span = cab.at(cab.table.saturating_add(off.into())).sub(0, 0x3a);
        let b = cx.read(span).await?;
        Ok(IsFile {
            span,
            name: u32_le(&b, 0).unwrap_or(0),
            dir: u32_le(&b, 4).unwrap_or(0),
            flags: u16_le(&b, 8).unwrap_or(0),
            size: u32_le(&b, 10).unwrap_or(0).into(),
            packed: u32_le(&b, 14).unwrap_or(0).into(),
            data: u32_le(&b, 0x26).unwrap_or(0).into(),
            md5: b.get(0x2a..0x3a).unwrap_or_default().to_vec(),
        })
    } else {
        let at = cab
            .table
            .saturating_add(cab.table2)
            .saturating_add(u64::from(index).saturating_mul(V6_FILE));
        let span = cab.at(at).sub(0, V6_FILE);
        let b = cx.read(span).await?;
        Ok(IsFile {
            span,
            flags: u16_le(&b, 0).unwrap_or(0),
            size: u64_le(&b, 2).unwrap_or(0),
            packed: u64_le(&b, 10).unwrap_or(0),
            data: u64_le(&b, 18).unwrap_or(0),
            md5: b.get(26..42).unwrap_or_default().to_vec(),
            name: u32_le(&b, 58).unwrap_or(0),
            dir: u16_le(&b, 62).unwrap_or(0).into(),
        })
    }
}

fn descriptor_fields(cab: &Cab, f: &IsFile) -> Vec<Node> {
    let s = f.span;
    let flags = crate::formats::util::lines::flags(FILE_FLAGS, f.flags.into(), 16);
    if cab.major == 5 {
        vec![
            Node::new("Name offset")
                .span(s.sub(0, 4))
                .value(hex(f.name, 64)),
            Node::new("Directory")
                .span(s.sub(4, 4))
                .value(uint(f.dir, 64)),
            Node::new("Flags").span(s.sub(8, 2)).value(flags),
            Node::new("Size").span(s.sub(10, 4)).value(uint(f.size, 64)),
            Node::new("Compressed size")
                .span(s.sub(14, 4))
                .value(uint(f.packed, 64)),
            Node::new("Unknown").span(s.sub(18, 0x14)),
            Node::new("Data offset")
                .span(s.sub(0x26, 4))
                .value(hex(f.data, 64)),
            Node::new("MD5")
                .span(s.sub(0x2a, 16))
                .value(Value::Bytes(f.md5.clone())),
        ]
    } else {
        vec![
            Node::new("Flags").span(s.sub(0, 2)).value(flags),
            Node::new("Size").span(s.sub(2, 8)).value(uint(f.size, 64)),
            Node::new("Compressed size")
                .span(s.sub(10, 8))
                .value(uint(f.packed, 64)),
            Node::new("Data offset")
                .span(s.sub(18, 8))
                .value(hex(f.data, 64)),
            Node::new("MD5")
                .span(s.sub(26, 16))
                .value(Value::Bytes(f.md5.clone())),
            Node::new("Unknown").span(s.sub(42, 16)),
            Node::new("Name offset")
                .span(s.sub(58, 4))
                .value(hex(f.name, 64)),
            Node::new("Directory")
                .span(s.sub(62, 2))
                .value(uint(f.dir, 64)),
            Node::new("Unknown").span(s.sub(64, 12)),
            Node::new("Previous link").span(s.sub(76, 4)),
            Node::new("Next link").span(s.sub(80, 4)),
            Node::new("Link flags").span(s.sub(84, 1)),
            Node::new("Volume").span(s.sub(85, 2)),
        ]
    }
}

async fn files(cx: Cx, (input, cab): (Input, Cab)) -> Result<()> {
    cx.set_count(Count::Exact(cab.files.into()));
    let first = cx.resume::<u32>().unwrap_or(0);
    for i in first..cab.files {
        cx.mark(move || i);
        let f = match descriptor(&cx, &cab, i).await {
            Ok(f) => f,
            Err(e) => {
                cx.push(Node::new(format!("File {i}")).diag(e)).await;
                continue;
            }
        };
        let name = string(&cx, &cab, cab.table.saturating_add(f.name.into())).await;
        let dir = directory_name(&cx, &cab, f.dir).await;
        let path = if dir.is_empty() {
            name
        } else {
            format!("{dir}\\{name}")
        };
        let mut fields = descriptor_fields(&cab, &f);
        let mut node = Node::new(path).span(f.span);
        if f.flags & INVALID != 0 {
            node = node.summary("invalid (no data)");
        } else {
            node = node.summary(size(f.size));
            fields.push(content(input, &cab, &f, i));
        }
        cx.push(node.lazy(emit_nodes, Arc::new(fields))).await;
    }
    Ok(())
}

fn content(input: Input, cab: &Cab, f: &IsFile, index: u32) -> Node {
    let Some((_, first, last)) = cab.volume else {
        return Node::new("Content").summary("in a separate volume (.cab)");
    };
    if index < first || index > last {
        return Node::new("Content").summary("in another volume");
    }
    let span = cab.file.sub(
        f.data,
        if f.flags & COMPRESSED != 0 {
            f.packed
        } else {
            f.size
        },
    );
    let mut node = Node::new("Content")
        .span(span)
        .lazy(file_content, (input, span, f.flags, f.size, f.md5.clone()));
    if f.flags & SPLIT != 0 {
        node = node.diag(Diagnostic::unsupported("file split across volumes"));
    }
    node
}

/// Undoes the obfuscation: `ror8(b ^ 0xd5, 2) - (i % 0x47)`, in 4 KiB
/// chunks with a checkpoint after each (the file may be large).
async fn deobfuscate(cx: &Cx, data: &mut [u8]) {
    const CHUNK: usize = 4096;
    for (n, chunk) in data.chunks_mut(CHUNK).enumerate() {
        let base = n.wrapping_mul(CHUNK);
        for (i, b) in chunk.iter_mut().enumerate() {
            let x = (*b ^ 0xd5).rotate_right(2);
            let i = base.wrapping_add(i);
            *b = x.wrapping_sub(u8::try_from(i % 0x47).unwrap_or(0));
        }
        cx.checkpoint().await;
    }
}

async fn file_content(
    cx: Cx,
    (input, span, flags, len, md5): (Input, Span, u16, u64, Vec<u8>),
) -> Result<()> {
    let mut data = span;
    if flags & OBFUSCATED != 0 {
        let origin = Origin {
            parent: span,
            transform: "installshield-deobfuscate",
        };
        data = match cx.derived(origin) {
            Some(d) => d.span,
            None => {
                let mut bytes = read_all(&cx, span).await?;
                deobfuscate(&cx, &mut bytes).await;
                cx.add_derived(origin, bytes, span.len, None)?.span
            }
        };
    }
    let out = if flags & COMPRESSED != 0 {
        let origin = Origin {
            parent: data,
            transform: "installshield-chunks",
        };
        match cx.derived(origin) {
            Some(d) => d.span,
            None => {
                let (bytes, error) = inflate_chunks(&cx, data, len).await?;
                cx.add_derived(origin, bytes, data.len, error)?.span
            }
        }
    } else {
        data
    };
    if out.len != len {
        cx.diag(Diagnostic::warning(format!(
            "decoded {:#x} bytes, expected {len:#x}",
            out.len
        )));
    }
    if out.len <= 16 << 20 && md5.iter().any(|&b| b != 0) {
        use crate::codec::crypto::hash::Md5;
        let bytes = read_all(&cx, out).await?;
        if crate::formats::util::datakit::digest_paced::<Md5>(&cx, &bytes).await == md5 {
            cx.emit(Node::new("MD5 check").span(out).summary("valid"));
        } else {
            cx.diag(Diagnostic::warning("MD5 mismatch"));
        }
    }
    dissect_or_data(cx, input.nested(out)).await
}

/// Inflates the chunks of a compressed file: each a 16-bit length and a
/// raw DEFLATE stream (flushed, possibly without a final block).
async fn inflate_chunks(cx: &Cx, data: Span, len: u64) -> Result<(Vec<u8>, Option<Diagnostic>)> {
    let limit = cx.limits().max_derived;
    let mut out = Vec::new();
    let mut pos = 0u64;
    while pos < data.len {
        let n = cx.read(data.sub(pos, 2)).await?;
        let n = u64::from(u16_le(&n, 0).unwrap_or(0));
        let chunk = data.sub(pos.saturating_add(2), n);
        if n == 0 || chunk.len < n {
            return Ok((
                out,
                Some(Diagnostic::malformed("bad chunk length").at(data.sub(pos, 2))),
            ));
        }
        let d = decode_span(cx, chunk, &Codec::Deflate, None).await?;
        if d.span.len == 0 {
            return Ok((out, d.error));
        }
        out.extend(read_all(cx, d.span).await?);
        if to_u64(out.len()) > limit.min(len.saturating_add(1 << 16)) {
            return Ok((
                out,
                Some(Diagnostic::limit("decoded more than the file's size")),
            ));
        }
        pos = pos.saturating_add(2).saturating_add(n);
    }
    Ok((out, None))
}

/// File groups (`components` false) or components: lists of entries
/// reached from the descriptor's 71 offsets, each `(name, descriptor,
/// next)`.
async fn groups(cx: Cx, (cab, components): (Cab, bool)) -> Result<()> {
    let base: u64 = if components { 0x15a } else { 0x3e };
    for slot in 0..MAX_GROUPS {
        let at = base.saturating_add(slot.saturating_mul(4));
        let mut offset = descriptor_word(&cx, &cab, at).await?;
        let mut visited = Vec::new();
        for _ in 0..64 {
            if offset == 0 || visited.contains(&offset) {
                break;
            }
            visited.push(offset);
            let list = cx.read(cab.at(offset.into()).sub(0, 12)).await?;
            let desc = u32_le(&list, 4).unwrap_or(0);
            let next = u32_le(&list, 8).unwrap_or(0);
            let entry = cab.at(desc.into());
            let name_off = descriptor_word(&cx, &cab, desc.into()).await?;
            let name = string(&cx, &cab, name_off.into()).await;
            let node = if components {
                let skip: u64 = if cab.major == 5 { 0x6c } else { 0x6b };
                let b = cx.read(entry.sub(4u64.saturating_add(skip), 6)).await?;
                let n = u16_le(&b, 0).unwrap_or(0);
                let table = u32_le(&b, 2).unwrap_or(0);
                let mut names = Vec::new();
                for k in 0..u64::from(n).min(MAX_GROUPS) {
                    let at = u64::from(table).saturating_add(k.saturating_mul(4));
                    let off = descriptor_word(&cx, &cab, at).await?;
                    names.push(
                        Node::new(format!("File group {k}"))
                            .span(cab.at(at).sub(0, 4))
                            .value(text(string(&cx, &cab, off.into()).await)),
                    );
                }
                Node::new(name)
                    .span(entry.sub(0, 4u64.saturating_add(skip).saturating_add(6)))
                    .summary(count(n, "file group", "file groups"))
                    .lazy(emit_nodes, Arc::new(names))
            } else {
                let skip: u64 = if cab.major == 5 { 0x48 } else { 0x12 };
                let b = cx.read(entry.sub(4u64.saturating_add(skip), 8)).await?;
                let first = u32_le(&b, 0).unwrap_or(0);
                let last = u32_le(&b, 4).unwrap_or(0);
                Node::new(name)
                    .span(entry.sub(0, 4u64.saturating_add(skip).saturating_add(8)))
                    .summary(format!("files {first}–{last}"))
            };
            cx.push(node).await;
            offset = next;
        }
    }
    Ok(())
}
