//! The resource directory tree (`IMAGE_RESOURCE_DIRECTORY`): three levels
//! (type, name, language) of directory tables with entries naming or
//! numbering their children, leading to `IMAGE_RESOURCE_DATA_ENTRY`s. The
//! data itself is dissected by type in [`super::resource`]; icon and cursor
//! groups are also reassembled into `.ico` / `.cur` files.

use super::resource::{self, RT_CURSOR, RT_GROUP_CURSOR, RT_GROUP_ICON, RT_ICON};
use super::tables::RESOURCE_TYPE;
use super::{LE, Pe, PeInfo, overflow, rva_field};
use crate::bytes::{to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Fields, parse, struct_node};
use crate::formats::embedded_as;
use crate::node::Node;
use crate::span::{Origin, Span};
use crate::value::{Value, lookup};

/// Windows uses three levels (type, name, language).
const MAX_RESOURCE_DEPTH: usize = 8;
const HIGH_BIT: u32 = 0x8000_0000;
/// Icon groups larger than this are not reassembled.
const MAX_GROUP_BYTES: u64 = 16 << 20;

#[derive(Clone)]
pub(super) struct ResourceDir {
    pe: Pe,
    /// RVA of the resource section; all offsets are relative to it.
    base: u32,
    offset: u32,
    /// Offsets of this directory and its ancestors, for cycle detection.
    path: Vec<u32>,
    /// Resource type (`RT_*`), once known from the first level.
    kind: Option<u32>,
    /// Ordinal resource name, once known from the second level.
    name: Option<u32>,
}

pub(super) async fn root(cx: Cx, (pe, base): (Pe, u32)) -> Result<()> {
    let dir = ResourceDir {
        pe,
        base,
        offset: 0,
        path: vec![0],
        kind: None,
        name: None,
    };
    let (types, total) = table(&cx, &dir).await?;
    cx.annotate(format!(
        "{total} resource type{}{}",
        if total == 1 { "" } else { "s" },
        if types.is_empty() {
            String::new()
        } else {
            format!(": {}", types.join(", "))
        }
    ));
    Ok(())
}

fn directory_header(f: &mut Fields<'_>, _: &()) -> Result<(u16, u16)> {
    f.u32("Characteristics").hex().desc("Reserved, 0").emit()?;
    f.u32("TimeDateStamp").timestamp().emit()?;
    f.u16("MajorVersion").emit()?;
    f.u16("MinorVersion").emit()?;
    let named = f
        .u16("NumberOfNamedEntries")
        .desc("Entries with string names, which come first")
        .emit()?;
    let ids = f
        .u16("NumberOfIdEntries")
        .desc("Entries with numeric IDs, after the named ones")
        .emit()?;
    Ok((named, ids))
}

/// Emits a directory table: its header and its entries. Returns the labels
/// of the entries (for the summary) and their count.
async fn table(cx: &Cx, dir: &ResourceDir) -> Result<(Vec<String>, u32)> {
    let pe = &dir.pe;
    let level = dir.path.len();
    let header_rva = dir.base.checked_add(dir.offset).ok_or_else(overflow)?;
    let header_span = pe.rva_exact(header_rva, 16)?;
    let (named, ids) = parse(cx, header_span, LE, &(), directory_header).await?;
    let total = u32::from(named).saturating_add(ids.into());
    cx.emit(struct_node(
        "Directory Header",
        header_span,
        LE,
        (),
        directory_header,
    ));
    let mut labels = Vec::new();
    for i in 0..total {
        let entry_rva = i
            .checked_mul(8)
            .and_then(|o| header_rva.checked_add(16)?.checked_add(o))
            .ok_or_else(overflow)?;
        let entry = pe.rva_exact(entry_rva, 8)?;
        let data = cx.read(entry).await?;
        let name = u32_le(&data, 0).unwrap_or(0);
        let offset = u32_le(&data, 4).unwrap_or(0);

        let mut diagnostics = Vec::new();
        let mut name_string = None;
        let label = if name & HIGH_BIT != 0 {
            match resource_name(cx, pe, dir.base, name & !HIGH_BIT).await {
                Ok((text, span)) => {
                    name_string = Some((text.clone(), span));
                    format!("{text:?}")
                }
                Err(e) => {
                    diagnostics.push(e);
                    "<unreadable name>".to_owned()
                }
            }
        } else {
            id_label(level, name)
        };
        if labels.len() < 8 {
            labels.push(label.clone());
        }
        let mut node = Node::new(label).span(entry);
        for d in diagnostics {
            node = node.diag(d);
        }

        let child = offset & !HIGH_BIT;
        let child_rva = dir.base.checked_add(child).ok_or_else(overflow)?;
        let subdirectory = offset & HIGH_BIT != 0;
        if subdirectory {
            if dir.path.contains(&child) {
                cx.push(node.diag(Diagnostic::malformed(format!(
                    "directory at offset {child:#x} contains itself"
                ))))
                .await;
                continue;
            }
            if level >= MAX_RESOURCE_DEPTH {
                cx.push(node.diag(Diagnostic::limit(format!(
                    "resource directories nested deeper than {MAX_RESOURCE_DEPTH}"
                ))))
                .await;
                continue;
            }
            if let Ok(at) = pe.rva_span(child_rva, 16) {
                node = node.target(at);
            }
            // The number of children, for the summary.
            if let Ok(h) = pe.rva_exact(child_rva, 16)
                && let Ok(head) = cx.read(h).await
            {
                let n = u32::from(u16_le(&head, 12).unwrap_or(0))
                    .saturating_add(u16_le(&head, 14).unwrap_or(0).into());
                node = node.summary(match level {
                    1 => format!("{n} resource{}", if n == 1 { "" } else { "s" }),
                    _ => format!("{n} language{}", if n == 1 { "" } else { "s" }),
                });
            }
        } else if let Ok(span) = pe.rva_span(child_rva, 16)
            && let Ok(e) = parse(cx, span, LE, pe, resource_data_entry).await
        {
            node = node
                .summary(format!("{:#x} bytes, code page {}", e.size, e.code_page))
                .target(span);
        }
        let mut path = dir.path.clone();
        path.push(child);
        let child_dir = ResourceDir {
            pe: pe.clone(),
            base: dir.base,
            offset: child,
            path,
            kind: if level == 1 && name & HIGH_BIT == 0 {
                Some(name)
            } else {
                dir.kind
            },
            name: if level == 2 && name & HIGH_BIT == 0 {
                Some(name)
            } else {
                dir.name
            },
        };
        node = node.lazy(
            crate::expander!(self::entry: EntryState),
            EntryState {
                dir: child_dir,
                entry,
                name_string,
                subdirectory,
            },
        );
        cx.push(node).await;
    }
    Ok((labels, total))
}

#[derive(Clone)]
struct EntryState {
    /// The directory or data entry the entry points to.
    dir: ResourceDir,
    entry: Span,
    name_string: Option<(String, Span)>,
    subdirectory: bool,
}

fn entry_fields(f: &mut Fields<'_>, level: &usize) -> Result<()> {
    let level = *level;
    let what = match level {
        1 => "type",
        2 => "resource",
        _ => "language",
    };
    f.u32("Name")
        .hex()
        .desc("Bit 31 set: offset of a counted UTF-16 name; otherwise a numeric ID")
        .with(|&v, n| {
            if v & HIGH_BIT != 0 {
                n.summary(format!(
                    "{what} named by the string at offset {:#x}",
                    v & !HIGH_BIT
                ))
            } else if level >= 3 {
                n.summary(crate::formats::util::lcid::describe(v))
            } else {
                n.summary(format!("{what} {}", id_label(level, v)))
            }
        })
        .emit()?;
    f.u32("OffsetToData")
        .hex()
        .desc("Bit 31 set: offset of a subdirectory; otherwise of a data entry")
        .with(|&v, n| {
            n.summary(if v & HIGH_BIT != 0 {
                format!("subdirectory at {:#x}", v & !HIGH_BIT)
            } else {
                format!("data entry at {v:#x}")
            })
        })
        .emit()?;
    Ok(())
}

async fn entry(cx: Cx, st: EntryState) -> Result<()> {
    let level = st.dir.path.len().saturating_sub(1);
    cx.emit(struct_node("Entry", st.entry, LE, level, entry_fields));
    if let Some((text, span)) = &st.name_string {
        cx.emit(
            Node::new("Name String")
                .span(*span)
                .value(Value::Text(text.clone()))
                .desc("Length-prefixed UTF-16 (IMAGE_RESOURCE_DIR_STRING_U)"),
        );
    }
    if st.subdirectory {
        table(&cx, &st.dir).await?;
        return Ok(());
    }
    let pe = &st.dir.pe;
    let rva = st
        .dir
        .base
        .checked_add(st.dir.offset)
        .ok_or_else(overflow)?;
    let span = pe.rva_span(rva, 16)?;
    data(&cx, pe, span, st.dir.kind, st.dir.name, st.dir.base).await
}

async fn resource_name(cx: &Cx, pe: &PeInfo, base: u32, offset: u32) -> Result<(String, Span)> {
    let rva = base.checked_add(offset).ok_or_else(overflow)?;
    let len = cx.read(pe.rva_exact(rva, 2)?).await?;
    let len = u16_le(&len, 0).unwrap_or(0);
    let bytes = u64::from(len).saturating_mul(2);
    let text = cx
        .read(pe.rva_exact(rva.checked_add(2).ok_or_else(overflow)?, bytes)?)
        .await?;
    let units: Vec<u16> = (0..usize::from(len))
        .filter_map(|i| u16_le(&text, i.saturating_mul(2)))
        .collect();
    Ok((
        String::from_utf16_lossy(&units),
        pe.rva_span(rva, bytes.saturating_add(2))?,
    ))
}

pub(super) fn id_label(level: usize, id: u32) -> String {
    match level {
        1 => lookup(RESOURCE_TYPE, id.into()).map_or_else(|| format!("#{id}"), str::to_owned),
        3 => format!("Language {}", crate::formats::util::lcid::describe(id)),
        _ => format!("#{id}"),
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct DataEntry {
    rva: u32,
    size: u32,
    code_page: u32,
}

fn resource_data_entry(f: &mut Fields<'_>, pe: &Pe) -> Result<DataEntry> {
    let rva = rva_field(f.u32("OffsetToData"), pe)
        .desc("RVA of the resource data (not an offset)")
        .emit()?;
    let size = f.u32("Size").hex().emit()?;
    let code_page = f
        .u32("CodePage")
        .desc("Code page of text in the data; usually 0 (Unicode)")
        .emit()?;
    f.u32("Reserved").emit()?;
    Ok(DataEntry {
        rva,
        size,
        code_page,
    })
}

async fn data(
    cx: &Cx,
    pe: &Pe,
    span: Span,
    kind: Option<u32>,
    name: Option<u32>,
    base: u32,
) -> Result<()> {
    cx.emit(struct_node(
        "Data Entry",
        span,
        LE,
        pe.clone(),
        resource_data_entry,
    ));
    let entry = parse(cx, span, LE, pe, resource_data_entry).await?;
    let wanted = u64::from(entry.size);
    let content = pe.rva_span(entry.rva, wanted)?;
    let mut node = resource::content(cx, pe.input, content, kind, name).await;
    if content.len < wanted {
        node = node.diag(Diagnostic::truncated(
            Span::new(content.source, content.offset, wanted),
            content.len,
        ));
    }
    cx.emit(node);
    if let Some(k @ (RT_GROUP_ICON | RT_GROUP_CURSOR)) = kind {
        let cursor = k == RT_GROUP_CURSOR;
        match assemble_group(cx, pe, base, content, cursor).await {
            Ok(Some(file)) => cx.emit(
                embedded_as(
                    if cursor {
                        "As .cur file"
                    } else {
                        "As .ico file"
                    },
                    pe.input.nested(file),
                    if cursor {
                        &crate::formats::image::ico::CUR
                    } else {
                        &crate::formats::image::ico::ICO
                    },
                )
                .desc("The group directory and the images it names, joined into an icon file"),
            ),
            Ok(None) => {}
            Err(e) => cx.diag(e),
        }
    }
    Ok(())
}

/// Follows type `kind`, then name `id` (or the first name), then the first
/// language, to a resource's data.
pub(super) async fn find(
    cx: &Cx,
    pe: &PeInfo,
    base: u32,
    kind: u32,
    id: Option<u32>,
) -> Result<Option<Span>> {
    let mut offset = 0u32;
    for level in 0..3 {
        let header_rva = base.checked_add(offset).ok_or_else(overflow)?;
        let header = cx.read(pe.rva_exact(header_rva, 16)?).await?;
        let total = usize::from(u16_le(&header, 12).unwrap_or(0))
            .saturating_add(u16_le(&header, 14).unwrap_or(0).into());
        let entries_rva = header_rva.checked_add(16).ok_or_else(overflow)?;
        let entries = cx
            .read(pe.rva_exact(entries_rva, to_u64(total.min(1024)).saturating_mul(8))?)
            .await?;
        let found = (0..total.min(1024)).find_map(|i| {
            let name = u32_le(&entries, i.saturating_mul(8))?;
            let target = u32_le(&entries, i.saturating_mul(8).saturating_add(4))?;
            match (level, id) {
                (0, _) => name == kind,
                (1, Some(id)) => name == id,
                _ => true,
            }
            .then_some(target)
        });
        let Some(target) = found else {
            return Ok(None);
        };
        offset = target & !HIGH_BIT;
        if target & HIGH_BIT == 0 {
            let entry_rva = base.checked_add(offset).ok_or_else(overflow)?;
            let entry = pe.rva_exact(entry_rva, 16)?;
            let raw = cx.read(entry).await?;
            let rva = u32_le(&raw, 0).unwrap_or(0);
            let size = u32_le(&raw, 4).unwrap_or(0);
            return Ok(Some(pe.rva_span(rva, size.into())?));
        }
    }
    Ok(None)
}

/// Rebuilds an `.ico` / `.cur` file from a group directory (`GRPICONDIR`,
/// 14-byte entries naming `RT_ICON` / `RT_CURSOR` resources by ID): a new
/// header with 16-byte entries holding file offsets, followed by the image
/// resources themselves (cursor images lose their hotspot prefix, which
/// moves into the directory entry).
async fn assemble_group(
    cx: &Cx,
    pe: &PeInfo,
    base: u32,
    group: Span,
    cursor: bool,
) -> Result<Option<Span>> {
    let data = cx.read_avail(group.sub(0, 3590)).await?;
    let count = usize::from(u16_le(&data, 4).unwrap_or(0)).min(256);
    if count == 0 {
        return Ok(None);
    }
    let image_type = if cursor { RT_CURSOR } else { RT_ICON };
    let mut images = Vec::new();
    let mut total = 0u64;
    for i in 0..count {
        let at = 6usize.saturating_add(i.saturating_mul(14));
        let Some(entry) = data.get(at..at.saturating_add(14)) else {
            break;
        };
        let id = u16_le(entry, 12).unwrap_or(0);
        let Some(mut image) = find(cx, pe, base, image_type, Some(id.into())).await? else {
            return Ok(None);
        };
        let mut hotspot = [0u8; 4];
        if cursor {
            let head = cx.read_avail(image.sub(0, 4)).await?;
            for (d, s) in hotspot.iter_mut().zip(&head) {
                *d = *s;
            }
            image = image.tail(4);
        }
        total = total.saturating_add(image.len);
        if total > MAX_GROUP_BYTES {
            return Ok(None);
        }
        images.push((entry.to_vec(), image, hotspot));
    }
    let header_len = 6u64.saturating_add(to_u64(images.len()).saturating_mul(16));
    let mut header = Vec::new();
    header.extend_from_slice(&0u16.to_le_bytes());
    header.extend_from_slice(&(if cursor { 2u16 } else { 1 }).to_le_bytes());
    header.extend_from_slice(&u16::try_from(images.len()).unwrap_or(0).to_le_bytes());
    let mut offset = header_len;
    for (entry, image, hotspot) in &images {
        let get = |i: usize| entry.get(i).copied().unwrap_or(0);
        if cursor {
            // CURSORDIR: wWidth, wHeight (doubled); ICONDIRENTRY: bytes.
            let width = u16_le(entry, 0).unwrap_or(0);
            let height = u16_le(entry, 2).unwrap_or(0) / 2;
            header.push(u8::try_from(width).unwrap_or(0));
            header.push(u8::try_from(height).unwrap_or(0));
            header.push(0);
            header.push(0);
            header.extend_from_slice(hotspot);
        } else {
            header.extend_from_slice(&[get(0), get(1), get(2), get(3)]);
            header.extend_from_slice(&[get(4), get(5), get(6), get(7)]);
        }
        header.extend_from_slice(&u32::try_from(image.len).unwrap_or(0).to_le_bytes());
        header.extend_from_slice(&u32::try_from(offset).unwrap_or(0).to_le_bytes());
        offset = offset.saturating_add(image.len);
    }
    let derived = cx.add_derived(
        Origin {
            parent: group,
            transform: "icon-directory",
        },
        header,
        group.len,
        None,
    )?;
    let mut pieces = vec![derived.span];
    pieces.extend(images.iter().map(|(_, image, _)| *image));
    Ok(Some(cx.add_pieces(
        Origin {
            parent: group,
            transform: "icon-group",
        },
        pieces,
    )?))
}
