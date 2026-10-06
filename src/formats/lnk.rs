//! Windows shell links (`.lnk`, MS-SHLLINK).
//!
//! A fixed header is followed by optional parts announced by its flags: the
//! target's shell item ID list, LinkInfo (volume and local or network path),
//! counted strings (name, relative path, working directory, arguments, icon)
//! and a list of extra data blocks.

use crate::bytes::{u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::Result;
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::datakit::{clip, name_or};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Guid, Value, flag};

const LE: Endian = Endian::Little;
const MAX_STRING: u64 = 0x10000;

pub static FORMAT: Format = Format {
    name: "lnk",
    title: "Windows shell link",
    extensions: &["lnk"],
    mime: "application/x-ms-shortcut",
    probe: Probe::Magic(&[(
        0,
        b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46",
    )]),
    dissect: crate::expander!(dissect: Input),
};

pub const LINK_FLAGS: FlagTable = &[
    flag(0x0000_0001, "HasLinkTargetIDList"),
    flag(0x0000_0002, "HasLinkInfo"),
    flag(0x0000_0004, "HasName"),
    flag(0x0000_0008, "HasRelativePath"),
    flag(0x0000_0010, "HasWorkingDir"),
    flag(0x0000_0020, "HasArguments"),
    flag(0x0000_0040, "HasIconLocation"),
    flag(0x0000_0080, "IsUnicode"),
    flag(0x0000_0100, "ForceNoLinkInfo"),
    flag(0x0000_0200, "HasExpString"),
    flag(0x0000_0400, "RunInSeparateProcess"),
    flag(0x0000_1000, "HasDarwinID"),
    flag(0x0000_2000, "RunAsUser"),
    flag(0x0000_4000, "HasExpIcon"),
    flag(0x0000_8000, "NoPidlAlias"),
    flag(0x0002_0000, "RunWithShimLayer"),
    flag(0x0004_0000, "ForceNoLinkTrack"),
    flag(0x0008_0000, "EnableTargetMetadata"),
    flag(0x0010_0000, "DisableLinkPathTracking"),
    flag(0x0020_0000, "DisableKnownFolderTracking"),
    flag(0x0040_0000, "DisableKnownFolderAlias"),
    flag(0x0080_0000, "AllowLinkToLink"),
    flag(0x0100_0000, "UnaliasOnSave"),
    flag(0x0200_0000, "PreferEnvironmentPath"),
    flag(0x0400_0000, "KeepLocalIDListForUNCTarget"),
];

pub const FILE_ATTRIBUTES: FlagTable = &[
    flag(0x0001, "READONLY"),
    flag(0x0002, "HIDDEN"),
    flag(0x0004, "SYSTEM"),
    flag(0x0010, "DIRECTORY"),
    flag(0x0020, "ARCHIVE"),
    flag(0x0040, "DEVICE"),
    flag(0x0080, "NORMAL"),
    flag(0x0100, "TEMPORARY"),
    flag(0x0200, "SPARSE_FILE"),
    flag(0x0400, "REPARSE_POINT"),
    flag(0x0800, "COMPRESSED"),
    flag(0x1000, "OFFLINE"),
    flag(0x2000, "NOT_CONTENT_INDEXED"),
    flag(0x4000, "ENCRYPTED"),
];

const SHOW: EnumTable = &[
    (1, "SW_SHOWNORMAL"),
    (3, "SW_SHOWMAXIMIZED"),
    (7, "SW_SHOWMINNOACTIVE"),
];

const DRIVE_TYPES: EnumTable = &[
    (0, "DRIVE_UNKNOWN"),
    (1, "DRIVE_NO_ROOT_DIR"),
    (2, "DRIVE_REMOVABLE"),
    (3, "DRIVE_FIXED"),
    (4, "DRIVE_REMOTE"),
    (5, "DRIVE_CDROM"),
    (6, "DRIVE_RAMDISK"),
];

const LINK_INFO_FLAGS: FlagTable = &[
    flag(1, "VolumeIDAndLocalBasePath"),
    flag(2, "CommonNetworkRelativeLinkAndPathSuffix"),
];

const EXTRA_BLOCKS: EnumTable = &[
    (0xa000_0001, "EnvironmentVariableDataBlock"),
    (0xa000_0002, "ConsoleDataBlock"),
    (0xa000_0003, "TrackerDataBlock"),
    (0xa000_0004, "ConsoleFEDataBlock"),
    (0xa000_0005, "SpecialFolderDataBlock"),
    (0xa000_0006, "DarwinDataBlock"),
    (0xa000_0007, "IconEnvironmentDataBlock"),
    (0xa000_0008, "ShimDataBlock"),
    (0xa000_0009, "PropertyStoreDataBlock"),
    (0xa000_000b, "KnownFolderDataBlock"),
    (0xa000_000c, "VistaAndAboveIDListDataBlock"),
];

/// Well-known shell folder GUIDs seen in root items.
const FOLDERS: &[(&str, &str)] = &[
    ("{20d04fe0-3aea-1069-a2d8-08002b30309d}", "My Computer"),
    ("{450d8fba-ad25-11d0-98a8-0800361b1103}", "My Documents"),
    (
        "{208d2c60-3aea-1069-a2d7-08002b30309d}",
        "My Network Places",
    ),
    ("{645ff040-5081-101b-9f08-00aa002f954e}", "Recycle Bin"),
    ("{59031a47-3f72-44a7-89c5-5595fe6b30ee}", "User Files"),
    ("{21ec2020-3aea-1069-a2dd-08002b30309d}", "Control Panel"),
    ("{031e4825-7b94-4dc3-b131-e946b44c8dd5}", "Libraries"),
    ("{f02c1a0d-be21-4350-88b0-7367fc96ef3c}", "Network"),
    ("{679f85cb-0220-4080-b29b-5540cc05aab6}", "Quick Access"),
    ("{e2e7934b-dce5-43c4-9576-7fe4f75e7480}", "Desktop"),
];

fn folder_name(guid: &Guid) -> Option<&'static str> {
    let text = guid.to_string();
    FOLDERS.iter().find(|(g, _)| *g == text).map(|(_, n)| *n)
}

/// `HotKeyFlags`: virtual key in the low byte, modifiers in the high byte.
fn hotkey(k: u16) -> String {
    if k == 0 {
        return "none".to_owned();
    }
    let mut parts = Vec::new();
    for (bit, name) in [(0x200, "Ctrl"), (0x400, "Alt"), (0x100, "Shift")] {
        if k & bit != 0 {
            parts.push(name.to_owned());
        }
    }
    let key = (k & 0xff) as u8;
    parts.push(match key {
        b'0'..=b'9' | b'A'..=b'Z' => char::from(key).to_string(),
        0x70..=0x87 => format!("F{}", key.saturating_sub(0x6f)),
        _ => format!("VK {key:#04x}"),
    });
    parts.join("+")
}

record! {
    pub struct Header {
        size: u32 "HeaderSize" .hex(),
        clsid: guid "LinkCLSID",
        flags: u32 "LinkFlags" .flags(LINK_FLAGS),
        attributes: u32 "FileAttributes" .flags(FILE_ATTRIBUTES),
        created: u64 "CreationTime" .filetime(),
        accessed: u64 "AccessTime" .filetime(),
        written: u64 "WriteTime" .filetime(),
        file_size: u32 "FileSize",
        icon_index: i32 "IconIndex",
        show: u32 "ShowCommand" .enumeration(SHOW),
        hotkey: u16 "HotKey" .hex() .with(|&k, n| n.summary(hotkey(k))),
        _reserved1: u16 "Reserved1",
        _reserved2: u32 "Reserved2",
        _reserved3: u32 "Reserved3",
    }
}

record! {
    pub struct LinkInfoHeader {
        size: u32 "LinkInfoSize",
        header_size: u32 "LinkInfoHeaderSize" .hex(),
        flags: u32 "LinkInfoFlags" .flags(LINK_INFO_FLAGS),
        volume: u32 "VolumeIDOffset" .hex(),
        local_base: u32 "LocalBasePathOffset" .hex(),
        network: u32 "CommonNetworkRelativeLinkOffset" .hex(),
        suffix: u32 "CommonPathSuffixOffset" .hex(),
    }
}

const STRINGS: [(u32, &str); 5] = [
    (0x04, "NAME_STRING"),
    (0x08, "RELATIVE_PATH"),
    (0x10, "WORKING_DIR"),
    (0x20, "COMMAND_LINE_ARGUMENTS"),
    (0x40, "ICON_LOCATION"),
];

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let (header, span) = cur.record::<Header>().await?;
    cx.emit(Header::node("ShellLinkHeader", span, LE));
    let unicode = header.flags & 0x80 != 0;
    let mut target = None;

    if header.flags & 0x01 != 0 {
        let start = cur.pos();
        let size = cur.u16().await?;
        let list = cur.span(size.into());
        cur.skip(size.into());
        let (items, path) = id_list_summary(&cx, list).await;
        target = target.or(path);
        cx.emit(
            Node::new("LinkTargetIDList")
                .span(cur.since(start))
                .summary(format!("{items} items"))
                .lazy(id_list, list),
        );
    }
    if header.flags & 0x02 != 0 && header.flags & 0x100 == 0 {
        let start = cur.pos();
        let size = cur.u32().await?;
        let span = file.sub(start, size.into());
        cur.seek(start.saturating_add(size.into()));
        let path = link_info_path(&cx, span).await.ok().flatten();
        let mut node = Node::new("LinkInfo").span(span).lazy(link_info, span);
        if let Some(p) = &path {
            node = node.summary(p.clone());
        }
        target = path.or(target);
        cx.emit(node);
    }
    let mut strings = Vec::new();
    for (bit, name) in STRINGS {
        if header.flags & bit == 0 {
            continue;
        }
        let start = cur.pos();
        let count = cur.u16().await?;
        let len = if unicode {
            u64::from(count).saturating_mul(2)
        } else {
            count.into()
        };
        let span = cur.span(len.min(MAX_STRING));
        let bytes = cx.read(span).await?;
        cur.skip(len);
        let text = if unicode {
            crate::text::utf16(&bytes, LE)
        } else {
            crate::text::latin1(&bytes)
        };
        strings.push((bit, text.clone()));
        cx.emit(
            Node::new(name)
                .span(cur.since(start))
                .value(Value::Text(text))
                .summary(format!("{count} characters")),
        );
    }
    let extra = file.tail(cur.pos());
    if !extra.is_empty() {
        cx.emit(Node::new("ExtraData").span(extra).lazy(extra_data, extra));
    }

    let mut summary = String::from("shell link");
    let relative = strings
        .iter()
        .find(|(b, _)| *b == 0x08)
        .map(|(_, t)| t.clone());
    if let Some(t) = target.or(relative) {
        summary = format!("{summary} → {}", clip(&t, 120));
    }
    if let Some((_, args)) = strings.iter().find(|(b, _)| *b == 0x20) {
        summary = format!("{summary} {}", clip(args, 60));
    }
    cx.annotate(summary);
    Ok(())
}

/// Item count and a path assembled from volume and file entry names.
async fn id_list_summary(cx: &Cx, list: Span) -> (u64, Option<String>) {
    let Ok(data) = cx.read_avail(list.sub(0, 0x10000)).await else {
        return (0, None);
    };
    let mut at = 0usize;
    let mut count = 0u64;
    let mut parts: Vec<String> = Vec::new();
    while let Some(size) = u16_le(&data, at) {
        if size < 2 {
            break;
        }
        let item = data
            .get(at.saturating_add(2)..at.saturating_add(size.into()))
            .unwrap_or_default();
        match shell_item(item) {
            ShellItem::Volume(v) => parts.push(v.trim_end_matches('\\').to_owned()),
            ShellItem::File { long, short, .. } => parts.push(long.unwrap_or(short)),
            _ => {}
        }
        count = count.saturating_add(1);
        at = at.saturating_add(size.into());
    }
    let path = (!parts.is_empty()).then(|| parts.join("\\"));
    (count, path)
}

enum ShellItem {
    Root(Guid),
    Volume(String),
    File {
        directory: bool,
        size: u32,
        modified: (u16, u16),
        attributes: u16,
        short: String,
        long: Option<String>,
    },
    Other(u8),
}

fn guid_at(data: &[u8], at: usize) -> Option<Guid> {
    let b = data.get(at..at.checked_add(16)?)?;
    let mut data4 = [0u8; 8];
    data4.copy_from_slice(b.get(8..16)?);
    Some(Guid {
        data1: u32_le(b, 0)?,
        data2: u16_le(b, 4)?,
        data3: u16_le(b, 6)?,
        data4,
    })
}

/// Decodes a shell item (without its size field).
fn shell_item(item: &[u8]) -> ShellItem {
    let kind = item.first().copied().unwrap_or(0);
    match kind {
        0x1f => match guid_at(item, 2) {
            Some(g) => ShellItem::Root(g),
            None => ShellItem::Other(kind),
        },
        0x20..=0x2f => ShellItem::Volume(crate::text::until_nul(item.get(1..).unwrap_or_default())),
        0x30..=0x3f => {
            let unicode = kind & 0x04 != 0;
            let size = u32_le(item, 2).unwrap_or(0);
            let date = u16_le(item, 6).unwrap_or(0);
            let time = u16_le(item, 8).unwrap_or(0);
            let attributes = u16_le(item, 10).unwrap_or(0);
            let rest = item.get(12..).unwrap_or_default();
            let (short, used) = if unicode {
                let (t, n, _) = crate::text::utf16z(rest, LE);
                (t, n)
            } else {
                let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
                (
                    crate::text::latin1(rest.get(..end).unwrap_or_default()),
                    end.saturating_add(1),
                )
            };
            // The BEEF0004 extension block (2-aligned) holds the long name.
            let ext = 12usize
                .saturating_add(used)
                .checked_next_multiple_of(2)
                .unwrap_or(usize::MAX);
            let long = item.get(ext..).and_then(|e| {
                if u32_le(e, 4)? != 0xbeef_0004 {
                    return None;
                }
                let name_at = match u16_le(e, 2)? {
                    3..=6 => 0x14,
                    7 => 0x26,
                    8 => 0x2a,
                    _ => 0x2e,
                };
                let (t, _, ok) = crate::text::utf16z(e.get(name_at..)?, LE);
                ok.then_some(t)
            });
            ShellItem::File {
                directory: kind & 0x01 != 0,
                size,
                modified: (date, time),
                attributes,
                short,
                long,
            }
        }
        _ => ShellItem::Other(kind),
    }
}

async fn id_list(cx: Cx, list: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, list, LE);
    let mut index = 0u64;
    while cur.remaining() >= 2 {
        let start = cur.pos();
        let size = cur.u16().await?;
        if size < 2 {
            cx.emit(Node::new("TerminalID").span(cur.since(start)));
            break;
        }
        let span = list.sub(start, size.into());
        let data = cx.read(span).await?;
        cur.seek(start.saturating_add(size.into()));
        let item = data.get(2..).unwrap_or_default();
        let (name, summary) = match shell_item(item) {
            ShellItem::Root(g) => (
                "Root folder".to_owned(),
                folder_name(&g).map_or_else(|| g.to_string(), |n| format!("{n} {g}")),
            ),
            ShellItem::Volume(v) => ("Volume".to_owned(), v),
            ShellItem::File {
                directory,
                size,
                modified,
                attributes,
                short,
                long,
            } => (
                if directory { "Directory" } else { "File" }.to_owned(),
                format!(
                    "{}{}, {size} bytes, modified {}, attributes {attributes:#x}",
                    long.as_deref().unwrap_or(&short),
                    if long.is_some() {
                        format!(" ({short})")
                    } else {
                        String::new()
                    },
                    crate::text::dos_datetime(modified.0, modified.1)
                ),
            ),
            ShellItem::Other(k) => (format!("Item type {k:#04x}"), format!("{size} bytes")),
        };
        cx.push(
            Node::new(format!("{name} {index}"))
                .span(span)
                .summary(summary)
                .lazy(item_fields, span),
        )
        .await;
        index = index.saturating_add(1);
    }
    Ok(())
}

async fn item_fields(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u16("ItemIDSize").emit()?;
    let kind = f.u8("Class type").hex().emit()?;
    match kind {
        0x1f => {
            f.u8("Sort index").emit()?;
            f.guid("Shell folder")
                .with(|g, n| match folder_name(g) {
                    Some(name) => n.summary(name),
                    None => n,
                })
                .emit()?;
        }
        0x20..=0x2f => {
            f.cstr("Volume name").emit()?;
        }
        0x30..=0x3f => {
            f.u8("Unknown").emit()?;
            f.u32("File size").emit()?;
            let date = f.u16("Modification date (DOS)").hex().emit()?;
            f.u16("Modification time (DOS)")
                .hex()
                .with(|&t, n| n.summary(crate::text::dos_datetime(date, t)))
                .emit()?;
            f.u16("File attributes").flags(FILE_ATTRIBUTES).emit()?;
            if kind & 0x04 != 0 {
                f.utf16z("Primary name").emit()?;
            } else {
                f.cstr("Primary name").emit()?;
            }
            if !f.pos().is_multiple_of(2) {
                f.skip(1);
            }
            if f.remaining() > 8 {
                let rest = f.remaining();
                f.node(
                    Node::new("Extension block")
                        .span(f.peek_span(rest))
                        .lazy(beef0004, f.peek_span(rest)),
                );
            }
        }
        _ => {
            if f.remaining() > 0 {
                f.bytes("Data", f.remaining()).emit()?;
            }
        }
    }
    Ok(())
}

async fn beef0004(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    let size = f.u16("Size").emit()?;
    let version = f.u16("Version").emit()?;
    f.u32("Signature").hex().emit()?;
    let date = f.u16("Creation date (DOS)").hex().emit()?;
    f.u16("Creation time (DOS)")
        .hex()
        .with(|&t, n| n.summary(crate::text::dos_datetime(date, t)))
        .emit()?;
    let date = f.u16("Access date (DOS)").hex().emit()?;
    f.u16("Access time (DOS)")
        .hex()
        .with(|&t, n| n.summary(crate::text::dos_datetime(date, t)))
        .emit()?;
    f.u16("Identifier").hex().emit()?;
    if version >= 7 {
        f.u16("Unknown").emit()?;
        f.u64("NTFS file reference")
            .hex()
            .with(|&r, n| {
                n.summary(format!(
                    "MFT entry {}, sequence {}",
                    r & 0xffff_ffff_ffff,
                    r >> 48
                ))
            })
            .emit()?;
        f.u64("Unknown").emit()?;
    }
    if version >= 3 {
        f.u16("Long string size").emit()?;
    }
    if version >= 9 {
        f.u32("Unknown").emit()?;
    }
    if version >= 8 {
        f.u32("Unknown").emit()?;
    }
    f.utf16z("Long name").emit()?;
    let end = u64::from(size).saturating_sub(2);
    if f.pos() < end {
        f.seek(end);
    }
    if f.remaining() >= 2 {
        f.u16("First extension block offset").hex().emit()?;
    }
    Ok(())
}

/// The local base path (plus suffix) or network path of a LinkInfo.
async fn link_info_path(cx: &Cx, span: Span) -> Result<Option<String>> {
    let data = cx.read_avail(span.sub(0, 0x10000)).await?;
    let get = |at: u32| -> Option<String> {
        let at = crate::bytes::to_usize(at.into());
        (at > 0).then(|| crate::text::until_nul(data.get(at..).unwrap_or_default()))
    };
    let flags = u32_le(&data, 8).unwrap_or(0);
    let suffix = get(u32_le(&data, 24).unwrap_or(0)).unwrap_or_default();
    if flags & 1 != 0 {
        let base = get(u32_le(&data, 16).unwrap_or(0)).unwrap_or_default();
        return Ok(Some(format!("{base}{suffix}")));
    }
    if flags & 2 != 0 {
        let link = crate::bytes::to_usize(u32_le(&data, 20).unwrap_or(0).into());
        let name = u32_le(&data, link.saturating_add(8)).unwrap_or(0);
        let net = get(u32::try_from(link).unwrap_or(0).saturating_add(name)).unwrap_or_default();
        return Ok(Some(format!("{net}\\{suffix}")));
    }
    Ok(None)
}

async fn link_info(cx: Cx, span: Span) -> Result<()> {
    let header = parse(
        &cx,
        span.sub(0, LinkInfoHeader::SIZE),
        LE,
        &(),
        LinkInfoHeader::layout,
    )
    .await?;
    cx.emit(LinkInfoHeader::node(
        "Header",
        span.sub(0, LinkInfoHeader::SIZE),
        LE,
    ));
    if header.header_size >= 0x24 {
        let ext = span.sub(LinkInfoHeader::SIZE, 8);
        cx.emit(struct_node("Unicode offsets", ext, LE, (), |f, _| {
            f.u32("LocalBasePathOffsetUnicode").hex().emit()?;
            f.u32("CommonPathSuffixOffsetUnicode").hex().emit()?;
            Ok(())
        }));
    }
    if header.flags & 1 != 0 && header.volume > 0 {
        let at = u64::from(header.volume);
        let size = crate::bytes::u32_le(&cx.read(span.sub_exact(at, 4)?).await?, 0).unwrap_or(0);
        let vol = span.sub(at, size.into());
        cx.emit(struct_node("VolumeID", vol, LE, (), volume_id));
    }
    if header.flags & 1 != 0 && header.local_base > 0 {
        cx.emit(cstring(&cx, "LocalBasePath", span, header.local_base).await?);
    }
    if header.flags & 2 != 0 && header.network > 0 {
        let at = u64::from(header.network);
        let size = crate::bytes::u32_le(&cx.read(span.sub_exact(at, 4)?).await?, 0).unwrap_or(0);
        let link = span.sub(at, size.into());
        cx.emit(struct_node(
            "CommonNetworkRelativeLink",
            link,
            LE,
            (),
            network_link,
        ));
    }
    if header.suffix > 0 {
        cx.emit(cstring(&cx, "CommonPathSuffix", span, header.suffix).await?);
    }
    Ok(())
}

async fn cstring(cx: &Cx, name: &'static str, span: Span, offset: u32) -> Result<Node> {
    let (text, at) = cx.cstr(span.tail(offset.into())).await?;
    Ok(Node::new(name).span(at).value(Value::Text(text)))
}

fn volume_id(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("VolumeIDSize").emit()?;
    f.u32("DriveType").enumeration(DRIVE_TYPES).emit()?;
    f.u32("DriveSerialNumber").hex().emit()?;
    let offset = f.u32("VolumeLabelOffset").hex().emit()?;
    if offset == 0x14 {
        let unicode = f.u32("VolumeLabelOffsetUnicode").hex().emit()?;
        f.seek(unicode.into());
        f.utf16z("VolumeLabel").emit()?;
    } else {
        f.seek(offset.into());
        f.cstr("VolumeLabel").emit()?;
    }
    Ok(())
}

const NETWORK_PROVIDERS: EnumTable = &[
    (0x0002_0000, "WNNC_NET_LANMAN"),
    (0x0001_0000, "WNNC_NET_MSNET"),
    (0x0024_0000, "WNNC_NET_DAV"),
    (0x0029_0000, "WNNC_NET_RDR2SAMPLE"),
];

const NETWORK_LINK_FLAGS: FlagTable = &[flag(1, "ValidDevice"), flag(2, "ValidNetType")];

fn network_link(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("CommonNetworkRelativeLinkSize").emit()?;
    let flags = f
        .u32("CommonNetworkRelativeLinkFlags")
        .flags(NETWORK_LINK_FLAGS)
        .emit()?;
    let net_name = f.u32("NetNameOffset").hex().emit()?;
    let device = f.u32("DeviceNameOffset").hex().emit()?;
    f.u32("NetworkProviderType")
        .enumeration(NETWORK_PROVIDERS)
        .emit()?;
    f.seek(net_name.into());
    f.cstr("NetName").emit()?;
    if flags & 1 != 0 && device > 0 {
        f.seek(device.into());
        f.cstr("DeviceName").emit()?;
    }
    Ok(())
}

async fn extra_data(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, LE);
    while cur.remaining() >= 4 {
        let start = cur.pos();
        let size = cur.u32().await?;
        if size < 4 {
            cx.emit(Node::new("TerminalBlock").span(cur.since(start)));
            break;
        }
        let signature = cur.u32().await?;
        cur.seek(start.saturating_add(size.into()));
        let block = span.sub(start, size.into());
        let name = name_or(EXTRA_BLOCKS, signature.into(), "Block");
        let layout: Option<crate::fields::Layout<(), ()>> = match signature {
            0xa000_0001 | 0xa000_0006 | 0xa000_0007 => Some(env_block),
            0xa000_0003 => Some(tracker_block),
            0xa000_0004 => Some(console_fe_block),
            0xa000_0005 => Some(special_folder_block),
            0xa000_0008 => Some(shim_block),
            0xa000_000b => Some(known_folder_block),
            _ => None,
        };
        let summary = format!("{size} bytes");
        let node = match (signature, layout) {
            (_, Some(layout)) => struct_node(name, block, LE, (), layout).summary(summary),
            (0xa000_000c, None) => Node::new(name)
                .span(block)
                .summary(summary)
                .lazy(vista_id_list, block),
            _ => Node::new(name).span(block).summary(summary),
        };
        cx.push(node).await;
    }
    Ok(())
}

fn block_header(f: &mut Fields<'_>) -> Result<()> {
    f.u32("BlockSize").emit()?;
    f.u32("BlockSignature").enumeration(EXTRA_BLOCKS).emit()?;
    Ok(())
}

fn env_block(f: &mut Fields<'_>, _: &()) -> Result<()> {
    block_header(f)?;
    f.ascii("TargetAnsi", 260).emit()?;
    f.utf16("TargetUnicode", 260).emit()?;
    Ok(())
}

fn tracker_block(f: &mut Fields<'_>, _: &()) -> Result<()> {
    block_header(f)?;
    f.u32("Length").emit()?;
    f.u32("Version").emit()?;
    f.ascii("MachineID", 16).emit()?;
    f.guid("Droid volume").emit()?;
    f.guid("Droid file").emit()?;
    f.guid("DroidBirth volume").emit()?;
    f.guid("DroidBirth file").emit()?;
    Ok(())
}

fn console_fe_block(f: &mut Fields<'_>, _: &()) -> Result<()> {
    block_header(f)?;
    f.u32("CodePage").emit()?;
    Ok(())
}

fn special_folder_block(f: &mut Fields<'_>, _: &()) -> Result<()> {
    block_header(f)?;
    f.u32("SpecialFolderID").emit()?;
    f.u32("Offset").hex().emit()?;
    Ok(())
}

fn shim_block(f: &mut Fields<'_>, _: &()) -> Result<()> {
    block_header(f)?;
    f.utf16z("LayerName").emit()?;
    Ok(())
}

fn known_folder_block(f: &mut Fields<'_>, _: &()) -> Result<()> {
    block_header(f)?;
    f.guid("KnownFolderID").emit()?;
    f.u32("Offset").hex().emit()?;
    Ok(())
}

async fn vista_id_list(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span.sub(0, 8)).await?;
    block_header(&mut Fields::emitting(&cx, &block, LE))?;
    let list = span.tail(8);
    cx.emit(Node::new("IDList").span(list).lazy(id_list, list));
    Ok(())
}
