//! Game audio and video middleware: FMOD sound banks, XACT wave banks and
//! Wwise sound banks, Sony VAG and OpenMG, CRI (HCA, USM, CPK, AFS) and
//! Electronic Arts audio streams.

use crate::bytes::{to_u64, u16_be, u16_le, u32_be, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Chunk, ChunkLayout, Cursor, Record, emit_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::val::text;
use crate::formats::{Head, Input, Probe, embedded};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::text::until_nul;
use crate::value::{EnumTable, Value};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

/// Pushes a node for every chunk of `region` from `start`; returns the chunks.
async fn chunks(cx: &Cx, region: Span, start: u64, layout: ChunkLayout) -> Result<Vec<Chunk>> {
    let mut cur = Cursor::new(cx, region, layout.endian);
    cur.seek(start);
    let mut out = Vec::new();
    while let Some(chunk) = cur.chunk(layout).await? {
        cx.push(chunk.node()).await;
        out.push(chunk);
    }
    Ok(out)
}

/// "3× A, 1× B" for chunk kinds in order of first appearance.
fn tally(found: &[Chunk]) -> String {
    let mut counts: Vec<(String, u32)> = Vec::new();
    for c in found {
        let id = c.name();
        match counts.iter_mut().find(|(k, _)| *k == id) {
            Some((_, n)) => *n = n.saturating_add(1),
            None => counts.push((id, 1)),
        }
    }
    counts
        .iter()
        .map(|(k, n)| format!("{n}× {k}"))
        .collect::<Vec<_>>()
        .join(", ")
}

// ---------------------------------------------------------------------------
// FMOD sound banks

const FSB5_CODECS: EnumTable = &[
    (1, "PCM8"),
    (2, "PCM16"),
    (3, "PCM24"),
    (4, "PCM32"),
    (5, "PCM float"),
    (6, "GameCube ADPCM"),
    (7, "IMA ADPCM"),
    (8, "VAG"),
    (9, "HEVAG"),
    (10, "XMA"),
    (11, "MPEG"),
    (12, "CELT"),
    (13, "ATRAC9"),
    (14, "xWMA"),
    (15, "Vorbis"),
    (16, "FMOD ADPCM"),
    (17, "Opus"),
];

declare_format!(pub FSB = "fsb", "FMOD sound bank", ["fsb", "bank"], "audio/x-fsb",
    Probe::Magic(&[(0, b"FSB5"), (0, b"FSB4"), (0, b"FSB3")]), fsb);

async fn fsb(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let magic = cx.read(file.sub(0, 4)).await?;
    if magic == b"FSB5" {
        let head = cx.block(file.sub(0, 28)).await?;
        let mut f = Fields::emitting(&cx, &head, LE);
        f.ascii("Signature", 4).emit()?;
        let version = f.u32("Version").emit()?;
        let samples = f.u32("Samples").emit()?;
        let headers = f.u32("Sample headers size").emit()?;
        let names = f.u32("Name table size").emit()?;
        let data = f.u32("Data size").emit()?;
        let mode = f.u32("Codec").enumeration(FSB5_CODECS).emit()?;
        let header_len: u64 = if version == 0 { 0x40 } else { 0x3c };
        let at = header_len;
        cx.emit(Node::new("Sample headers").span(file.sub(at, headers.into())));
        let at = at.saturating_add(headers.into());
        if names > 0 {
            cx.emit(Node::new("Name table").span(file.sub(at, names.into())));
        }
        let at = at.saturating_add(names.into());
        cx.emit(Node::new("Sample data").span(file.sub(at, data.into())));
        let codec = FSB5_CODECS
            .iter()
            .find(|(k, _)| *k == u64::from(mode))
            .map_or("unknown codec", |(_, v)| v);
        cx.annotate(format!("FMOD FSB5 bank, {samples} samples, {codec}"));
    } else {
        let v4 = magic == b"FSB4";
        let head = cx.block(file.sub(0, 24)).await?;
        let mut f = Fields::emitting(&cx, &head, LE);
        f.ascii("Signature", 4).emit()?;
        let samples = f.u32("Samples").emit()?;
        let headers = f.u32("Sample headers size").emit()?;
        let data = f.u32("Data size").emit()?;
        f.u32("Version").hex().emit()?;
        f.u32("Mode").hex().emit()?;
        let header_len: u64 = if v4 { 48 } else { 24 };
        // FSB4 sample headers: u16 size, name[30], ...
        let mut pos = header_len;
        let end = header_len.saturating_add(headers.into());
        let mut n = 0u32;
        while pos.saturating_add(32) <= end && n < samples {
            let h = cx.read(file.sub(pos, 32)).await?;
            let size = u64::from(u16_le(&h, 0).unwrap_or(0));
            if size < 32 {
                break;
            }
            cx.push(
                Node::new(until_nul(h.get(2..32).unwrap_or_default()))
                    .span(file.sub(pos, size))
                    .summary("sample header"),
            )
            .await;
            pos = pos.saturating_add(size);
            n = n.saturating_add(1);
        }
        cx.emit(Node::new("Sample data").span(file.sub(end, data.into())));
        cx.annotate(format!(
            "FMOD {} bank, {samples} samples",
            if v4 { "FSB4" } else { "FSB3" }
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// XACT wave banks and Wwise sound banks

declare_format!(pub XWB = "xwb", "XACT wave bank", ["xwb"], "audio/x-xwb",
    Probe::Magic(&[(0, b"WBND"), (0, b"DNBW")]), xwb);

async fn xwb(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let endian = if cx.read(file.sub(0, 4)).await? == b"WBND" {
        LE
    } else {
        BE
    };
    let head = cx.block(file.sub(0, 52)).await?;
    let mut f = Fields::emitting(&cx, &head, endian);
    f.ascii("Signature", 4).emit()?;
    let version = f.u32("Content version").emit()?;
    let v42 = version >= 42;
    if v42 {
        f.u32("Header version").emit()?;
    }
    const SEGMENTS: [(&str, &str, &str); 5] = [
        ("Bank data", "Bank data offset", "Bank data length"),
        (
            "Entry metadata",
            "Entry metadata offset",
            "Entry metadata length",
        ),
        ("Seek tables", "Seek tables offset", "Seek tables length"),
        ("Entry names", "Entry names offset", "Entry names length"),
        ("Wave data", "Wave data offset", "Wave data length"),
    ];
    let mut regions = Vec::new();
    for (name, offset_label, len_label) in SEGMENTS {
        let offset = f.u32(offset_label).hex().emit()?;
        let len = f.u32(len_label).emit()?;
        regions.push((name, u64::from(offset), u64::from(len)));
    }
    let mut bank = String::new();
    let mut count = 0u32;
    for (name, offset, len) in &regions {
        if *len == 0 {
            continue;
        }
        let span = file.sub(*offset, *len);
        let mut node = Node::new(*name).span(span);
        if *name == "Bank data" {
            let b = cx.read_avail(span.sub(0, 72)).await?;
            count = if endian == LE {
                u32_le(&b, 4)
            } else {
                u32_be(&b, 4)
            }
            .unwrap_or(0);
            bank = until_nul(b.get(8..72).unwrap_or_default());
            node = node.summary(format!("{bank:?}, {count} entries"));
        }
        cx.emit(node);
    }
    cx.annotate(format!(
        "XACT wave bank {bank:?} (v{version}), {count} waves"
    ));
    Ok(())
}

fn bnk_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"BKHD") && u32_le(h.data, 4).is_some_and(|n| (8..=0x100).contains(&n))
}

declare_format!(pub WWISE_BNK = "wwise-bnk", "Wwise sound bank", ["bnk"], "audio/x-wwise-bnk",
    Probe::Custom(bnk_probe), wwise_bnk);

async fn wwise_bnk(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut pos = 0u64;
    let mut version = 0u32;
    let mut id = 0u32;
    let mut index: Vec<(u32, u64, u64)> = Vec::new();
    let mut media = 0usize;
    while pos.saturating_add(8) <= file.len {
        let h = cx.read(file.sub(pos, 8)).await?;
        let kind = String::from_utf8_lossy(h.get(..4).unwrap_or_default()).into_owned();
        let size = u64::from(u32_le(&h, 4).unwrap_or(0));
        let body = file.sub(pos.saturating_add(8), size);
        let span = file.sub(pos, size.saturating_add(8));
        match kind.as_str() {
            "BKHD" => {
                let b = cx.read_avail(body.sub(0, 8)).await?;
                version = u32_le(&b, 0).unwrap_or(0);
                id = u32_le(&b, 4).unwrap_or(0);
                cx.push(
                    Node::new("BKHD")
                        .span(span)
                        .summary(format!("bank header, version {version}, id {id:#x}")),
                )
                .await;
            }
            "DIDX" => {
                let b = cx.read(body.sub(0, size.min(12 * 4096))).await?;
                for e in b.as_chunks::<12>().0 {
                    index.push((
                        u32_le(e, 0).unwrap_or(0),
                        u32_le(e, 4).unwrap_or(0).into(),
                        u32_le(e, 8).unwrap_or(0).into(),
                    ));
                }
                media = index.len();
                cx.push(
                    Node::new("DIDX")
                        .span(span)
                        .summary(format!("media index, {media} entries")),
                )
                .await;
            }
            "DATA" => {
                let mut node = Node::new("DATA")
                    .span(span)
                    .summary(format!("{} media files", index.len()));
                // Media are embedded WEM (RIFF) files.
                node = node.lazy(bnk_media, (input, body, index.clone()));
                cx.push(node).await;
            }
            "HIRC" => {
                let b = cx.read_avail(body.sub(0, 4)).await?;
                cx.push(
                    Node::new("HIRC")
                        .span(span)
                        .summary(format!("{} hierarchy objects", u32_le(&b, 0).unwrap_or(0))),
                )
                .await;
            }
            _ => {
                cx.push(Node::new(kind).span(span).summary(format!("{size} bytes")))
                    .await
            }
        }
        pos = pos.saturating_add(8).saturating_add(size);
    }
    cx.annotate(format!(
        "Wwise sound bank {id:#x} (v{version}), {media} embedded media"
    ));
    Ok(())
}

async fn bnk_media(
    cx: Cx,
    (input, data, index): (Input, Span, Vec<(u32, u64, u64)>),
) -> Result<()> {
    for (id, offset, size) in index {
        cx.push(embedded(
            format!("{id}.wem"),
            input.nested(data.sub(offset, size)),
        ))
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Sony: VAG, OpenMG (OMA)

declare_format!(pub VAG = "vag", "Sony VAG audio", ["vag", "vig"], "audio/x-vag",
    Probe::Magic(&[(0, b"VAGp"), (0, b"VAGi")]), vag);

record! {
    pub struct VagHeader {
        magic: ascii[4] "Signature",
        version: u32 "Version" .hex(),
        reserved: u32 "Reserved",
        size: u32 "Data size",
        rate: u32 "Sample rate",
        reserved2: bytes[10] "Reserved",
        channels: u8 "Channels",
        reserved3: u8 "Reserved",
        name: ascii[16] "Name",
    }
}

async fn vag(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: VagHeader = emit_record(&cx, file.sub(0, VagHeader::SIZE), BE).await?;
    cx.emit(
        Node::new("ADPCM data")
            .span(file.sub(48, h.size.into()))
            .summary(format!("{} frames of 16 bytes", h.size / 16)),
    );
    cx.annotate(format!(
        "Sony VAG {:?}, {} Hz, {} channel(s)",
        h.name.trim(),
        h.rate,
        h.channels.max(1)
    ));
    Ok(())
}

declare_format!(pub OMA = "openmg", "Sony OpenMG audio (OMA/AA3)", ["oma", "omg", "aa3"], "audio/x-oma",
    Probe::Magic(&[(0, b"ea3\x03"), (0, b"EA3\x03")]), oma);

async fn oma(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 10)).await?;
    let size = head
        .get(6..10)
        .unwrap_or_default()
        .iter()
        .fold(0u64, |a, &b| a.wrapping_shl(7) | u64::from(b & 0x7f));
    let tag = file.sub(0, size.saturating_add(10));
    cx.emit(
        Node::new("ID3-style tag")
            .span(tag)
            .summary(format!("{} bytes", size)),
    );
    let at = tag.len;
    let h = cx.read_avail(file.sub(at, 0x60)).await?;
    let codec = h.get(0x20).copied().unwrap_or(0xff);
    let name = match codec {
        0 => "ATRAC3",
        1 => "ATRAC3plus",
        3 => "MP3",
        4 => "LPCM",
        5 => "WMA",
        _ => "unknown codec",
    };
    cx.emit(Node::new("EA3 header").span(file.sub(at, 0x60)));
    cx.emit(
        Node::new("Codec")
            .span(file.sub(at.saturating_add(0x20), 1))
            .value(Value::Enum {
                raw: codec.into(),
                bits: 8,
                name: Some(name),
            }),
    );
    cx.emit(Node::new("Audio").span(file.tail(at.saturating_add(0x60))));
    cx.annotate(format!("OpenMG audio, {name}"));
    Ok(())
}

// ---------------------------------------------------------------------------
// CRI Middleware: HCA, USM, CPK, AFS

fn hca_probe(h: &Head<'_>) -> bool {
    h.data
        .get(..4)
        .is_some_and(|m| m.iter().map(|b| b & 0x7f).eq(b"HCA\0".iter().copied()))
}

declare_format!(pub HCA = "hca", "CRI HCA audio", ["hca"], "audio/x-hca",
    Probe::Custom(hca_probe), hca);

async fn hca(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 8)).await?;
    let version = u16_be(&head, 4).unwrap_or(0);
    let header_len = u64::from(u16_be(&head, 6).unwrap_or(0));
    cx.emit(Node::new("Signature").span(file.sub(0, 4)));
    cx.emit(
        Node::new("Version")
            .span(file.sub(4, 2))
            .value(text(format!("{}.{}", version >> 8, version & 0xff))),
    );
    cx.emit(
        Node::new("Header size")
            .span(file.sub(6, 2))
            .value(Value::UInt {
                value: header_len,
                bits: 16,
                radix: crate::value::Radix::Dec,
            }),
    );
    let header = cx.read(file.sub(0, header_len)).await?;
    let mut at = 8usize;
    let mut summary = String::new();
    let mut encrypted = false;
    while at.saturating_add(4) <= header.len().saturating_sub(2) {
        let id: String = header
            .get(at..at.saturating_add(4))
            .unwrap_or_default()
            .iter()
            .map(|b| char::from(b & 0x7f))
            .collect();
        let id = id.trim_end_matches('\0').to_owned();
        let len: usize = match id.as_str() {
            "fmt" => 16,
            "comp" => 16,
            "dec" => 16,
            "vbr" => 8,
            "ath" => 6,
            "loop" => 16,
            "ciph" => 6,
            "rva" => 8,
            "comm" => 5usize.saturating_add(usize::from(
                header.get(at.saturating_add(4)).copied().unwrap_or(0),
            )),
            "pad" => header.len().saturating_sub(2).saturating_sub(at),
            _ => break,
        };
        let span = file.sub(to_u64(at), to_u64(len));
        let mut node = Node::new(id.clone()).span(span);
        if id == "fmt" {
            let channels = header.get(at.saturating_add(4)).copied().unwrap_or(0);
            let rate = header
                .get(at.saturating_add(5)..at.saturating_add(8))
                .unwrap_or_default()
                .iter()
                .fold(0u32, |a, &b| a.wrapping_shl(8) | u32::from(b));
            let blocks = u32_be(&header, at.saturating_add(8)).unwrap_or(0);
            summary = format!("{channels} channel(s), {rate} Hz, {blocks} blocks");
            node = node.summary(summary.clone());
        } else if id == "ciph" {
            let kind = u16_be(&header, at.saturating_add(4)).unwrap_or(0);
            encrypted = kind != 0;
            node = node.summary(match kind {
                0 => "no encryption",
                1 => "static key",
                56 => "keyed",
                _ => "unknown",
            });
        }
        cx.emit(node);
        at = at.saturating_add(len);
    }
    cx.emit(Node::new("Frames").span(file.tail(header_len)));
    cx.annotate(format!(
        "CRI HCA v{}.{}, {summary}{}",
        version >> 8,
        version & 0xff,
        if encrypted { ", encrypted" } else { "" }
    ));
    Ok(())
}

declare_format!(pub USM = "cri-usm", "CRI Sofdec2 movie (USM)", ["usm"], "video/x-cri-usm",
    Probe::Magic(&[(0, b"CRID")]), usm);

async fn usm(cx: Cx, input: Input) -> Result<()> {
    let found = chunks(&cx, input.span, 0, ChunkLayout::new(4, 4, BE)).await?;
    cx.annotate(format!("CRI USM movie: {}", tally(&found)));
    Ok(())
}

declare_format!(pub CPK = "cri-cpk", "CRI file package (CPK)", ["cpk"], "application/x-cri-cpk",
    Probe::Magic(&[(0, b"CPK ")]), cpk);

async fn cpk(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 4).emit()?;
    f.u32("Flags").hex().emit()?;
    let size = f.u64("Table size").emit()?;
    // The @UTF table (big-endian): size, version, rows offset, strings,
    // data, table name, columns, row width, rows. Usually XOR-masked.
    let t = cx.read_avail(file.sub(16, 32)).await?;
    let masked = !t.starts_with(b"@UTF");
    let table = file.sub(16, size);
    let mut node = Node::new("@UTF table").span(table);
    let mut name = String::new();
    if masked {
        node = node.diag(Diagnostic::unsupported("table is XOR-masked"));
    } else {
        let strings = u64::from(u32_be(&t, 12).unwrap_or(0));
        let name_at = u64::from(u32_be(&t, 20).unwrap_or(0));
        let columns = u16_be(&t, 24).unwrap_or(0);
        let rows = u32_be(&t, 28).unwrap_or(0);
        let (n, _) = cx
            .cstr(table.sub(8u64.saturating_add(strings).saturating_add(name_at), 256))
            .await?;
        name = n;
        node = node.summary(format!("{name:?}, {columns} columns × {rows} rows"));
    }
    cx.emit(node);
    cx.emit(Node::new("Content").span(file.tail(16u64.saturating_add(size))));
    cx.annotate(format!(
        "CRI CPK package{}",
        if masked {
            " (masked table)".to_owned()
        } else {
            format!(", table {name:?}")
        }
    ));
    Ok(())
}

declare_format!(pub AFS = "cri-afs", "CRI AFS archive", ["afs"], "application/x-cri-afs",
    Probe::Magic(&[(0, b"AFS\0")]), afs);

async fn afs(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let count = u32_le(&cx.read(file.sub(4, 4)).await?, 0).unwrap_or(0);
    cx.emit(Node::new("Files").span(file.sub(4, 4)).value(Value::UInt {
        value: count.into(),
        bits: 32,
        radix: crate::value::Radix::Dec,
    }));
    let table_len = u64::from(count).saturating_mul(8);
    let table = cx.read(file.sub_exact(8, table_len)?).await?;
    // The name directory's location follows the table (or sits just before
    // the first file).
    let dir = cx
        .read_avail(file.sub(8u64.saturating_add(table_len), 8))
        .await?;
    let dir_at = u64::from(u32_le(&dir, 0).unwrap_or(0));
    let dir_len = u64::from(u32_le(&dir, 4).unwrap_or(0));
    let names = if dir_at > 0 && dir_len >= u64::from(count).saturating_mul(48) {
        cx.read_avail(file.sub(dir_at, u64::from(count).saturating_mul(48)))
            .await?
    } else {
        Vec::new()
    };
    for i in 0..usize::try_from(count).unwrap_or(0) {
        let offset = u64::from(u32_le(&table, i.saturating_mul(8)).unwrap_or(0));
        let size = u64::from(u32_le(&table, i.saturating_mul(8).saturating_add(4)).unwrap_or(0));
        let name = names
            .get(i.saturating_mul(48)..i.saturating_mul(48).saturating_add(32))
            .map(until_nul)
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| format!("file{i:04}"));
        cx.push(
            embedded(name, input.nested(file.sub(offset, size)))
                .target(file.sub(8u64.saturating_add(to_u64(i).saturating_mul(8)), 8)),
        )
        .await;
    }
    cx.annotate(format!("CRI AFS archive, {count} files"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Electronic Arts audio streams

declare_format!(pub EA_SCHL = "ea-schl", "Electronic Arts audio stream (SCHl)", ["asf", "str", "eam"], "audio/x-ea",
    Probe::Magic(&[(0, b"SCHl")]), ea_schl);

async fn ea_schl(cx: Cx, input: Input) -> Result<()> {
    let found = chunks(&cx, input.span, 0, ChunkLayout::new(4, 4, LE).inclusive()).await?;
    let blocks = found.iter().filter(|c| c.id == b"SCDl").count();
    cx.annotate(format!("EA audio stream, {blocks} data blocks"));
    Ok(())
}
