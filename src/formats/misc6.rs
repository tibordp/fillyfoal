//! Legacy archivers and compressors (HA, UHARC, YZ1, DGCA, GCA, PAQ8,
//! freeze, compact, squeeze, crunch, Amiga XPK and LZX, PackIt; BinHex lives in
//! retro::micros),
//! paint-program files, small image formats, help/e-book formats and embedded
//! key-value databases.

use crate::bytes::{to_u64, u16_le, u32_be, u32_le, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{ChunkLayout, Cursor};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::{Head, Input, Probe, embedded, embedded_as};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

fn uint(value: u64, bits: u8) -> Value {
    Value::UInt {
        value,
        bits,
        radix: Radix::Dec,
    }
}

fn zstr(b: &[u8]) -> String {
    crate::text::until_nul(b)
}

use crate::formats::text::scan::head_lines as lines;

/// Header-only dissector body: emits a signature and the rest as one node.
async fn signature_and_body(
    cx: &Cx,
    file: Span,
    magic_len: u64,
    body: &'static str,
) -> Result<Vec<u8>> {
    let head = cx.read_avail(file.sub(0, 64)).await?;
    cx.emit(Node::new("Signature").span(file.sub(0, magic_len)));
    cx.emit(Node::new(body).span(file.tail(magic_len)));
    Ok(head)
}

// ---------------------------------------------------------------------------
// HA

fn ha_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"HA")
        && u16_le(h.data, 2).is_some_and(|n| n > 0 && n < 0x4000)
        && h.data
            .get(4)
            .is_some_and(|&v| v >> 4 == 2 && matches!(v & 0x0f, 0 | 1 | 2 | 14 | 15))
}

declare_format!(pub HA = "ha", "HA archive", ["ha"], "application/x-ha",
    Probe::Custom(ha_probe), ha);

const HA_METHODS: EnumTable = &[
    (0, "stored"),
    (1, "ASC"),
    (2, "HSC"),
    (14, "directory"),
    (15, "special"),
];

async fn ha(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let count = u16_le(&cx.read(file.sub(2, 2)).await?, 0).unwrap_or(0);
    cx.emit(Node::new("Signature").span(file.sub(0, 2)));
    cx.emit(
        Node::new("Entries")
            .span(file.sub(2, 2))
            .value(uint(count.into(), 16)),
    );
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(4);
    for _ in 0..count {
        let start = cur.pos();
        let kind = cur.u8().await?;
        let packed = u64::from(cur.u32().await?);
        let original = cur.u32().await?;
        cur.skip(8);
        let (path, _) = cur.cstr(1024).await?;
        let (name, _) = cur.cstr(1024).await?;
        let info = u64::from(cur.u8().await?);
        cur.skip(info);
        let header = cur.since(start);
        let data = cur.span(packed);
        if data.len < packed {
            return Err(Diagnostic::truncated(
                Span::new(data.source, data.offset, packed),
                data.len,
            )
            .at(header));
        }
        cur.skip(packed);
        let method = HA_METHODS
            .iter()
            .find(|(k, _)| *k == u64::from(kind & 0x0f))
            .map_or("?", |(_, v)| v);
        let full = if path.is_empty() {
            name
        } else {
            format!(
                "{}/{name}",
                path.replace(['\u{ff}', '\u{fffd}'], "/")
                    .trim_end_matches('/')
            )
        };
        let node = if kind & 0x0f == 0 {
            embedded(full, input.nested(data))
        } else {
            Node::new(full).span(data)
        };
        cx.push(
            node.summary(format!("{method}, {packed} → {original} bytes"))
                .target(header),
        )
        .await;
    }
    cx.annotate(format!("HA archive, {count} entries"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Header-only archivers

declare_format!(pub UHARC = "uharc", "UHARC archive", ["uha"], "application/x-uharc",
    Probe::Magic(&[(0, b"UHA")]), uharc);

async fn uharc(cx: Cx, input: Input) -> Result<()> {
    let head = signature_and_body(&cx, input.span, 3, "Compressed data").await?;
    cx.annotate(format!(
        "UHARC archive, format {:#x}",
        head.get(3).copied().unwrap_or(0)
    ));
    Ok(())
}

declare_format!(pub YZ1 = "yz1", "Yamazaki zipper archive (YZ1)", ["yz1"], "application/x-yz1",
    Probe::Magic(&[(0, b"yz01")]), yz1);

async fn yz1(cx: Cx, input: Input) -> Result<()> {
    signature_and_body(&cx, input.span, 4, "Compressed data").await?;
    cx.annotate("YZ1 archive");
    Ok(())
}

declare_format!(pub DGCA = "dgca", "DGCA archive", ["dgc"], "application/x-dgca",
    Probe::Magic(&[(0, b"DGCA")]), dgca);

async fn dgca(cx: Cx, input: Input) -> Result<()> {
    signature_and_body(&cx, input.span, 4, "Archive body").await?;
    cx.annotate("DGCA archive");
    Ok(())
}

declare_format!(pub GCA = "gca", "GCA archive", ["gca"], "application/x-gca",
    Probe::Magic(&[(0, b"GCAX")]), gca);

async fn gca(cx: Cx, input: Input) -> Result<()> {
    signature_and_body(&cx, input.span, 4, "Archive body").await?;
    cx.annotate("GCA archive");
    Ok(())
}

declare_format!(pub PAQ8 = "paq8", "PAQ8 archive", ["paq8", "paq8l", "paq8px"], "application/x-paq8",
    Probe::Magic(&[(0, b"paq8")]), paq8);

async fn paq8(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    // A text header: "paq8l -N\r\n", then "size\tname\r\n" per file, then
    // "\x1a\x0c" and the compressed stream.
    let head = cx.read_avail(file.sub(0, 1 << 14)).await?;
    let end = head
        .windows(2)
        .position(|w| w == b"\x1a\x0c")
        .unwrap_or(head.len());
    let mut pos = 0u64;
    let mut version = String::new();
    let mut files = 0u32;
    for line in head.get(..end).unwrap_or_default().split(|&b| b == b'\n') {
        let len = to_u64(line.len());
        let t = String::from_utf8_lossy(line)
            .trim_end_matches('\r')
            .to_owned();
        if !t.is_empty() {
            if version.is_empty() {
                version = t.clone();
                cx.emit(Node::new("Header").span(file.sub(pos, len)).value(text(t)));
            } else if let Some((size, name)) = t.split_once('\t') {
                files = files.saturating_add(1);
                cx.emit(
                    Node::new(name.to_owned())
                        .span(file.sub(pos, len))
                        .summary(format!("{size} bytes")),
                );
            }
        }
        pos = pos.saturating_add(len).saturating_add(1);
    }
    cx.emit(Node::new("Compressed stream").span(file.tail(to_u64(end).saturating_add(2))));
    cx.annotate(format!("{version} archive, {files} files"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Unix and CP/M compressors: freeze, compact, squeeze, crunch

declare_format!(pub FREEZE = "freeze", "freeze compressed file", ["f", "fz"], "application/x-freeze",
    Probe::Magic(&[(0, b"\x1f\x9f"), (0, b"\x1f\x9e")]), freeze);

async fn freeze(cx: Cx, input: Input) -> Result<()> {
    let head = signature_and_body(&cx, input.span, 2, "Frozen data").await?;
    cx.annotate(if head.get(1) == Some(&0x9f) {
        "freeze 2.x compressed data"
    } else {
        "freeze 1.x compressed data"
    });
    Ok(())
}

declare_format!(pub COMPACT = "compact", "compact (Huffman) compressed file", ["c"], "application/x-compact",
    Probe::Magic(&[(0, b"\x1f\xff")]), compact);

async fn compact(cx: Cx, input: Input) -> Result<()> {
    signature_and_body(&cx, input.span, 2, "Adaptive Huffman data").await?;
    cx.annotate("compact (adaptive Huffman) data");
    Ok(())
}

fn cpm_name(h: &Head<'_>, at: usize) -> bool {
    let name = h.data.get(at..).unwrap_or_default();
    let len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    (1..=16).contains(&len)
        && name
            .get(..len)
            .is_some_and(|n| n.iter().all(|b| b.is_ascii_graphic()))
}

fn squeeze_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"\x76\xff") && cpm_name(h, 4)
}

declare_format!(pub SQUEEZE = "squeeze", "CP/M squeezed file", ["qqq", "sq"], "application/x-squeeze",
    Probe::Custom(squeeze_probe), squeeze);

async fn squeeze(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 4)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u16("Magic").hex().emit()?;
    f.u16("Checksum").hex().emit()?;
    let (name, span) = cx.cstr(file.sub(4, 32)).await?;
    cx.emit(
        Node::new("Original name")
            .span(span)
            .value(text(name.clone())),
    );
    let at = span.end().saturating_sub(file.offset);
    let nodes = u64::from(u16_le(&cx.read(file.sub(at, 2)).await?, 0).unwrap_or(0));
    cx.emit(
        Node::new("Huffman tree")
            .span(file.sub(at, nodes.saturating_mul(4).saturating_add(2)))
            .summary(format!("{nodes} nodes")),
    );
    cx.emit(
        Node::new("Squeezed data")
            .span(file.tail(at.saturating_add(2).saturating_add(nodes.saturating_mul(4)))),
    );
    cx.annotate(format!("squeezed {name:?}"));
    Ok(())
}

fn crunch_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"\x76\xfe") && cpm_name(h, 2)
}

declare_format!(pub CRUNCH = "crunch", "CP/M crunched file", ["zzz", "cr"], "application/x-crunch",
    Probe::Custom(crunch_probe), crunch);

async fn crunch(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Magic").span(file.sub(0, 2)));
    let (name, span) = cx.cstr(file.sub(2, 32)).await?;
    cx.emit(
        Node::new("Original name")
            .span(span)
            .value(text(name.clone())),
    );
    let at = span.end().saturating_sub(file.offset);
    let info = cx.read(file.sub(at, 4)).await?;
    cx.emit(
        Node::new("Reference revision")
            .span(file.sub(at, 1))
            .value(uint(info.first().copied().unwrap_or(0).into(), 8)),
    );
    cx.emit(
        Node::new("Significant revision")
            .span(file.sub(at.saturating_add(1), 1))
            .value(uint(info.get(1).copied().unwrap_or(0).into(), 8)),
    );
    cx.emit(Node::new("Crunched data").span(file.tail(at.saturating_add(4))));
    cx.annotate(format!("crunched {name:?} (LZW)"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Amiga: XPK, LZX

declare_format!(pub XPK = "xpk", "Amiga XPK packed file", ["xpk"], "application/x-xpk",
    Probe::Magic(&[(0, b"XPKF")]), xpk);

async fn xpk(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 36)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Signature", 4).emit()?;
    let len = f.u32("Packed length").emit()?;
    let packer = f.ascii("Packer", 4).emit()?;
    let unpacked = f.u32("Unpacked length").emit()?;
    f.bytes("Initial bytes", 16).emit()?;
    f.u8("Flags").hex().emit()?;
    f.u8("Header checksum").hex().emit()?;
    f.u8("Sub-library version").emit()?;
    f.u8("Master library version").emit()?;
    cx.emit(Node::new("Chunks").span(file.sub(36, u64::from(len).saturating_sub(28))));
    cx.annotate(format!("XPK {packer}, {unpacked} bytes unpacked"));
    Ok(())
}

declare_format!(pub AMIGA_LZX = "amiga-lzx", "Amiga LZX archive", ["lzx"], "application/x-lzx",
    Probe::Magic(&[(0, b"LZX")]), amiga_lzx);

async fn amiga_lzx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Archive header").span(file.sub(0, 10)));
    let mut pos = 10u64;
    let mut n = 0u32;
    while pos.saturating_add(31) <= file.len {
        let h = cx.read(file.sub(pos, 31)).await?;
        let unpacked = u32_le(&h, 2).unwrap_or(0);
        let packed = u64::from(u32_le(&h, 6).unwrap_or(0));
        let mode = h.get(11).copied().unwrap_or(0);
        let comment = u64::from(h.get(14).copied().unwrap_or(0));
        let name_len = u64::from(h.get(30).copied().unwrap_or(0));
        let name = String::from_utf8_lossy(
            &cx.read(file.sub_exact(pos.saturating_add(31), name_len)?)
                .await?,
        )
        .into_owned();
        let header = file.sub(pos, 31u64.saturating_add(name_len).saturating_add(comment));
        let data = file.sub_exact(header.end().saturating_sub(file.offset), packed)?;
        let node = if mode == 0 {
            embedded(name, input.nested(data))
        } else {
            Node::new(name).span(data)
        };
        let how = match mode {
            0 => "stored",
            2 => "LZX",
            _ => "unknown method",
        };
        cx.push(
            node.summary(format!(
                "{how}, {unpacked} bytes{}",
                if packed == 0 { " (merged)" } else { "" }
            ))
            .target(header),
        )
        .await;
        n = n.saturating_add(1);
        pos = data.end().saturating_sub(file.offset);
    }
    cx.annotate(format!("Amiga LZX archive, {n} entries"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Classic Mac: PackIt

declare_format!(pub PACKIT = "packit", "PackIt archive", ["pit"], "application/x-packit",
    Probe::Magic(&[(0, b"PMag"), (0, b"PMa4"), (0, b"PMa5"), (0, b"PMa6")]), packit);

async fn packit(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut pos = 0u64;
    let mut n = 0u32;
    while pos.saturating_add(4) <= file.len {
        let magic = cx.read(file.sub(pos, 4)).await?;
        if magic == b"PEnd" {
            cx.emit(Node::new("End marker").span(file.sub(pos, 4)));
            break;
        }
        if magic != b"PMag" {
            cx.push(Node::new("Compressed entry").span(file.tail(pos)).diag(
                Diagnostic::unsupported(format!(
                    "{} (Huffman-compressed entries)",
                    String::from_utf8_lossy(&magic)
                )),
            ))
            .await;
            break;
        }
        let h = cx.read(file.sub_exact(pos.saturating_add(4), 94)?).await?;
        let name_len = usize::from(h.first().copied().unwrap_or(0)).min(63);
        let name =
            String::from_utf8_lossy(h.get(1..name_len.saturating_add(1)).unwrap_or_default())
                .into_owned();
        let kind = String::from_utf8_lossy(h.get(64..68).unwrap_or_default()).into_owned();
        let creator = String::from_utf8_lossy(h.get(68..72).unwrap_or_default()).into_owned();
        let data_len = u64::from(u32_be(&h, 76).unwrap_or(0));
        let rsrc_len = u64::from(u32_be(&h, 80).unwrap_or(0));
        let header = file.sub(pos, 98);
        let data = file.sub_exact(pos.saturating_add(98), data_len)?;
        let rsrc = file.sub_exact(data.end().saturating_sub(file.offset), rsrc_len)?;
        let entry = file.sub(
            pos,
            98u64
                .saturating_add(data_len)
                .saturating_add(rsrc_len)
                .saturating_add(2),
        );
        cx.push(
            Node::new(name)
                .span(entry)
                .summary(format!(
                    "{kind}/{creator}, data {data_len}, resource {rsrc_len}"
                ))
                .lazy(packit_entry, (input, header, data, rsrc)),
        )
        .await;
        n = n.saturating_add(1);
        pos = entry.end().saturating_sub(file.offset);
    }
    cx.annotate(format!("PackIt archive, {n} files"));
    Ok(())
}

async fn packit_entry(
    cx: Cx,
    (input, header, data, rsrc): (Input, Span, Span, Span),
) -> Result<()> {
    cx.emit(Node::new("Header").span(header));
    if data.len > 0 {
        cx.emit(embedded("Data fork", input.nested(data)));
    }
    if rsrc.len > 0 {
        cx.emit(embedded_as(
            "Resource fork",
            input.nested(rsrc),
            &crate::formats::platform::MAC_RESOURCE,
        ));
    }
    cx.emit(Node::new("CRC").span(Span::new(rsrc.source, rsrc.end(), 2)));
    Ok(())
}

// ---------------------------------------------------------------------------
// Paint programs: Corel PHOTO-PAINT, Clip Studio Paint, FireAlpaca MDP,
// GIMP palettes

declare_format!(pub CPT = "corel-cpt", "Corel PHOTO-PAINT image", ["cpt"], "image/x-corel-cpt",
    Probe::Magic(&[(0, b"CPT7FILE"), (0, b"CPT8FILE"), (0, b"CPT9FILE"), (0, b"CPTFILE")]), corel_cpt);

async fn corel_cpt(cx: Cx, input: Input) -> Result<()> {
    let head = signature_and_body(&cx, input.span, 8, "Image data").await?;
    cx.annotate(format!(
        "Corel PHOTO-PAINT {} image",
        String::from_utf8_lossy(head.get(..8).unwrap_or_default()).trim_end_matches("FILE")
    ));
    Ok(())
}

declare_format!(pub CLIP = "clip-studio", "Clip Studio Paint file", ["clip"], "application/x-clip-studio",
    Probe::Magic(&[(0, b"CSFCHUNK")]), clip_studio);

async fn clip_studio(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 24)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Signature", 8).emit()?;
    f.u64("File size").emit()?;
    f.u64("First chunk offset").hex().emit()?;
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(24);
    let mut n = 0u32;
    // Chunks: "CHNK" + kind[4] + u64 size.
    while let Some(chunk) = cur.chunk(ChunkLayout::new(8, 8, BE)).await? {
        let kind = String::from_utf8_lossy(chunk.id.get(4..).unwrap_or_default()).into_owned();
        let node = if kind == "SQLi" {
            embedded_as(
                "CHNKSQLi",
                input.nested(chunk.body),
                &crate::formats::sqlite::FORMAT,
            )
        } else {
            chunk.node()
        };
        cx.push(node).await;
        n = n.saturating_add(1);
    }
    cx.annotate(format!("Clip Studio Paint file, {n} chunks"));
    Ok(())
}

declare_format!(pub MDP = "firealpaca-mdp", "FireAlpaca / MediBang image (MDP)", ["mdp"], "image/x-mdp",
    Probe::Magic(&[(0, b"mdipack")]), mdp);

async fn mdp(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 16)).await?;
    let xml_len = u64::from(u32_le(&head, 8).unwrap_or(0));
    let data_len = u64::from(u32_le(&head, 12).unwrap_or(0));
    cx.emit(Node::new("Signature").span(file.sub(0, 8)));
    cx.emit(
        Node::new("Description length")
            .span(file.sub(8, 4))
            .value(uint(xml_len, 32)),
    );
    cx.emit(
        Node::new("Binary length")
            .span(file.sub(12, 4))
            .value(uint(data_len, 32)),
    );
    cx.emit(embedded(
        "Description (XML)",
        input.nested(file.sub(16, xml_len)),
    ));
    cx.emit(Node::new("Layer data").span(file.sub(16u64.saturating_add(xml_len), data_len)));
    cx.annotate("MDP image");
    Ok(())
}

declare_format!(pub GIMP_GPL = "gimp-palette", "GIMP palette", ["gpl"], "application/x-gimp-palette",
    Probe::Magic(&[(0, b"GIMP Palette\n"), (0, b"GIMP Palette\r\n")]), gimp_palette);

async fn gimp_palette(cx: Cx, input: Input) -> Result<()> {
    let all = lines(&cx, input.span, 1 << 20).await?;
    let mut name = String::new();
    let mut colours = 0u32;
    for (line, span) in all.iter().skip(1) {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = t.split_once(':') {
            if k == "Name" {
                name = v.trim().to_owned();
            }
            cx.emit(Node::new(k.to_owned()).span(*span).value(text(v.trim())));
            continue;
        }
        let parts: Vec<&str> = t.split_whitespace().collect();
        let rgb: Vec<u8> = parts
            .iter()
            .take(3)
            .filter_map(|p| p.parse().ok())
            .collect();
        if let [r, g, b] = rgb[..] {
            let label = parts.get(3..).map(|p| p.join(" ")).unwrap_or_default();
            cx.push(
                Node::new(format!("#{r:02x}{g:02x}{b:02x}"))
                    .span(*span)
                    .summary(label),
            )
            .await;
            colours = colours.saturating_add(1);
        }
    }
    cx.annotate(format!("GIMP palette {name:?}, {colours} colours"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Small image formats: PGF, XV thumbnails, Khoros VIFF

declare_format!(pub PGF = "pgf", "Progressive Graphics File", ["pgf"], "image/x-pgf",
    Probe::Magic(&[(0, b"PGF")]), pgf);

async fn pgf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 24)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 3).emit()?;
    let version = f.u8("Version").hex().emit()?;
    let size = f.u32("Header size").emit()?;
    let w = f.u32("Width").emit()?;
    let h = f.u32("Height").emit()?;
    let levels = f.u8("Levels").emit()?;
    f.u8("Quality").emit()?;
    let bpp = f.u8("Bits per pixel").emit()?;
    let channels = f.u8("Channels").emit()?;
    f.u8("Mode").emit()?;
    f.u8("Used bits per channel").emit()?;
    cx.emit(Node::new("Image data").span(file.tail(8u64.saturating_add(size.into()))));
    cx.annotate(format!(
        "PGF v{version:x}, {w}×{h}, {bpp} bpp, {channels} channel(s), {levels} levels"
    ));
    Ok(())
}

declare_format!(pub XV_THUMB = "xv-thumbnail", "XV thumbnail", [], "image/x-xv-thumbnail",
    Probe::Magic(&[(0, b"P7 332\n")]), xv_thumb);

async fn xv_thumb(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let all = lines(&cx, file, 4096).await?;
    let mut dims = String::new();
    for (line, span) in &all {
        if line.starts_with("#IMGINFO:") {
            cx.emit(
                Node::new("Image info")
                    .span(*span)
                    .value(text(line.trim_start_matches("#IMGINFO:"))),
            );
        } else if !line.starts_with('#') && !line.starts_with("P7") && !line.is_empty() {
            dims = line.clone();
            cx.emit(
                Node::new("Dimensions")
                    .span(*span)
                    .value(text(line.clone())),
            );
            cx.emit(
                Node::new("Pixels (3-3-2 RGB)")
                    .span(file.tail(span.end().saturating_sub(file.offset).saturating_add(1))),
            );
            break;
        }
    }
    let wh: Vec<&str> = dims.split_whitespace().collect();
    cx.annotate(format!(
        "XV thumbnail, {}×{}",
        wh.first().unwrap_or(&"?"),
        wh.get(1).unwrap_or(&"?")
    ));
    Ok(())
}

fn viff_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"\xab\x01") && h.data.get(2) == Some(&1) && h.data.get(3) == Some(&3)
}

declare_format!(pub VIFF = "viff", "Khoros VIFF image", ["xv", "viff"], "image/x-viff",
    Probe::Custom(viff_probe), viff);

async fn viff(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 1024)).await?;
    let big = head.get(4).copied().unwrap_or(0) == 0x2;
    let int = |at: usize| {
        if big {
            u32_be(&head, at)
        } else {
            u32_le(&head, at)
        }
        .unwrap_or(0)
    };
    cx.emit(Node::new("Identifier").span(file.sub(0, 4)));
    cx.emit(
        Node::new("Machine dependency")
            .span(file.sub(4, 1))
            .value(Value::Enum {
                raw: head.get(4).copied().unwrap_or(0).into(),
                bits: 8,
                name: Some(if big {
                    "big-endian (IEEE)"
                } else {
                    "little-endian"
                }),
            }),
    );
    let comment = zstr(head.get(8..520).unwrap_or_default());
    cx.emit(
        Node::new("Comment")
            .span(file.sub(8, 512))
            .value(text(comment)),
    );
    let (w, h) = (int(520), int(524));
    cx.emit(
        Node::new("Width")
            .span(file.sub(520, 4))
            .value(uint(w.into(), 32)),
    );
    cx.emit(
        Node::new("Height")
            .span(file.sub(524, 4))
            .value(uint(h.into(), 32)),
    );
    cx.emit(Node::new("Image data").span(file.tail(1024)));
    cx.annotate(format!("VIFF image, {w}×{h}"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Help and e-book formats: OS/2 INF/HLP, Psion TCR, AmigaGuide

declare_format!(pub OS2_INF = "os2-inf", "OS/2 Information Presentation Facility (INF/HLP)", ["inf", "hlp"], "application/x-os2-inf",
    Probe::Magic(&[(0, b"HSP\x01"), (0, b"HSP\x10")]), os2_inf);

async fn os2_inf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x9b)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 3).emit()?;
    let kind = f
        .u8("Flags")
        .enumeration(&[(1, "INF"), (0x10, "HLP")])
        .emit()?;
    f.u16("Header size").emit()?;
    let major = f.u8("Major version").emit()?;
    let minor = f.u8("Minor version").emit()?;
    let toc = f.u16("Table of contents entries").emit()?;
    f.u32("Table of contents offset").hex().emit()?;
    f.u32("Table of contents size").emit()?;
    f.u32("TOC offsets offset").hex().emit()?;
    let resources = f.u16("Resource panels").emit()?;
    f.u32("Resource index offset").hex().emit()?;
    let names = f.u16("Named panels").emit()?;
    f.u32("Name index offset").hex().emit()?;
    let index = f.u16("Index entries").emit()?;
    f.u32("Index offset").hex().emit()?;
    f.u32("Index size").emit()?;
    f.bytes("Reserved", 10).emit()?;
    f.u32("Search table offset").hex().emit()?;
    f.u32("Search table size").emit()?;
    let slots = f.u16("Slots").emit()?;
    f.u32("Slot table offset").hex().emit()?;
    f.u32("Dictionary size").emit()?;
    let words = f.u16("Dictionary words").emit()?;
    f.u32("Dictionary offset").hex().emit()?;
    f.u32("Image offset").hex().emit()?;
    f.u8("Maximum TOC level").emit()?;
    f.u32("NLS table offset").hex().emit()?;
    f.u32("NLS table size").emit()?;
    f.u32("Extended header offset").hex().emit()?;
    f.bytes("Reserved", 12).emit()?;
    let title = f.ascii("Title", 48).emit()?;
    let _ = (resources, names);
    cx.annotate(format!(
        "OS/2 {} {major}.{minor} {:?}: {toc} topics, {index} index entries, {slots} slots, {words} words",
        if kind == 0x10 { "HLP" } else { "INF" },
        title.trim()
    ));
    Ok(())
}

declare_format!(pub TCR = "psion-tcr", "Psion TCR text", ["tcr"], "text/x-psion-tcr",
    Probe::Magic(&[(0, b"!!8-Bit!!")]), tcr);

async fn tcr(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Signature").span(file.sub(0, 9)));
    // 256 Pascal strings: the dictionary each output byte expands to.
    let mut pos = 9u64;
    let mut sample = Vec::new();
    for i in 0..256u32 {
        let len = u64::from(
            cx.read(file.sub_exact(pos, 1)?)
                .await?
                .first()
                .copied()
                .unwrap_or(0),
        );
        if i < 8 {
            sample.push(
                String::from_utf8_lossy(&cx.read(file.sub(pos.saturating_add(1), len)).await?)
                    .into_owned(),
            );
        }
        pos = pos.saturating_add(1).saturating_add(len);
    }
    cx.emit(
        Node::new("Dictionary")
            .span(file.sub(9, pos.saturating_sub(9)))
            .summary(format!("256 entries, starting {sample:?}")),
    );
    cx.emit(Node::new("Compressed text").span(file.tail(pos)));
    cx.annotate(format!(
        "Psion TCR, {} compressed bytes",
        file.len.saturating_sub(pos)
    ));
    Ok(())
}

declare_format!(pub AMIGAGUIDE = "amigaguide", "AmigaGuide hypertext", ["guide"], "text/x-amigaguide",
    Probe::Magic(&[(0, b"@database"), (0, b"@DATABASE")]), amigaguide);

async fn amigaguide(cx: Cx, input: Input) -> Result<()> {
    let all = lines(&cx, input.span, 1 << 20).await?;
    let mut nodes = 0u32;
    let mut open: Option<(String, String, Span)> = None;
    for (line, span) in &all {
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("@node") {
            let rest = line.get(5..).unwrap_or(rest).trim();
            let (name, title) = match rest.split_once(' ') {
                Some((n, t)) => (n.to_owned(), t.trim_matches('"').to_owned()),
                None => (rest.to_owned(), String::new()),
            };
            open = Some((name, title, *span));
        } else if lower.starts_with("@endnode") {
            if let Some((name, title, start)) = open.take() {
                nodes = nodes.saturating_add(1);
                let whole = Span::new(
                    start.source,
                    start.offset,
                    span.end().saturating_sub(start.offset),
                );
                cx.push(Node::new(name).span(whole).summary(title)).await;
            }
        } else if open.is_none() && line.starts_with('@') {
            let (k, v) = line.split_once(' ').unwrap_or((line.as_str(), ""));
            cx.push(
                Node::new(k.to_owned())
                    .span(*span)
                    .value(text(v.trim_matches('"'))),
            )
            .await;
        }
    }
    cx.annotate(format!("AmigaGuide, {nodes} nodes"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Embedded databases: Tokyo Cabinet, Kyoto Cabinet, GDBM, RRDtool,
// WiredTiger, Realm

declare_format!(pub TOKYO = "tokyo-cabinet", "Tokyo Cabinet database", ["tch", "tcb", "tcf", "tct"], "application/x-tokyo-cabinet",
    Probe::Magic(&[(0, b"ToKyO CaBiNeT\n")]), tokyo);

async fn tokyo(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 64)).await?;
    let version = zstr(head.get(14..32).unwrap_or_default());
    let kind = head.get(32).copied().unwrap_or(0);
    let kind_name = match kind {
        0 => "hash",
        1 => "B+ tree",
        2 => "fixed-length",
        3 => "table",
        _ => "unknown",
    };
    cx.emit(Node::new("Signature").span(file.sub(0, 14)));
    cx.emit(
        Node::new("Version")
            .span(file.sub(14, 18))
            .value(text(version.clone())),
    );
    cx.emit(Node::new("Type").span(file.sub(32, 1)).value(Value::Enum {
        raw: kind.into(),
        bits: 8,
        name: Some(kind_name),
    }));
    let records = u64_le(&head, 48).unwrap_or(0);
    let size = u64_le(&head, 56).unwrap_or(0);
    cx.emit(
        Node::new("Buckets")
            .span(file.sub(40, 8))
            .value(uint(u64_le(&head, 40).unwrap_or(0), 64)),
    );
    cx.emit(
        Node::new("Records")
            .span(file.sub(48, 8))
            .value(uint(records, 64)),
    );
    cx.emit(
        Node::new("File size")
            .span(file.sub(56, 8))
            .value(uint(size, 64)),
    );
    cx.emit(Node::new("Body").span(file.tail(256)));
    cx.annotate(format!(
        "Tokyo Cabinet {kind_name} database {version}, {records} records"
    ));
    Ok(())
}

declare_format!(pub KYOTO = "kyoto-cabinet", "Kyoto Cabinet database", ["kch", "kct"], "application/x-kyoto-cabinet",
    Probe::Magic(&[(0, b"KC\n\0")]), kyoto);

async fn kyoto(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 64)).await?;
    cx.emit(Node::new("Signature").span(file.sub(0, 4)));
    cx.emit(
        Node::new("Library version")
            .span(file.sub(4, 1))
            .value(uint(head.get(4).copied().unwrap_or(0).into(), 8)),
    );
    cx.emit(
        Node::new("Library revision")
            .span(file.sub(5, 1))
            .value(uint(head.get(5).copied().unwrap_or(0).into(), 8)),
    );
    cx.emit(
        Node::new("Format version")
            .span(file.sub(6, 1))
            .value(uint(head.get(6).copied().unwrap_or(0).into(), 8)),
    );
    let kind = head.get(8).copied().unwrap_or(0);
    let kind_name = match kind {
        0x31 => "hash",
        0x32 => "B+ tree",
        _ => "unknown",
    };
    cx.emit(Node::new("Type").span(file.sub(8, 1)).value(Value::Enum {
        raw: kind.into(),
        bits: 8,
        name: Some(kind_name),
    }));
    cx.emit(Node::new("Body").span(file.tail(64)));
    cx.annotate(format!("Kyoto Cabinet {kind_name} database"));
    Ok(())
}

fn gdbm_probe(h: &Head<'_>) -> bool {
    let m = |v: u32| (0x1357_9acd..=0x1357_9acf).contains(&v);
    u32_le(h.data, 0).is_some_and(m) || u32_be(h.data, 0).is_some_and(m)
}

declare_format!(pub GDBM = "gdbm", "GNU dbm database", ["gdbm", "db"], "application/x-gdbm",
    Probe::Custom(gdbm_probe), gdbm);

async fn gdbm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 4)).await?;
    let endian = if u32_le(&head, 0).is_some_and(|v| v >> 8 == 0x13_579a) {
        LE
    } else {
        BE
    };
    let block = cx.block(file.sub(0, 32)).await?;
    let mut f = Fields::emitting(&cx, &block, endian);
    let magic = f.u32("Magic").hex().emit()?;
    let block_size = f.u32("Block size").emit()?;
    f.u32("Directory offset").hex().emit()?;
    f.u32("Directory size").emit()?;
    let bits = f.u32("Directory bits").emit()?;
    f.u32("Bucket size").emit()?;
    let elems = f.u32("Bucket elements").emit()?;
    f.u32("Next block").hex().emit()?;
    let variant = match magic & 0xf {
        0xe => "standard",
        0xd => "32-bit offsets",
        _ => "64-bit offsets",
    };
    cx.emit(Node::new("Blocks").span(file.tail(u64::from(block_size).min(file.len))));
    cx.annotate(format!(
        "GDBM ({variant}), {block_size}-byte blocks, {bits} directory bits, {elems} per bucket"
    ));
    Ok(())
}

declare_format!(pub RRD = "rrdtool", "RRDtool round-robin database", ["rrd"], "application/x-rrd",
    Probe::Magic(&[(0, b"RRD\0")]), rrd);

async fn rrd(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    // The 64-bit layout: cookie[4], version[5], (pad), double float cookie at
    // 16, ds_cnt, rra_cnt, pdp_step as 8-byte longs, 10 × 8-byte params.
    let head = cx.read(file.sub(0, 128)).await?;
    let version = zstr(head.get(4..9).unwrap_or_default());
    let cookie = f64::from_le_bytes(
        head.get(16..24)
            .and_then(|s| s.try_into().ok())
            .unwrap_or([0; 8]),
    );
    if (cookie - 8.642_135e130).abs() > 1e125 {
        return Err(Diagnostic::unsupported(
            "not a little-endian 64-bit RRD (float cookie mismatch)",
        )
        .at(file.sub(16, 8)));
    }
    let ds = u64_le(&head, 24).unwrap_or(0);
    let rra = u64_le(&head, 32).unwrap_or(0);
    let step = u64_le(&head, 40).unwrap_or(0);
    cx.emit(Node::new("Cookie").span(file.sub(0, 4)));
    cx.emit(
        Node::new("Version")
            .span(file.sub(4, 5))
            .value(text(version.clone())),
    );
    cx.emit(
        Node::new("Float cookie")
            .span(file.sub(16, 8))
            .value(Value::Float(cookie)),
    );
    cx.emit(
        Node::new("Data sources")
            .span(file.sub(24, 8))
            .value(uint(ds, 64)),
    );
    cx.emit(
        Node::new("Archives")
            .span(file.sub(32, 8))
            .value(uint(rra, 64)),
    );
    cx.emit(
        Node::new("Step (s)")
            .span(file.sub(40, 8))
            .value(uint(step, 64)),
    );
    let mut pos = 128u64;
    for _ in 0..ds.min(256) {
        let d = cx.read(file.sub_exact(pos, 120)?).await?;
        let name = zstr(d.get(..20).unwrap_or_default());
        let kind = zstr(d.get(20..40).unwrap_or_default());
        cx.push(
            Node::new(format!("DS {name}"))
                .span(file.sub(pos, 120))
                .summary(kind),
        )
        .await;
        pos = pos.saturating_add(120);
    }
    for _ in 0..rra.min(256) {
        let d = cx.read(file.sub_exact(pos, 120)?).await?;
        let cf = zstr(d.get(..20).unwrap_or_default());
        let rows = u64_le(&d, 24).unwrap_or(0);
        let pdp = u64_le(&d, 32).unwrap_or(0);
        cx.push(
            Node::new(format!("RRA {cf}"))
                .span(file.sub(pos, 120))
                .summary(format!("{rows} rows × {} s", pdp.saturating_mul(step))),
        )
        .await;
        pos = pos.saturating_add(120);
    }
    cx.emit(Node::new("Live data and archives").span(file.tail(pos)));
    cx.annotate(format!(
        "RRD v{version}, {ds} data sources, {rra} archives, step {step} s"
    ));
    Ok(())
}

declare_format!(pub WIREDTIGER = "wiredtiger", "WiredTiger database marker", [], "text/x-wiredtiger",
    Probe::Magic(&[(0, b"WiredTiger\nWiredTiger ")]), wiredtiger);

async fn wiredtiger(cx: Cx, input: Input) -> Result<()> {
    let all = lines(&cx, input.span, 4096).await?;
    let mut version = String::new();
    for (line, span) in all.iter().take(2) {
        if let Some(v) = line.strip_prefix("WiredTiger ") {
            version = v.to_owned();
        }
        cx.emit(Node::new("Line").span(*span).value(text(line.clone())));
    }
    cx.annotate(format!("WiredTiger {version}"));
    Ok(())
}

fn realm_probe(h: &Head<'_>) -> bool {
    h.at(16, b"T-DB")
}

declare_format!(pub REALM = "realm", "Realm database", ["realm"], "application/x-realm",
    Probe::Custom(realm_probe), realm);

async fn realm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 24)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u64("Top ref 0").hex().emit()?;
    f.u64("Top ref 1").hex().emit()?;
    f.ascii("Signature", 4).emit()?;
    let v0 = f.u8("File format 0").emit()?;
    let v1 = f.u8("File format 1").emit()?;
    f.u8("Reserved").emit()?;
    let flags = f.u8("Flags").hex().emit()?;
    cx.emit(Node::new("Arrays").span(file.tail(24)));
    cx.annotate(format!(
        "Realm database, format {}",
        if flags & 1 != 0 { v1 } else { v0 }
    ));
    Ok(())
}
