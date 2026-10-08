//! Legacy archivers: HA, header-only archivers (UHARC, YZ1, DGCA, GCA,
//! PAQ8), Amiga XPK and LZX, and classic Mac PackIt.

use crate::bytes::{to_u64, u16_le, u32_be, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
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
    for i in 0..count {
        cx.progress(i.into(), count.into());
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
        cx.progress_in(file, data.end());
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
        cx.progress_in(file, entry.end());
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
            &crate::formats::system::platform::MAC_RESOURCE,
        ));
    }
    cx.emit(Node::new("CRC").span(Span::new(rsrc.source, rsrc.end(), 2)));
    Ok(())
}
