//! Nintendo NW4R (Wii) and NW4C/NW4F (3DS, Wii U, Switch) binaries.

use crate::bytes::{to_u64, u32_be};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::{Head, Input, Probe};
use crate::node::Node;

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// Nintendo NW4R (Wii) and NW4C/NW4F (3DS, Wii U, Switch) binaries

fn nw_probe(h: &Head<'_>) -> bool {
    const MAGICS: &[&[u8; 4]] = &[
        b"CSTM", b"FSTM", b"CWAV", b"FWAV", b"CSAR", b"FSAR", b"CLYT", b"FLYT", b"CLAN", b"FLAN",
    ];
    MAGICS.iter().any(|m| h.starts_with(*m)) && (h.at(4, b"\xff\xfe") || h.at(4, b"\xfe\xff"))
}

declare_format!(pub NW4 = "nw4-binary", "Nintendo NW4C/NW4F resource", ["bcstm", "bfstm", "bcwav", "bfwav", "bcsar", "bfsar", "bclyt", "bflyt", "bclan", "bflan"], "application/x-nintendo-nw4",
    Probe::Custom(nw_probe), nw4);

async fn nw4(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let bom = cx.read(file.sub(4, 2)).await?;
    let endian = if bom == b"\xfe\xff" { BE } else { LE };
    let head = cx.block(file.sub(0, 20)).await?;
    let mut f = Fields::emitting(&cx, &head, endian);
    let magic = f.ascii("Signature", 4).emit()?;
    f.u16("Byte-order mark").hex().emit()?;
    let header_len = f.u16("Header size").emit()?;
    let version = f.u32("Version").hex().emit()?;
    f.u32("File size").emit()?;
    let sections = f.u16("Sections").emit()?;
    f.u16("Reserved").emit()?;
    let layout = matches!(magic.as_str(), "CLYT" | "FLYT" | "CLAN" | "FLAN");
    let mut cur = Cursor::new(&cx, file, endian);
    if layout {
        // Blocks follow the header: magic, size.
        cur.seek(header_len.into());
        for _ in 0..sections {
            let start = cur.pos();
            let id = String::from_utf8_lossy(&cur.bytes(4).await?).into_owned();
            let size = u64::from(cur.u32().await?);
            if size < 8 {
                return Err(
                    Diagnostic::malformed("block smaller than its header").at(cur.since(start))
                );
            }
            cur.seek(start.saturating_add(size));
            cx.push(
                Node::new(id)
                    .span(file.sub(start, size))
                    .summary(format!("{size} bytes")),
            )
            .await;
        }
    } else {
        // A table of section references: id, padding, offset, size.
        cur.seek(20);
        for _ in 0..sections {
            let start = cur.pos();
            let id = cur.u16().await?;
            cur.skip(2);
            let offset = u64::from(cur.u32().await?);
            let size = u64::from(cur.u32().await?);
            let name = match id {
                0x2000 => "SAR STRG".to_owned(),
                0x2001 => "SAR INFO".to_owned(),
                0x2002 => "SAR FILE".to_owned(),
                0x4000 => "INFO".to_owned(),
                0x4001 => "SEEK".to_owned(),
                0x4002 => "DATA".to_owned(),
                0x4003 => "REGN".to_owned(),
                0x4004 => "PDAT".to_owned(),
                0x7000 => "INFO".to_owned(),
                0x7001 => "DATA".to_owned(),
                _ => format!("Section {id:#06x}"),
            };
            cx.push(
                Node::new(name)
                    .span(file.sub(offset, size))
                    .target(cur.since(start))
                    .summary(format!("{size} bytes")),
            )
            .await;
        }
    }
    cx.annotate(format!(
        "Nintendo {magic} v{}.{}.{}, {sections} sections",
        version >> 24,
        (version >> 16) & 0xff,
        (version >> 8) & 0xff
    ));
    Ok(())
}

fn nw4r_probe(h: &Head<'_>) -> bool {
    const MAGICS: &[&[u8; 4]] = &[
        b"RSTM", b"RWAV", b"RSAR", b"RSEQ", b"RBNK", b"RWSD", b"RWAR",
    ];
    MAGICS.iter().any(|m| h.starts_with(*m)) && h.at(4, b"\xfe\xff")
}

declare_format!(pub NW4R = "nw4r-binary", "Nintendo NW4R (Wii) sound resource", ["brstm", "brwav", "brsar", "brseq", "brbnk", "brwsd", "brwar"], "application/x-nintendo-nw4r",
    Probe::Custom(nw4r_probe), nw4r);

async fn nw4r(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    let magic = f.ascii("Signature", 4).emit()?;
    f.u16("Byte-order mark").hex().emit()?;
    let version = f.u16("Version").hex().emit()?;
    f.u32("File size").emit()?;
    let header_len = f.u16("Header size").emit()?;
    let blocks = f.u16("Blocks").emit()?;
    // Block references (offset, size) follow, then the blocks: magic, size.
    let refs = cx
        .read_avail(file.sub(16, u64::from(blocks).saturating_mul(8)))
        .await?;
    for i in 0..usize::from(blocks) {
        let offset = u64::from(u32_be(&refs, i.saturating_mul(8)).unwrap_or(0));
        let size = u64::from(u32_be(&refs, i.saturating_mul(8).saturating_add(4)).unwrap_or(0));
        let id = String::from_utf8_lossy(&cx.read_avail(file.sub(offset, 4)).await?).into_owned();
        cx.push(
            Node::new(if id.is_empty() {
                format!("Block {i}")
            } else {
                id
            })
            .span(file.sub(offset, size))
            .target(file.sub(16u64.saturating_add(to_u64(i).saturating_mul(8)), 8))
            .summary(format!("{size} bytes")),
        )
        .await;
    }
    let _ = header_len;
    cx.annotate(format!(
        "Nintendo {magic} v{}.{}, {blocks} blocks",
        version >> 8,
        version & 0xff
    ));
    Ok(())
}
