//! Game packfiles: GTA IMG v2, Descent HOG, Build GRP, EA BIG, Blood RFF
//! and FromSoftware BND.

use crate::bytes::{u16_le, u32_be, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::{Input, Probe, embedded};
use crate::node::Node;
use crate::value::{Radix, Value};

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

/// NUL-terminated (or padded) Latin-1 text.
fn zstr(b: &[u8]) -> String {
    crate::text::until_nul(b)
}

// ---------------------------------------------------------------------------
// Archives: GTA IMG v2, Descent HOG, Build GRP, EA BIG, Blood RFF,
// FromSoftware BND

declare_format!(pub GTA_IMG = "gta-img", "GTA San Andreas archive (IMG v2)", ["img"], "application/x-gta-img",
    Probe::Magic(&[(0, b"VER2")]), gta_img);

async fn gta_img(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let count = u32_le(&cx.read(file.sub(4, 4)).await?, 0).unwrap_or(0);
    cx.emit(
        Node::new("Entries")
            .span(file.sub(4, 4))
            .value(uint(count.into(), 32)),
    );
    for i in 0..count {
        let at = 8u64.saturating_add(u64::from(i).saturating_mul(32));
        let e = cx.read(file.sub_exact(at, 32)?).await?;
        let offset = u64::from(u32_le(&e, 0).unwrap_or(0)).saturating_mul(2048);
        let sectors = u64::from(u16_le(&e, 4).unwrap_or(0));
        let name = zstr(e.get(8..32).unwrap_or_default());
        let data = file.sub(offset, sectors.saturating_mul(2048));
        cx.push(embedded(name, input.nested(data)).target(file.sub(at, 32)))
            .await;
    }
    cx.annotate(format!("GTA IMG v2 archive, {count} entries"));
    Ok(())
}

declare_format!(pub HOG = "descent-hog", "Descent archive (HOG)", ["hog"], "application/x-descent-hog",
    Probe::Magic(&[(0, b"DHF")]), hog);

async fn hog(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut pos = 3u64;
    let mut n = 0u32;
    while pos.saturating_add(17) <= file.len {
        let h = cx.read(file.sub(pos, 17)).await?;
        let name = zstr(h.get(..13).unwrap_or_default());
        let size = u64::from(u32_le(&h, 13).unwrap_or(0));
        let data = file.sub_exact(pos.saturating_add(17), size)?;
        cx.push(embedded(name, input.nested(data)).target(file.sub(pos, 17)))
            .await;
        n = n.saturating_add(1);
        pos = data.end().saturating_sub(file.offset);
    }
    cx.annotate(format!("Descent HOG archive, {n} files"));
    Ok(())
}

declare_format!(pub GRP = "build-grp", "Build engine group file (GRP)", ["grp"], "application/x-build-grp",
    Probe::Magic(&[(0, b"KenSilverman")]), grp);

async fn grp(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let count = u32_le(&cx.read(file.sub(12, 4)).await?, 0).unwrap_or(0);
    let dir_len = u64::from(count).saturating_add(1).saturating_mul(16);
    let mut data_at = dir_len;
    for i in 0..count {
        let at = 16u64.saturating_add(u64::from(i).saturating_mul(16));
        let e = cx.read(file.sub_exact(at, 16)?).await?;
        let name = zstr(e.get(..12).unwrap_or_default());
        let size = u64::from(u32_le(&e, 12).unwrap_or(0));
        cx.push(embedded(name, input.nested(file.sub(data_at, size))).target(file.sub(at, 16)))
            .await;
        data_at = data_at.saturating_add(size);
    }
    cx.annotate(format!("Build engine GRP, {count} files"));
    Ok(())
}

declare_format!(pub BIG = "ea-big", "EA BIG archive", ["big"], "application/x-ea-big",
    Probe::Magic(&[(0, b"BIGF"), (0, b"BIG4")]), big);

async fn big(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Signature", 4).emit()?;
    f.skip(4);
    let size = u32_le(&cx.read(file.sub(4, 4)).await?, 0).unwrap_or(0);
    cx.emit(
        Node::new("Archive size (little-endian)")
            .span(file.sub(4, 4))
            .value(uint(size.into(), 32)),
    );
    let count = f.u32("Entries").emit()?;
    f.u32("Header size").emit()?;
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(16);
    for _ in 0..count {
        let start = cur.pos();
        let offset = u64::from(cur.u32().await?);
        let size = u64::from(cur.u32().await?);
        let (name, _) = cur.cstr(512).await?;
        cx.push(embedded(name, input.nested(file.sub(offset, size))).target(cur.since(start)))
            .await;
    }
    cx.annotate(format!("EA BIG archive, {count} files"));
    Ok(())
}

declare_format!(pub RFF = "blood-rff", "Blood resource file (RFF)", ["rff"], "application/x-blood-rff",
    Probe::Magic(&[(0, b"RFF\x1a")]), rff);

async fn rff(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 4).emit()?;
    let version = f.u16("Version").hex().emit()?;
    f.u16("Padding").emit()?;
    let dir = f.u32("Directory offset").hex().emit()?;
    let count = f.u32("Entries").emit()?;
    let dir_span = file.sub(dir.into(), u64::from(count).saturating_mul(48));
    let mut node = Node::new("Directory")
        .span(dir_span)
        .summary(format!("{count} × 48-byte entries"));
    if version >= 0x301 {
        node = node.diag(Diagnostic::unsupported("directory is XOR-encrypted"));
    }
    cx.emit(node);
    cx.annotate(format!(
        "Blood RFF v{}.{}, {count} entries",
        version >> 8,
        version & 0xff
    ));
    Ok(())
}

declare_format!(pub BND = "fromsoft-bnd", "FromSoftware binder (BND3/BND4)", ["bnd", "chrbnd", "partsbnd", "objbnd", "mtdbnd", "anibnd"], "application/x-fromsoft-bnd",
    Probe::Magic(&[(0, b"BND3"), (0, b"BND4")]), bnd);

async fn bnd(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 0x40)).await?;
    let v4 = head.starts_with(b"BND4");
    let (count, version) = if v4 {
        let big = head.get(9).copied().unwrap_or(0) != 0;
        let count = if big {
            u32_be(&head, 0x0c)
        } else {
            u32_le(&head, 0x0c)
        }
        .unwrap_or(0);
        (count, zstr(head.get(0x18..0x20).unwrap_or_default()))
    } else {
        let big = head.get(0x0d).copied().unwrap_or(0) != 0;
        let count = if big {
            u32_be(&head, 0x10)
        } else {
            u32_le(&head, 0x10)
        }
        .unwrap_or(0);
        (count, zstr(head.get(4..12).unwrap_or_default()))
    };
    cx.emit(Node::new("Signature").span(file.sub(0, 4)));
    cx.emit(
        Node::new("Version")
            .span(file.sub(if v4 { 0x18 } else { 4 }, 8))
            .value(text(version.clone())),
    );
    cx.emit(
        Node::new("Files")
            .span(file.sub(if v4 { 0x0c } else { 0x10 }, 4))
            .value(uint(count.into(), 32)),
    );
    cx.emit(Node::new("Body").span(file.tail(if v4 { 0x40 } else { 0x20 })));
    cx.annotate(format!(
        "{} binder {version:?}, {count} files",
        if v4 { "BND4" } else { "BND3" }
    ));
    Ok(())
}
