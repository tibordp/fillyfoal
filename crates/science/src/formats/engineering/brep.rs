//! Boundary-representation CAD models: Rhino 3DM and ACIS binary (SAB).

use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::lines::{preview, text, uint};
use crate::formats::{Input, Probe};
use crate::node::Node;
use crate::value::{EnumTable, lookup};

const LE: Endian = Endian::Little;

// ---------------------------------------------------------------------------
// Rhino 3DM

declare_format!(pub RHINO_3DM = "rhino-3dm", "Rhinoceros 3D model (3DM)", ["3dm"], "model/x-3dm",
    Probe::Magic(&[(0, b"3D Geometry File Format ")]), rhino_3dm);

const RHINO_TCODES: EnumTable = &[
    (0x0000_0001, "Comment block"),
    (0x0000_7fff, "End of file"),
    (0x1000_0010, "Material table"),
    (0x1000_0011, "Layer table"),
    (0x1000_0012, "Light table"),
    (0x1000_0013, "Object table"),
    (0x1000_0014, "Properties table"),
    (0x1000_0015, "Settings table"),
    (0x1000_0016, "Bitmap table"),
    (0x1000_0017, "Texture mapping table"),
    (0x1000_0018, "Group table"),
    (0x1000_0019, "Font table"),
    (0x1000_0020, "Dimension style table"),
    (0x1000_0021, "Instance definition table"),
    (0x1000_0022, "Hatch pattern table"),
    (0x1000_0023, "Linetype table"),
    (0x1000_0024, "History record table"),
    (0x1000_0025, "User table"),
    (0x1000_0026, "Section style table"),
    (0x1000_0027, "Linetype table"),
    (0xffff_ffff, "End of table"),
];

async fn rhino_3dm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 32)).await?;
    let version: u32 = String::from_utf8_lossy(head.get(24..32).unwrap_or_default())
        .trim()
        .parse()
        .unwrap_or(0);
    cx.emit(
        Node::new("Signature")
            .span(file.sub(0, 24))
            .value(text("3D Geometry File Format")),
    );
    cx.emit(
        Node::new("Version")
            .span(file.sub(24, 8))
            .value(uint(version.into())),
    );
    // Version 5 and later (stored as 5 or as 50+) use 8-byte chunk lengths.
    let wide = version >= 5 && version != 0;
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(32);
    let mut comment = String::new();
    let mut chunks = 0u32;
    while cur.remaining() >= 8 {
        let start = cur.pos();
        let code = cur.u32().await?;
        let len = if wide {
            cur.u64().await?
        } else {
            u64::from(cur.u32().await?)
        };
        let short = code & 0x8000_0000 != 0 && code != 0xffff_ffff;
        let body = if short { cur.span(0) } else { cur.span(len) };
        if !short {
            cur.skip(len);
        }
        if code == 1 {
            comment = String::from_utf8_lossy(&cx.read_avail(body.sub(0, 512)).await?)
                .trim_end_matches('\0')
                .to_owned();
        }
        let name = lookup(RHINO_TCODES, code.into())
            .map_or_else(|| format!("Chunk {code:#010x}"), str::to_owned);
        let node = Node::new(name)
            .span(cur.since(start))
            .value(crate::formats::util::lines::hex(code.into(), 32));
        cx.push(if short {
            node.summary(format!("value {len}"))
        } else {
            node.summary(format!("{len} bytes"))
        })
        .await;
        chunks = chunks.saturating_add(1);
        if code == 0x7fff {
            break;
        }
    }
    cx.annotate(format!(
        "Rhino 3DM v{version}, {chunks} chunk(s){}",
        if comment.is_empty() {
            String::new()
        } else {
            format!("; {}", preview(&comment, 80))
        }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// ACIS binary (SAB)

declare_format!(pub ACIS_SAB = "acis-sab", "ACIS solid model (binary SAB)", ["sab"], "model/x-acis-sab",
    Probe::Magic(&[(0, b"ACIS BinaryFile")]), acis_sab);

async fn acis_sab(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(
        Node::new("Signature")
            .span(file.sub(0, 15))
            .value(text("ACIS BinaryFile")),
    );
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(15);
    let names = [
        "Version",
        "Records",
        "Bodies",
        "Flags",
        "Product ID",
        "ACIS version",
        "Date",
        "Units (mm)",
        "Resolution",
        "Normal tolerance",
    ];
    let mut values = Vec::new();
    for name in names {
        let start = cur.pos();
        let tag = cur.u8().await?;
        let v = match tag {
            0x04 => crate::formats::util::lines::int(i64::from(cur.u32().await?.cast_signed())),
            0x06 => crate::formats::util::lines::float(cur.int::<f64>().await?),
            0x07 => {
                let n = cur.u8().await?;
                text(String::from_utf8_lossy(&cur.bytes(n.into()).await?).into_owned())
            }
            0x08 => {
                let n = cur.u16().await?;
                text(String::from_utf8_lossy(&cur.bytes(n.into()).await?).into_owned())
            }
            _ => {
                cx.diag(
                    Diagnostic::unsupported(format!("SAB tag {tag:#04x}")).at(cur.since(start)),
                );
                break;
            }
        };
        values.push(v.clone());
        cx.emit(Node::new(name).span(cur.since(start)).value(v));
    }
    cx.emit(Node::new("Entity records").span(file.tail(cur.pos())));
    let show = |i: usize| {
        values.get(i).map(|v| match v {
            crate::value::Value::Text(t) => t.clone(),
            crate::value::Value::Int { value, .. } => value.to_string(),
            crate::value::Value::Float(f) => f.to_string(),
            _ => String::new(),
        })
    };
    cx.annotate(format!(
        "ACIS SAB v{}, {} bod(ies){}{}",
        show(0).unwrap_or_default(),
        show(2).unwrap_or_default(),
        show(4).map(|p| format!(", {p}")).unwrap_or_default(),
        show(5).map(|p| format!(" ({p})")).unwrap_or_default()
    ));
    Ok(())
}
