//! 3D meshes: VRML, OFF and MD5 mesh text files; Source MDL and Unreal PSK
//! binaries.

use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, emit_record};
use crate::error::Result;
use crate::fields::Endian;
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::value::Value;

const LE: Endian = Endian::Little;

fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

use crate::formats::text::scan::head_lines as lines;

// ---------------------------------------------------------------------------
// 3D text formats: VRML, OFF, MD5 mesh; binary: Source MDL, Unreal PSK

declare_format!(pub VRML = "vrml", "VRML world", ["wrl", "vrml"], "model/vrml",
    Probe::Magic(&[(0, b"#VRML V2.0"), (0, b"#VRML V1.0"), (0, b"#VRML ")]), vrml);

async fn vrml(cx: Cx, input: Input) -> Result<()> {
    let all = lines(&cx, input.span, 1 << 20).await?;
    let header = all.first().map(|(l, _)| l.clone()).unwrap_or_default();
    if let Some((line, span)) = all.first() {
        cx.emit(Node::new("Header").span(*span).value(text(line.clone())));
    }
    let mut defs = 0u32;
    for (line, span) in all.iter().skip(1) {
        let t = line.trim_start();
        if let Some(rest) = t.strip_prefix("DEF ") {
            defs = defs.saturating_add(1);
            cx.push(
                Node::new(
                    rest.split_whitespace()
                        .next()
                        .unwrap_or_default()
                        .to_owned(),
                )
                .span(*span)
                .summary(
                    rest.split_whitespace()
                        .nth(1)
                        .unwrap_or_default()
                        .to_owned(),
                ),
            )
            .await;
        }
    }
    cx.annotate(format!(
        "{}, {defs} named nodes",
        header.trim_start_matches('#').trim()
    ));
    Ok(())
}

fn off_probe(h: &Head<'_>) -> bool {
    ["OFF\n", "OFF\r\n", "COFF\n", "NOFF\n", "OFF \n"]
        .iter()
        .any(|m| h.starts_with(m.as_bytes()))
        || (h.starts_with(b"OFF ") && h.data.get(4).is_some_and(u8::is_ascii_digit))
}

declare_format!(pub OFF = "off", "Object File Format mesh", ["off"], "model/x-off",
    Probe::Custom(off_probe), off);

async fn off(cx: Cx, input: Input) -> Result<()> {
    let all = lines(&cx, input.span, 4096).await?;
    let mut numbers = Vec::new();
    for (line, _) in &all {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let t = t
            .trim_start_matches(|c: char| c.is_ascii_alphabetic())
            .trim();
        numbers.extend(t.split_whitespace().filter_map(|w| w.parse::<u64>().ok()));
        if numbers.len() >= 2 {
            break;
        }
    }
    if let Some((line, span)) = all.first() {
        cx.emit(Node::new("Header").span(*span).value(text(line.clone())));
    }
    cx.emit(Node::new("Data").span(input.span));
    cx.annotate(format!(
        "OFF mesh, {} vertices, {} faces",
        numbers.first().copied().unwrap_or(0),
        numbers.get(1).copied().unwrap_or(0)
    ));
    Ok(())
}

declare_format!(pub MD5MESH = "md5mesh", "id Tech 4 MD5 model", ["md5mesh", "md5anim"], "model/x-md5",
    Probe::Magic(&[(0, b"MD5Version ")]), md5mesh);

async fn md5mesh(cx: Cx, input: Input) -> Result<()> {
    let all = lines(&cx, input.span, 1 << 20).await?;
    let mut kv = Vec::new();
    for (line, span) in &all {
        let mut it = line.split_whitespace();
        if let (Some(k), Some(v)) = (it.next(), it.next())
            && (k.starts_with("num") || k == "MD5Version" || k == "commandline" || k == "frameRate")
        {
            kv.push((k.to_owned(), v.to_owned()));
            cx.emit(
                Node::new(k.to_owned())
                    .span(*span)
                    .value(text(v.trim_matches('"'))),
            );
        }
    }
    let get = |k: &str| {
        kv.iter()
            .find(|(a, _)| a == k)
            .map_or(String::from("?"), |(_, v)| v.clone())
    };
    let anim = kv.iter().any(|(k, _)| k == "numFrames");
    cx.annotate(if anim {
        format!(
            "MD5 animation, {} frames at {} fps",
            get("numFrames"),
            get("frameRate")
        )
    } else {
        format!(
            "MD5 mesh, {} joints, {} meshes",
            get("numJoints"),
            get("numMeshes")
        )
    });
    Ok(())
}

declare_format!(pub SOURCE_MDL = "source-mdl", "Source engine model", ["mdl"], "model/x-source-mdl",
    Probe::Magic(&[(0, b"IDST")]), source_mdl);

record! {
    pub struct StudioHeader {
        id: ascii[4] "Identifier",
        version: i32 "Version",
        checksum: u32 "Checksum" .hex(),
        name: ascii[64] "Name",
        length: i32 "File length",
    }
}

async fn source_mdl(cx: Cx, input: Input) -> Result<()> {
    let h: StudioHeader = emit_record(&cx, input.span.sub(0, StudioHeader::SIZE), LE).await?;
    cx.emit(Node::new("Model data").span(input.span.tail(StudioHeader::SIZE)));
    cx.annotate(format!(
        "Source model {:?}, version {}",
        h.name.trim_end(),
        h.version
    ));
    Ok(())
}

declare_format!(pub PSK = "unreal-psk", "Unreal skeletal mesh (PSK/PSA)", ["psk", "psa", "pskx"], "model/x-unreal-psk",
    Probe::Magic(&[(0, b"ACTRHEAD"), (0, b"ANIMHEAD")]), psk);

async fn psk(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let mut chunks = Vec::new();
    while cur.remaining() >= 32 {
        let start = cur.pos();
        let id = crate::text::until_nul(&cur.bytes(20).await?);
        let _flags = cur.u32().await?;
        let size = cur.u32().await?;
        let count = cur.u32().await?;
        cur.skip(u64::from(size).saturating_mul(count.into()));
        chunks.push(id.clone());
        cx.push(
            Node::new(id)
                .span(cur.since(start))
                .summary(format!("{count} × {size} bytes")),
        )
        .await;
    }
    cx.annotate(format!(
        "Unreal {} ({} chunks)",
        if chunks.first().is_some_and(|c| c == "ANIMHEAD") {
            "animation"
        } else {
            "skeletal mesh"
        },
        chunks.len()
    ));
    Ok(())
}
