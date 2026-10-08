//! Paint-program documents: Corel PHOTO-PAINT, Clip Studio Paint, FireAlpaca
//! MDP and GIMP palettes.

use crate::bytes::u32_le;
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{ChunkLayout, Cursor};
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::{Input, Probe, embedded, embedded_as};
use crate::node::Node;
use crate::span::Span;
use crate::value::{Radix, Value};

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
    for (n, (line, span)) in all.iter().skip(1).enumerate() {
        if n % 1024 == 1023 {
            cx.checkpoint().await;
        }
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
