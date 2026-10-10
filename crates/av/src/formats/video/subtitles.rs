//! Broadcast and disc subtitles: EBU STL, Scenarist SCC and VobSub indexes.

use crate::bytes::u16_le;
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, emit_record};
use crate::error::Result;
use crate::fields::Endian;
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::record;

const LE: Endian = Endian::Little;

use crate::formats::text::scan::head_lines as lines;
use crate::formats::util::val::text;

// ---------------------------------------------------------------------------
// Subtitles: EBU STL, Scenarist SCC, VobSub index

fn ebu_probe(h: &Head<'_>) -> bool {
    h.at(3, b"STL25.01") || h.at(3, b"STL30.01") || h.at(3, b"STL24.01") || h.at(3, b"STL50.01")
}

declare_format!(pub EBU_STL = "ebu-stl", "EBU STL subtitles", ["stl"], "application/x-ebu-stl",
    Probe::Custom(ebu_probe), ebu_stl);

record! {
    pub struct EbuGsi {
        code_page: ascii[3] "Code page",
        disk_format: ascii[8] "Disk format code",
        display_standard: ascii[1] "Display standard",
        character_table: ascii[2] "Character code table",
        language: ascii[2] "Language code",
        programme: ascii[32] "Original programme title",
        episode: ascii[32] "Original episode title",
        translated_programme: ascii[32] "Translated programme title",
        translated_episode: ascii[32] "Translated episode title",
        translator: ascii[32] "Translator's name",
        translator_contact: ascii[32] "Translator's contact details",
        reference: ascii[16] "Subtitle list reference",
        created: ascii[6] "Creation date",
        revised: ascii[6] "Revision date",
        revision: ascii[2] "Revision number",
        tti_blocks: ascii[5] "Total TTI blocks",
        subtitles: ascii[5] "Total subtitles",
        groups: ascii[3] "Subtitle groups",
    }
}

async fn ebu_stl(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let gsi: EbuGsi = emit_record(&cx, file.sub(0, EbuGsi::SIZE), LE).await?;
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(1024);
    let mut n = 0u32;
    while cur.remaining() >= 128 {
        let start = cur.pos();
        let block = cur.bytes(128).await?;
        n = n.saturating_add(1);
        let number = u16_le(&block, 1).unwrap_or(0);
        let tc = |at: usize| {
            format!(
                "{:02}:{:02}:{:02}:{:02}",
                block.get(at).copied().unwrap_or(0),
                block.get(at.saturating_add(1)).copied().unwrap_or(0),
                block.get(at.saturating_add(2)).copied().unwrap_or(0),
                block.get(at.saturating_add(3)).copied().unwrap_or(0)
            )
        };
        let text_field: String = block
            .get(16..128)
            .unwrap_or_default()
            .iter()
            .filter(|&&b| (0x20..0x7f).contains(&b))
            .map(|&b| char::from(b))
            .collect();
        cx.push(
            Node::new(format!("Subtitle {number}"))
                .span(cur.since(start))
                .summary(format!("{} → {}: {}", tc(5), tc(9), text_field.trim())),
        )
        .await;
    }
    cx.annotate(format!(
        "EBU STL ({}), {:?}, {n} TTI blocks",
        gsi.disk_format,
        gsi.programme.trim()
    ));
    Ok(())
}

declare_format!(pub SCC = "scc", "Scenarist closed captions", ["scc"], "text/x-scc",
    Probe::Magic(&[(0, b"Scenarist_SCC V1.0")]), scc);

async fn scc(cx: Cx, input: Input) -> Result<()> {
    let all = lines(&cx, input.span, 1 << 20).await?;
    let mut captions = 0u32;
    for (line, span) in all {
        if let Some((tc, codes)) = line.split_once('\t') {
            captions = captions.saturating_add(1);
            cx.push(
                Node::new(tc.to_owned())
                    .span(span)
                    .summary(format!("{} code words", codes.split_whitespace().count())),
            )
            .await;
        } else if line.starts_with("Scenarist") {
            cx.emit(Node::new("Header").span(span).value(text(line)));
        }
    }
    cx.annotate(format!("SCC captions, {captions} lines"));
    Ok(())
}

declare_format!(pub VOBSUB = "vobsub-idx", "VobSub subtitle index", ["idx"], "text/x-vobsub",
    Probe::Magic(&[(0, b"# VobSub index file")]), vobsub);

async fn vobsub(cx: Cx, input: Input) -> Result<()> {
    let all = lines(&cx, input.span, 1 << 20).await?;
    let mut tracks = Vec::new();
    let mut stamps = 0u32;
    for (line, span) in all {
        if let Some(rest) = line.strip_prefix("id: ") {
            tracks.push(rest.split(',').next().unwrap_or_default().to_owned());
            cx.push(Node::new(format!("Track {rest}")).span(span)).await;
        } else if line.starts_with("timestamp:") {
            stamps = stamps.saturating_add(1);
        } else if let Some((k, v)) = line.split_once(": ").filter(|_| !line.starts_with('#')) {
            cx.push(Node::new(k.to_owned()).span(span).value(text(v)))
                .await;
        }
    }
    cx.annotate(format!(
        "VobSub index, tracks [{}], {stamps} subtitles",
        tracks.join(", ")
    ));
    Ok(())
}
