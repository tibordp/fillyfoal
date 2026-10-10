//! Codec streams with their own framing: RealAudio, Psion WVE and 3GPP EVS.

use crate::bytes::{u16_be, u32_be};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::{Input, Probe};
use crate::node::Node;
use crate::span::Span;

use crate::formats::util::val::{text, uint};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// RealAudio, Psion, EVS

declare_format!(pub REALAUDIO = "realaudio", "RealAudio (.ra)", ["ra"], "audio/x-pn-realaudio",
    Probe::Magic(&[(0, b".ra\xfd")]), realaudio);

async fn pascal(cur: &mut Cursor<'_>) -> Result<(String, Span)> {
    let len = u64::from(cur.u8().await?);
    let span = cur.span(len);
    Ok((
        String::from_utf8_lossy(&cur.bytes(len).await?).into_owned(),
        span,
    ))
}

async fn realaudio(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let version = u16_be(&cx.read(file.sub(4, 2)).await?, 0).unwrap_or(0);
    cx.emit(Node::new("Signature").span(file.sub(0, 4)));
    cx.emit(
        Node::new("Version")
            .span(file.sub(4, 2))
            .value(uint(version, 16)),
    );
    if version == 3 {
        let mut cur = Cursor::new(&cx, file, BE);
        cur.seek(22);
        let mut parts = Vec::new();
        for label in ["Title", "Author", "Copyright", "Comment"] {
            let (s, span) = pascal(&mut cur).await?;
            cx.emit(Node::new(label).span(span).value(text(s.clone())));
            parts.push(s);
        }
        cx.emit(Node::new("Audio (14.4 kbps)").span(file.tail(cur.pos())));
        cx.annotate(format!(
            "RealAudio 1.0 {:?}",
            parts.first().cloned().unwrap_or_default()
        ));
        return Ok(());
    }
    let head = cx.read(file.sub(0, 70)).await?;
    let data = u32_be(&head, 12).unwrap_or(0);
    let flavor = u16_be(&head, 22).unwrap_or(0);
    let rate = u16_be(&head, 48).unwrap_or(0);
    let bits = u16_be(&head, 52).unwrap_or(0);
    let channels = u16_be(&head, 54).unwrap_or(0);
    let fourcc = String::from_utf8_lossy(head.get(62..66).unwrap_or_default()).into_owned();
    cx.emit(
        Node::new("Data size")
            .span(file.sub(12, 4))
            .value(uint(data, 32)),
    );
    cx.emit(
        Node::new("Codec flavor")
            .span(file.sub(22, 2))
            .value(uint(flavor, 16)),
    );
    cx.emit(
        Node::new("Sample rate")
            .span(file.sub(48, 2))
            .value(uint(rate, 16)),
    );
    cx.emit(
        Node::new("Channels")
            .span(file.sub(54, 2))
            .value(uint(channels, 16)),
    );
    cx.emit(
        Node::new("Codec")
            .span(file.sub(62, 4))
            .value(text(fourcc.clone())),
    );
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(69);
    let mut title = String::new();
    for label in ["Title", "Author", "Copyright"] {
        let (s, span) = pascal(&mut cur).await?;
        if label == "Title" {
            title = s.clone();
        }
        cx.emit(Node::new(label).span(span).value(text(s)));
    }
    cx.emit(Node::new("Audio").span(file.sub(file.len.saturating_sub(data.into()), data.into())));
    cx.annotate(format!(
        "RealAudio v{version} {title:?}: {fourcc}, {rate} Hz, {bits}-bit, {channels} ch"
    ));
    Ok(())
}

declare_format!(pub PSION_WVE = "psion-wve", "Psion Series 3 sound (WVE)", ["wve"], "audio/x-psion-wve",
    Probe::Magic(&[(0, b"ALawSoundFile**\0")]), psion_wve);

async fn psion_wve(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 32)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 16).emit()?;
    f.u16("Version").hex().emit()?;
    let samples = f.u32("Samples").emit()?;
    f.u16("Silence before repeat").emit()?;
    f.u16("Repeats").emit()?;
    cx.emit(Node::new("A-law samples (8 kHz)").span(file.tail(32)));
    cx.annotate(format!(
        "Psion A-law sound, {samples} samples ({:.2} s)",
        f64::from(samples) / 8000.0
    ));
    Ok(())
}

declare_format!(pub EVS = "evs", "3GPP EVS speech (MIME storage)", ["evs", "3ga"], "audio/evs",
    Probe::Magic(&[(0, b"#!EVS_MC1.0\n")]), evs);

async fn evs(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let channels = u32_be(&cx.read(file.sub(12, 4)).await?, 0).unwrap_or(0);
    cx.emit(Node::new("Signature").span(file.sub(0, 12)));
    cx.emit(
        Node::new("Channels")
            .span(file.sub(12, 4))
            .value(uint(channels, 32)),
    );
    cx.emit(Node::new("Frames").span(file.tail(16)));
    cx.annotate(format!("EVS speech, {channels} channel(s)"));
    Ok(())
}
