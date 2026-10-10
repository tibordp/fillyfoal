//! Headers in front of sample data: NIST SPHERE, Audio Visual Research
//! (AVR) and Portable Voice Format (PVF).

use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Record, emit_record};
use crate::error::Result;
use crate::fields::Endian;
use crate::formats::{Input, Probe};
use crate::node::Node;
use crate::record;
use crate::value::Value;

const BE: Endian = Endian::Big;

fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

use crate::formats::text::scan::head_lines as header_lines;

// ---------------------------------------------------------------------------
// Audio: NIST SPHERE, Audio Visual Research, Portable Voice Format

declare_format!(pub SPHERE = "nist-sphere", "NIST SPHERE audio", ["sph", "nist", "wv1", "wv2"], "audio/x-nist-sphere",
    Probe::Magic(&[(0, b"NIST_1A\n")]), sphere);

async fn sphere(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let size: u64 = String::from_utf8_lossy(&cx.read(file.sub(8, 8)).await?)
        .trim()
        .parse()
        .unwrap_or(1024);
    let header = file.sub(0, size);
    let all = header_lines(&cx, header, size).await?;
    let mut fields = Vec::new();
    for (line, span) in all.iter().skip(2) {
        if line.trim() == "end_head" {
            break;
        }
        let mut parts = line.splitn(3, ' ');
        if let (Some(k), Some(_), Some(v)) = (parts.next(), parts.next(), parts.next()) {
            fields.push((k.to_owned(), v.to_owned()));
            cx.emit(Node::new(k.to_owned()).span(*span).value(text(v)));
        }
    }
    cx.emit(Node::new("Samples").span(file.tail(size)));
    let get = |k: &str| {
        fields
            .iter()
            .find(|(a, _)| a == k)
            .map_or("?", |(_, v)| v.as_str())
    };
    cx.annotate(format!(
        "NIST SPHERE, {} Hz, {} channel(s), {}",
        get("sample_rate"),
        get("channel_count"),
        get("sample_coding")
    ));
    Ok(())
}

declare_format!(pub AVR = "avr", "Audio Visual Research sample", ["avr"], "audio/x-avr",
    Probe::Magic(&[(0, b"2BIT")]), avr);

record! {
    pub struct AvrHeader {
        magic: ascii[4] "Signature",
        name: ascii[8] "Name",
        mono: u16 "Channels (0 mono, 0xffff stereo)" .hex(),
        resolution: u16 "Bits per sample",
        signed: u16 "Signed (0xffff)" .hex(),
        looped: u16 "Looping (0xffff)" .hex(),
        midi: u16 "MIDI note" .hex(),
        rate: u32 "Sample rate (low 24 bits)" .hex(),
        length: u32 "Length (samples)",
        loop_begin: u32 "Loop begin",
        loop_end: u32 "Loop end",
    }
}

async fn avr(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: AvrHeader = emit_record(&cx, file.sub(0, AvrHeader::SIZE), BE).await?;
    cx.emit(Node::new("Samples").span(file.tail(128)));
    cx.annotate(format!(
        "AVR {:?}, {} Hz, {}-bit {}",
        h.name.trim(),
        h.rate & 0xff_ffff,
        h.resolution,
        if h.mono == 0 { "mono" } else { "stereo" }
    ));
    Ok(())
}

declare_format!(pub PVF = "pvf", "Portable Voice Format", ["pvf"], "audio/x-pvf",
    Probe::Magic(&[(0, b"PVF1\n"), (0, b"PVF2\n")]), pvf);

async fn pvf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let all = header_lines(&cx, file, 64).await?;
    let (Some((magic, m)), Some((params, p))) = (all.first(), all.get(1)) else {
        return Ok(());
    };
    cx.emit(Node::new("Signature").span(*m).value(text(magic.clone())));
    let v: Vec<&str> = params.split_whitespace().collect();
    for (label, value) in ["Channels", "Sample rate", "Bits per sample"]
        .iter()
        .zip(&v)
    {
        cx.emit(Node::new(*label).span(*p).value(text(*value)));
    }
    cx.emit(
        Node::new("Samples").span(file.tail(p.end().saturating_sub(file.offset).saturating_add(1))),
    );
    cx.annotate(format!(
        "{magic} voice, {} channel(s), {} Hz, {}-bit",
        v.first().unwrap_or(&"?"),
        v.get(1).unwrap_or(&"?"),
        v.get(2).unwrap_or(&"?")
    ));
    Ok(())
}
