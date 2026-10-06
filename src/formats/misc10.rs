//! Tracker modules (PTM, DMF, IMF, J2B, GDM, MT2, AMS, Symphonie,
//! Digitrakker, PLM, PSM, AMF), Gravis UltraSound patches, speech audio
//! (RealAudio, Psion, EVS), and old game/demo video
//! (SMUSH, DXA, Acorn Replay, SGI movies).

use crate::bytes::{u16_be, u16_le, u32_be, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{ChunkLayout, Cursor, Record, emit_record};
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::text::scan::head_lines;
use crate::formats::{Codec, Head, Input, Probe, content, embedded};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{Radix, Value};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

fn uint(value: u64, bits: u8) -> Value {
    Value::UInt { value, bits, radix: Radix::Dec }
}

fn zstr(b: &[u8]) -> String {
    crate::text::until_nul(b)
}

// ---------------------------------------------------------------------------
// Tracker modules

fn ptm_probe(h: &Head<'_>) -> bool {
    h.at(44, b"PTMF") && h.data.get(28) == Some(&0x1a)
}

declare_format!(pub PTM = "ptm", "PolyTracker module", ["ptm"], "audio/x-ptm",
    Probe::Custom(ptm_probe), ptm);

record! {
    pub struct PtmHeader {
        title: ascii[28] "Title",
        eof: u8 "EOF marker" .hex(),
        minor: u8 "Version (minor)",
        major: u8 "Version (major)",
        reserved: u8 "Reserved",
        orders: u16 "Orders",
        samples: u16 "Samples",
        patterns: u16 "Patterns",
        channels: u16 "Channels",
        flags: u16 "Flags" .hex(),
        reserved2: u16 "Reserved",
        magic: ascii[4] "Signature",
    }
}

async fn ptm(cx: Cx, input: Input) -> Result<()> {
    let h: PtmHeader = emit_record(&cx, input.span.sub(0, PtmHeader::SIZE), LE).await?;
    cx.emit(Node::new("Orders, samples and patterns").span(input.span.tail(PtmHeader::SIZE)));
    cx.annotate(format!("PolyTracker {}.{:02x} module {:?}: {} channels, {} patterns, {} samples", h.major, h.minor, h.title.trim(), h.channels, h.patterns, h.samples));
    Ok(())
}

declare_format!(pub DMF = "xtracker-dmf", "X-Tracker module (DMF)", ["dmf"], "audio/x-dmf",
    Probe::Magic(&[(0, b"DDMF")]), dmf);

async fn dmf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 66)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 4).emit()?;
    let version = f.u8("Version").emit()?;
    let tracker = f.ascii("Tracker", 8).emit()?;
    let title = f.ascii("Song name", 30).emit()?;
    let composer = f.ascii("Composer", 20).emit()?;
    f.u8("Day").emit()?;
    f.u8("Month").emit()?;
    f.u8("Year").emit()?;
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(66);
    while let Some(chunk) = cur.chunk(ChunkLayout::new(4, 4, LE)).await? {
        let end = chunk.id == b"ENDE";
        cx.push(chunk.node()).await;
        if end {
            break;
        }
    }
    cx.annotate(format!("{} v{version} module {:?} by {:?}", tracker.trim(), title.trim(), composer.trim()));
    Ok(())
}

fn imf_probe(h: &Head<'_>) -> bool {
    h.at(60, b"IM10")
}

declare_format!(pub IMF = "imago-imf", "Imago Orpheus module", ["imf"], "audio/x-imf",
    Probe::Custom(imf_probe), imf);

record! {
    pub struct ImfHeader {
        title: ascii[32] "Title",
        orders: u16 "Orders",
        patterns: u16 "Patterns",
        instruments: u16 "Instruments",
        flags: u16 "Flags" .hex(),
        unused: bytes[8] "Unused",
        tempo: u8 "Tempo",
        bpm: u8 "BPM",
        master: u8 "Master volume",
        amp: u8 "Amplification",
        unused2: bytes[8] "Unused",
        magic: ascii[4] "Signature",
    }
}

async fn imf(cx: Cx, input: Input) -> Result<()> {
    let h: ImfHeader = emit_record(&cx, input.span.sub(0, ImfHeader::SIZE), LE).await?;
    cx.emit(Node::new("Channels, orders, patterns and instruments").span(input.span.tail(ImfHeader::SIZE)));
    cx.annotate(format!("Imago Orpheus module {:?}: {} patterns, {} instruments, {} BPM", h.title.trim(), h.patterns, h.instruments, h.bpm));
    Ok(())
}

declare_format!(pub J2B = "j2b", "Jazz Jackrabbit 2 music (J2B)", ["j2b"], "audio/x-j2b",
    Probe::Magic(&[(0, b"MUSE\xde\xad\xbe\xaf"), (0, b"MUSE\xde\xad\xba\xbe")]), j2b);

async fn j2b(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 24)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.bytes("Signature", 8).emit()?;
    f.u32("File length").emit()?;
    f.u32("CRC32").hex().emit()?;
    let packed = f.u32("Compressed length").emit()?;
    let unpacked = f.u32("Uncompressed length").emit()?;
    cx.emit(content("Module (RIFF AM)", input, file.sub(24, packed.into()), Codec::Zlib, Some(unpacked.into())));
    cx.annotate(format!("Jazz Jackrabbit 2 music, {packed} → {unpacked} bytes"));
    Ok(())
}

fn gdm_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"GDM\xfe") && h.at(0x47, b"GMFS")
}

declare_format!(pub GDM = "gdm", "General Digital Music module", ["gdm"], "audio/x-gdm",
    Probe::Custom(gdm_probe), gdm);

async fn gdm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x76)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.bytes("Signature", 4).emit()?;
    let title = f.ascii("Title", 32).emit()?;
    let musician = f.ascii("Musician", 32).emit()?;
    f.bytes("EOF marker", 3).emit()?;
    f.ascii("Format signature", 4).emit()?;
    let major = f.u8("Format major").emit()?;
    let minor = f.u8("Format minor").emit()?;
    f.u16("Tracker ID").emit()?;
    f.u8("Tracker major").emit()?;
    f.u8("Tracker minor").emit()?;
    f.bytes("Panning map", 32).emit()?;
    f.u8("Master volume").emit()?;
    f.u8("Tempo").emit()?;
    f.u8("BPM").emit()?;
    let original = f.u16("Original format").enumeration(&[(1, "MOD"), (2, "MTM"), (3, "S3M"), (4, "669"), (5, "FAR"), (6, "ULT"), (7, "STM"), (8, "MED")]).emit()?;
    cx.emit(Node::new("Tables, patterns and samples").span(file.tail(0x76)));
    let _ = original;
    cx.annotate(format!("GDM {major}.{minor} module {:?} by {:?}", title.trim(), musician.trim()));
    Ok(())
}

declare_format!(pub MT2 = "mt2", "MadTracker 2 module", ["mt2"], "audio/x-mt2",
    Probe::Magic(&[(0, b"MT20")]), mt2);

async fn mt2(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x7e)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 4).emit()?;
    f.u32("User ID").hex().emit()?;
    let version = f.u16("Version").hex().emit()?;
    let tracker = f.ascii("Tracker", 32).emit()?;
    let title = f.ascii("Title", 64).emit()?;
    let positions = f.u16("Positions").emit()?;
    f.u16("Restart position").emit()?;
    let patterns = f.u16("Patterns").emit()?;
    let tracks = f.u16("Tracks").emit()?;
    let samples = f.u16("Samples").emit()?;
    f.u8("Ticks per line").emit()?;
    f.u8("Lines per beat").emit()?;
    f.u32("Flags").hex().emit()?;
    let instruments = f.u16("Instruments").emit()?;
    let _ = samples;
    cx.emit(Node::new("Song, patterns, drums and instruments").span(file.tail(0x7e)));
    cx.annotate(format!("MadTracker {}.{:02x} module {:?} ({}): {positions} positions, {patterns} patterns, {tracks} tracks, {instruments} instruments", version >> 8, version & 0xff, title.trim(), tracker.trim()));
    Ok(())
}

declare_format!(pub AMS = "ams", "Velvet Studio / Extreme's Tracker module (AMS)", ["ams"], "audio/x-ams",
    Probe::Magic(&[(0, b"AMShdr\x1a"), (0, b"Extreme")]), ams);

async fn ams(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 64)).await?;
    if head.starts_with(b"AMShdr") {
        let len = u64::from(head.get(7).copied().unwrap_or(0));
        let title = String::from_utf8_lossy(&cx.read(file.sub(8, len)).await?).into_owned();
        let v = cx.read(file.sub(8u64.saturating_add(len), 2)).await?;
        cx.emit(Node::new("Signature").span(file.sub(0, 7)));
        cx.emit(Node::new("Title").span(file.sub(8, len)).value(text(title.clone())));
        let version = u16_le(&v, 0).unwrap_or(0);
        cx.emit(Node::new("Version").span(file.sub(8u64.saturating_add(len), 2)).value(text(format!("{}.{}", version >> 8, version & 0xff))));
        cx.emit(Node::new("Module").span(file.tail(10u64.saturating_add(len))));
        cx.annotate(format!("Velvet Studio module {title:?}"));
    } else {
        let version = u16_le(&head, 7).unwrap_or(0);
        cx.emit(Node::new("Signature").span(file.sub(0, 7)));
        cx.emit(Node::new("Version").span(file.sub(7, 2)).value(text(format!("{}.{}", version >> 8, version & 0xff))));
        cx.emit(Node::new("Module").span(file.tail(9)));
        cx.annotate("Extreme's Tracker module");
    }
    Ok(())
}

declare_format!(pub SYMPHONIE = "symphonie", "Symphonie module", ["symmod"], "audio/x-symphonie",
    Probe::Magic(&[(0, b"SymM")]), symphonie);

async fn symphonie(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 8)).await?;
    cx.emit(Node::new("Signature").span(file.sub(0, 4)));
    cx.emit(Node::new("Version").span(file.sub(4, 4)).value(uint(u32_be(&head, 4).unwrap_or(0).into(), 32)));
    // Chunks: a signed type, then (for data chunks) a length.
    let mut pos = 8u64;
    let mut n = 0u32;
    while pos.saturating_add(4) <= file.len && n < 4096 {
        let t = i32::from_be_bytes(cx.read(file.sub(pos, 4)).await?.get(..4).and_then(|s| s.try_into().ok()).unwrap_or([0; 4]));
        let (len, name) = match t {
            -1 => (8u64, "Channels"),
            -2 => (8, "Track length"),
            -3 => (8, "Pattern size"),
            -4 => (8, "Number of instruments"),
            -5 => (8, "Event size"),
            -6 => (8, "Tempo"),
            -7 => (8, "External samples"),
            -10 => (8, "Position size"),
            -11 => (8, "Sample boost"),
            -12 => (8, "Stereo detune"),
            -13 => (8, "Stereo phase"),
            _ => {
                let l = u64::from(u32_be(&cx.read(file.sub_exact(pos.saturating_add(4), 4)?).await?, 0).unwrap_or(0));
                (l.saturating_add(8), "Data chunk")
            }
        };
        cx.push(Node::new(name).span(file.sub(pos, len)).summary(format!("type {t}"))).await;
        pos = pos.saturating_add(len);
        n = n.saturating_add(1);
    }
    cx.annotate(format!("Symphonie module, {n} chunks"));
    Ok(())
}

declare_format!(pub DIGITRAKKER = "digitrakker-mdl", "Digitrakker module (MDL)", ["mdl"], "audio/x-mdl",
    Probe::Magic(&[(0, b"DMDL")]), digitrakker);

async fn digitrakker(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let version = cx.read(file.sub(4, 1)).await?.first().copied().unwrap_or(0);
    cx.emit(Node::new("Signature").span(file.sub(0, 4)));
    cx.emit(Node::new("Version").span(file.sub(4, 1)).value(text(format!("{}.{}", version >> 4, version & 0xf))));
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(5);
    let mut title = String::new();
    while let Some(chunk) = cur.chunk(ChunkLayout::new(2, 4, LE)).await? {
        let mut node = chunk.node();
        if chunk.id == b"IN" {
            let b = cx.read(chunk.body.sub(0, 52)).await?;
            title = String::from_utf8_lossy(b.get(..32).unwrap_or_default()).trim().to_owned();
            let composer = String::from_utf8_lossy(b.get(32..52).unwrap_or_default()).trim().to_owned();
            node = node.summary(format!("{title:?} by {composer:?}"));
        }
        cx.push(node).await;
    }
    cx.annotate(format!("Digitrakker module {title:?}"));
    Ok(())
}

declare_format!(pub PLM = "plm", "Disorder Tracker 2 module (PLM)", ["plm"], "audio/x-plm",
    Probe::Magic(&[(0, b"PLM\x1a")]), plm);

async fn plm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x60)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.bytes("Signature", 4).emit()?;
    let size = f.u8("Header size").emit()?;
    let version = f.u8("Version").emit()?;
    let title = f.ascii("Title", 48).emit()?;
    let channels = f.u8("Channels").emit()?;
    f.u8("Flags").hex().emit()?;
    f.u8("Maximum volume").emit()?;
    f.u8("Amplification").emit()?;
    f.u8("BPM").emit()?;
    f.u8("Speed").emit()?;
    f.bytes("Panning", 32).emit()?;
    let samples = f.u8("Samples").emit()?;
    let patterns = f.u8("Patterns").emit()?;
    let orders = f.u16("Orders").emit()?;
    cx.emit(Node::new("Orders, patterns and samples").span(file.tail(size.into())));
    cx.annotate(format!("Disorder Tracker v{version} module {:?}: {channels} channels, {patterns} patterns, {samples} samples, {orders} orders", title.trim()));
    Ok(())
}

fn psm_probe(h: &Head<'_>) -> bool {
    (h.starts_with(b"PSM ") && h.at(8, b"FILE")) || h.starts_with(b"PSM\xfe")
}

declare_format!(pub PSM = "psm", "Epic MegaGames MASI module (PSM)", ["psm"], "audio/x-psm",
    Probe::Custom(psm_probe), psm);

async fn psm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    if cx.read(file.sub(0, 4)).await? == b"PSM\xfe" {
        let head = cx.block(file.sub(0, 64)).await?;
        let mut f = Fields::emitting(&cx, &head, LE);
        f.bytes("Signature", 4).emit()?;
        let title = f.ascii("Title", 60).emit()?;
        cx.emit(Node::new("Module").span(file.tail(64)));
        cx.annotate(format!("Protracker Studio module {:?}", title.trim()));
        return Ok(());
    }
    cx.emit(Node::new("Header").span(file.sub(0, 12)).summary("PSM FILE"));
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(12);
    let mut title = String::new();
    let mut samples = 0u32;
    while let Some(chunk) = cur.chunk(ChunkLayout::new(4, 4, LE)).await? {
        let mut node = chunk.node();
        match chunk.id.as_slice() {
            b"TITL" => {
                title = zstr(&cx.read_avail(chunk.body.sub(0, 64)).await?);
                node = node.value(text(title.clone()));
            }
            b"DSMP" => samples = samples.saturating_add(1),
            _ => {}
        }
        cx.push(node).await;
    }
    cx.annotate(format!("MASI module {title:?}, {samples} samples"));
    Ok(())
}

fn amf_probe(h: &Head<'_>) -> bool {
    (h.starts_with(b"AMF") && h.data.get(3).is_some_and(|v| (0x0a..=0x0e).contains(v))) || h.starts_with(b"ASYLUM Music Format V1.0\0")
}

declare_format!(pub AMF = "amf-module", "DSMI / ASYLUM module (AMF)", ["amf"], "audio/x-amf",
    Probe::Custom(amf_probe), amf);

async fn amf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    if cx.read(file.sub(0, 6)).await? == b"ASYLUM" {
        let head = cx.block(file.sub(0, 38)).await?;
        let mut f = Fields::emitting(&cx, &head, LE);
        f.ascii("Signature", 32).emit()?;
        f.u8("Speed").emit()?;
        f.u8("Tempo").emit()?;
        let samples = f.u8("Samples").emit()?;
        let patterns = f.u8("Patterns").emit()?;
        let orders = f.u8("Orders").emit()?;
        f.u8("Restart position").emit()?;
        cx.emit(Node::new("Orders, samples and patterns").span(file.tail(38)));
        cx.annotate(format!("ASYLUM module: {samples} samples, {patterns} patterns, {orders} orders"));
        return Ok(());
    }
    let head = cx.block(file.sub(0, 41)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 3).emit()?;
    let version = f.u8("Version").hex().emit()?;
    let title = f.ascii("Title", 32).emit()?;
    let samples = f.u8("Samples").emit()?;
    let orders = f.u8("Orders").emit()?;
    let tracks = f.u16("Tracks").emit()?;
    let channels = f.u8("Channels").emit()?;
    cx.emit(Node::new("Module").span(file.tail(41)));
    cx.annotate(format!("DSMI AMF v{}.{} module {:?}: {channels} channels, {orders} orders, {tracks} tracks, {samples} samples", version >> 4, version & 0xf, title.trim()));
    Ok(())
}

// ---------------------------------------------------------------------------
// Gravis UltraSound patch

declare_format!(pub GUS_PAT = "gus-patch", "Gravis UltraSound patch", ["pat"], "audio/x-gus-patch",
    Probe::Magic(&[(0, b"GF1PATCH110\0ID#000002\0"), (0, b"GF1PATCH100\0ID#000002\0")]), gus_patch);

async fn gus_patch(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 129)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 22).emit()?;
    let description = f.ascii("Description", 60).emit()?;
    f.u8("Instruments").emit()?;
    f.u8("Voices").emit()?;
    f.u8("Channels").emit()?;
    let waves = f.u16("Waveforms").emit()?;
    f.u16("Master volume").emit()?;
    f.u32("Data size").emit()?;
    let ins = cx.read(file.sub_exact(129, 63)?).await?;
    let name = zstr(ins.get(2..18).unwrap_or_default());
    cx.emit(Node::new("Instrument").span(file.sub(129, 63)).summary(format!("{name:?}, {} layer(s)", ins.get(22).copied().unwrap_or(0))));
    cx.emit(Node::new("Layer").span(file.sub(192, 47)));
    let mut pos = 239u64;
    for _ in 0..waves.min(256) {
        let w = cx.read(file.sub_exact(pos, 96)?).await?;
        let wname = zstr(w.get(..7).unwrap_or_default());
        let size = u64::from(u32_le(&w, 8).unwrap_or(0));
        let rate = u16_le(&w, 20).unwrap_or(0);
        let root = u32_le(&w, 30).unwrap_or(0);
        let modes = w.get(55).copied().unwrap_or(0);
        let bits = if modes & 1 != 0 { 16 } else { 8 };
        cx.push(
            Node::new(if wname.is_empty() { "Waveform".to_owned() } else { wname })
                .span(file.sub(pos, 96u64.saturating_add(size)))
                .summary(format!("{size} bytes, {rate} Hz, {bits}-bit, root {:.1} Hz{}", f64::from(root) / 1000.0, if modes & 4 != 0 { ", looped" } else { "" })),
        )
        .await;
        pos = pos.saturating_add(96).saturating_add(size);
    }
    cx.annotate(format!("GUS patch {name:?} ({}), {waves} waveforms", description.trim()));
    Ok(())
}

// ---------------------------------------------------------------------------
// RealAudio, Psion, EVS

declare_format!(pub REALAUDIO = "realaudio", "RealAudio (.ra)", ["ra"], "audio/x-pn-realaudio",
    Probe::Magic(&[(0, b".ra\xfd")]), realaudio);

async fn pascal(cur: &mut Cursor<'_>) -> Result<(String, Span)> {
    let len = u64::from(cur.u8().await?);
    let span = cur.span(len);
    Ok((String::from_utf8_lossy(&cur.bytes(len).await?).into_owned(), span))
}

async fn realaudio(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let version = u16_be(&cx.read(file.sub(4, 2)).await?, 0).unwrap_or(0);
    cx.emit(Node::new("Signature").span(file.sub(0, 4)));
    cx.emit(Node::new("Version").span(file.sub(4, 2)).value(uint(version.into(), 16)));
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
        cx.annotate(format!("RealAudio 1.0 {:?}", parts.first().cloned().unwrap_or_default()));
        return Ok(());
    }
    let head = cx.read(file.sub(0, 70)).await?;
    let data = u32_be(&head, 12).unwrap_or(0);
    let flavor = u16_be(&head, 22).unwrap_or(0);
    let rate = u16_be(&head, 48).unwrap_or(0);
    let bits = u16_be(&head, 52).unwrap_or(0);
    let channels = u16_be(&head, 54).unwrap_or(0);
    let fourcc = String::from_utf8_lossy(head.get(62..66).unwrap_or_default()).into_owned();
    cx.emit(Node::new("Data size").span(file.sub(12, 4)).value(uint(data.into(), 32)));
    cx.emit(Node::new("Codec flavor").span(file.sub(22, 2)).value(uint(flavor.into(), 16)));
    cx.emit(Node::new("Sample rate").span(file.sub(48, 2)).value(uint(rate.into(), 16)));
    cx.emit(Node::new("Channels").span(file.sub(54, 2)).value(uint(channels.into(), 16)));
    cx.emit(Node::new("Codec").span(file.sub(62, 4)).value(text(fourcc.clone())));
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
    cx.annotate(format!("RealAudio v{version} {title:?}: {fourcc}, {rate} Hz, {bits}-bit, {channels} ch"));
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
    cx.annotate(format!("Psion A-law sound, {samples} samples ({:.2} s)", f64::from(samples) / 8000.0));
    Ok(())
}

declare_format!(pub EVS = "evs", "3GPP EVS speech (MIME storage)", ["evs", "3ga"], "audio/evs",
    Probe::Magic(&[(0, b"#!EVS_MC1.0\n")]), evs);

async fn evs(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let channels = u32_be(&cx.read(file.sub(12, 4)).await?, 0).unwrap_or(0);
    cx.emit(Node::new("Signature").span(file.sub(0, 12)));
    cx.emit(Node::new("Channels").span(file.sub(12, 4)).value(uint(channels.into(), 32)));
    cx.emit(Node::new("Frames").span(file.tail(16)));
    cx.annotate(format!("EVS speech, {channels} channel(s)"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Video: LucasArts SMUSH, DXA, Acorn Replay, SGI movies

fn smush_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"ANIM") && h.at(8, b"AHDR")
}

declare_format!(pub SMUSH = "smush", "LucasArts SMUSH animation (SAN/ANM)", ["san", "anm", "snm"], "video/x-smush",
    Probe::Custom(smush_probe), smush);

async fn smush(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let size = u64::from(u32_be(&cx.read(file.sub(4, 4)).await?, 0).unwrap_or(0));
    cx.emit(Node::new("ANIM").span(file.sub(0, 8)).summary(format!("{size} bytes")));
    let mut cur = Cursor::new(&cx, file.sub(8, size), BE);
    let mut frames = 0u32;
    let mut version = 0u16;
    let mut declared = 0u16;
    while let Some(chunk) = cur.chunk(ChunkLayout::new(4, 4, BE).align(2)).await? {
        if chunk.id == b"AHDR" {
            let b = cx.read(chunk.body.sub(0, 4)).await?;
            version = u16_le(&b, 0).unwrap_or(0);
            declared = u16_le(&b, 2).unwrap_or(0);
        } else if chunk.id == b"FRME" {
            frames = frames.saturating_add(1);
        }
        cx.push(chunk.node()).await;
    }
    cx.annotate(format!("SMUSH animation v{version}, {declared} frames declared, {frames} present"));
    Ok(())
}

declare_format!(pub DXA = "dxa", "DXA video (ScummVM)", ["dxa"], "video/x-dxa",
    Probe::Magic(&[(0, b"DEXA")]), dxa);

async fn dxa(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 15)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Signature", 4).emit()?;
    f.u8("Flags").hex().emit()?;
    let frames = f.u16("Frames").emit()?;
    let rate = f.u32("Frame rate").emit()?;
    let w = f.u16("Width").emit()?;
    let h = f.u16("Height").emit()?;
    let signed = i32::from_ne_bytes(rate.to_ne_bytes());
    let fps = match signed {
        r if r > 0 => 1000.0 / f64::from(r),
        r if r < 0 => 100_000.0 / f64::from(r.unsigned_abs()),
        _ => 10.0,
    };
    let mut pos = 15u64;
    let tag = cx.read_avail(file.sub(pos, 4)).await?;
    if tag == b"WAVE" {
        let size = u64::from(u32_be(&cx.read(file.sub(pos.saturating_add(4), 4)).await?, 0).unwrap_or(0));
        cx.emit(embedded("Sound (WAV)", input.nested(file.sub(pos.saturating_add(8), size))));
        pos = pos.saturating_add(8).saturating_add(size);
    }
    cx.emit(Node::new("Frames").span(file.tail(pos)).summary(format!("{frames} FRAM/NULL records")));
    cx.annotate(format!("DXA video, {w}×{h}, {frames} frames at {fps:.2} fps"));
    Ok(())
}

declare_format!(pub ARMOVIE = "armovie", "Acorn Replay movie (ARMovie)", ["rpl"], "video/x-armovie",
    Probe::Magic(&[(0, b"ARMovie\n")]), armovie);

async fn armovie(cx: Cx, input: Input) -> Result<()> {
    let lines = head_lines(&cx, input.span, 1024).await?;
    const LABELS: [&str; 15] = [
        "Signature", "Name", "Date and copyright", "Author", "Video format", "Width", "Height", "Pixel depth", "Frames per second",
        "Sound format", "Sound rate", "Sound channels", "Sound precision", "Frames per chunk", "Chunks",
    ];
    let mut values = Vec::new();
    for ((line, span), label) in lines.iter().zip(LABELS) {
        let value = line.split(" ;").next().unwrap_or(line).trim().to_owned();
        values.push(value.clone());
        cx.emit(Node::new(label).span(*span).value(text(value)));
    }
    let get = |i: usize| values.get(i).cloned().unwrap_or_default();
    cx.annotate(format!("Acorn Replay movie {:?}: {}×{}, {} fps", get(1), get(5), get(6), get(8)));
    Ok(())
}

declare_format!(pub SGI_MOVIE = "sgi-movie", "SGI movie", ["mv", "movie", "sgi"], "video/x-sgi-movie",
    Probe::Magic(&[(0, b"MOVI")]), sgi_movie);

async fn sgi_movie(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 8)).await?;
    let version = u16_be(&head, 4).unwrap_or(0);
    cx.emit(Node::new("Signature").span(file.sub(0, 4)));
    cx.emit(Node::new("Version").span(file.sub(4, 2)).value(uint(version.into(), 16)));
    cx.emit(Node::new("Movie").span(file.tail(8)));
    cx.annotate(format!("SGI movie, version {version}"));
    Ok(())
}
