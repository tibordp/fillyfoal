//! Sequenced music: Doom MUS, HMI MIDI, AHX, MO3, DigiBooster and
//! Farandole modules.

use crate::bytes::{u16_le, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{ChunkLayout, Cursor, Record, emit_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::{Input, Probe};
use crate::node::Node;
use crate::record;
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
// Music: Doom MUS, HMI, AHX, MO3, DigiBooster, Farandole

declare_format!(pub MUS = "doom-mus", "DMX music (Doom MUS)", ["mus"], "audio/x-doom-mus",
    Probe::Magic(&[(0, b"MUS\x1a")]), mus);

record! {
    pub struct MusHeader {
        magic: ascii[4] "Signature",
        score_len: u16 "Score length",
        score_start: u16 "Score offset" .hex(),
        channels: u16 "Primary channels",
        secondary: u16 "Secondary channels",
        instruments: u16 "Instruments",
        reserved: u16 "Reserved",
    }
}

async fn mus(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: MusHeader = emit_record(&cx, file.sub(0, MusHeader::SIZE), LE).await?;
    cx.emit(
        Node::new("Instrument list").span(file.sub(16, u64::from(h.instruments).saturating_mul(2))),
    );
    cx.emit(Node::new("Score").span(file.sub(h.score_start.into(), h.score_len.into())));
    cx.annotate(format!(
        "Doom MUS, {} channels, {} instruments",
        h.channels, h.instruments
    ));
    Ok(())
}

declare_format!(pub HMI = "hmi-midi", "HMI MIDI song", ["hmp", "hmi"], "audio/x-hmi",
    Probe::Magic(&[(0, b"HMIMIDIP"), (0, b"HMI-MIDISONG")]), hmi);

async fn hmi(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 0x40)).await?;
    let hmp = head.starts_with(b"HMIMIDIP");
    cx.emit(
        Node::new("Signature")
            .span(file.sub(0, if hmp { 8 } else { 12 }))
            .value(text(zstr(head.get(..18).unwrap_or_default()))),
    );
    let tracks = if hmp {
        u32_le(&head, 0x30)
    } else {
        u16_le(&head, 0xe4).map(u32::from)
    }
    .unwrap_or(0);
    if hmp {
        cx.emit(
            Node::new("Tracks")
                .span(file.sub(0x30, 4))
                .value(uint(tracks.into(), 32)),
        );
    }
    cx.emit(Node::new("Body").span(file.tail(0x40)));
    cx.annotate(format!(
        "HMI {} song{}",
        if hmp { "HMP" } else { "HMI" },
        if hmp {
            format!(", {tracks} tracks")
        } else {
            String::new()
        }
    ));
    Ok(())
}

declare_format!(pub AHX = "ahx", "AHX/THX chiptune module", ["ahx", "thx"], "audio/x-ahx",
    Probe::Magic(&[(0, b"THX\0"), (0, b"THX\x01")]), ahx);

async fn ahx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 14)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Signature", 3).emit()?;
    let rev = f.u8("Revision").emit()?;
    let names = f.u16("Name table offset").hex().emit()?;
    let len = f.u16("Positions and flags").hex().emit()?;
    f.u16("Restart position").emit()?;
    f.u8("Track length").emit()?;
    let tracks = f.u8("Tracks").emit()?;
    let samples = f.u8("Instruments").emit()?;
    f.u8("Subsongs").emit()?;
    let (title, span) = cx.cstr(file.sub(names.into(), 256)).await?;
    cx.emit(Node::new("Title").span(span).value(text(title.clone())));
    cx.annotate(format!(
        "AHX v{rev} {title:?}, {} positions, {tracks} tracks, {samples} instruments",
        len & 0xfff
    ));
    Ok(())
}

declare_format!(pub MO3 = "mo3", "MO3 compressed module", ["mo3"], "audio/x-mo3",
    Probe::Magic(&[(0, b"MO3")]), mo3);

async fn mo3(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 3).emit()?;
    let version = f.u8("Version").emit()?;
    let size = f.u32("Decompressed header size").emit()?;
    cx.emit(
        Node::new("Compressed music data")
            .span(file.tail(8))
            .diag(Diagnostic::unsupported("MO3 delta/LZ compression")),
    );
    cx.annotate(format!("MO3 v{version} module, {size}-byte header"));
    Ok(())
}

declare_format!(pub DBM = "digibooster", "DigiBooster Pro module", ["dbm"], "audio/x-dbm",
    Probe::Magic(&[(0, b"DBM0")]), dbm);

async fn dbm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Signature", 4).emit()?;
    let version = f.u16("Version").hex().emit()?;
    f.u16("Reserved").emit()?;
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(8);
    let mut title = String::new();
    while let Some(chunk) = cur.chunk(ChunkLayout::new(4, 4, BE)).await? {
        let mut node = chunk.node();
        if chunk.id == b"NAME" {
            title = zstr(&cx.read_avail(chunk.body.sub(0, 64)).await?);
            node = node.value(text(title.clone()));
        }
        cx.push(node).await;
    }
    cx.annotate(format!(
        "DigiBooster Pro {}.{:02x} module {title:?}",
        version >> 8,
        version & 0xff
    ));
    Ok(())
}

declare_format!(pub FAR = "farandole", "Farandole Composer module", ["far"], "audio/x-far",
    Probe::Magic(&[(0, b"FAR\xfe")]), far);

async fn far(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x32)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.bytes("Signature", 4).emit()?;
    let title = f.ascii("Title", 40).emit()?;
    f.bytes("EOF marker", 3).emit()?;
    let header = f.u16("Header length").emit()?;
    let version = f.u8("Version").hex().emit()?;
    cx.emit(Node::new("Patterns and samples").span(file.tail(header.into())));
    cx.annotate(format!(
        "Farandole {}.{} module {:?}",
        version >> 4,
        version & 0xf,
        title.trim()
    ));
    Ok(())
}
