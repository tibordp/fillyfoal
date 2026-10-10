//! Codec configuration that `vidutil` does not cover (the AC-3 and E-AC-3
//! specific boxes), the bit-reader helpers isobmff layouts share, and AV1
//! OBU lists (item data, `av1C` config OBUs) decoded by `vidutil`.

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::Result;
use crate::fields::Fields;
use crate::formats::util::sound::Bits as BitFields;
use crate::formats::util::vidutil::bitwalk::Walker;
use crate::formats::util::vidutil::{self, lookup_or, nal};
use crate::span::{SourceId, Span};
use crate::value::EnumTable;

pub use crate::formats::util::vidutil::khz;

/// A bit reader over the next `n` bytes of `f`, emitting when `cx` is
/// given; `f` advances past them.
pub fn bits_at<'a>(cx: Option<&'a Cx>, f: &mut Fields<'a>, n: u64) -> BitFields<'a> {
    let span = f.peek_span(n);
    let start = to_usize(f.pos());
    let data: &'a [u8] = f.block().data.get(start..).unwrap_or_default();
    let data = data.get(..to_usize(n)).unwrap_or(data);
    f.skip(n);
    match cx {
        Some(cx) => BitFields::emitting(cx, data, span),
        None => BitFields::new(data, span),
    }
}

/// A placeholder span for silent bit parsing of in-memory bytes.
pub fn nowhere(len: usize) -> Span {
    Span::new(SourceId(0), 0, to_u64(len))
}

/// A channel count as a layout name where one is customary.
pub fn channel_count(n: u64) -> String {
    match n {
        1 => "mono".to_owned(),
        2 => "stereo".to_owned(),
        6 => "5.1".to_owned(),
        8 => "7.1".to_owned(),
        _ => format!("{n} ch"),
    }
}

// ---------------------------------------------------------------------------
// AC-3 and E-AC-3 (ETSI TS 102 366 annex F)

pub const AC3_RATES: EnumTable = &[(0, "48000 Hz"), (1, "44100 Hz"), (2, "32000 Hz")];
const AC3_RATE_HZ: [u64; 3] = [48000, 44100, 32000];

pub const AC3_ACMOD: EnumTable = &[
    (0, "1+1 (dual mono)"),
    (1, "1/0 (mono)"),
    (2, "2/0 (stereo)"),
    (3, "3/0 (L C R)"),
    (4, "2/1 (L R S)"),
    (5, "3/1 (L C R S)"),
    (6, "2/2 (L R SL SR)"),
    (7, "3/2 (L C R SL SR)"),
];

pub const AC3_BSMOD: EnumTable = &[
    (0, "complete main"),
    (1, "music and effects"),
    (2, "visually impaired"),
    (3, "hearing impaired"),
    (4, "dialogue"),
    (5, "commentary"),
    (6, "emergency"),
    (7, "voice over / karaoke"),
];

const AC3_BITRATES: [u64; 19] = [
    32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 448, 512, 576, 640,
];

/// What a `dac3` or the first `dec3` substream says.
#[derive(Clone, Debug, Default)]
pub struct Ac3 {
    pub rate: u64,
    pub acmod: u64,
    pub lfe: bool,
    pub kbps: u64,
    pub atmos: bool,
}

impl Ac3 {
    pub fn channels(&self) -> u64 {
        let base = [2u64, 1, 2, 3, 3, 4, 4, 5]
            .get(to_usize(self.acmod))
            .copied()
            .unwrap_or(0);
        base.saturating_add(u64::from(self.lfe))
    }

    pub fn layout(&self) -> String {
        match (self.acmod, self.lfe) {
            (0, _) => "dual mono".to_owned(),
            (1, false) => "mono".to_owned(),
            (2, false) => "stereo".to_owned(),
            (2, true) => "2.1".to_owned(),
            (7, false) => "5.0".to_owned(),
            (7, true) => "5.1".to_owned(),
            _ => {
                let base = lookup_or(AC3_ACMOD, self.acmod);
                let base = base.split(' ').next().unwrap_or_default().to_owned();
                if self.lfe {
                    format!("{base}+LFE")
                } else {
                    base
                }
            }
        }
    }

    pub fn summary(&self) -> String {
        let mut s = format!("{}, {}, {} kb/s", khz(self.rate), self.layout(), self.kbps);
        if self.atmos {
            s.push_str(", Dolby Atmos (JOC)");
        }
        s
    }
}

pub fn dac3_layout(b: &mut BitFields<'_>) -> Result<Ac3> {
    let fscod = b
        .field("Sample rate code (fscod)", 2)
        .enumeration(AC3_RATES)
        .emit()?;
    b.field("Bit stream identification (bsid)", 5).emit()?;
    b.field("Bit stream mode (bsmod)", 3)
        .enumeration(AC3_BSMOD)
        .emit()?;
    let acmod = b
        .field("Audio coding mode (acmod)", 3)
        .enumeration(AC3_ACMOD)
        .emit()?;
    let lfe = b.field("LFE on", 1).flag().emit()?;
    let rate = b
        .field("Bit rate code", 5)
        .with(|v, n| match AC3_BITRATES.get(to_usize(v)) {
            Some(k) => n.summary(format!("{k} kb/s")),
            None => n,
        })
        .emit()?;
    b.field("Reserved", 5).emit()?;
    Ok(Ac3 {
        rate: AC3_RATE_HZ.get(to_usize(fscod)).copied().unwrap_or(0),
        acmod,
        lfe: lfe == 1,
        kbps: AC3_BITRATES.get(to_usize(rate)).copied().unwrap_or(0),
        atmos: false,
    })
}

pub fn dec3_layout(b: &mut BitFields<'_>) -> Result<Ac3> {
    let kbps = b
        .field("Data rate", 13)
        .with(|v, n| n.summary(format!("{v} kb/s")))
        .emit()?;
    let subs = b
        .field("Independent substreams", 3)
        .with(|v, n| n.summary(format!("{}", v.saturating_add(1))))
        .desc("Number of independent substreams minus one")
        .emit()?;
    let mut first: Option<Ac3> = None;
    for _ in 0..=subs {
        let fscod = b
            .field("Sample rate code (fscod)", 2)
            .enumeration(AC3_RATES)
            .emit()?;
        b.field("Bit stream identification (bsid)", 5).emit()?;
        b.field("Reserved", 1).emit()?;
        b.field("Audio service (asvc)", 1).flag().emit()?;
        b.field("Bit stream mode (bsmod)", 3)
            .enumeration(AC3_BSMOD)
            .emit()?;
        let acmod = b
            .field("Audio coding mode (acmod)", 3)
            .enumeration(AC3_ACMOD)
            .emit()?;
        let lfe = b.field("LFE on", 1).flag().emit()?;
        b.field("Reserved", 3).emit()?;
        let deps = b.field("Dependent substreams", 4).emit()?;
        if deps > 0 {
            b.field("Channel locations", 9).hex().emit()?;
        } else {
            b.field("Reserved", 1).emit()?;
        }
        if first.is_none() {
            first = Some(Ac3 {
                rate: AC3_RATE_HZ.get(to_usize(fscod)).copied().unwrap_or(0),
                acmod,
                lfe: lfe == 1,
                kbps,
                atmos: false,
            });
        }
    }
    let mut info = first.unwrap_or_default();
    let save = b.pos();
    if b.read(16).is_some() {
        b.seek(save);
        b.field("Reserved", 7).emit()?;
        let joc = b
            .field("E-AC-3 extension type A", 1)
            .flag()
            .desc("Joint object coding (Dolby Atmos)")
            .emit()?;
        b.field("Complexity index type A", 8).emit()?;
        info.atmos = joc == 1;
    } else {
        b.seek(save);
    }
    Ok(info)
}

// ---------------------------------------------------------------------------
// AV1 OBUs

/// Emits the OBUs in `span` (AV1 configuration OBUs or item data),
/// decoded: headers, sequence header, frame headers, metadata.
pub async fn obus(cx: &Cx, span: Span) -> Result<()> {
    let data = vidutil::read_small(cx, span, 0x10000).await?;
    let mut w = Walker::new(&data, span.sub(0, to_u64(data.len())), false, true);
    let mut seq = None;
    let ok = nal::obus(&mut w, &mut seq).is_some();
    for node in w.finish(ok) {
        cx.emit(node);
    }
    if to_u64(data.len()) < span.len {
        cx.emit(
            crate::node::Node::new("Rest of the OBUs")
                .span(span.tail(to_u64(data.len())))
                .summary(format!(
                    "{} bytes",
                    span.len.saturating_sub(to_u64(data.len()))
                )),
        );
    }
    Ok(())
}
