//! Smaller RIFF forms: animated cursors (ACON), RIFF MIDI (RMID),
//! Downloadable Sounds (DLS), SoundFont 2 (sfbk), xWMA, Video CD (CDXA),
//! palettes (PAL), bitmaps (RDIB) and Qualcomm PureVoice (QLCM).

use crate::bytes::{u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Fields, parse};
use crate::formats::embedded;
use crate::formats::iff::{Chunk, Ctx, find, scan, wav};
use crate::formats::sound::{peek_text, table};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{FlagTable, flag};

const ANI_FLAGS: FlagTable = &[flag(0x1, "ICON"), flag(0x2, "SEQUENCE")];

record! {
    /// ANIHEADER
    pub struct AniHeader {
        size: u32 "Header size",
        frames: u32 "Frames",
        steps: u32 "Steps",
        width: u32 "Width",
        height: u32 "Height",
        bit_count: u32 "Bits per pixel",
        planes: u32 "Planes",
        rate: u32 "Default rate" .desc("Jiffies (1/60 s) per step"),
        flags: u32 "Flags" .flags(ANI_FLAGS),
    }
}

record! {
    pub struct Jiffies {
        value: u32 "Value",
    }
}

record! {
    pub struct InstrumentHeader {
        regions: u32 "Regions",
        bank: u32 "Bank" .hex() .desc("Bit 31: drum instrument"),
        program: u32 "Program",
    }
}

record! {
    pub struct RegionHeader {
        key_low: u16 "Key range low",
        key_high: u16 "Key range high",
        velocity_low: u16 "Velocity range low",
        velocity_high: u16 "Velocity range high",
        options: u16 "Options" .hex(),
        key_group: u16 "Key group",
    }
}

record! {
    pub struct WaveLink {
        options: u16 "Options" .hex(),
        phase_group: u16 "Phase group",
        channel: u32 "Channel" .hex(),
        table_index: u32 "Pool table index",
    }
}

record! {
    pub struct WaveSample {
        size: u32 "Structure size",
        unity_note: u16 "Unity note",
        fine_tune: i16 "Fine tune",
        attenuation: i32 "Attenuation",
        options: u32 "Options" .hex(),
        loops: u32 "Sample loops",
    }
}

record! {
    pub struct PresetHeader {
        name: ascii[20] "Name",
        preset: u16 "Preset",
        bank: u16 "Bank",
        bag: u16 "Bag index",
        library: u32 "Library",
        genre: u32 "Genre",
        morphology: u32 "Morphology",
    }
}

record! {
    pub struct Bag {
        generator: u16 "Generator index",
        modulator: u16 "Modulator index",
    }
}

record! {
    pub struct Modulator {
        source: u16 "Source" .hex(),
        destination: u16 "Destination",
        amount: i16 "Amount",
        amount_source: u16 "Amount source" .hex(),
        transform: u16 "Transform",
    }
}

record! {
    pub struct Generator {
        operator: u16 "Operator",
        amount: u16 "Amount" .hex(),
    }
}

record! {
    pub struct InstrumentName {
        name: ascii[20] "Name",
        bag: u16 "Bag index",
    }
}

record! {
    pub struct SampleHeader {
        name: ascii[20] "Name",
        start: u32 "Start",
        end: u32 "End",
        loop_start: u32 "Loop start",
        loop_end: u32 "Loop end",
        rate: u32 "Sample rate",
        pitch: u8 "Original pitch",
        correction: i8 "Pitch correction",
        link: u16 "Sample link",
        kind: u16 "Sample type" .enumeration(SAMPLE_TYPE),
    }
}

const SAMPLE_TYPE: crate::value::EnumTable = &[
    (1, "mono"),
    (2, "right"),
    (4, "left"),
    (8, "linked"),
    (0x8001, "ROM mono"),
    (0x8002, "ROM right"),
    (0x8004, "ROM left"),
    (0x8008, "ROM linked"),
];

record! {
    pub struct PaletteEntry {
        red: u8 "Red",
        green: u8 "Green",
        blue: u8 "Blue",
        flags: u8 "Flags" .hex(),
    }
}

record! {
    pub struct Dpds {
        value: u32 "Decoded bytes",
    }
}

fn version(ms: u32, ls: u32) -> String {
    format!("{}.{}.{}.{}", ms >> 16, ms & 0xffff, ls >> 16, ls & 0xffff)
}

pub async fn summary(cx: &Cx, chunk: &Chunk) -> Result<Option<String>> {
    let e = chunk.endian();
    Ok(match (&chunk.ctx.form, &chunk.id) {
        (b"ACON", b"anih") => {
            let h = parse(cx, chunk.data, e, &(), AniHeader::layout).await?;
            Some(format!("{} frames, {} steps", h.frames, h.steps))
        }
        (b"DLS ", b"colh") => {
            let n = cx.read(chunk.data.sub(0, 4)).await?;
            Some(format!("{} instruments", u32_le(&n, 0).unwrap_or(0)))
        }
        (b"DLS ", b"vers") => {
            let v = cx.read(chunk.data.sub(0, 8)).await?;
            Some(version(
                u32_le(&v, 0).unwrap_or(0),
                u32_le(&v, 4).unwrap_or(0),
            ))
        }
        (b"DLS ", b"insh") => {
            let h = parse(cx, chunk.data, e, &(), InstrumentHeader::layout).await?;
            Some(format!(
                "bank {:#x}, program {}, {} regions",
                h.bank, h.program, h.regions
            ))
        }
        (_, b"fmt ") if &chunk.ctx.form != b"CDXA" && &chunk.ctx.form != b"QLCM" => Some(
            parse(cx, chunk.data, e, &(), wav::wave_format)
                .await?
                .summary(),
        ),
        (b"sfbk", b"ifil" | b"iver") => {
            let v = cx.read(chunk.data.sub(0, 4)).await?;
            Some(format!(
                "{}.{:02}",
                u16_le(&v, 0).unwrap_or(0),
                u16_le(&v, 2).unwrap_or(0)
            ))
        }
        (b"sfbk", b"isng" | b"irom") => Some(peek_text(cx, chunk.data, 64).await?),
        (b"sfbk", b"phdr") => Some(format!("{} presets", records(chunk, 38))),
        (b"sfbk", b"inst") => Some(format!("{} instruments", records(chunk, 22))),
        (b"sfbk", b"shdr") => Some(format!("{} samples", records(chunk, 46))),
        (b"PAL ", b"data") => {
            let h = cx.read(chunk.data.sub(0, 4)).await?;
            Some(format!("{} colors", u16_le(&h, 2).unwrap_or(0)))
        }
        (b"CDXA", b"data") => Some(format!("{} sectors of 2352 bytes", chunk.size / 2352)),
        _ => None,
    })
}

/// Entries of a SoundFont table, excluding the terminal record.
fn records(chunk: &Chunk, size: u64) -> u64 {
    chunk.size.checked_div(size).unwrap_or(0).saturating_sub(1)
}

pub async fn chunk(cx: &Cx, chunk: &Chunk) -> Result<bool> {
    let e = chunk.endian();
    let data = chunk.data;
    let input = chunk.input();
    match (&chunk.ctx.form, &chunk.id) {
        // Animated cursors
        (b"ACON", b"anih") => cx.emit(AniHeader::node("Header", data, e)),
        (b"ACON", b"rate") => cx.emit(table::<Jiffies>(
            "Rates",
            data,
            e,
            "Step",
            Some(|j| format!("{} jiffies", j.value)),
        )),
        (b"ACON", b"seq ") => cx.emit(table::<Jiffies>(
            "Sequence",
            data,
            e,
            "Step",
            Some(|j| format!("frame {}", j.value)),
        )),
        (b"ACON", b"icon") => cx.emit(embedded("Icon", input.nested(data))),

        // RIFF MIDI and bitmaps
        (b"RMID", b"data") => cx.emit(embedded("MIDI file", input.nested(data))),
        (b"RDIB", b"data") => cx.emit(embedded("Bitmap", input.nested(data))),

        // Downloadable Sounds and the shared WAVEFORMATEX
        (b"DLS ", b"colh") => {
            let block = cx.block(data.sub(0, 4)).await?;
            Fields::emitting(cx, &block, e).u32("Instruments").emit()?;
        }
        (b"DLS ", b"vers") => {
            let block = cx.block(data.sub(0, 8)).await?;
            let mut f = Fields::emitting(cx, &block, e);
            f.u32("Version (high)").hex().emit()?;
            f.u32("Version (low)").hex().emit()?;
        }
        (b"DLS ", b"insh") => cx.emit(InstrumentHeader::node("Instrument header", data, e)),
        (b"DLS ", b"rgnh") => cx.emit(RegionHeader::node("Region header", data, e)),
        (b"DLS ", b"wlnk") => cx.emit(WaveLink::node("Wave link", data, e)),
        (b"DLS ", b"wsmp") => {
            cx.emit(WaveSample::node(
                "Wave sample",
                data.sub(0, WaveSample::SIZE),
                e,
            ));
            let loops = data.tail(WaveSample::SIZE);
            if !loops.is_empty() {
                cx.emit(Node::new("Loops").span(loops));
            }
        }
        (b"DLS ", b"ptbl") => {
            let block = cx.block(data.sub(0, 8)).await?;
            let mut f = Fields::emitting(cx, &block, e);
            let size = f.u32("Structure size").emit()?;
            f.u32("Cues").emit()?;
            cx.emit(table::<Jiffies>(
                "Offsets",
                data.tail(size.into()),
                e,
                "Cue",
                Some(|j| format!("{:#x}", j.value)),
            ));
        }
        (b"DLS " | b"XWMA" | b"RMMP", b"fmt ") => {
            let block = cx.block(data).await?;
            wav::wave_format(&mut Fields::emitting(cx, &block, e), &())?;
        }
        (b"DLS " | b"XWMA", b"data") => cx.emit(Node::new("Samples").span(data)),
        (b"XWMA", b"dpds") => cx.emit(table::<Dpds>(
            "Packet table",
            data,
            e,
            "Packet",
            Some(|d| format!("{} bytes decoded", d.value)),
        )),

        // SoundFont 2
        (b"sfbk", b"ifil" | b"iver") => {
            let block = cx.block(data.sub(0, 4)).await?;
            let mut f = Fields::emitting(cx, &block, e);
            f.u16("Major").emit()?;
            f.u16("Minor").emit()?;
        }
        (b"sfbk", b"phdr") => cx.emit(table::<PresetHeader>(
            "Presets",
            data,
            e,
            "Preset",
            Some(|p| format!("{} (bank {}, preset {})", p.name, p.bank, p.preset)),
        )),
        (b"sfbk", b"pbag" | b"ibag") => cx.emit(table::<Bag>("Bags", data, e, "Bag", None)),
        (b"sfbk", b"pmod" | b"imod") => {
            cx.emit(table::<Modulator>("Modulators", data, e, "Modulator", None));
        }
        (b"sfbk", b"pgen" | b"igen") => cx.emit(table::<Generator>(
            "Generators",
            data,
            e,
            "Generator",
            Some(|g| format!("operator {}, amount {:#x}", g.operator, g.amount)),
        )),
        (b"sfbk", b"inst") => cx.emit(table::<InstrumentName>(
            "Instruments",
            data,
            e,
            "Instrument",
            Some(|i| i.name.clone()),
        )),
        (b"sfbk", b"shdr") => cx.emit(table::<SampleHeader>(
            "Samples",
            data,
            e,
            "Sample",
            Some(|s| format!("{}, {} Hz", s.name, s.rate)),
        )),
        (b"sfbk", b"smpl" | b"sm24") => cx.emit(Node::new("Samples").span(data)),

        // Palettes
        (b"PAL ", b"data") => {
            let block = cx.block(data.sub(0, 4)).await?;
            let mut f = Fields::emitting(cx, &block, e);
            f.u16("Version").hex().emit()?;
            f.u16("Entries").emit()?;
            cx.emit(table::<PaletteEntry>(
                "Colors",
                data.tail(4),
                e,
                "Color",
                Some(|c| format!("#{:02x}{:02x}{:02x}", c.red, c.green, c.blue)),
            ));
        }

        // Video CD
        (b"CDXA", b"data") => cx.emit(
            Node::new("Sectors")
                .span(data)
                .desc("Raw 2352-byte CD-ROM XA sectors holding an MPEG program stream"),
        ),
        _ => return Ok(false),
    }
    Ok(true)
}

pub async fn describe(cx: &Cx, ctx: &Ctx, region: Span) -> Result<Option<String>> {
    let e = ctx.endian;
    Ok(match &ctx.form {
        b"ACON" => match find(cx, ctx, region, b"anih").await? {
            Some(h) => {
                let h = parse(cx, h.data, e, &(), AniHeader::layout).await?;
                Some(format!(
                    "Animated cursor, {} frames, {} steps, {} jiffies per step",
                    h.frames, h.steps, h.rate
                ))
            }
            None => None,
        },
        b"RMID" => Some("MIDI in RIFF".to_owned()),
        b"DLS " => match find(cx, ctx, region, b"colh").await? {
            Some(c) => {
                let n = cx.read(c.data.sub(0, 4)).await?;
                Some(format!(
                    "DLS collection, {} instruments",
                    u32_le(&n, 0).unwrap_or(0)
                ))
            }
            None => Some("DLS collection".to_owned()),
        },
        b"sfbk" => {
            let mut line = "SoundFont".to_owned();
            for entry in scan(cx, ctx, region, 16).await? {
                let kind = cx.read_avail(entry.data.sub(0, 4)).await?;
                if &entry.id != b"LIST" || kind != b"INFO" {
                    continue;
                }
                let info = scan(cx, ctx, entry.data.tail(4), 32).await?;
                if let Some(v) = info.iter().find(|c| &c.id == b"ifil") {
                    let v = cx.read(v.data.sub(0, 4)).await?;
                    line.push_str(&format!(
                        " {}.{:02}",
                        u16_le(&v, 0).unwrap_or(0),
                        u16_le(&v, 2).unwrap_or(0)
                    ));
                }
                if let Some(name) = info.iter().find(|c| &c.id == b"INAM") {
                    let name = peek_text(cx, name.data, 64).await?;
                    line.push_str(&format!(", {name}"));
                }
            }
            Some(line)
        }
        b"XWMA" => match find(cx, ctx, region, b"fmt ").await? {
            Some(f) => Some(format!(
                "xWMA, {}",
                parse(cx, f.data, e, &(), wav::wave_format).await?.summary()
            )),
            None => None,
        },
        b"CDXA" => Some("Video CD MPEG track".to_owned()),
        b"PAL " => Some("RIFF palette".to_owned()),
        b"QLCM" => Some("Qualcomm PureVoice audio".to_owned()),
        _ => None,
    })
}
