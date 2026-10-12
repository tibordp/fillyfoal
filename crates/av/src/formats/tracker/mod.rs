//! Tracker modules: ProTracker-style MOD, Scream Tracker 3 (S3M),
//! FastTracker 2 (XM) and Impulse Tracker (IT).
//!
//! Each format has a header, an order list, and tables of samples,
//! instruments and patterns, either stored back to back (MOD, XM) or
//! reached through pointer tables (S3M, IT). The helpers here list such
//! tables lazily.
//!
//! Less common modules are in `more` and `pc`.

pub mod it;
pub mod more;
pub mod pc;
pub mod protracker;
pub mod s3m;
pub mod xm;

use crate::bytes::{to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::util::fmt::plural;
use crate::formats::util::sound::Describe;
use crate::node::{Count, Node};
use crate::span::Span;

/// "C-4" style note names (0 = C-0).
pub fn note_name(n: u8) -> String {
    const NAMES: [&str; 12] = [
        "C-", "C#", "D-", "D#", "E-", "F-", "F#", "G-", "G#", "A-", "A#", "B-",
    ];
    let name = NAMES.get(usize::from(n % 12)).copied().unwrap_or("?");
    format!("{name}{}", n / 12)
}

/// The order list as text: "0 1 2 1 …", with markers shown as `+++`
/// (skip) and `---` (end).
pub fn orders(list: &[u8]) -> String {
    // Unused entries at the end are end markers (255).
    let used = list
        .iter()
        .rposition(|&o| o != 255)
        .map_or(0, |p| p.saturating_add(1));
    let list = list.get(..used).unwrap_or_default();
    let mut out: Vec<String> = Vec::new();
    for &o in list.iter().take(64) {
        out.push(match o {
            254 => "+++".to_owned(),
            255 => "---".to_owned(),
            n => n.to_string(),
        });
    }
    if list.len() > 64 {
        out.push("…".to_owned());
    }
    out.join(" ")
}

/// A node for an order list at `span`.
pub async fn order_node(cx: &Cx, span: Span) -> Result<Node> {
    let list = cx.read_avail(span).await?;
    Ok(Node::new("Orders")
        .span(span)
        .summary(plural(list.len(), "entry"))
        .value(crate::formats::util::val::text(orders(&list))))
}

/// How a pointer table addresses its targets.
#[derive(Clone, Copy, Debug)]
pub struct Pointers {
    /// The pointer array.
    pub table: Span,
    /// 2 (S3M paragraphs) or 4 (IT byte offsets).
    pub width: u8,
    /// What a pointer is multiplied by (16 for S3M, 1 for IT).
    pub scale: u64,
}

/// A lazy node listing records of type `R` reached through `pointers`,
/// relative to `file`. `describe` summarises each record; `data` locates
/// the sample data a record points to, shown as a child after its fields.
pub fn pointed<R: Record>(
    name: &'static str,
    file: Span,
    pointers: Pointers,
    item: &'static str,
    describe: Option<Describe<R>>,
    data: Option<DataOf<R>>,
) -> Node {
    let count = pointers
        .table
        .len
        .checked_div(pointers.width.into())
        .unwrap_or(0);
    Node::new(name)
        .span(pointers.table)
        .summary(plural(count, "entry"))
        .lazy(expand_pointed::<R>, (file, pointers, item, describe, data))
}

/// Where a record's sample data is, given the record and the file.
pub type DataOf<R> = fn(&R, Span) -> Option<SampleData>;

/// Sample data a sample header points to.
#[derive(Clone, Debug)]
pub enum SampleData {
    /// Stored as is (or with a fixed-size coding): its span and a summary.
    Plain(Span, String),
    /// Impulse Tracker 2.14/2.15 compressed: blocks of a 16-bit length and
    /// a bit stream, each holding up to 0x8000 (8-bit) or 0x4000 (16-bit)
    /// samples of one channel. `region` runs from the first block to the
    /// end of the file.
    It214 {
        region: Span,
        frames: u32,
        sixteen: bool,
        stereo: bool,
        it215: bool,
    },
}

type PointedState<R> = (
    Span,
    Pointers,
    &'static str,
    Option<Describe<R>>,
    Option<DataOf<R>>,
);

async fn expand_pointed<R: Record>(
    cx: Cx,
    (file, pointers, item, describe, data): PointedState<R>,
) -> Result<()> {
    let table = cx.read(pointers.table).await?;
    let width = usize::from(pointers.width.max(1));
    cx.set_count(Count::Exact(to_u64(
        table.len().checked_div(width).unwrap_or(0),
    )));
    let mut index = 0u64;
    let mut at = 0usize;
    while at.saturating_add(width) <= table.len() {
        let ptr = if width == 2 {
            u64::from(u16_le(&table, at).unwrap_or(0))
        } else {
            u64::from(u32_le(&table, at).unwrap_or(0))
        };
        let label = format!("{item} {}", index.saturating_add(1));
        if ptr == 0 {
            cx.push(Node::new(label).summary("empty")).await;
        } else {
            let span = file.sub(ptr.saturating_mul(pointers.scale), R::SIZE);
            let mut node = R::node(label.clone(), span, Endian::Little);
            if let Ok((r, _)) = Cursor::new(&cx, span, Endian::Little).record::<R>().await {
                if let Some(data) = data {
                    let found = data(&r, file);
                    node = Node::new(label)
                        .span(span)
                        .lazy(record_with_data::<R>, (span, found));
                }
                if let Some(describe) = describe {
                    node = node.summary(describe(&r));
                }
            }
            cx.push(node).await;
        }
        at = at.saturating_add(width);
        index = index.saturating_add(1);
    }
    Ok(())
}

async fn record_with_data<R: Record>(
    cx: Cx,
    (span, data): (Span, Option<SampleData>),
) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, Endian::Little);
    R::read(&mut f)?;
    match data {
        None => {}
        Some(SampleData::Plain(span, summary)) => {
            cx.emit(Node::new("Sample data").span(span).summary(summary));
        }
        Some(SampleData::It214 {
            region,
            frames,
            sixteen,
            stereo,
            it215,
        }) => cx.emit(it214_node(&cx, region, frames, sixteen, stereo, it215).await?),
    }
    Ok(())
}

/// Samples per IT214 block.
fn it214_block(sixteen: bool) -> u32 {
    if sixteen { 0x4000 } else { 0x8000 }
}

/// Walks the block lengths of IT-compressed sample data (one read per
/// block) and returns a node spanning the blocks, listing them lazily.
async fn it214_node(
    cx: &Cx,
    region: Span,
    frames: u32,
    sixteen: bool,
    stereo: bool,
    it215: bool,
) -> Result<Node> {
    let per_block = it214_block(sixteen);
    let blocks_per_channel = frames.div_ceil(per_block);
    let blocks = u64::from(blocks_per_channel).saturating_mul(if stereo { 2 } else { 1 });
    let mut pos = 0u64;
    let mut walked = 0u64;
    let mut short = false;
    while walked < blocks {
        let head = cx.read_avail(region.sub(pos, 2)).await?;
        let Some(len) = u16_le(&head, 0) else {
            short = true;
            break;
        };
        let next = pos.saturating_add(2).saturating_add(len.into());
        if next > region.len {
            short = true;
            break;
        }
        pos = next;
        walked = walked.saturating_add(1);
    }
    let span = region.sub(0, pos);
    let mut node = Node::new("Sample data")
        .span(span)
        .summary(format!(
            "IT{} compressed, {walked_block}, {frames_sample}{}{}",
            if it215 { "215" } else { "214" },
            if sixteen { ", 16-bit" } else { ", 8-bit" },
            if stereo { ", stereo" } else { "" },
            walked_block = plural(walked, "block"),
            frames_sample = plural(frames, "sample")
        ))
        .lazy(it214_blocks, (span, sixteen));
    if short {
        node = node.diag(crate::error::Diagnostic::truncated(
            region.sub(pos, 2),
            region.len.saturating_sub(pos),
        ));
    }
    Ok(node)
}

async fn it214_blocks(cx: Cx, (span, sixteen): (Span, bool)) -> Result<()> {
    let mut pos = 0u64;
    let mut index = 0u64;
    while pos < span.len {
        let head = cx.read_avail(span.sub(pos, 2)).await?;
        let Some(len) = u16_le(&head, 0) else { break };
        let block = span.sub(pos, 2u64.saturating_add(len.into()));
        cx.push(
            Node::new(format!("Block {index}"))
                .span(block)
                .summary(format!(
                    "{len} bytes, up to {}",
                    plural(it214_block(sixteen), "sample")
                )),
        )
        .await;
        pos = pos.saturating_add(block.len.max(2));
        index = index.saturating_add(1);
    }
    Ok(())
}

/// "name" or "(unnamed)".
pub fn named(s: &str) -> String {
    let t = s.trim();
    if t.is_empty() {
        "(unnamed)".to_owned()
    } else {
        t.to_owned()
    }
}

/// A note column as trackers show it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Note {
    /// No note.
    None,
    /// A key, 0 = C-0.
    Key(u8),
    /// Key off (`===`).
    Off,
    /// Note cut (`^^^`).
    Cut,
    /// Note fade (`~~~`).
    Fade,
    /// A value outside the format's range.
    Invalid(u8),
}

impl Note {
    fn text(self) -> String {
        match self {
            Note::None => "...".to_owned(),
            Note::Key(n) => note_name(n),
            Note::Off => "===".to_owned(),
            Note::Cut => "^^^".to_owned(),
            Note::Fade => "~~~".to_owned(),
            Note::Invalid(n) => format!("?{n:02X}"),
        }
    }
}

/// One channel of a pattern row: note, instrument, volume column and
/// effect, each `None`/0 when empty.
#[derive(Clone, Debug)]
pub struct Cell {
    pub note: Note,
    pub instrument: u8,
    pub volume: Option<String>,
    pub effect: Option<String>,
}

impl Cell {
    pub const EMPTY: Cell = Cell {
        note: Note::None,
        instrument: 0,
        volume: None,
        effect: None,
    };

    pub fn is_empty(&self) -> bool {
        self.note == Note::None
            && self.instrument == 0
            && self.volume.is_none()
            && self.effect.is_none()
    }

    /// "C-5 01 v64 A06", with dots for empty columns.
    pub fn text(&self) -> String {
        let instrument = if self.instrument == 0 {
            "..".to_owned()
        } else {
            format!("{:02}", self.instrument)
        };
        format!(
            "{} {instrument} {} {}",
            self.note.text(),
            self.volume.as_deref().unwrap_or("..."),
            self.effect.as_deref().unwrap_or("...")
        )
    }
}

/// A row's summary: the non-empty cells as "channel: cell" (channels
/// counted from 1), or "empty".
pub fn row_summary(cells: &[(usize, Cell)]) -> String {
    let used: Vec<String> = cells
        .iter()
        .filter(|(_, c)| !c.is_empty())
        .map(|(ch, c)| format!("{}: {}", ch.saturating_add(1), c.text()))
        .collect();
    if used.is_empty() {
        "empty".to_owned()
    } else {
        used.join(" | ")
    }
}

/// An S3M/IT effect column: command 1 is `A`, ..., 26 is `Z`.
pub fn letter_effect(command: u8, param: u8) -> Option<String> {
    if command == 0 {
        return None;
    }
    let letter = if command <= 26 {
        char::from(b'@'.saturating_add(command))
    } else {
        '?'
    };
    Some(format!("{letter}{param:02X}"))
}

/// Schism Tracker's version from the low 12 bits of its tracker ID and
/// the extended version field: versions from 0x050 on are dates, in days
/// since 2009-10-31, and 0xfff means the day count is in `extended` (as
/// libxmp and OpenMPT decode them).
pub fn schism_version(version: u16, extended: u32) -> String {
    let version = version & 0x0fff;
    if version < 0x50 {
        return format!("Schism Tracker 0.{version:x}");
    }
    let offset = if version == 0x0fff {
        i64::from(extended)
    } else {
        i64::from(version.saturating_sub(0x50))
    };
    let base = crate::formats::util::civil::days_from_civil(2009, 10, 31).unwrap_or(0);
    let (y, m, d) = crate::formats::util::civil::civil(base.saturating_add(offset));
    format!("Schism Tracker {y:04}-{m:02}-{d:02}")
}

/// Bytes of PCM sample data: `frames` frames of 8- or 16-bit samples,
/// mono or stereo.
pub fn pcm_bytes(frames: u32, sixteen: bool, stereo: bool) -> u64 {
    u64::from(frames)
        .saturating_mul(if sixteen { 2 } else { 1 })
        .saturating_mul(if stereo { 2 } else { 1 })
}
