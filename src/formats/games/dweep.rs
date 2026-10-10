//! Dweep Gold (Dexterity Software, 2000) levels and level packs (`.dwp`).
//!
//! Reverse engineered from editor-made levels and the game's executable.
//! The game keeps levels as raw 488-byte records and writes them out as
//! they are in memory:
//!
//! | Offset | Size | Field |
//! |---|---|---|
//! | 0x000 | 40 | title, NUL-terminated |
//! | 0x028 | 200 | tip, NUL-terminated |
//! | 0x0F0 | 160 | board, 16 × 10 cells, row-major |
//! | 0x190 | 80 | starting inventory: 10 × (u32 type, u32 variant), slot 0 unused |
//! | 0x1E0 | 8 | never read or written |
//!
//! A single level is `"Dweep\0"`, the copyright notice (40 bytes), one record
//! and a u32 theme (538 bytes). A pack is `"Dweep\0"`, a 40-byte pack title,
//! a u32 level count and the records; the original game's pack holds one
//! record more than its count says. The editor creates a level with
//! `operator new` and initialises only the first byte of each string, the
//! inventory and the board: the rest of the strings and the last 8 bytes are
//! whatever was in memory.

use crate::bytes::{to_u64, to_usize, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::formats::util::datakit::uint;
use crate::formats::util::vidutil::plural;
use crate::formats::{Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

const MAGIC: &[u8] = b"Dweep\0";
const COPYRIGHT: &[u8] = b"Copyright \xa9 2000 by Dexterity Software.";
/// Size of a level record.
const RECORD: u64 = 488;
/// Size of a single-level file.
const SINGLE: u64 = 538;
/// Where a pack's records start.
const PACK_HEADER: u64 = 50;
const WIDTH: u64 = 16;
const HEIGHT: u64 = 10;
const TITLE: (u64, u64) = (0, 40);
const TIP: (u64, u64) = (0x28, 200);
const BOARD: (u64, u64) = (0xf0, 160);
const INVENTORY: (u64, u64) = (0x190, 80);
const UNUSED: (u64, u64) = (0x1e0, 8);

fn probe(h: &Head<'_>) -> bool {
    if !h.data.starts_with(MAGIC) {
        return false;
    }
    let single = h.data.get(6..).is_some_and(|d| d.starts_with(COPYRIGHT));
    let count = u32_le(h.data, 0x2e).unwrap_or(0);
    // A pack holds its listed levels and at most one more (the game's own
    // pack hides a bonus level beyond its count); a shorter file is a
    // truncated pack, which the dissector reports.
    let fits = !h.len_known
        || h.len.saturating_sub(PACK_HEADER)
            <= u64::from(count).saturating_add(1).saturating_mul(RECORD);
    single || (h.len >= PACK_HEADER && (1..=10_000).contains(&count) && fits)
}

declare_format!(pub FORMAT = "dweep", "Dweep Gold level or level pack", ["dwp"], "application/octet-stream",
    Probe::Custom(probe), dissect);

const CELLS: EnumTable = &[
    (0, "Floor"),
    (1, "Block"),
    (2, "Heat Plate"),
    (3, "Freeze Plate"),
    (4, "Goal (baby Dweeps)"),
    (5, "Dweep"),
    (6, "Laser, up"),
    (7, "Laser, right"),
    (8, "Laser, down"),
    (9, "Laser, left"),
    (10, "Mirror, /"),
    (11, "Mirror, \\"),
    (12, "Fan, up"),
    (13, "Fan, right"),
    (14, "Fan, down"),
    (15, "Fan, left"),
    (16, "Bomb"),
    (17, "Laser item, up"),
    (18, "Laser item, right"),
    (19, "Laser item, down"),
    (20, "Laser item, left"),
    (21, "Mirror item, /"),
    (22, "Mirror item, \\"),
    (23, "Fan item, up"),
    (24, "Fan item, right"),
    (25, "Fan item, down"),
    (26, "Fan item, left"),
    (27, "Bomb item"),
    (28, "Wrench, counter-clockwise"),
    (29, "Wrench, clockwise"),
    (30, "Water Bucket"),
    (31, "Hammer"),
    (32, "Torch"),
];

/// Two characters per cell for the row maps: fixed objects in capitals,
/// items to pick up in lower case.
const GLYPHS: &[&str] = &[
    "..", "##", "HP", "FP", "GO", "DW", "L^", "L>", "Lv", "L<", "M/", "M\\", "F^", "F>", "Fv",
    "F<", "BO", "l^", "l>", "lv", "l<", "m/", "m\\", "f^", "f>", "fv", "f<", "bo", "w-", "w+",
    "wb", "hm", "to",
];

const LEGEND: &str = "Two characters per cell: .. floor, ## block, HP heat plate, \
FP freeze plate, GO goal, DW Dweep, L laser, M mirror, F fan, BO bomb (^ > v < \
direction, / \\ orientation); lower case l, m, f, bo are items to pick up; \
w- and w+ wrenches (counter-clockwise, clockwise), wb water bucket, hm hammer, \
to torch; ?? unknown";

const ITEMS: EnumTable = &[
    (1, "Laser"),
    (2, "Mirror"),
    (3, "Fan"),
    (4, "Wrench"),
    (5, "Water Bucket"),
    (6, "Bomb"),
    (7, "Hammer"),
    (8, "Torch"),
    (9, "empty"),
];

const DIRECTIONS: &[&str] = &["up", "right", "down", "left"];

const THEMES: EnumTable = &[
    (0, "Theme 1 (wood)"),
    (1, "Theme 2 (parquet)"),
    (2, "Theme 3 (stone)"),
    (3, "Theme 4 (sand)"),
    (4, "Theme 5 (ice)"),
];

fn windows_1252(bytes: &[u8]) -> String {
    crate::codec::charset::decode_label("windows-1252", bytes)
        .unwrap_or_else(|| crate::text::latin1(bytes))
}

/// The variant of an inventory item, in words.
fn variant(item: u32, v: u32) -> Option<&'static str> {
    let i = to_usize(v.into());
    match item {
        1 | 3 => DIRECTIONS.get(i).copied(),
        2 => ["/", "\\"].get(i).copied(),
        4 => ["counter-clockwise", "clockwise"].get(i).copied(),
        _ => None,
    }
}

fn item_name(item: u32, v: u32) -> String {
    let name = lookup(ITEMS, item.into()).unwrap_or("unknown item");
    match variant(item, v) {
        Some(var) => format!("{name}, {var}"),
        None if matches!(item, 5..=9) && v == 0 => name.to_owned(),
        None => format!("{name}, variant {v}"),
    }
}

/// A fixed-size, NUL-terminated string field. Bytes after the terminator
/// are leftover memory; they are pointed out when they are not zero.
fn string_node(name: &'static str, span: Span, bytes: &[u8]) -> Node {
    let end = bytes.iter().position(|&b| b == 0);
    let text = windows_1252(bytes.get(..end.unwrap_or(bytes.len())).unwrap_or_default());
    let mut node = Node::new(name).span(span).value(Value::Text(text));
    match end {
        None => {
            node = node.diag(Diagnostic::malformed("the string is not NUL-terminated").at(span));
        }
        Some(end) => {
            let rest = bytes.get(end.saturating_add(1)..).unwrap_or_default();
            if rest.iter().any(|&b| b != 0) {
                let from = to_u64(end).saturating_add(1);
                node = node.diag(
                    Diagnostic::note(
                        "bytes after the terminator are not zero: memory the editor never cleared",
                    )
                    .at(span.sub(from, span.len.saturating_sub(from))),
                );
            }
        }
    }
    node
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let span = input.span;
    let head = cx.read_avail(span.sub(0, PACK_HEADER)).await?;
    cx.emit(
        Node::new("Signature")
            .span(span.sub(0, 6))
            .value(Value::Text("Dweep".into())),
    );
    let single = head.get(6..).is_some_and(|d| d.starts_with(COPYRIGHT));
    if single {
        cx.emit(string_node(
            "Copyright",
            span.sub(6, 40),
            head.get(6..46).unwrap_or_default(),
        ));
        let record = span.sub(0x2e, RECORD);
        let title = level(&cx, record).await?;
        let theme_span = span.sub(0x2e_u64.saturating_add(RECORD), 4);
        let theme = u32_le(&cx.read_avail(theme_span).await?, 0);
        if let Some(theme) = theme {
            cx.emit(Node::new("Theme").span(theme_span).value(Value::Enum {
                raw: theme.into(),
                bits: 32,
                name: lookup(THEMES, theme.into()),
            }));
        }
        if span.len > SINGLE {
            cx.diag(Diagnostic::note(format!(
                "{} bytes follow the level",
                span.len.saturating_sub(SINGLE)
            )));
        }
        cx.annotate(format!("Dweep level {title:?}"));
        return Ok(());
    }

    cx.emit(string_node(
        "Pack title",
        span.sub(6, 40),
        head.get(6..46).unwrap_or_default(),
    ));
    let count = u32_le(&head, 0x2e).unwrap_or(0);
    cx.emit(
        Node::new("Level count")
            .span(span.sub(0x2e, 4))
            .value(uint(count, 32)),
    );
    let records = span.tail(PACK_HEADER);
    let stored = records.len / RECORD;
    let pack_title = windows_1252(
        head.get(6..46)
            .unwrap_or_default()
            .split(|&b| b == 0)
            .next()
            .unwrap_or_default(),
    );
    let mut summary = format!("Dweep level pack {pack_title:?}, {count} levels");
    if stored > u64::from(count) {
        summary.push_str(&format!(
            " (+{} beyond the count)",
            stored.saturating_sub(count.into())
        ));
    }
    cx.annotate(summary);
    cx.emit(
        Node::new("Levels")
            .span(records)
            .summary(format!("{stored} records of {RECORD} bytes"))
            .lazy(levels, (records, count)),
    );
    let rest = records.len % RECORD;
    if rest != 0 {
        cx.diag(
            Diagnostic::malformed(format!("{rest} bytes after the last whole level record"))
                .at(records.tail(records.len.saturating_sub(rest))),
        );
    }
    if stored < u64::from(count) {
        cx.diag(Diagnostic::truncated(
            records.sub(0, u64::from(count).saturating_mul(RECORD)),
            records.len,
        ));
    }
    Ok(())
}

async fn levels(cx: Cx, (records, count): (Span, u32)) -> Result<()> {
    let n = records.len / RECORD;
    cx.set_count(Count::Exact(n));
    for i in 0..n {
        cx.checkpoint().await;
        let record = records.sub(i.saturating_mul(RECORD), RECORD);
        let title = cx.read_avail(record.sub(TITLE.0, TITLE.1)).await?;
        let title = windows_1252(title.split(|&b| b == 0).next().unwrap_or_default());
        let mut node = Node::new(format!("Level {}", i.saturating_add(1)))
            .span(record)
            .value(Value::Text(title))
            .lazy(level_node, record);
        if i >= u64::from(count) {
            node = node.diag(Diagnostic::note(
                "beyond the level count: stored in the pack, but not listed by the game",
            ));
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn level_node(cx: Cx, record: Span) -> Result<()> {
    level(&cx, record).await.map(|_| ())
}

/// Emits the fields of a level record; returns its title.
async fn level(cx: &Cx, record: Span) -> Result<String> {
    let data = cx.read_avail(record).await?;
    let part = |(at, len): (u64, u64)| {
        data.get(to_usize(at)..to_usize(at.saturating_add(len)))
            .unwrap_or_default()
    };
    let title = string_node("Title", record.sub(TITLE.0, TITLE.1), part(TITLE));
    let name = match &title.value {
        Some(Value::Text(t)) => t.clone(),
        _ => String::new(),
    };
    cx.emit(title);
    cx.emit(string_node("Tip", record.sub(TIP.0, TIP.1), part(TIP)));

    let board = part(BOARD);
    let board_span = record.sub(BOARD.0, BOARD.1);
    // Where the one Dweep (or goal) is, and a diagnostic unless there is
    // exactly one.
    let place = |code: u8, what: &str| {
        let at: Vec<usize> = (0..board.len())
            .filter(|&i| board.get(i) == Some(&code))
            .collect();
        let pos = |i: usize| format!("({}, {})", to_u64(i) % WIDTH, to_u64(i) / WIDTH);
        match at.as_slice() {
            [] => (
                format!("no {what}"),
                Some(format!("the board has no {what}")),
            ),
            [one] => (format!("{what} at {}", pos(*one)), None),
            many => (
                format!("{} {what}s", many.len()),
                Some(format!(
                    "the board has {} {what}s; a level has one",
                    many.len()
                )),
            ),
        }
    };
    let (dweep, dweep_problem) = place(5, "Dweep");
    let (goal, goal_problem) = place(4, "goal");
    // Lasers, mirrors, fans and bombs placed on the board (blocks and plates
    // are scenery; items are what Dweep picks up).
    let devices = board.iter().filter(|&&c| (6..=16).contains(&c)).count();
    let items = board.iter().filter(|&&c| (17..=32).contains(&c)).count();
    let mut board_node = Node::new("Board")
        .span(board_span)
        .summary(format!(
            "{WIDTH} × {HEIGHT}; {dweep}, {goal}, {}, {}",
            plural(to_u64(devices), "device"),
            plural(to_u64(items), "item")
        ))
        .desc(LEGEND)
        .lazy(rows, board_span);
    for problem in [dweep_problem, goal_problem].into_iter().flatten() {
        board_node = board_node.diag(Diagnostic::warning(problem));
    }
    cx.emit(board_node);

    let inventory = part(INVENTORY);
    let names: Vec<String> = (1..10u64)
        .filter_map(|slot| {
            let at = to_usize(slot.saturating_mul(8));
            let item = u32_le(inventory, at)?;
            let v = u32_le(inventory, at.saturating_add(4))?;
            (!matches!(item, 0 | 9)).then(|| item_name(item, v))
        })
        .collect();
    let inv_span = record.sub(INVENTORY.0, INVENTORY.1);
    cx.emit(
        Node::new("Starting inventory")
            .span(inv_span)
            .summary(if names.is_empty() {
                "empty".to_owned()
            } else {
                names.join("; ")
            })
            .lazy(slots, inv_span),
    );

    let unused_span = record.sub(UNUSED.0, UNUSED.1);
    let unused = part(UNUSED);
    let mut node = Node::new("Unused")
        .span(unused_span)
        .value(Value::Bytes(unused.to_vec()))
        .desc("Never read or written by the game");
    if unused.iter().any(|&b| b != 0) {
        node = node.diag(Diagnostic::note(
            "not zero: memory the editor never cleared",
        ));
    }
    cx.emit(node);
    if to_u64(data.len()) < RECORD {
        cx.diag(Diagnostic::truncated(record, to_u64(data.len())));
    }
    Ok(name)
}

async fn rows(cx: Cx, board: Span) -> Result<()> {
    let data = cx.read_avail(board).await?;
    for y in 0..HEIGHT {
        let row = board.sub(y.saturating_mul(WIDTH), WIDTH);
        let cells = data
            .get(
                to_usize(y.saturating_mul(WIDTH))
                    ..to_usize(y.saturating_add(1).saturating_mul(WIDTH)),
            )
            .unwrap_or_default();
        let map: Vec<&str> = cells
            .iter()
            .map(|&c| GLYPHS.get(usize::from(c)).copied().unwrap_or("??"))
            .collect();
        cx.emit(
            Node::new(format!("Row {y}"))
                .span(row)
                .value(Value::Text(map.join(" ")))
                .lazy(row_cells, (row, y)),
        );
    }
    Ok(())
}

async fn row_cells(cx: Cx, (row, y): (Span, u64)) -> Result<()> {
    let data = cx.read_avail(row).await?;
    for (x, &code) in data.iter().enumerate() {
        let mut node = Node::new(format!("({x}, {y})"))
            .span(row.sub(to_u64(x), 1))
            .value(Value::Enum {
                raw: code.into(),
                bits: 8,
                name: lookup(CELLS, code.into()),
            });
        if lookup(CELLS, code.into()).is_none() {
            node = node.diag(Diagnostic::malformed(format!("unknown tile code {code}")));
        }
        cx.emit(node);
    }
    Ok(())
}

async fn slots(cx: Cx, inventory: Span) -> Result<()> {
    let data = cx.read_avail(inventory).await?;
    for slot in 0..10u64 {
        let at = slot.saturating_mul(8);
        let span = inventory.sub(at, 8);
        let (Some(item), Some(v)) = (
            u32_le(&data, to_usize(at)),
            u32_le(&data, to_usize(at.saturating_add(4))),
        ) else {
            break;
        };
        let mut node = Node::new(format!("Slot {slot}"))
            .span(span)
            .lazy(slot_fields, (span, item));
        node = if slot == 0 {
            node.summary("never used: the game numbers slots from 1")
        } else if item == 0 && v == 0 {
            node.summary("unset (packs leave the slots after the first empty one at 0)")
        } else {
            node.value(Value::Text(item_name(item, v)))
        };
        cx.emit(node);
    }
    Ok(())
}

async fn slot_fields(cx: Cx, (span, item): (Span, u32)) -> Result<()> {
    let data = cx.read_avail(span).await?;
    if let Some(t) = u32_le(&data, 0) {
        cx.emit(Node::new("Type").span(span.sub(0, 4)).value(Value::Enum {
            raw: t.into(),
            bits: 32,
            name: lookup(ITEMS, t.into()),
        }));
    }
    if let Some(v) = u32_le(&data, 4) {
        let mut node = Node::new("Variant").span(span.sub(4, 4)).value(uint(v, 32));
        if let Some(var) = variant(item, v) {
            node = node.summary(var);
        }
        cx.emit(node);
    }
    Ok(())
}
