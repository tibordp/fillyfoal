//! The WebP lossless (VP8L) image stream (RFC 9649, section 3), decoded:
//! transforms (with their sub-images: predictor modes, color transform
//! multipliers, the color table), the color cache, meta prefix codes and
//! their entropy image, the prefix codes themselves, and the
//! entropy-coded pixels, counted as literals, backward references and
//! color cache hits.
//!
//! Sub-images are decoded to their values; the main image is only walked
//! symbol by symbol (no pixel values are kept), a bounded number of
//! pixels between checkpoints.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::arcutil::push_nodes;
use crate::formats::util::fmt::{grouped, plural};
use crate::formats::util::val;
use crate::node::Node;
use crate::span::Span;
use crate::value::{Color, Value};

/// Pixels decoded between checkpoints.
const STEP: u64 = 1 << 16;
/// The most pixels a sub-image may have (its values are kept).
const MAX_SUBIMAGE: u64 = 1 << 24;
/// Prefix code groups listed one by one, at most.
const MAX_LISTED_GROUPS: usize = 256;

fn bad(what: impl Into<String>) -> Diagnostic {
    Diagnostic::malformed(what.into())
}

/// Bits read least significant first.
struct BitReader<'a> {
    data: &'a [u8],
    pos: u64,
}

impl BitReader<'_> {
    fn bit(&mut self) -> Result<u32> {
        let byte = self
            .data
            .get(to_usize(self.pos >> 3))
            .ok_or_else(|| bad("the image stream ends early"))?;
        let b = u32::from(byte >> (self.pos & 7)) & 1;
        self.pos = self.pos.saturating_add(1);
        Ok(b)
    }

    fn read(&mut self, n: u32) -> Result<u32> {
        let mut v = 0u32;
        for i in 0..n.min(32) {
            v |= self.bit()? << i;
        }
        Ok(v)
    }
}

/// A canonical prefix code, decoded a bit at a time (as `puff` does).
#[derive(Clone, Debug, Default)]
struct Code {
    /// A code with one symbol takes no bits.
    single: Option<u16>,
    counts: [u16; 16],
    symbols: Vec<u16>,
    /// Symbols with a code.
    used: usize,
}

impl Code {
    fn from_lengths(lengths: &[u8]) -> Result<Code> {
        let mut counts = [0u16; 16];
        for &l in lengths {
            if let Some(c) = counts.get_mut(usize::from(l)) {
                *c = c.saturating_add(1);
            }
        }
        if let Some(c) = counts.get_mut(0) {
            *c = 0;
        }
        let used: usize = counts.iter().map(|&c| usize::from(c)).sum();
        let mut code = Code {
            used,
            ..Code::default()
        };
        if used <= 1 {
            // One symbol (or none: treated as symbol 0) takes no bits.
            let sym = lengths.iter().position(|&l| l != 0).unwrap_or(0);
            code.single = Some(u16::try_from(sym).unwrap_or(0));
            return Ok(code);
        }
        // Kraft: the code must be complete.
        let mut left = 1i64;
        for &c in counts.iter().skip(1) {
            left = left.saturating_mul(2).saturating_sub(i64::from(c));
            if left < 0 {
                return Err(bad("over-subscribed prefix code"));
            }
        }
        if left != 0 {
            return Err(bad("incomplete prefix code"));
        }
        for len in 1..16u8 {
            for (sym, &l) in lengths.iter().enumerate() {
                if l == len {
                    code.symbols.push(u16::try_from(sym).unwrap_or(0));
                }
            }
        }
        code.counts = counts;
        Ok(code)
    }

    fn read(&self, br: &mut BitReader<'_>) -> Result<u16> {
        if let Some(s) = self.single {
            return Ok(s);
        }
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for &count in self.counts.iter().skip(1) {
            code |= i32::try_from(br.bit()?).unwrap_or(0);
            let count = i32::from(count);
            if code.saturating_sub(first) < count {
                let at = index.saturating_add(code.saturating_sub(first));
                return self
                    .symbols
                    .get(usize::try_from(at).unwrap_or(usize::MAX))
                    .copied()
                    .ok_or_else(|| bad("bad prefix code"));
            }
            index = index.saturating_add(count);
            first = first.saturating_add(count) << 1;
            code <<= 1;
        }
        Err(bad("bad prefix code"))
    }
}

const CODE_LENGTH_ORDER: [usize; 19] = [
    17, 18, 0, 1, 2, 3, 4, 5, 16, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
];

/// Reads one prefix code over an alphabet of `size` symbols.
fn read_code(br: &mut BitReader<'_>, size: usize) -> Result<Code> {
    let mut lengths = vec![0u8; size];
    if br.read(1)? == 1 {
        // Simple: one or two symbols of length 1.
        let two = br.read(1)? == 1;
        let first_bits = if br.read(1)? == 1 { 8 } else { 1 };
        let s0 = to_usize(br.read(first_bits)?.into());
        *lengths
            .get_mut(s0)
            .ok_or_else(|| bad("simple code symbol out of range"))? = 1;
        if two {
            let s1 = to_usize(br.read(8)?.into());
            *lengths
                .get_mut(s1)
                .ok_or_else(|| bad("simple code symbol out of range"))? = 1;
        }
        return Code::from_lengths(&lengths);
    }
    let mut cl = [0u8; 19];
    let n = 4usize.saturating_add(to_usize(br.read(4)?.into()));
    for &i in CODE_LENGTH_ORDER.iter().take(n) {
        if let Some(slot) = cl.get_mut(i) {
            *slot = u8::try_from(br.read(3)?).unwrap_or(0);
        }
    }
    let cl_code = Code::from_lengths(&cl)?;
    let mut max = size;
    if br.read(1)? == 1 {
        let nbits = 2u32.saturating_add(br.read(3)?.saturating_mul(2));
        max = 2usize.saturating_add(to_usize(br.read(nbits)?.into()));
        if max > size {
            return Err(bad("more code lengths than symbols"));
        }
    }
    let mut sym = 0usize;
    let mut prev = 8u8;
    while sym < size {
        if max == 0 {
            break;
        }
        max = max.saturating_sub(1);
        let c = cl_code.read(br)?;
        if c < 16 {
            let l = u8::try_from(c).unwrap_or(0);
            if let Some(slot) = lengths.get_mut(sym) {
                *slot = l;
            }
            sym = sym.saturating_add(1);
            if l != 0 {
                prev = l;
            }
            continue;
        }
        let (bits, base, value) = match c {
            16 => (2, 3, prev),
            17 => (3, 3, 0),
            _ => (7, 11, 0),
        };
        let repeat = to_usize(br.read(bits)?.into()).saturating_add(base);
        if sym.saturating_add(repeat) > size {
            return Err(bad("code length repeat past the alphabet"));
        }
        for slot in lengths.iter_mut().skip(sym).take(repeat) {
            *slot = value;
        }
        sym = sym.saturating_add(repeat);
    }
    Code::from_lengths(&lengths)
}

/// The five codes for a block: green (with lengths and cache indices),
/// red, blue, alpha, distance.
#[derive(Clone, Debug)]
struct Group([Code; 5]);

fn read_group(br: &mut BitReader<'_>, cache_size: usize) -> Result<Group> {
    let sizes = [
        256usize.saturating_add(24).saturating_add(cache_size),
        256,
        256,
        256,
        40,
    ];
    let mut codes: [Code; 5] = Default::default();
    for (code, size) in codes.iter_mut().zip(sizes) {
        *code = read_code(br, size)?;
    }
    Ok(Group(codes))
}

impl Group {
    fn code(&self, i: usize) -> &Code {
        // Always five.
        self.0.get(i).unwrap_or(&EMPTY)
    }
}

static EMPTY: Code = Code {
    single: Some(0),
    counts: [0; 16],
    symbols: Vec::new(),
    used: 0,
};

/// A length or distance from its prefix symbol and extra bits.
fn prefix_value(br: &mut BitReader<'_>, code: u32) -> Result<u64> {
    if code < 4 {
        return Ok(u64::from(code).saturating_add(1));
    }
    let extra = (code.saturating_sub(2)) >> 1;
    let offset = (2u64.saturating_add(u64::from(code & 1))) << extra;
    Ok(offset
        .saturating_add(u64::from(br.read(extra)?))
        .saturating_add(1))
}

/// Distance codes 1 to 120: (dx, dy) of a nearby pixel.
const DISTANCE_MAP: [(i8, i8); 120] = [
    (0, 1),
    (1, 0),
    (1, 1),
    (-1, 1),
    (0, 2),
    (2, 0),
    (1, 2),
    (-1, 2),
    (2, 1),
    (-2, 1),
    (2, 2),
    (-2, 2),
    (0, 3),
    (3, 0),
    (1, 3),
    (-1, 3),
    (3, 1),
    (-3, 1),
    (2, 3),
    (-2, 3),
    (3, 2),
    (-3, 2),
    (0, 4),
    (4, 0),
    (1, 4),
    (-1, 4),
    (4, 1),
    (-4, 1),
    (3, 3),
    (-3, 3),
    (2, 4),
    (-2, 4),
    (4, 2),
    (-4, 2),
    (0, 5),
    (3, 4),
    (-3, 4),
    (4, 3),
    (-4, 3),
    (5, 0),
    (1, 5),
    (-1, 5),
    (5, 1),
    (-5, 1),
    (2, 5),
    (-2, 5),
    (5, 2),
    (-5, 2),
    (4, 4),
    (-4, 4),
    (3, 5),
    (-3, 5),
    (5, 3),
    (-5, 3),
    (0, 6),
    (6, 0),
    (1, 6),
    (-1, 6),
    (6, 1),
    (-6, 1),
    (2, 6),
    (-2, 6),
    (6, 2),
    (-6, 2),
    (4, 5),
    (-4, 5),
    (5, 4),
    (-5, 4),
    (3, 6),
    (-3, 6),
    (6, 3),
    (-6, 3),
    (0, 7),
    (7, 0),
    (1, 7),
    (-1, 7),
    (5, 5),
    (-5, 5),
    (7, 1),
    (-7, 1),
    (4, 6),
    (-4, 6),
    (6, 4),
    (-6, 4),
    (2, 7),
    (-2, 7),
    (7, 2),
    (-7, 2),
    (3, 7),
    (-3, 7),
    (7, 3),
    (-7, 3),
    (5, 6),
    (-5, 6),
    (6, 5),
    (-6, 5),
    (8, 0),
    (4, 7),
    (-4, 7),
    (7, 4),
    (-7, 4),
    (8, 1),
    (8, 2),
    (6, 6),
    (-6, 6),
    (8, 3),
    (5, 7),
    (-5, 7),
    (7, 5),
    (-7, 5),
    (8, 4),
    (6, 7),
    (-6, 7),
    (7, 6),
    (-7, 6),
    (8, 5),
    (7, 7),
    (-7, 7),
    (8, 6),
    (8, 7),
];

fn distance(code: u64, width: u64) -> u64 {
    if code > 120 {
        return code.saturating_sub(120);
    }
    let (dx, dy) = DISTANCE_MAP
        .get(to_usize(code.saturating_sub(1)))
        .copied()
        .unwrap_or((0, 1));
    let d = i64::from(dx)
        .saturating_add(i64::from(dy).saturating_mul(i64::try_from(width).unwrap_or(i64::MAX)));
    u64::try_from(d.max(1)).unwrap_or(1)
}

/// How an image's pixels were coded.
#[derive(Clone, Copy, Debug, Default)]
struct Counts {
    literals: u64,
    refs: u64,
    ref_pixels: u64,
    cached: u64,
}

impl Counts {
    fn text(&self) -> String {
        let mut parts = vec![plural(grouped(self.literals), "literal pixel")];
        if self.refs > 0 {
            parts.push(format!(
                "{} covering {}",
                plural(grouped(self.refs), "backward reference"),
                plural(grouped(self.ref_pixels), "pixel")
            ));
        }
        if self.cached > 0 {
            parts.push(format!(
                "{} from the color cache",
                plural(grouped(self.cached), "pixel")
            ));
        }
        parts.join(", ")
    }
}

/// The prefix codes of an image, with where they are and which block
/// uses which group.
struct Coding {
    cache_bits: u32,
    groups: Vec<Group>,
    /// Meta prefix codes: block size bits, entropy image width, and each
    /// block's group.
    meta: Option<(u32, u64, Vec<u16>)>,
    nodes: Vec<Node>,
}

/// An entropy-coded image of `w` × `h` pixels being decoded.
struct Pixels {
    w: u64,
    total: u64,
    pos: u64,
    counts: Counts,
    /// Values, kept for sub-images.
    values: Option<Vec<u32>>,
    cache: Vec<u32>,
}

impl Pixels {
    fn new(w: u64, h: u64, keep: bool) -> Pixels {
        let total = w.saturating_mul(h);
        Pixels {
            w,
            total,
            pos: 0,
            counts: Counts::default(),
            values: keep.then(|| Vec::with_capacity(to_usize(total.min(MAX_SUBIMAGE)))),
            cache: Vec::new(),
        }
    }

    fn push(&mut self, argb: u32, cache_bits: u32) {
        if let Some(v) = self.values.as_mut() {
            v.push(argb);
            if cache_bits > 0 {
                let i = (0x1e35_a7bd_u32.wrapping_mul(argb)) >> (32u32.saturating_sub(cache_bits));
                if let Some(slot) = self.cache.get_mut(to_usize(i.into())) {
                    *slot = argb;
                }
            }
        }
    }

    /// Decodes up to `budget` pixels; true when the image is complete.
    fn step(&mut self, br: &mut BitReader<'_>, c: &Coding, budget: u64) -> Result<bool> {
        if self.values.is_some() && self.cache.is_empty() && c.cache_bits > 0 {
            self.cache = vec![0; 1usize << c.cache_bits];
        }
        let end = self.pos.saturating_add(budget).min(self.total);
        let cache_size = if c.cache_bits > 0 {
            1u32 << c.cache_bits
        } else {
            0
        };
        while self.pos < end {
            let group = match &c.meta {
                Some((bits, ew, map)) => {
                    let x = self.pos.checked_rem(self.w).unwrap_or(0) >> bits;
                    let y = self.pos.checked_div(self.w).unwrap_or(0) >> bits;
                    let i = map
                        .get(to_usize(y.saturating_mul(*ew).saturating_add(x)))
                        .copied()
                        .unwrap_or(0);
                    c.groups.get(usize::from(i))
                }
                None => c.groups.first(),
            }
            .ok_or_else(|| bad("no prefix code group for a block"))?;
            let s = u32::from(group.code(0).read(br)?);
            if s < 256 {
                let r = u32::from(group.code(1).read(br)?);
                let b = u32::from(group.code(2).read(br)?);
                let a = u32::from(group.code(3).read(br)?);
                self.push((a << 24) | (r << 16) | (s << 8) | b, c.cache_bits);
                self.pos = self.pos.saturating_add(1);
                self.counts.literals = self.counts.literals.saturating_add(1);
            } else if s < 280 {
                let len = prefix_value(br, s.saturating_sub(256))?;
                let dcode = u32::from(group.code(4).read(br)?);
                let dist = distance(prefix_value(br, dcode)?, self.w);
                if dist > self.pos {
                    return Err(bad("backward reference before the first pixel"));
                }
                let len = len.min(self.total.saturating_sub(self.pos));
                if self.values.is_some() {
                    // Pixel by pixel: the copy may overlap what it makes.
                    let from = to_usize(self.pos.saturating_sub(dist));
                    for k in 0..to_usize(len) {
                        let px = self
                            .values
                            .as_ref()
                            .and_then(|v| v.get(from.saturating_add(k)))
                            .copied()
                            .unwrap_or(0);
                        self.push(px, c.cache_bits);
                    }
                }
                self.pos = self.pos.saturating_add(len);
                self.counts.refs = self.counts.refs.saturating_add(1);
                self.counts.ref_pixels = self.counts.ref_pixels.saturating_add(len);
            } else {
                let i = s.saturating_sub(280);
                if i >= cache_size {
                    return Err(bad("color cache index out of range"));
                }
                let px = self.cache.get(to_usize(i.into())).copied().unwrap_or(0);
                self.push(px, c.cache_bits);
                self.pos = self.pos.saturating_add(1);
                self.counts.cached = self.counts.cached.saturating_add(1);
            }
        }
        Ok(self.pos >= self.total)
    }
}

/// What reading a stream found: nodes, and where it ended.
pub struct Decoded {
    pub nodes: Vec<Node>,
    pub summary: String,
}

/// A byte span for the bits `from..to` of the stream at `span`.
fn bit_span(span: Span, from: u64, to: u64) -> Span {
    let start = from >> 3;
    let end = to.div_ceil(8).max(start);
    span.sub(start, end.saturating_sub(start))
}

fn div_up(n: u64, bits: u32) -> u64 {
    n.saturating_add((1u64 << bits).saturating_sub(1)) >> bits
}

/// Reads an entropy-coded image's color cache flag, meta prefix codes
/// (main image only) and prefix codes.
fn read_coding(br: &mut BitReader<'_>, span: Span, w: u64, h: u64, main: bool) -> Result<Coding> {
    let mut nodes = Vec::new();
    let start = br.pos;
    let cache_bits = if br.read(1)? == 1 {
        let b = br.read(4)?;
        if !(1..=11).contains(&b) {
            return Err(bad(format!("color cache of {b} bits (1 to 11 allowed)")));
        }
        b
    } else {
        0
    };
    nodes.push(
        Node::new("Color cache")
            .span(bit_span(span, start, br.pos))
            .summary(if cache_bits == 0 {
                "none".to_owned()
            } else {
                format!(
                    "{} bits, {}",
                    cache_bits,
                    plural(1u64 << cache_bits, "entry")
                )
            })
            .desc("Recently used colors, coded by a hash index"),
    );
    let mut meta = None;
    if main {
        let at = br.pos;
        if br.read(1)? == 1 {
            let bits = br.read(3)?.saturating_add(2);
            let (ew, eh) = (div_up(w, bits), div_up(h, bits));
            let (values, sub) = sub_image(br, span, ew, eh)?;
            let map: Vec<u16> = values
                .iter()
                .map(|&p| u16::try_from((p >> 8) & 0xffff).unwrap_or(0))
                .collect();
            let block = 1u64 << bits;
            nodes.push(
                Node::new("Entropy image")
                    .span(bit_span(span, at, br.pos))
                    .summary(format!(
                        "{block}×{block} blocks, a {ew}×{eh} image of prefix code group numbers"
                    ))
                    .lazy(push_nodes, Arc::new(sub)),
            );
            meta = Some((bits, ew, map));
        }
    }
    let groups_n = meta
        .as_ref()
        .and_then(|(_, _, m)| m.iter().max())
        .map_or(1, |&m| usize::from(m).saturating_add(1));
    let at = br.pos;
    let cache_size = if cache_bits > 0 {
        1usize << cache_bits
    } else {
        0
    };
    let mut groups = Vec::with_capacity(groups_n.min(4096));
    let mut listed = Vec::new();
    for i in 0..groups_n {
        let g_at = br.pos;
        let g = read_group(br, cache_size)?;
        if i < MAX_LISTED_GROUPS {
            listed.push(group_node(i, &g, bit_span(span, g_at, br.pos)));
        }
        groups.push(g);
    }
    nodes.push(
        Node::new("Prefix codes")
            .span(bit_span(span, at, br.pos))
            .summary(plural(to_u64(groups_n), "group"))
            .desc("Each group: codes for green (and lengths and cache indices), red, blue, alpha and distance")
            .lazy(push_nodes, Arc::new(listed)),
    );
    Ok(Coding {
        cache_bits,
        groups,
        meta,
        nodes,
    })
}

fn group_node(i: usize, g: &Group, span: Span) -> Node {
    let names = ["green", "red", "blue", "alpha", "distance"];
    let parts: Vec<String> = names
        .iter()
        .enumerate()
        .map(|(k, n)| format!("{n} {}", g.code(k).used))
        .collect();
    Node::new(format!("Group {i}"))
        .span(span)
        .summary(format!("symbols coded: {}", parts.join(", ")))
}

/// Decodes a sub-image of `w` × `h` (no transforms, no meta codes) to its
/// values, with nodes describing its coding.
fn sub_image(br: &mut BitReader<'_>, span: Span, w: u64, h: u64) -> Result<(Vec<u32>, Vec<Node>)> {
    if w.saturating_mul(h) > MAX_SUBIMAGE {
        return Err(Diagnostic::limit(format!("a {w}×{h} sub-image")));
    }
    let coding = read_coding(br, span, w, h, false)?;
    let mut px = Pixels::new(w, h, true);
    let at = br.pos;
    px.step(br, &coding, u64::MAX)?;
    let mut nodes = coding.nodes;
    nodes.push(
        Node::new("Pixels")
            .span(bit_span(span, at, br.pos))
            .summary(px.counts.text()),
    );
    Ok((px.values.unwrap_or_default(), nodes))
}

const PREDICTORS: [&str; 14] = [
    "black (0xff000000)",
    "L",
    "T",
    "TR",
    "TL",
    "average(average(L, TR), T)",
    "average(L, TL)",
    "average(L, T)",
    "average(TL, T)",
    "average(T, TR)",
    "average(average(L, TL), average(T, TR))",
    "select",
    "clamp(L + T − TL)",
    "clamp(average(L, T) + (average(L, T) − TL) / 2)",
];

/// The transforms: nodes, and the image width after them (color
/// indexing packs pixels).
fn transforms(
    br: &mut BitReader<'_>,
    span: Span,
    mut w: u64,
    h: u64,
    alpha: bool,
) -> Result<(Vec<Node>, u64)> {
    let mut nodes = Vec::new();
    let mut seen = [false; 4];
    while br.read(1)? == 1 {
        let at = br.pos.saturating_sub(1);
        let kind = br.read(2)?;
        let slot = seen
            .get_mut(to_usize(kind.into()))
            .ok_or_else(|| bad("transform type"))?;
        if *slot {
            return Err(bad("a transform is used twice"));
        }
        *slot = true;
        let node = match kind {
            0 | 1 => {
                let bits = br.read(3)?.saturating_add(2);
                let (tw, th) = (div_up(w, bits), div_up(h, bits));
                let (values, sub) = sub_image(br, span, tw, th)?;
                let block = 1u64 << bits;
                let mut kids = Vec::new();
                if kind == 0 {
                    let mut hist = [0u64; 16];
                    for v in &values {
                        if let Some(c) = hist.get_mut(to_usize(((v >> 8) & 0xf).into())) {
                            *c = c.saturating_add(1);
                        }
                    }
                    for (mode, &n) in hist.iter().enumerate() {
                        if n > 0 {
                            let name = PREDICTORS.get(mode).copied().unwrap_or("invalid");
                            kids.push(
                                Node::new(format!("Mode {mode}: {name}"))
                                    .summary(plural(n, "block")),
                            );
                        }
                    }
                }
                kids.push(Node::new("Sub-image").lazy(push_nodes, Arc::new(sub)));
                let (title, what) = if kind == 0 {
                    ("Predictor transform", "prediction modes")
                } else {
                    (
                        "Color transform",
                        "green-to-red, green-to-blue and red-to-blue multipliers",
                    )
                };
                Node::new(title)
                    .summary(format!(
                        "{block}×{block} blocks, a {tw}×{th} image of {what}"
                    ))
                    .lazy(push_nodes, Arc::new(kids))
            }
            2 => Node::new("Subtract green transform")
                .summary("green is subtracted from red and blue"),
            _ => {
                let size = u64::from(br.read(8)?).saturating_add(1);
                let (values, sub) = sub_image(br, span, size, 1)?;
                // Each entry is a delta from the previous one, per channel.
                let mut prev = [0u8; 4];
                let mut colors = Vec::with_capacity(values.len());
                for v in values {
                    for (p, d) in prev.iter_mut().zip(v.to_le_bytes()) {
                        *p = p.wrapping_add(d);
                    }
                    colors.push(prev);
                }
                let bits = match size {
                    0..=2 => 3,
                    3..=4 => 2,
                    5..=16 => 1,
                    _ => 0,
                };
                let mut kids: Vec<Node> = colors
                    .iter()
                    .enumerate()
                    .map(|(i, &[b, g, r, a])| {
                        if alpha {
                            // Alpha values travel in the green channel.
                            Node::new(format!("Level {i}")).value(val::uint(g, 8))
                        } else {
                            Node::new(format!("Color {i}"))
                                .value(Value::color(Color::rgba8(r, g, b, a)))
                        }
                    })
                    .collect();
                kids.push(Node::new("Sub-image").lazy(push_nodes, Arc::new(sub)));
                w = div_up(w, bits);
                Node::new("Color indexing transform")
                    .summary(format!(
                        "{}{}",
                        plural(size, if alpha { "alpha level" } else { "color" }),
                        match bits {
                            1 => ", 2 pixels per byte",
                            2 => ", 4 pixels per byte",
                            3 => ", 8 pixels per byte",
                            _ => "",
                        }
                    ))
                    .lazy(push_nodes, Arc::new(kids))
            }
        };
        nodes.push(node.span(bit_span(span, at, br.pos)));
    }
    Ok((nodes, w))
}

/// Decodes an image stream of `w` × `h` (after the VP8L header, or an
/// `ALPH` chunk's lossless data, `alpha`) at `span`: its parts as nodes.
pub async fn image_stream(cx: &Cx, span: Span, w: u64, h: u64, alpha: bool) -> Result<Decoded> {
    let data = cx.read_avail(span).await?;
    let mut br = BitReader {
        data: &data,
        pos: 0,
    };
    let (mut nodes, packed) = match transforms(&mut br, span, w, h, alpha) {
        Ok(t) => t,
        Err(e) => return Ok(failed(Vec::new(), span, br.pos, e)),
    };
    let coding = match read_coding(&mut br, span, packed, h, true) {
        Ok(c) => c,
        Err(e) => return Ok(failed(nodes, span, br.pos, e)),
    };
    let transforms_n = nodes.len();
    let groups = coding.groups.len();
    nodes.extend(coding.nodes.iter().cloned());
    let at = br.pos;
    let mut px = Pixels::new(packed, h, false);
    loop {
        match px.step(&mut br, &coding, STEP) {
            Ok(true) => break,
            Ok(false) => cx.checkpoint().await,
            Err(e) => {
                nodes.push(
                    Node::new("Pixels")
                        .span(bit_span(span, at, br.pos))
                        .summary(px.counts.text())
                        .diag(e.at(span)),
                );
                return Ok(Decoded {
                    nodes,
                    summary: "undecodable".to_owned(),
                });
            }
        }
    }
    let used = br.pos.div_ceil(8);
    nodes.push(
        Node::new("Pixels")
            .span(bit_span(span, at, br.pos))
            .summary(px.counts.text()),
    );
    if used < span.len {
        nodes.push(
            Node::new("Unused")
                .span(span.tail(used))
                .summary(plural(span.len.saturating_sub(used), "byte")),
        );
    }
    Ok(Decoded {
        nodes,
        summary: format!(
            "{}, {}, {}",
            match transforms_n {
                0 => "no transforms".to_owned(),
                n => plural(to_u64(n), "transform"),
            },
            plural(to_u64(groups), "prefix code group"),
            px.counts.text()
        ),
    })
}

fn failed(mut nodes: Vec<Node>, span: Span, pos: u64, e: Diagnostic) -> Decoded {
    nodes.push(Node::new("Undecodable").span(span.tail(pos >> 3)).diag(e));
    Decoded {
        nodes,
        summary: "undecodable".to_owned(),
    }
}
