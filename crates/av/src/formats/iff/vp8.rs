//! The VP8 key frame header at the start of a lossy WebP image's first
//! partition (RFC 6386, sections 9.2 to 9.11 and 19.2), read with VP8's
//! boolean entropy decoder (section 7.3): color space and clamping,
//! segmentation, loop filter, the number of token partitions, quantizer
//! indices and coefficient probability updates. What follows in the
//! partition is per-macroblock: segment IDs, skip flags and prediction
//! modes.

use std::sync::Arc;

use crate::formats::util::arcutil::push_nodes;
use crate::formats::util::val;
use crate::node::Node;
use crate::value::{EnumTable, Value};

/// VP8's boolean entropy decoder: each bool is read with a probability
/// (out of 256) of being 0. Reading past the end continues with zeros
/// and is noted.
pub struct BoolDecoder<'a> {
    data: &'a [u8],
    /// The next byte to shift in.
    pos: usize,
    value: u32,
    range: u32,
    bits: u32,
    /// Bytes shifted in past the end.
    over: usize,
}

impl<'a> BoolDecoder<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        let mut d = BoolDecoder {
            data,
            pos: 0,
            value: 0,
            range: 255,
            bits: 0,
            over: 0,
        };
        d.value = (d.byte() << 8) | d.byte();
        d
    }

    fn byte(&mut self) -> u32 {
        let b = match self.data.get(self.pos) {
            Some(&b) => u32::from(b),
            None => {
                self.over = self.over.saturating_add(1);
                0
            }
        };
        self.pos = self.pos.saturating_add(1);
        b
    }

    /// A bool that is 0 with probability `prob / 256`.
    pub fn bool(&mut self, prob: u8) -> bool {
        let split =
            1u32.saturating_add(self.range.saturating_sub(1).saturating_mul(u32::from(prob)) >> 8);
        let big = split << 8;
        let one = self.value >= big;
        if one {
            self.range = self.range.saturating_sub(split);
            self.value = self.value.saturating_sub(big);
        } else {
            self.range = split;
        }
        while self.range < 128 {
            self.value <<= 1;
            self.range <<= 1;
            self.bits = self.bits.saturating_add(1);
            if self.bits == 8 {
                self.bits = 0;
                self.value |= self.byte();
            }
        }
        one
    }

    pub fn flag(&mut self) -> bool {
        self.bool(128)
    }

    /// `L(n)`: an n-bit unsigned literal, most significant bit first.
    pub fn literal(&mut self, n: u32) -> u32 {
        (0..n).fold(0, |v, _| (v << 1) | u32::from(self.flag()))
    }

    /// A magnitude of `n` bits, then a sign bit.
    pub fn signed(&mut self, n: u32) -> i32 {
        let magnitude = i32::try_from(self.literal(n)).unwrap_or(0);
        if self.flag() {
            magnitude.saturating_neg()
        } else {
            magnitude
        }
    }

    /// Bytes of the partition read so far (the decoder holds two ahead).
    pub fn consumed(&self) -> usize {
        self.pos.saturating_sub(2).min(self.data.len())
    }

    /// Whether the header ran past the partition's end.
    pub fn overran(&self) -> bool {
        self.over > 2
    }
}

/// `coeff_update_probs` (RFC 6386, section 13.4): the probability that
/// each of the 4 × 8 × 3 × 11 token probabilities is not updated.
#[rustfmt::skip]
const COEFF_UPDATE_PROBS: [[u8; 11]; 96] = [
    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [176, 246, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [223, 241, 252, 255, 255, 255, 255, 255, 255, 255, 255],
    [249, 253, 253, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 244, 252, 255, 255, 255, 255, 255, 255, 255, 255],
    [234, 254, 254, 255, 255, 255, 255, 255, 255, 255, 255],
    [253, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 246, 254, 255, 255, 255, 255, 255, 255, 255, 255],
    [239, 253, 254, 255, 255, 255, 255, 255, 255, 255, 255],
    [254, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 248, 254, 255, 255, 255, 255, 255, 255, 255, 255],
    [251, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 253, 254, 255, 255, 255, 255, 255, 255, 255, 255],
    [251, 254, 254, 255, 255, 255, 255, 255, 255, 255, 255],
    [254, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 254, 253, 255, 254, 255, 255, 255, 255, 255, 255],
    [250, 255, 254, 255, 254, 255, 255, 255, 255, 255, 255],
    [254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [217, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [225, 252, 241, 253, 255, 255, 254, 255, 255, 255, 255],
    [234, 250, 241, 250, 253, 255, 253, 254, 255, 255, 255],
    [255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [223, 254, 254, 255, 255, 255, 255, 255, 255, 255, 255],
    [238, 253, 254, 254, 255, 255, 255, 255, 255, 255, 255],
    [255, 248, 254, 255, 255, 255, 255, 255, 255, 255, 255],
    [249, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 253, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [247, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 253, 254, 255, 255, 255, 255, 255, 255, 255, 255],
    [252, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 254, 254, 255, 255, 255, 255, 255, 255, 255, 255],
    [253, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 254, 253, 255, 255, 255, 255, 255, 255, 255, 255],
    [250, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [186, 251, 250, 255, 255, 255, 255, 255, 255, 255, 255],
    [234, 251, 244, 254, 255, 255, 255, 255, 255, 255, 255],
    [251, 251, 243, 253, 254, 255, 254, 255, 255, 255, 255],
    [255, 253, 254, 255, 255, 255, 255, 255, 255, 255, 255],
    [236, 253, 254, 255, 255, 255, 255, 255, 255, 255, 255],
    [251, 253, 253, 254, 254, 255, 255, 255, 255, 255, 255],
    [255, 254, 254, 255, 255, 255, 255, 255, 255, 255, 255],
    [254, 254, 254, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [254, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [248, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [250, 254, 252, 254, 255, 255, 255, 255, 255, 255, 255],
    [248, 254, 249, 253, 255, 255, 255, 255, 255, 255, 255],
    [255, 253, 253, 255, 255, 255, 255, 255, 255, 255, 255],
    [246, 253, 253, 255, 255, 255, 255, 255, 255, 255, 255],
    [252, 254, 251, 254, 254, 255, 255, 255, 255, 255, 255],
    [255, 254, 252, 255, 255, 255, 255, 255, 255, 255, 255],
    [248, 254, 253, 255, 255, 255, 255, 255, 255, 255, 255],
    [253, 255, 254, 254, 255, 255, 255, 255, 255, 255, 255],
    [255, 251, 254, 255, 255, 255, 255, 255, 255, 255, 255],
    [245, 251, 254, 255, 255, 255, 255, 255, 255, 255, 255],
    [253, 253, 254, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 251, 253, 255, 255, 255, 255, 255, 255, 255, 255],
    [252, 253, 254, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 252, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [249, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 255, 253, 255, 255, 255, 255, 255, 255, 255, 255],
    [250, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
    [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
];

const COLOR_SPACE: EnumTable = &[(0, "YUV (ITU-R BT.601)"), (1, "reserved")];
const CLAMPING: EnumTable = &[(0, "required"), (1, "not needed")];
const FILTER_TYPE: EnumTable = &[(0, "normal"), (1, "simple")];
const SEGMENT_MODE: EnumTable = &[
    (0, "deltas from the frame's values"),
    (1, "absolute values"),
];
const REF_FRAMES: [&str; 4] = ["intra", "last frame", "golden frame", "altref frame"];
const MODES: [&str; 4] = ["B_PRED", "ZEROMV", "NEAREST/NEAR/NEWMV", "SPLITMV"];

/// What the frame header holds, as nodes, with the partition count and
/// a one-line summary.
pub struct FrameHeader {
    pub nodes: Vec<Node>,
    pub summary: String,
    pub partitions: u32,
    /// Bytes of the first partition the header takes (approximately: the
    /// decoder reads ahead).
    pub consumed: usize,
    pub overran: bool,
}

fn uint(name: &'static str, v: u32, bits: u8) -> Node {
    Node::new(name).value(val::uint(v, bits))
}

fn flag(name: &'static str, v: bool) -> Node {
    Node::new(name).value(Value::Bool(v))
}

/// An optional signed update: `None` if its flag is clear.
fn update(d: &mut BoolDecoder<'_>, bits: u32) -> Option<i32> {
    d.flag().then(|| d.signed(bits))
}

fn delta_node(name: String, v: Option<i32>) -> Node {
    match v {
        Some(v) => Node::new(name).value(val::int(v, 8)),
        None => Node::new(name).summary("not updated"),
    }
}

/// Decodes a key frame's header from the start of its first partition.
pub fn frame_header(data: &[u8]) -> FrameHeader {
    let mut d = BoolDecoder::new(data);
    let mut nodes = Vec::new();
    let color = d.literal(1);
    nodes.push(Node::new("Color space").value(val::enumv(color, 1, COLOR_SPACE)));
    let clamp = d.literal(1);
    nodes.push(
        Node::new("Clamping")
            .value(val::enumv(clamp, 1, CLAMPING))
            .desc("Whether the decoder must clamp reconstructed pixels to 0..255"),
    );
    let segmentation = d.flag();
    let mut seg = Node::new("Segmentation").value(Value::Bool(segmentation));
    if segmentation {
        seg = seg.desc("Macroblocks belong to one of four segments, each with its own quantizer and loop filter level");
        let mut kids = Vec::new();
        let map = d.flag();
        kids.push(flag("Update segment map", map));
        let data = d.flag();
        kids.push(flag("Update segment data", data));
        if data {
            let mode = d.literal(1);
            kids.push(Node::new("Segment values").value(val::enumv(mode, 1, SEGMENT_MODE)));
            for i in 0..4 {
                kids.push(delta_node(
                    format!("Quantizer, segment {i}"),
                    update(&mut d, 7),
                ));
            }
            for i in 0..4 {
                kids.push(delta_node(
                    format!("Loop filter level, segment {i}"),
                    update(&mut d, 6),
                ));
            }
        }
        if map {
            for i in 0..3 {
                let name = format!("Segment tree probability {i}");
                kids.push(if d.flag() {
                    Node::new(name).value(val::uint(d.literal(8), 8))
                } else {
                    Node::new(name)
                        .value(val::uint(255u32, 8))
                        .summary("default")
                });
            }
        }
        seg = seg.lazy(push_nodes, Arc::new(kids));
    }
    nodes.push(seg);
    let filter = d.literal(1);
    nodes.push(Node::new("Filter type").value(val::enumv(filter, 1, FILTER_TYPE)));
    let level = d.literal(6);
    let mut level_node = uint("Loop filter level", level, 6);
    if level == 0 {
        level_node = level_node.summary("no loop filter");
    }
    nodes.push(level_node);
    nodes.push(uint("Sharpness", d.literal(3), 3));
    let adjust = d.flag();
    let mut lf = Node::new("Loop filter adjustments")
        .value(Value::Bool(adjust))
        .desc("Per-macroblock loop filter level deltas by reference frame and prediction mode");
    if adjust {
        let changed = d.flag();
        let mut kids = vec![flag("Update deltas", changed)];
        if changed {
            for name in REF_FRAMES {
                kids.push(delta_node(format!("Delta, {name}"), update(&mut d, 6)));
            }
            for name in MODES {
                kids.push(delta_node(format!("Delta, {name}"), update(&mut d, 6)));
            }
        }
        lf = lf.lazy(push_nodes, Arc::new(kids));
    }
    nodes.push(lf);
    let partitions = 1u32 << d.literal(2);
    nodes.push(
        uint("Token partitions", partitions, 4)
            .desc("DCT coefficients are split by macroblock row over this many partitions, for parallel decoding"),
    );
    let q = d.literal(7);
    let mut quant = vec![uint("Y AC", q, 7)];
    for name in [
        "Y DC delta",
        "Y2 DC delta",
        "Y2 AC delta",
        "UV DC delta",
        "UV AC delta",
    ] {
        quant.push(delta_node(name.to_owned(), update(&mut d, 4)));
    }
    nodes.push(
        Node::new("Quantizer indices")
            .summary(format!("base {q} of 127"))
            .desc("Indices into the dequantization tables: Y AC, and deltas from it for the other coefficient groups; higher is coarser")
            .lazy(push_nodes, Arc::new(quant)),
    );
    nodes.push(flag("Refresh entropy probabilities", d.flag()));
    let mut updated = 0usize;
    for row in &COEFF_UPDATE_PROBS {
        for &p in row {
            if d.bool(p) {
                d.literal(8);
                updated = updated.saturating_add(1);
            }
        }
    }
    nodes.push(
        Node::new("Coefficient probability updates")
            .value(val::uint(u32::try_from(updated).unwrap_or(u32::MAX), 16))
            .summary("of 1056")
            .desc("Token probabilities replaced for this frame"),
    );
    let skip = d.flag();
    nodes.push(
        flag("Skip empty macroblocks", skip)
            .desc("Whether each macroblock says if it has no non-zero coefficients"),
    );
    if skip {
        nodes.push(
            uint("Probability a macroblock is not skipped", d.literal(8), 8).desc("Out of 256"),
        );
    }
    let filter_text = if level == 0 {
        "no loop filter".to_owned()
    } else {
        format!(
            "{} loop filter {level}",
            if filter == 0 { "normal" } else { "simple" }
        )
    };
    FrameHeader {
        summary: format!(
            "quantizer {q}, {filter_text}, {}{}",
            if partitions == 1 {
                "1 token partition".to_owned()
            } else {
                format!("{partitions} token partitions")
            },
            if segmentation { ", segmented" } else { "" }
        ),
        nodes,
        partitions,
        consumed: d.consumed(),
        overran: d.overran(),
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// RFC 6386's boolean encoder (section 7.3), flushed with zeros.
    struct Encoder {
        out: Vec<u8>,
        bottom: u32,
        range: u32,
        count: i32,
    }

    impl Encoder {
        fn new() -> Self {
            Encoder {
                out: Vec::new(),
                bottom: 0,
                range: 255,
                count: 24,
            }
        }

        fn carry(&mut self) {
            for b in self.out.iter_mut().rev() {
                if *b == 255 {
                    *b = 0;
                } else {
                    *b += 1;
                    break;
                }
            }
        }

        fn bool(&mut self, prob: u8, one: bool) {
            let split = 1 + (((self.range - 1) * u32::from(prob)) >> 8);
            if one {
                self.bottom = self.bottom.wrapping_add(split);
                self.range -= split;
            } else {
                self.range = split;
            }
            while self.range < 128 {
                self.range <<= 1;
                if self.bottom & (1 << 31) != 0 {
                    self.carry();
                }
                self.bottom <<= 1;
                self.count -= 1;
                if self.count == 0 {
                    self.out.push((self.bottom >> 24) as u8);
                    self.bottom &= (1 << 24) - 1;
                    self.count = 8;
                }
            }
        }

        fn literal(&mut self, n: u32, v: u32) {
            for i in (0..n).rev() {
                self.bool(128, (v >> i) & 1 == 1);
            }
        }

        fn signed(&mut self, n: u32, v: i32) {
            self.literal(n, v.unsigned_abs());
            self.bool(128, v < 0);
        }

        fn finish(mut self) -> Vec<u8> {
            for _ in 0..32 {
                self.bool(128, false);
            }
            self.out
        }
    }

    #[test]
    fn a_header_with_segments_and_partitions_reads_back() {
        let mut e = Encoder::new();
        e.literal(2, 0); // color space, clamping
        e.literal(1, 1); // segmentation
        e.literal(1, 0); // no map update
        e.literal(1, 1); // data update
        e.literal(1, 0); // deltas
        for q in [Some(-5), None, Some(12), None] {
            e.literal(1, u32::from(q.is_some()));
            if let Some(q) = q {
                e.signed(7, q);
            }
        }
        for _ in 0..4 {
            e.literal(1, 0);
        }
        e.literal(1, 1); // simple filter
        e.literal(6, 20);
        e.literal(3, 2);
        e.literal(1, 0); // no loop filter adjustments
        e.literal(2, 2); // four token partitions
        e.literal(7, 60);
        for d in [None, None, None, None, Some(3)] {
            e.literal(1, u32::from(d.is_some()));
            if let Some(d) = d {
                e.signed(4, d);
            }
        }
        e.literal(1, 1); // refresh entropy probabilities
        for (i, row) in COEFF_UPDATE_PROBS.iter().enumerate() {
            for (j, &p) in row.iter().enumerate() {
                let update = i == 5 && j < 2;
                e.bool(p, update);
                if update {
                    e.literal(8, 99);
                }
            }
        }
        e.literal(1, 1);
        e.literal(8, 200);
        let data = e.finish();
        let h = frame_header(&data);
        assert_eq!(h.partitions, 4);
        assert!(!h.overran);
        assert_eq!(
            h.summary,
            "quantizer 60, simple loop filter 20, 4 token partitions, segmented"
        );
        let names: Vec<_> = h.nodes.iter().map(|n| n.name.to_string()).collect();
        assert_eq!(
            names.last().map(String::as_str),
            Some("Probability a macroblock is not skipped")
        );
        let updates = h
            .nodes
            .iter()
            .find(|n| n.name == "Coefficient probability updates")
            .and_then(|n| n.value.clone());
        assert_eq!(updates, Some(val::uint(2u32, 16)));
    }
}
