//! WavPack: a sequence of `wvpk` blocks, each a 32-byte header (sizes,
//! sample counts, flags with the sample rate index, CRC) followed by
//! metadata sub-blocks; APE/ID3v1 tags may follow.

use crate::bytes::u32_le;
use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::audio::ape::trailing_tags;
use crate::formats::util::sound::{duration_of, leaf};
use crate::formats::{Format, Input, Probe, embedded};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, field, flag};

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "wavpack",
    title: "WavPack",
    extensions: &["wv", "wvc"],
    mime: "audio/x-wavpack",
    probe: Probe::Custom(|h| {
        h.starts_with(b"wvpk")
            && crate::bytes::u16_le(h.data, 8).is_some_and(|v| (0x402..=0x410).contains(&v))
    }),
    dissect: crate::expander!(dissect: Input),
};

const RATES: [u32; 15] = [
    6000, 8000, 9600, 11025, 12000, 16000, 22050, 24000, 32000, 44100, 48000, 64000, 88200, 96000,
    192000,
];

const FLAGS: FlagTable = &[
    field(0x3, 0x0, "1_BYTE"),
    field(0x3, 0x1, "2_BYTES"),
    field(0x3, 0x2, "3_BYTES"),
    field(0x3, 0x3, "4_BYTES"),
    flag(0x4, "MONO"),
    flag(0x8, "HYBRID"),
    flag(0x10, "JOINT_STEREO"),
    flag(0x20, "CROSS_DECORRELATION"),
    flag(0x40, "HYBRID_NOISE_SHAPING"),
    flag(0x80, "FLOAT"),
    flag(0x100, "INT32"),
    flag(0x200, "HYBRID_BITRATE"),
    flag(0x400, "HYBRID_BALANCE"),
    flag(0x800, "INITIAL_BLOCK"),
    flag(0x1000, "FINAL_BLOCK"),
    flag(0x1000_0000, "IIR"),
    flag(0x2000_0000, "FALSE_STEREO"),
    flag(0x8000_0000, "DSD"),
];

const SUB_BLOCK: EnumTable = &[
    (0x00, "dummy"),
    (0x01, "encoder info"),
    (0x02, "decorrelation terms"),
    (0x03, "decorrelation weights"),
    (0x04, "decorrelation samples"),
    (0x05, "entropy variables"),
    (0x06, "hybrid profile"),
    (0x07, "shaping weights"),
    (0x08, "float info"),
    (0x09, "int32 info"),
    (0x0a, "WavPack bitstream"),
    (0x0b, "correction bitstream"),
    (0x0c, "extension bitstream"),
    (0x0d, "channel info"),
    (0x0e, "DSD block"),
    (0x21, "RIFF header"),
    (0x22, "RIFF trailer"),
    (0x23, "alternate header"),
    (0x24, "alternate trailer"),
    (0x25, "configuration"),
    (0x26, "MD5 checksum"),
    (0x27, "sample rate"),
    (0x28, "alternate extension"),
    (0x29, "alternate MD5"),
    (0x2a, "new configuration"),
    (0x2b, "channel identities"),
    (0x2f, "block checksum"),
];

record! {
    pub struct BlockHeader {
        id: ascii[4] "ID",
        size: u32 "Block size" .desc("Bytes after this field"),
        version: u16 "Version" .hex(),
        index_high: u8 "Block index (high bits)",
        total_high: u8 "Total samples (high bits)",
        total: u32 "Total samples" .desc("0xffffffff = unknown"),
        index: u32 "Block index" .desc("Index of the first sample in this block"),
        samples: u32 "Block samples",
        flags: u32 "Flags" .hex() .with(|&f, n| n.summary(describe_flags(f))),
        crc: u32 "CRC" .hex(),
    }
}

/// Flag names plus the numeric sub-fields (shift, magnitude, rate index).
fn describe_flags(f: u32) -> String {
    let (names, _) = crate::value::decode_flags(FLAGS, u64::from(f & !0x07ff_e000));
    let rate = RATES
        .get(crate::bytes::to_usize(((f >> 23) & 0xf).into()))
        .map_or_else(|| "custom rate".to_owned(), |r| format!("{r} Hz"));
    format!(
        "{}; shift {}, magnitude {}, {rate}",
        names.join(" | "),
        (f >> 13) & 0x1f,
        (f >> 18) & 0x1f
    )
}

impl BlockHeader {
    fn rate(&self) -> Option<u32> {
        RATES
            .get(crate::bytes::to_usize(((self.flags >> 23) & 0xf).into()))
            .copied()
    }

    fn describe(&self) -> String {
        let bytes = (self.flags & 3).saturating_add(1);
        let kind = if self.flags & 0x80 != 0 {
            "float".to_owned()
        } else {
            format!("{}-bit", bytes.saturating_mul(8))
        };
        format!(
            "{}{}, {kind}, {}",
            self.rate()
                .map_or_else(|| "custom".to_owned(), |r| r.to_string()),
            if self.rate().is_some() {
                " Hz"
            } else {
                " rate"
            },
            if self.flags & 4 != 0 {
                "mono"
            } else {
                "stereo"
            }
        )
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (end, tags) = trailing_tags(&cx, input).await?;
    let first = parse(
        &cx,
        file.sub(0, BlockHeader::SIZE),
        LE,
        &(),
        BlockHeader::layout,
    )
    .await?;
    let total = if first.total == u32::MAX {
        None
    } else {
        Some(u64::from(first.total) | (u64::from(first.total_high) << 32))
    };
    let mut line = format!("WavPack {}", first.describe());
    if first.flags & 0x8 != 0 {
        line.push_str(", hybrid (lossy)");
    } else {
        line.push_str(", lossless");
    }
    if let (Some(n), Some(rate)) = (total, first.rate())
        && let Some(d) = duration_of(n, rate.into())
    {
        line.push_str(&format!(", {d}"));
    }
    cx.annotate(line);
    let blocks = file.sub(0, end);
    cx.emit(
        Node::new("Blocks")
            .span(blocks)
            .summary(format!("{} bytes", blocks.len))
            .lazy(list_blocks, (input, blocks)),
    );
    for node in tags {
        cx.emit(node);
    }
    Ok(())
}

async fn list_blocks(cx: Cx, (input, region): (Input, Span)) -> Result<()> {
    let mut pos = 0u64;
    let mut index = 0u64;
    while region.len.saturating_sub(pos) >= BlockHeader::SIZE {
        let head = parse(
            &cx,
            region.sub(pos, BlockHeader::SIZE),
            LE,
            &(),
            BlockHeader::layout,
        )
        .await?;
        if head.id != "wvpk" {
            cx.emit(
                Node::new("Unparsed data")
                    .span(region.tail(pos))
                    .diag(Diagnostic::malformed("expected a wvpk block")),
            );
            return Ok(());
        }
        let len = u64::from(head.size).saturating_add(8);
        let span = region.sub(pos, len);
        let mut node = Node::new(format!("Block {index}"))
            .span(span)
            .summary(format!(
                "samples {}..{}, {}",
                head.index,
                u64::from(head.index).saturating_add(head.samples.into()),
                head.describe()
            ));
        if span.len < len {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, len),
                span.len,
            ));
        }
        cx.push(node.lazy(block, (input, span))).await;
        pos = pos.saturating_add(len.max(BlockHeader::SIZE));
        index = index.saturating_add(1);
    }
    if pos < region.len {
        cx.emit(Node::new("Trailing bytes").span(region.tail(pos)));
    }
    Ok(())
}

async fn block(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    cx.emit(BlockHeader::node(
        "Header",
        span.sub(0, BlockHeader::SIZE),
        LE,
    ));
    let mut cur = Cursor::new(&cx, span.tail(BlockHeader::SIZE), LE);
    while !cur.at_end() {
        let start = cur.pos();
        let id = cur.u8().await?;
        let words = if id & 0x80 != 0 {
            let b = cur.bytes(3).await?;
            u64::from(crate::bytes::u24_le(&b, 0).unwrap_or(0))
        } else {
            u64::from(cur.u8().await?)
        };
        let len = words.saturating_mul(2);
        let header_len = cur.pos().saturating_sub(start);
        let data = cur.span(len);
        cur.skip(len);
        let function = id & 0x3f;
        let real = if id & 0x40 != 0 {
            len.saturating_sub(1)
        } else {
            len
        };
        let name = crate::value::lookup(SUB_BLOCK, function.into()).map_or_else(
            || format!("Sub-block {function:#04x}"),
            |n| {
                let mut s = n.to_owned();
                if let Some(c) = s.get(..1) {
                    s = c.to_uppercase() + s.get(1..).unwrap_or_default();
                }
                s
            },
        );
        let node = Node::new(name)
            .span(cur.since(start))
            .value(crate::formats::util::sound::hex(id, 8))
            .summary(format!("{real} bytes"));
        let state = (
            input,
            cur.since(start),
            header_len,
            data.sub(0, real),
            function,
        );
        cx.emit(node.lazy(sub_block, state));
        cx.checkpoint().await;
    }
    Ok(())
}

async fn sub_block(
    cx: Cx,
    (input, span, header_len, data, function): (Input, Span, u64, Span, u8),
) -> Result<()> {
    let head = cx.read(span.sub(0, header_len)).await?;
    let id = head.first().copied().unwrap_or(0);
    cx.emit(
        leaf(
            "ID",
            span.sub(0, 1),
            crate::formats::util::sound::hex(id, 8),
        )
        .summary(format!(
            "function {:#04x}{}{}",
            id & 0x3f,
            if id & 0x40 != 0 { ", odd size" } else { "" },
            if id & 0x80 != 0 { ", large" } else { "" }
        )),
    );
    cx.emit(leaf(
        "Size (words)",
        span.sub(1, header_len.saturating_sub(1)),
        crate::formats::util::sound::uint(
            if id & 0x80 != 0 {
                crate::bytes::u24_le(&head, 1).unwrap_or(0)
            } else {
                head.get(1).copied().unwrap_or(0).into()
            },
            24,
        ),
    ));
    match function {
        0x21 | 0x23 => cx.emit(embedded("Original header", input.nested(data))),
        0x27 => {
            let raw = cx.read_avail(data.sub(0, 4)).await?;
            let mut b = raw.clone();
            b.resize(4, 0);
            cx.emit(leaf(
                "Sample rate",
                data,
                crate::formats::util::sound::uint(u32_le(&b, 0).unwrap_or(0), 32),
            ));
        }
        _ => cx.emit(Node::new("Data").span(data)),
    }
    Ok(())
}
