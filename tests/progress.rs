//! Progress reporting: what a host sees while an expansion runs, whether or
//! not the dissector reports progress itself (`Session::activity`,
//! `Session::progress`, `Session::read_activity`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::Host;
use fillyfoal::codec::Codec;
use fillyfoal::{
    Activity, ChildState, Cx, Limits, Node, NodeId, Progress, ReadProgress, Result, SourceId, Span,
    Value,
};

/// Decoded length of `tests/data/lazy/big.zlib`.
const BIG_LEN: u64 = 64 << 20;

fn big_zlib() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/lazy/big.zlib"
    ))
    .unwrap()
}

/// A zlib stream of stored blocks holding `data`.
fn zlib_stored(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x78, 0x01];
    let blocks: Vec<&[u8]> = data.chunks(65_535).collect();
    for (i, block) in blocks.iter().enumerate() {
        out.push(u8::from(i + 1 == blocks.len()));
        let len = block.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(block);
    }
    out.extend_from_slice(&fillyfoal::codec::adler32(data).to_be_bytes());
    out
}

fn file_span(data: &[u8]) -> Span {
    Span::new(SourceId::default_host(), 0, data.len() as u64)
}

/// Polls `id` with `budget` until it is idle, answering byte requests, and
/// calls `seen` with its activity after every poll that leaves it running
/// (checking that `Session::progress` is its estimate).
fn drive(host: &mut Host, id: NodeId, budget: u64, mut seen: impl FnMut(&Activity)) {
    let mut polls = 0u64;
    loop {
        polls += 1;
        assert!(polls < 1_000_000, "no end in sight");
        match host.session.poll_node(id, budget) {
            Progress::Idle => break,
            Progress::NeedBytes(requests) => host.supply(requests),
            Progress::Yielded => {}
            Progress::NeedSecret(_) => panic!("no secrets here"),
        }
        if let Some(activity) = host.session.activity(id) {
            assert_eq!(host.session.progress(id), activity.estimate());
            seen(&activity);
        }
    }
}

/// Checks that estimates never decrease, and returns them.
#[derive(Default)]
struct Rising {
    estimates: Vec<(u64, u64)>,
}

impl Rising {
    fn push(&mut self, estimate: (u64, u64)) {
        if let Some(&(done, total)) = self.estimates.last() {
            assert_eq!(total, estimate.1, "the measure changed");
            assert!(
                estimate.0 >= done,
                "progress went back: {done} -> {}",
                estimate.0
            );
        }
        self.estimates.push(estimate);
    }

    /// Distinct values seen.
    fn steps(&self) -> usize {
        let mut v: Vec<u64> = self.estimates.iter().map(|e| e.0).collect();
        v.dedup();
        v.len()
    }
}

fn host_for(data: Vec<u8>) -> Host {
    let mut host = Host::new(data, Limits::default());
    host.max_polls = 10_000_000;
    host
}

fn emitted_bytes(host: &Host, id: NodeId) -> Vec<u8> {
    let c = host.session.children(id).unwrap();
    assert_eq!(c.state, ChildState::Complete, "{:?}", c.error);
    match host.session.node(c.ids[0]).unwrap().value.clone() {
        Some(Value::Bytes(b)) => b,
        other => panic!("{other:?}"),
    }
}

/// Reads 16 bytes far into the stream decoded with `codec`, of recorded
/// length `len` (`None`: unsized).
async fn far_read(cx: Cx, (file, codec, len): (Span, Codec, Option<u64>)) -> Result<()> {
    let s = match len {
        Some(len) => cx.decode_lazy(file, &codec, len)?,
        None => cx.decode_lazy_unsized(file, &codec)?,
    };
    let bytes = cx.read(s.sub(BIG_LEN - 16, 16)).await?;
    cx.emit(Node::new("end").value(Value::Bytes(bytes)));
    Ok(())
}

/// An expansion stuck in a far read into a lazily decoded stream cannot
/// report progress itself; the session reports how far the decoding it
/// waits on has got, rising to the end.
#[test]
fn far_read_reports_decoding_progress() {
    let data = big_zlib();
    let file = file_span(&data);
    let mut host = host_for(data);
    let root = host
        .session
        .add_root(Node::new("far").lazy(far_read, (file, Codec::Zlib, Some(BIG_LEN))));
    host.session.expand(root, 1);
    let mut rising = Rising::default();
    let mut polls = 0;
    drive(&mut host, root, 1000, |a| {
        polls += 1;
        assert_eq!(a.reported, None);
        assert_eq!(a.decoding.len(), 1, "{a:?}");
        let d = &a.decoding[0];
        assert_eq!(d.codec, "zlib");
        assert_eq!(d.len, Some(BIG_LEN));
        assert_eq!(d.target, BIG_LEN);
        rising.push(a.estimate().expect("an estimate while decoding"));
    });
    assert!(polls >= 10, "decoded in {polls} polls");
    assert!(rising.steps() >= 10, "{:?}", rising.estimates);
    let &(done, total) = rising.estimates.last().unwrap();
    assert_eq!(total, BIG_LEN);
    assert!(done > BIG_LEN / 2, "{done}");
    assert_eq!(emitted_bytes(&host, root).len(), 16);
    assert_eq!(host.session.progress(root), None, "finished");
}

/// The same with a stream whose decoded size nothing records: its length is
/// a provisional upper bound, so the estimate is the encoded bytes consumed.
#[test]
fn unsized_stream_reports_encoded_consumption() {
    let data = big_zlib();
    let encoded = data.len() as u64;
    let file = file_span(&data);
    let mut host = host_for(data);
    let root = host
        .session
        .add_root(Node::new("far").lazy(far_read, (file, Codec::Zlib, None)));
    host.session.expand(root, 1);
    let mut rising = Rising::default();
    drive(&mut host, root, 1000, |a| {
        let d = &a.decoding[0];
        assert_eq!(d.len, None);
        assert!(d.encoded_len_known);
        assert_eq!(d.encoded_len, encoded);
        rising.push(a.estimate().expect("an estimate while decoding"));
    });
    assert!(rising.steps() >= 10, "{:?}", rising.estimates);
    assert!(rising.estimates.iter().all(|&(_, total)| total == encoded));
    assert_eq!(emitted_bytes(&host, root).len(), 16);
}

/// Reads far into a zlib stream that is itself the content of a stored
/// zlib stream.
async fn nested_read(cx: Cx, (file, inner_len): (Span, u64)) -> Result<()> {
    let outer = cx.decode_lazy(file, &Codec::Zlib, inner_len)?;
    let inner = cx.decode_lazy(outer, &Codec::Zlib, BIG_LEN)?;
    let bytes = cx.read(inner.sub(BIG_LEN - 16, 16)).await?;
    cx.emit(Node::new("end").value(Value::Bytes(bytes)));
    Ok(())
}

/// A read into a stream inside a decoded stream waits on both: the chain
/// lists them outermost first, and the estimate follows the inner one.
#[test]
fn nested_streams_report_the_chain_outermost_first() {
    let inner = big_zlib();
    let inner_len = inner.len() as u64;
    let data = zlib_stored(&inner);
    let file = file_span(&data);
    let mut host = host_for(data);
    let root = host
        .session
        .add_root(Node::new("nested").lazy(nested_read, (file, inner_len)));
    host.session.expand(root, 1);
    let mut rising = Rising::default();
    let mut both = 0;
    drive(&mut host, root, 1000, |a| {
        assert!(!a.decoding.is_empty());
        let last = a.decoding.last().unwrap();
        assert_eq!(last.len, Some(BIG_LEN), "the inner stream is last");
        if let [outer, inner] = a.decoding.as_slice() {
            both += 1;
            assert_eq!(outer.len, Some(inner_len));
            assert_eq!(outer.encoded_len, file.len);
            assert_ne!(outer.source, inner.source);
            assert_eq!(inner.encoded_len, inner_len);
        }
        rising.push(a.estimate().unwrap());
    });
    assert!(both > 0, "never saw both streams");
    assert_eq!(rising.estimates.last().unwrap().1, BIG_LEN);
    assert_eq!(emitted_bytes(&host, root).len(), 16);
}

/// Reports progress itself, then does a far read.
async fn reporting_read(cx: Cx, file: Span) -> Result<()> {
    cx.progress(1, 3);
    let s = cx.decode_lazy(file, &Codec::Zlib, BIG_LEN)?;
    let bytes = cx.read(s.sub(BIG_LEN - 16, 16)).await?;
    cx.emit(Node::new("end").value(Value::Bytes(bytes)));
    Ok(())
}

/// What a dissector reports comes first: it knows its work best.
#[test]
fn reported_progress_keeps_priority() {
    let data = big_zlib();
    let file = file_span(&data);
    let mut host = host_for(data);
    let root = host
        .session
        .add_root(Node::new("reporting").lazy(reporting_read, file));
    host.session.expand(root, 1);
    let mut seen = 0;
    drive(&mut host, root, 1000, |a| {
        seen += 1;
        assert_eq!(a.reported, Some((1, 3)));
        assert_eq!(a.estimate(), Some((1, 3)));
        assert_eq!(a.decoding.len(), 1, "the decoding is still shown");
    });
    assert!(seen >= 10);
}

/// Reads its span sequentially in 4 KiB pieces, never reporting progress.
async fn silent_walk(cx: Cx, file: Span) -> Result<()> {
    let mut sum = 0u64;
    let mut pos = 0;
    while pos < file.len {
        let piece = cx.read(file.sub(pos, 4096)).await?;
        sum = piece.iter().fold(sum, |s, &b| s.wrapping_add(u64::from(b)));
        pos += piece.len() as u64;
    }
    cx.emit(Node::new("sum").value(Value::UInt {
        value: sum,
        bits: 64,
        radix: fillyfoal::Radix::Dec,
    }));
    Ok(())
}

/// A walker that never reports still shows progress: where it last read,
/// within the node's span.
#[test]
fn silent_walker_gets_read_position_progress() {
    let data: Vec<u8> = (0..(4u32 << 20)).map(|i| (i % 251) as u8).collect();
    // The node covers the second half of the file.
    let half = data.len() as u64 / 2;
    let span = Span::new(SourceId::default_host(), half, half);
    let mut host = host_for(data);
    let root = host
        .session
        .add_root(Node::new("walk").span(span).lazy(silent_walk, span));
    host.session.expand(root, 1);
    let mut rising = Rising::default();
    drive(&mut host, root, 50, |a| {
        assert_eq!(a.reported, None);
        assert!(a.decoding.is_empty());
        if let Some(estimate) = a.estimate() {
            assert_eq!(a.reading.unwrap().extent, Some(span));
            rising.push(estimate);
        }
    });
    assert!(rising.steps() >= 10, "{:?}", rising.estimates);
    assert!(rising.estimates.iter().all(|&(_, total)| total == half));
    assert!(rising.estimates.last().unwrap().0 > half / 2);
}

/// Emits one node spanning the lazily decoded stream.
async fn stream(cx: Cx, file: Span) -> Result<()> {
    let s = cx.decode_lazy(file, &Codec::Zlib, BIG_LEN)?;
    cx.emit(Node::new("stream").span(s));
    Ok(())
}

/// A host's own bounded reads (`read_step`) show the decoding they wait on.
#[test]
fn read_step_exposes_the_decode_chain() {
    let data = big_zlib();
    let file = file_span(&data);
    let mut host = host_for(data);
    let root = host.session.add_root(Node::new("big").lazy(stream, file));
    host.session.expand(root, 1);
    host.run();
    let child = host.session.children(root).unwrap().ids[0];
    let tail = host
        .session
        .node(child)
        .unwrap()
        .span
        .unwrap()
        .sub(BIG_LEN - 16, 16);
    let mut rising = Rising::default();
    loop {
        match host.session.read_step(tail, 1000) {
            ReadProgress::Done(data) => {
                assert_eq!(data.len(), 16);
                break;
            }
            ReadProgress::NeedBytes(requests) => host.supply(requests),
            ReadProgress::Yielded => {}
        }
        let chain = host.session.read_activity();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].codec, "zlib");
        assert_eq!(chain[0].target, BIG_LEN);
        rising.push(chain[0].estimate().unwrap());
        assert!(rising.estimates.len() < 1_000_000);
    }
    assert!(rising.steps() >= 10, "{:?}", rising.estimates);
    assert!(host.session.read_activity().is_empty(), "the read finished");
}

/// A zstd frame of `blocks` one-byte raw blocks, with no content size.
fn zstd_many_blocks(blocks: usize) -> Vec<u8> {
    let mut out = 0xfd2f_b528u32.to_le_bytes().to_vec();
    out.push(0x00); // FHD: no content size, window descriptor follows
    out.push(0x58); // Window_Descriptor
    for i in 0..blocks {
        let last = u32::from(i + 1 == blocks);
        let header = last | (1 << 3); // raw block of one byte
        out.extend_from_slice(&header.to_le_bytes()[..3]);
        out.push((i % 251) as u8);
    }
    out
}

/// The zstd listing walks every block of a frame to find its end; a single
/// frame can be most of a large file, so the walk reports as it goes.
#[test]
fn zstd_single_frame_walk_reports_rising_progress() {
    let data = zstd_many_blocks(100_000);
    let len = data.len() as u64;
    let mut host = Host::named("one-frame.zst", data, Limits::default());
    host.max_polls = 10_000_000;
    let root = host.root;
    host.session.expand(root, 10);
    let mut reported = Rising::default();
    drive(&mut host, root, 2000, |a| {
        if let Some(r) = a.reported {
            reported.push(r);
        }
    });
    assert!(reported.steps() >= 10, "{:?}", reported.estimates);
    assert!(reported.estimates.iter().all(|&(_, total)| total == len));
    assert!(reported.estimates.last().unwrap().0 > len / 2);
    let names: Vec<String> = host
        .session
        .children(root)
        .unwrap()
        .ids
        .iter()
        .map(|&c| host.session.node(c).unwrap().name.to_string())
        .collect();
    assert_eq!(names, ["Decompressed", "Frame 0"]);
}
