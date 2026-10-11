//! Audio: checksums are charged (a large TTA frame is hashed in paced
//! steps, not in one poll), and files behind an ID3v2 tag too long for the
//! probes to see past are still dissected as their own format.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::Host;
use fillyfoal::codec::crc32;
use fillyfoal::{Limits, NodeId, Progress};

/// Expands `id` and polls it with `budget` units at a time until it
/// settles, answering byte requests; returns how many polls yielded.
fn yields_expanding(host: &mut Host, id: NodeId, budget: u64) -> u32 {
    host.session.expand(id, 100);
    let mut yields = 0;
    for _ in 0..100_000 {
        match host.session.poll_node(id, budget) {
            Progress::Idle => return yields,
            Progress::Yielded => yields += 1,
            Progress::NeedSecret(_) => panic!("unexpected secret request"),
            Progress::NeedBytes(requests) => host.supply(requests),
        }
    }
    panic!("did not settle");
}

/// A TTA file of one frame of `frame` bytes (CRC included).
fn tta_one_frame(frame: u32) -> Vec<u8> {
    let rate = 44_100u32;
    let samples = rate * 256 / 245; // exactly one frame
    let mut h = b"TTA1".to_vec();
    h.extend(1u16.to_le_bytes());
    h.extend(2u16.to_le_bytes());
    h.extend(16u16.to_le_bytes());
    h.extend(rate.to_le_bytes());
    h.extend(samples.to_le_bytes());
    let crc = crc32(&h);
    h.extend(crc.to_le_bytes());
    let seek = frame.to_le_bytes();
    h.extend(seek);
    h.extend(crc32(&seek).to_le_bytes());
    let body: Vec<u8> = (0..frame - 4).map(|i| (i % 251) as u8).collect();
    let crc = crc32(&body);
    h.extend(body);
    h.extend(crc.to_le_bytes());
    h
}

#[test]
fn tta_frame_crc_is_hashed_in_steps() {
    let mut host = Host::named("big.tta", tta_one_frame(1 << 20), Limits::default());
    let root = host.root;
    host.explore(root, 1, 100);
    let frames = host.child(root, "Frames").expect("frames");
    host.explore(frames, 1, 100);
    let frame = host.child(frames, "Frame 0").expect("frame");
    // Reading the MiB costs about 256 units; hashing it about 1024 more.
    let yields = yields_expanding(&mut host, frame, 300);
    assert!(yields >= 3, "{yields} yields");
    let crc = host.child(frame, "CRC").expect("crc");
    assert_eq!(
        host.session.node(crc).unwrap().summary.as_deref(),
        Some("valid")
    );
}

/// An ID3v2.3 tag of `len` bytes: a title frame, then padding.
fn id3_tag(len: usize) -> Vec<u8> {
    let mut frames = b"TIT2".to_vec();
    frames.extend(5u32.to_be_bytes());
    frames.extend([0, 0, 0]);
    frames.extend(b"Tone");
    frames.resize(len - 10, 0);
    let n = frames.len() as u32;
    let mut tag = b"ID3\x03\x00\x00".to_vec();
    tag.extend([
        (n >> 21) as u8 & 0x7f,
        (n >> 14) as u8 & 0x7f,
        (n >> 7) as u8 & 0x7f,
        n as u8 & 0x7f,
    ]);
    tag.extend(frames);
    tag
}

#[test]
fn audio_behind_a_long_id3_tag_is_dissected_as_itself() {
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    for (path, annotation) in [
        ("external/flac/tone.flac", "FLAC, "),
        ("external/aac/tone.aac", "AAC LC, "),
        ("external/tta/tone.tta", "TTA 16-bit"),
        ("external/wavpack/tone.wv", "WavPack 16-bit"),
        ("synthetic/ape/tone.ape", "Monkey's Audio"),
        ("synthetic/musepack/tone.mpc", "Musepack SV8"),
        ("external/mp3/layer2.mp2", "MPEG-2 Layer II"),
    ] {
        // Longer than the probes' head, as cover art often makes it.
        let mut data = id3_tag(100_000);
        data.extend(std::fs::read(fixtures.join(path)).unwrap());
        let mut host = Host::named("tagged", data, Limits::default());
        let root = host.root;
        host.explore(root, 1, 100);
        let node = host.session.node(root).unwrap();
        let summary = node.summary.clone().unwrap_or_default();
        assert!(summary.starts_with(annotation), "{path}: {summary}");
        assert!(host.child(root, "ID3v2 tag").is_some(), "{path}");
        assert!(host.child(root, "Data").is_none(), "{path}");
        assert!(
            common::diagnostics(&host).is_empty(),
            "{path}: {:?}",
            common::diagnostics(&host)
        );
    }
}
