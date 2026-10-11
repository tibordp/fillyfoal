//! Audio dissectors charge for the checksums they compute: a large TTA
//! frame is hashed in paced steps, not in one poll.

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
