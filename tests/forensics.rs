//! Forensic artefacts: logs that can be huge and mostly empty (a sparse
//! lastlog indexed by UID) are walked in bounded, proportionate steps, and
//! ring-buffer logs that have wrapped are summarised from their oldest
//! record.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::Host;
use fillyfoal::{Limits, NodeId, Progress, formats};

/// Polls `id` with budgets of `budget` until it settles, answering byte
/// requests; returns how many polls yielded.
fn poll_steps(host: &mut Host, id: NodeId, budget: u64) -> u32 {
    let mut yields = 0;
    for _ in 0..1_000_000 {
        match host.session.poll_node(id, budget) {
            Progress::Idle => return yields,
            Progress::Yielded => yields += 1,
            Progress::NeedSecret(_) => panic!("no secrets here"),
            Progress::NeedBytes(requests) => host.supply(requests),
        }
    }
    panic!("did not settle");
}

fn child_names(host: &Host, id: NodeId) -> Vec<String> {
    let children = host.session.children(id).unwrap();
    children
        .ids
        .iter()
        .map(|&c| host.session.node(c).unwrap().name.to_string())
        .collect()
}

fn lastlog_record(t: u32, line: &str, host: &str) -> Vec<u8> {
    let mut r = vec![0u8; 292];
    r[..4].copy_from_slice(&t.to_le_bytes());
    r[4..4 + line.len()].copy_from_slice(line.as_bytes());
    r[36..36 + host.len()].copy_from_slice(host.as_bytes());
    r
}

#[test]
fn a_sparse_lastlog_is_read_in_windows() {
    // 120,000 UIDs (35 MB), logins only for UID 0 and the last UID.
    let n = 120_000usize;
    let mut data = vec![0u8; n * 292];
    data[..292].copy_from_slice(&lastlog_record(1_700_000_000, "tty1", ""));
    data[(n - 1) * 292..].copy_from_slice(&lastlog_record(1_700_000_100, "pts/0", "10.0.0.2"));
    let format = formats::by_name("lastlog").unwrap();
    let mut host = Host::open("lastlog", data, Limits::default(), Some(format));
    let root = host.root;
    host.session.expand(root, 100);
    let yields = poll_steps(&mut host, root, 5_000);
    // Reading 35 MB costs about 8,600 units; one read per record cost
    // about 120,000.
    assert!(yields <= 4, "{yields} steps");
    assert_eq!(child_names(&host, root), ["UID 0", "UID 119999"]);
}

/// The external `fillyfoal.evtx` (4 chunks: records 1–181, 182–360,
/// 361–540, 541–600) with its chunk ring wrapped: physical order
/// [c2, c3, c0, c1], first chunk 2, last chunk 1, header CRC fixed.
fn rotated_evtx() -> Vec<u8> {
    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/external/evtx/fillyfoal.evtx"
    ))
    .unwrap();
    let (block, chunk) = (0x1000, 0x10000);
    let mut out = data[..block].to_vec();
    out[8..16].copy_from_slice(&2u64.to_le_bytes());
    out[16..24].copy_from_slice(&1u64.to_le_bytes());
    out[0x2a..0x2c].copy_from_slice(&4u16.to_le_bytes());
    let crc = fillyfoal::codec::crc32(&out[..120]);
    out[0x7c..0x80].copy_from_slice(&crc.to_le_bytes());
    for i in [2, 3, 0, 1] {
        out.extend_from_slice(&data[block + i * chunk..block + (i + 1) * chunk]);
    }
    out
}

#[test]
fn a_wrapped_evtx_counts_records_from_its_first_chunk() {
    let mut host = Host::named("rotated.evtx", rotated_evtx(), Limits::default());
    host.explore(host.root, 1, 1000);
    let root = host.session.node(host.root).unwrap();
    let summary = root.summary.clone().unwrap_or_default();
    assert!(summary.contains("records 1–600 (600 events)"), "{summary}");
}
