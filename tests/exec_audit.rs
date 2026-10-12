//! Executable and object formats keep their work and memory bounded on
//! crafted inputs.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::Host;
use fillyfoal::{ChildState, Limits};

/// An OMF object: THEADR, `n` COMENT records, MODEND.
fn omf_comments(n: usize) -> Vec<u8> {
    fn record(out: &mut Vec<u8>, kind: u8, body: &[u8]) {
        let start = out.len();
        out.push(kind);
        out.extend_from_slice(&((body.len() + 1) as u16).to_le_bytes());
        out.extend_from_slice(body);
        let sum = out[start..].iter().fold(0u8, |a, &b| a.wrapping_add(b));
        out.push(sum.wrapping_neg());
    }
    let mut out = Vec::new();
    record(&mut out, 0x80, b"\x05t.asm");
    for _ in 0..n {
        record(&mut out, 0x88, b"\x00\x00hi");
    }
    record(&mut out, 0x8a, b"\x00");
    out
}

/// A JKS key store of `n` trusted-certificate entries (version 2, tiny
/// placeholder certificates) and a digest.
fn jks_entries(n: usize) -> Vec<u8> {
    let mut out = b"\xfe\xed\xfe\xed".to_vec();
    out.extend_from_slice(&2u32.to_be_bytes());
    out.extend_from_slice(&(n as u32).to_be_bytes());
    for i in 0..n {
        out.extend_from_slice(&2u32.to_be_bytes());
        let alias = format!("cert{i}");
        out.extend_from_slice(&(alias.len() as u16).to_be_bytes());
        out.extend_from_slice(alias.as_bytes());
        out.extend_from_slice(&0u64.to_be_bytes());
        out.extend_from_slice(&5u16.to_be_bytes());
        out.extend_from_slice(b"X.509");
        out.extend_from_slice(&64u32.to_be_bytes());
        out.extend_from_slice(&[0x30; 64]);
    }
    out.extend_from_slice(&[0; 20]);
    out
}

/// The key store's entry walk reads each byte about once: it used to read
/// a 1 MiB block per entry, quadratic in the number of entries.
#[test]
fn jks_entry_walk_reads_linearly() {
    let data = jks_entries(5_000);
    let len = data.len() as u64;
    let mut host = Host::named("t.jks", data, Limits::default());
    host.session.expand(host.root, 100);
    host.run();
    let summary = host.session.node(host.root).unwrap().summary.clone();
    assert!(
        summary.as_deref().unwrap_or("").contains("5000 entries"),
        "{summary:?}"
    );
    let work = host.session.work_done();
    // About one unit per 4 KiB read; the old walk spent over 100 000.
    assert!(work < 5_000, "{work} units for {len} bytes");
}

#[test]
fn omf_pushes_records_as_it_walks() {
    let data = omf_comments(200_000);
    let len = data.len() as u64;
    let mut host = Host::named("t.obj", data, Limits::default());
    host.session.expand(host.root, 100);
    host.run();
    let children = host.session.children(host.root).unwrap();
    assert_eq!(children.ids.len(), 100);
    assert_eq!(children.state, ChildState::More);
    // The first page needs the first records, not the whole 1.6 MB file.
    assert!(
        host.bytes_supplied < len / 4,
        "{} of {len}",
        host.bytes_supplied
    );

    // The whole walk ends with the record count in the summary.
    host.explore(host.root, 1, 100_000);
    let summary = host.session.node(host.root).unwrap().summary.clone();
    assert_eq!(
        summary.as_deref(),
        Some("OMF object module t.asm, 200002 records")
    );
}
