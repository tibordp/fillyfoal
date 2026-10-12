//! An Unreal pak whose files all name irregular index entries (v10+) lists
//! them in time linear in the index: the irregular entries are found once,
//! not re-walked from the first for every file.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use std::time::{Duration, Instant};

use common::Host;
use fillyfoal::{Limits, NodeId, Progress};

fn fstring(s: &str) -> Vec<u8> {
    let mut out = ((s.len() + 1) as i32).to_le_bytes().to_vec();
    out.extend_from_slice(s.as_bytes());
    out.push(0);
    out
}

/// A v11 pak of `n` empty stored files, each named by an irregular
/// (FPakEntry) index entry; every file names the last one.
fn irregular_pak(n: u32) -> Vec<u8> {
    let mut irregular = Vec::new();
    for _ in 0..n {
        irregular.extend(0u64.to_le_bytes()); // offset
        irregular.extend(0u64.to_le_bytes()); // stored size
        irregular.extend(0u64.to_le_bytes()); // size
        irregular.extend(0u32.to_le_bytes()); // method: none
        irregular.extend([0u8; 20]); // SHA-1
        irregular.push(0); // flags
        irregular.extend(0u32.to_le_bytes()); // block size
    }
    let mut directory = 1u32.to_le_bytes().to_vec();
    directory.extend(fstring("/"));
    directory.extend(n.to_le_bytes());
    for i in 0..n {
        directory.extend(fstring(&format!("f{i}.bin")));
        directory.extend((-(n as i32)).to_le_bytes());
    }
    let mut index = fstring("../../../");
    index.extend(n.to_le_bytes());
    index.extend(0u64.to_le_bytes()); // path hash seed
    index.extend(0u32.to_le_bytes()); // no path hash index
    let dir_flag_at = index.len();
    index.extend([0u8; 4 + 8 + 8 + 20]); // full directory index, below
    index.extend(0u32.to_le_bytes()); // no encoded entries
    index.extend(n.to_le_bytes());
    index.extend(irregular);
    // No data: the index starts the file and the directory follows it.
    let dir_offset = index.len() as u64;
    index[dir_flag_at..dir_flag_at + 4].copy_from_slice(&1u32.to_le_bytes());
    index[dir_flag_at + 4..dir_flag_at + 12].copy_from_slice(&dir_offset.to_le_bytes());
    index[dir_flag_at + 12..dir_flag_at + 20]
        .copy_from_slice(&(directory.len() as u64).to_le_bytes());
    let mut pak = index.clone();
    pak.extend(&directory);
    pak.extend([0x11u8; 16]); // encryption key GUID
    pak.push(0); // index not encrypted
    pak.extend([0xe1, 0x12, 0x6f, 0x5a]);
    pak.extend(11u32.to_le_bytes());
    pak.extend(0u64.to_le_bytes()); // index offset
    pak.extend((index.len() as u64).to_le_bytes());
    pak.extend([0u8; 20]);
    for name in ["Zlib", "Gzip", "LZ4", "", ""] {
        let mut b = name.as_bytes().to_vec();
        b.resize(32, 0);
        pak.extend(b);
    }
    pak
}

/// Polls `id` (a page of `page` children) to the end, answering byte
/// requests; every poll must return quickly.
fn open(host: &mut Host, id: NodeId, page: u64) {
    host.session.expand(id, page);
    for _ in 0..10_000_000 {
        let start = Instant::now();
        let progress = host.session.poll_node(id, 2_000);
        assert!(start.elapsed() < common::POLL_CEILING, "slow poll");
        match progress {
            Progress::Idle => return,
            Progress::Yielded => {}
            Progress::NeedSecret(_) => panic!("unexpected secret request"),
            Progress::NeedBytes(requests) => host.supply(requests),
        }
    }
    panic!("did not settle");
}

#[test]
fn irregular_entries_are_indexed_once() {
    let n = 0x1_0000;
    let mut host = Host::named("irregular.pak", irregular_pak(n), Limits::default());
    let root = host.root;
    let start = Instant::now();
    open(&mut host, root, 10);
    let index = host.child(root, "Index").expect("index");
    open(&mut host, index, 10);
    let files = host.child(index, "Files").expect("files");
    open(&mut host, files, u64::from(n));
    // Re-walking the entries for each file took about 2^32 entry parses.
    assert!(start.elapsed() < Duration::from_secs(60));
    let listing = host.session.children(files).unwrap();
    assert_eq!(listing.ids.len(), n as usize);
    let last = host
        .child(files, &format!("f{}.bin", n - 1))
        .expect("last file");
    let node = host.session.node(last).unwrap();
    assert!(node.diagnostics.is_empty(), "{:?}", node.diagnostics);
}
