//! HFS+ on the macOS-written `features.img` fixture: a data fork whose
//! extents continue in the extents overflow file reads back whole and in
//! order, decmpfs files decompress to what was written, and hard links
//! show their indirect node's content.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::Host;
use fillyfoal::{Limits, NodeId, Span};

fn host() -> Host {
    let path = std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/external/hfsplus/features.img.gz"
    ));
    Host::named(
        "features.img",
        common::fixture_bytes(path),
        Limits::default(),
    )
}

fn open(host: &mut Host, path: &[&str]) -> NodeId {
    let mut id = host.root;
    for name in path {
        host.session.expand_more(id, 10_000);
        host.run();
        id = host
            .child(id, name)
            .unwrap_or_else(|| panic!("no {name:?} under:\n{}", host.render()));
    }
    host.session.expand_more(id, 10_000);
    host.run();
    id
}

fn read(host: &mut Host, span: Span) -> Vec<u8> {
    loop {
        match host.session.read(span) {
            Ok(bytes) => return bytes,
            Err(requests) => host.supply(requests),
        }
    }
}

fn content(host: &mut Host, path: &[&str]) -> Vec<u8> {
    let file = open(host, path);
    let node = host.child(file, "Content").expect("a Content node");
    let span = host.session.node(node).unwrap().span.unwrap();
    read(host, span)
}

#[test]
fn overflow_extents_complete_the_data_fork() {
    let mut host = host();
    let data = content(&mut host, &["Root folder", "frag.bin"]);
    assert_eq!(data.len(), 12 * 4096);
    for (i, block) in data.chunks(4096).enumerate() {
        let head = format!("block {i:02}\n");
        assert!(block.starts_with(head.as_bytes()), "block {i}");
        assert!(block[head.len()..].iter().all(|&b| b == 0), "block {i}");
    }
}

#[test]
fn decmpfs_files_decompress() {
    let mut host = host();
    let small = content(&mut host, &["Root folder", "docs", "small.dat"]);
    let want: Vec<u8> = (0..1400)
        .flat_map(|i| format!("record {i:06}\0\0\0").into_bytes())
        .collect();
    assert_eq!(small, want);
    // Three LZVN chunks of NUL-separated words (content.py).
    let words = content(&mut host, &["Root folder", "docs", "words.dat"]);
    assert_eq!(words.len(), 176_030);
    let known = [
        "filly", "foal", "mare", "colt", "hay", "oats", "barn", "field", "gallop", "trot",
        "canter", "saddle", "bridle", "stable", "meadow",
    ];
    let mut count = 0;
    for w in words.split(|&b| b == 0) {
        assert!(known.contains(&std::str::from_utf8(w).unwrap()), "{w:?}");
        count += 1;
    }
    assert_eq!(count, 30_000);
}

#[test]
fn hard_links_show_the_indirect_node() {
    let mut host = host();
    for path in [
        &["Root folder", "a.txt"][..],
        &["Root folder", "docs", "hard.txt"],
    ] {
        assert_eq!(content(&mut host, path), b"one file, two names\n");
    }
}
