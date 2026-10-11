//! NTFS files whose attributes continue in extension records (through an
//! $ATTRIBUTE_LIST), on the ntfs-3g/ntfs3 fixture: every named stream is
//! listed, a $DATA runlist split over three records reads back as the
//! file written, and freed index records are not listed.

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
        "/tests/fixtures/external/ntfs/ntfs3g-attrlist.img.raw.zst"
    ));
    Host::named(
        "ntfs3g-attrlist.img",
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

fn names(host: &Host, id: NodeId) -> Vec<String> {
    host.session
        .children(id)
        .unwrap()
        .ids
        .iter()
        .map(|&c| host.session.node(c).unwrap().name.to_string())
        .collect()
}

fn read(host: &mut Host, span: Span) -> Vec<u8> {
    loop {
        match host.session.read(span) {
            Ok(bytes) => return bytes,
            Err(requests) => host.supply(requests),
        }
    }
}

#[test]
fn all_named_streams_are_listed() {
    let mut host = host();
    let id = open(&mut host, &["Root directory", "ads.txt"]);
    let streams = names(&host, id)
        .into_iter()
        .filter(|n| n.starts_with("$DATA:stream_number_"))
        .count();
    assert_eq!(streams, 30);
}

#[test]
fn a_split_runlist_reads_back_whole() {
    let mut host = host();
    let file = open(&mut host, &["Root directory", "sparse.bin"]);
    let content = host.child(file, "Content").unwrap();
    let span = host.session.node(content).unwrap().span.unwrap();
    assert_eq!(span.len, 599 * 4096);
    let data = read(&mut host, span);
    for k in 0..300 {
        let block = &data[2 * k * 4096..(2 * k + 1) * 4096];
        let head = format!("sparse block {k:06}\n");
        assert!(block.starts_with(head.as_bytes()), "block {k}");
        assert!(block[head.len()..].iter().all(|&b| b == b'.'), "block {k}");
        if k < 299 {
            let hole = &data[(2 * k + 1) * 4096..(2 * k + 2) * 4096];
            assert!(hole.iter().all(|&b| b == 0), "hole after block {k}");
        }
    }
}

#[test]
fn freed_index_records_are_skipped() {
    let mut host = host();
    let id = open(&mut host, &["Root directory", "big"]);
    let files = names(&host, id)
        .into_iter()
        .filter(|n| n.starts_with("file_with"))
        .count();
    assert_eq!(files, 30);
}
