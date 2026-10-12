//! APFS directory view on the macOS-written `tree.img` fixture: files read
//! back from their extents (with holes), a decmpfs file decompresses, hard
//! links share their inode, and a large extended attribute is read from its
//! own data stream.

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
        "/tests/fixtures/external/apfs/tree.img.gz"
    ));
    Host::named("tree.img", common::fixture_bytes(path), Limits::default())
}

const VOLUME: [&str; 2] = ["Volume (object 1026)", "Root directory"];

fn open(host: &mut Host, path: &[&str]) -> NodeId {
    let mut id = host.root;
    for name in VOLUME.iter().chain(path) {
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

fn bytes_of(host: &mut Host, id: NodeId) -> Vec<u8> {
    let span = host.session.node(id).unwrap().span.unwrap();
    read(host, span)
}

fn content(host: &mut Host, path: &[&str]) -> Vec<u8> {
    let file = open(host, path);
    let node = host.child(file, "Content").expect("a Content node");
    bytes_of(host, node)
}

#[test]
fn extents_and_holes() {
    let mut host = host();
    let data = content(&mut host, &["frag.bin"]);
    assert_eq!(data.len(), 12 * 4096);
    for (i, block) in data.chunks(4096).enumerate() {
        assert!(
            block.starts_with(format!("block {i:02}\n").as_bytes()),
            "block {i}"
        );
    }
    let sparse = content(&mut host, &["sparse.bin"]);
    assert_eq!(sparse.len(), 69635);
    assert!(sparse.starts_with(b"start"));
    assert!(sparse.ends_with(b"end"));
    assert!(sparse[5..69632].iter().all(|&b| b == 0));
}

#[test]
fn decmpfs_file_decompresses() {
    let mut host = host();
    let words = content(&mut host, &["docs", "words.dat"]);
    assert_eq!(words.len(), 176_030);
    assert_eq!(words.split(|&b| b == 0).count(), 30_000);
    assert!(
        words
            .split(|&b| b == 0)
            .all(|w| w.len() >= 3 && w.iter().all(u8::is_ascii_lowercase))
    );
}

#[test]
fn hard_links_and_streamed_attributes() {
    let mut host = host();
    assert_eq!(content(&mut host, &["a.txt"]), b"one file, two names\n");
    assert_eq!(
        content(&mut host, &["docs", "hard.txt"]),
        b"one file, two names\n"
    );
    let file = open(&mut host, &["xattr.txt"]);
    let attrs = host.child(file, "Extended attributes").unwrap();
    host.session.expand_more(attrs, 100);
    host.run();
    let big = host.child(attrs, "org.example.big").unwrap();
    assert_eq!(
        bytes_of(&mut host, big),
        "0123456789abcdef".repeat(512).as_bytes()
    );
}
