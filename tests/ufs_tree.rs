//! UFS directory trees and file content read back against the tree
//! makefs was given (tests/data/linux-fs/make-ufs-tree.sh): a UFS1
//! little-endian volume in four cylinder groups and a UFS2 big-endian one
//! in two, with a file past the direct blocks, a sparse file, nested
//! directories and symbolic links short and long.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::Host;
use fillyfoal::{Limits, NodeId, Span, Value};

fn host(name: &str) -> Host {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/external/ufs")
        .join(name);
    Host::named(name, common::fixture_bytes(&path), Limits::default())
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

fn content(host: &mut Host, path: &[&str]) -> Vec<u8> {
    let id = open(host, path);
    let span: Span = host.session.node(id).unwrap().span.unwrap();
    loop {
        match host.session.read(span) {
            Ok(bytes) => return bytes,
            Err(requests) => host.supply(requests),
        }
    }
}

fn check(name: &str) {
    let mut host = host(name);
    let root = "Root directory";
    let numbers: String = (1..=40000).map(|i| format!("{i}\n")).collect();
    let big = content(&mut host, &[root, "big.txt", "Content"]);
    assert_eq!(big.len(), numbers.len());
    assert!(big == numbers.as_bytes(), "big.txt differs");
    let mut sparse = vec![0u8; 200 * 1024];
    sparse.extend(b"end\n");
    assert!(content(&mut host, &[root, "sparse.bin", "Content"]) == sparse);
    assert_eq!(
        content(&mut host, &[root, "a", "b", "c", "deep.txt", "Content"]),
        b"deep\n"
    );
    assert_eq!(
        content(
            &mut host,
            &[root, "many", "entry-with-a-longer-name-17.txt", "Content"]
        ),
        b"17\n"
    );
    let many = open(&mut host, &[root, "many"]);
    // The directory's inode, then its 40 entries.
    assert_eq!(host.session.children(many).unwrap().ids.len(), 41);
    let target = open(&mut host, &[root, "link", "Target"]);
    assert_eq!(
        host.session.node(target).unwrap().value,
        Some(Value::Text("hello.txt".into()))
    );
    let long: String = (1..=10)
        .map(|i| format!("long-symlink-target-{i:02}/"))
        .collect::<String>()
        + "end";
    assert_eq!(
        content(&mut host, &[root, "longlink", "Content"]),
        long.as_bytes()
    );
    assert!(
        common::diagnostic_kinds(&host).is_empty(),
        "{}",
        host.render()
    );
}

#[test]
fn ufs1_tree_reads_back() {
    check("makefs-tree-ufs1.img.raw.zst");
}

#[test]
fn ufs2_big_endian_tree_reads_back() {
    check("makefs-tree-be-ufs2.img.raw.zst");
}
