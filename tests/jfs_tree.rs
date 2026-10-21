//! JFS directory trees and file content read back against what
//! tests/data/linux-fs/make-jfs-nilfs-tree.sh wrote: a file of several
//! extents, a sparse file, nested directories, a directory of 40 entries
//! (past the dtree root, into dtree pages) and symbolic links.

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

fn host() -> Host {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/external/jfs/tree.jfs.raw.zst");
    Host::named("tree.jfs", common::fixture_bytes(&path), Limits::default())
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

fn target(host: &mut Host, path: &[&str]) -> Option<Value> {
    let id = open(host, path);
    host.session.node(id).unwrap().value.clone()
}

#[test]
fn files_and_directories_read_back() {
    let mut host = host();
    let root = "Root directory";
    let numbers: String = (1..=40000).map(|i| format!("{i}\n")).collect();
    assert!(content(&mut host, &[root, "big.txt", "Content"]) == numbers.as_bytes());
    let mut sparse = vec![0u8; 200 * 1024];
    sparse.extend(b"end\n");
    assert!(content(&mut host, &[root, "sparse.bin", "Content"]) == sparse);
    assert_eq!(
        content(&mut host, &[root, "hello.txt", "Content"]),
        b"Hello, fillyfoal!\n"
    );
    assert_eq!(
        content(&mut host, &[root, "a", "b", "c", "deep.txt", "Content"]),
        b"deep\n"
    );
    assert_eq!(
        content(
            &mut host,
            &[root, "many", "entry-with-a-longer-name-37.txt", "Content"]
        ),
        b"37\n"
    );
    let many = open(&mut host, &[root, "many"]);
    // The directory's inode, then its 40 entries.
    assert_eq!(host.session.children(many).unwrap().ids.len(), 41);
    assert_eq!(
        target(&mut host, &[root, "link", "Target"]),
        Some(Value::Text("hello.txt".into()))
    );
    let long: String = (1..=10)
        .map(|i| format!("long-symlink-target-{i:02}/"))
        .collect::<String>()
        + "end";
    assert_eq!(
        target(&mut host, &[root, "longlink", "Target"]),
        Some(Value::Text(long))
    );
    assert!(
        common::diagnostic_kinds(&host).is_empty(),
        "{:?}",
        common::diagnostics(&host)
    );
}
