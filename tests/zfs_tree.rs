//! ZFS datasets, directory trees and file content read back against what
//! tests/data/zfs/make-zfs.sh wrote: LZ4 and zstd file systems, a
//! snapshot taken before a file grew, a volume, and a mirror member.

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

fn host(name: &str) -> Host {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/external/zfs")
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

#[test]
fn files_read_back_from_lz4_and_zstd_datasets() {
    let mut host = host("tank.img.raw.zst");
    let numbers: String = (1..=20000).map(|i| format!("{i}\n")).collect();
    for ds in ["lz4", "zstd"] {
        let dataset = format!("tank/{ds}");
        let file = |name| ["Datasets", dataset.as_str(), name, "Content"];
        let hello = format!("hello from fillyfoal ({ds})\n");
        let hello = if ds == "lz4" {
            hello + "after-snapshot\n"
        } else {
            hello
        };
        assert_eq!(content(&mut host, &file("hello.txt")), hello.as_bytes());
        assert!(content(&mut host, &file("numbers.txt")) == numbers.as_bytes());
        assert!(content(&mut host, &file("zeds.bin")) == [b'z'; 8192]);
    }
    assert_eq!(
        content(
            &mut host,
            &["Datasets", "tank/lz4", "dir", "nested.txt", "Content"]
        ),
        b"nested\n"
    );
    assert!(
        common::diagnostic_kinds(&host).is_empty(),
        "{:?}",
        common::diagnostics(&host)
    );
}

#[test]
fn a_snapshot_shows_the_file_as_it_was() {
    let mut host = host("tank.img.raw.zst");
    assert_eq!(
        content(
            &mut host,
            &["Datasets", "tank/lz4@snap1", "hello.txt", "Content"]
        ),
        b"hello from fillyfoal (lz4)\n"
    );
}

#[test]
fn a_volume_shows_its_data() {
    let mut host = host("tank.img.raw.zst");
    let data = content(&mut host, &["Datasets", "tank/vol", "Content"]);
    assert_eq!(data.len(), 4 << 20);
    assert!(data.starts_with(b"fillyfoal zvol block 0\n"));
}

#[test]
fn a_mirror_member_is_read_alone() {
    let mut host = host("mirror-a.img.raw.zst");
    assert_eq!(
        content(&mut host, &["Datasets", "mpool", "readme.txt", "Content"]),
        b"mirrored by fillyfoal\n"
    );
}
