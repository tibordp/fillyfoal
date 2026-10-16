//! xfsdump: a large file's extent groups make one file, and a directory
//! entry whose checksum does not match is a warning, not the end of the
//! listing.

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

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/external/xfsdump")
        .join(name);
    common::fixture_bytes(&path)
}

fn expand(host: &mut Host, id: NodeId) {
    host.session.expand_more(id, 10_000);
    host.run();
}

fn open(host: &mut Host, path: &[&str]) -> NodeId {
    let mut id = host.root;
    for name in path {
        expand(host, id);
        id = host
            .child(id, name)
            .unwrap_or_else(|| panic!("no {name:?} under:\n{}", host.render()));
    }
    expand(host, id);
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

/// A file of 16 MiB + 8 KiB is dumped as two extent groups (two file
/// records of inode 131): the listing shows it once, and its content runs
/// across both.
#[test]
fn extent_groups_make_one_file() {
    let mut host = Host::named(
        "groups.xfsdump",
        fixture("groups.xfsdump.raw.zst"),
        Limits::default(),
    );
    let files = open(&mut host, &["Files"]);
    assert_eq!(names(&host, files), ["/groups.bin", "/small.txt", "End"]);
    let file = open(&mut host, &["Files", "/groups.bin"]);
    let parts = names(&host, file);
    assert_eq!(
        parts[..3],
        ["Extent group 0", "Extent group 1", "Content"],
        "{}",
        host.render()
    );
    let content = open(&mut host, &["Files", "/groups.bin", "Content"]);
    let first = host.session.children(content).unwrap().ids[0];
    let span = host.session.node(first).unwrap().span.unwrap();
    assert_eq!(span.len, 16 * 1024 * 1024 + 8192);
    // Across the boundary between the groups.
    let across = Span::new(span.source, 0x100_0000 - 4, 8);
    let bytes = loop {
        match host.session.read(across) {
            Ok(bytes) => break bytes,
            Err(requests) => host.supply(requests),
        }
    };
    assert_eq!(bytes, [0, 0xff, 0x80, 1, 0, 0xff, 0x80, 1]);
    assert!(!host.render().contains("!"), "{}", host.render());
}

/// Where the level 0 fixture keeps the checksum of the root directory's
/// entry for `readme.txt`, and the dump attributes.
const README_DIRENT_CHECKSUM: usize = 0x510f;
const DUMP_ATTRS: usize = 0xf44;

/// A damaged directory entry checksum is a warning on its directory and
/// entry; every directory and file is still listed and named.
#[test]
fn a_bad_dirent_checksum_is_a_warning() {
    let mut dump = fixture("level0.xfsdump.raw.zst");
    dump[README_DIRENT_CHECKSUM] ^= 0x55;
    let mut host = Host::named("bad.xfsdump", dump.clone(), Limits::default());
    let dirs = open(&mut host, &["Directories"]);
    assert_eq!(names(&host, dirs), ["/", "/sub"]);
    let files = open(&mut host, &["Files"]);
    let listed = names(&host, files);
    assert!(listed.iter().any(|n| n == "/readme.txt"), "{listed:?}");
    assert!(listed.iter().any(|n| n == "/sub/lines.txt"), "{listed:?}");
    open(&mut host, &["Directories", "/"]);
    let tree = host.render();
    assert!(
        tree.contains("warning: 1 directory entry with a checksum mismatch"),
        "{tree}"
    );
    assert!(
        tree.contains("warning: directory entry checksum mismatch"),
        "{tree}"
    );
    assert!(!tree.contains("Unreadable record"), "{tree}");

    // A dump without entry checksums (attribute bit 10 clear): nothing to
    // check.
    let attrs = u32::from_be_bytes(dump[DUMP_ATTRS..DUMP_ATTRS + 4].try_into().unwrap());
    assert_ne!(attrs & 1 << 10, 0);
    dump[DUMP_ATTRS..DUMP_ATTRS + 4].copy_from_slice(&(attrs & !(1 << 10)).to_be_bytes());
    let mut host = Host::named("unchecked.xfsdump", dump, Limits::default());
    open(&mut host, &["Directories", "/"]);
    let tree = host.render();
    assert!(!tree.contains("directory entry"), "{tree}");
}
