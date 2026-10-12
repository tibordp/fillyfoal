//! A CHM's LZX section is decoded from the nearest reset interval its
//! reset table records: opening a file near the end of the section does
//! not decode the section from its start.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::Host;
use fillyfoal::Limits;

/// Work (budget units, the same on every machine) to open `file` of
/// chmcmd.chm once the file list is shown, and the rendered tree. This
/// includes identifying the file's content (about the same for any small
/// file), so tests compare files rather than absolute counts.
fn open(file: &str) -> (u64, String) {
    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/external/chm/chmcmd.chm"
    ))
    .unwrap();
    let mut host = Host::new(data, Limits::default());
    let root = host.root;
    host.explore(root, 1, 1000);
    let files = host.child(root, "Files").expect("Files");
    host.explore(files, 1, 1000);
    let node = host.child(files, file).expect(file);
    let before = host.session.work_done();
    host.explore(node, 2, 1000);
    (host.session.work_done() - before, host.render())
}

#[test]
fn late_files_decode_from_the_nearest_reset() {
    // The section is 114888 bytes: four 32 KiB frames, a reset every two
    // (frame 2 starts at compressed offset 5142 of 8288). `/#STRINGS`
    // (offset 0x1bf90) lies in frame 3, so it decodes frames 2 and 3.
    let (work, tree) = open("/#STRINGS");
    assert!(!tree.contains("malformed"), "{tree}");
    // `/$OBJINST` (offset 0) decodes frame 0 only. With seeds, `/#STRINGS`
    // costs 2 units more (frames 2 and 3 from the reset); decoding from the
    // start (all four frames) cost 20 more.
    let (first, _) = open("/$OBJINST");
    assert!(
        work < first + 11,
        "{work} units, {first} for a file in frame 0"
    );
}
