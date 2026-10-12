//! TempleOS DolDoc and sprites: work stays in proportion to the input. A
//! document of a quarter of a million commands is scanned once (its
//! listings share the scan), and a sprite element claiming a huge bitmap
//! costs nothing to reject.

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

#[test]
fn many_commands_are_scanned_once() {
    let mut data = b"$WW,1$".to_vec();
    while data.len() < 2 << 20 {
        data.extend_from_slice(b"$TX,\"a\"$ $$\n");
    }
    let mut host = Host::open("big.DD", data.clone(), Limits::default(), None);
    let root = host.root;
    host.session.expand(root, 100);
    host.run();
    let scan = host.session.work_done();
    // About a unit per command and per KiB.

    assert!(scan < 400_000, "scan cost {scan} units");
    let commands = host.child(root, "Commands").expect("Commands");
    host.session.expand(commands, 100);
    host.run();
    let tx = host.child(commands, "TX").expect("TX");
    host.session.expand(tx, 100);
    host.run();
    let listing = host.session.work_done() - scan;
    assert!(listing < 20_000, "first page cost {listing} units");
}

#[test]
fn huge_bitmap_claims_are_rejected_cheaply() {
    // $SP$ then a bin holding one BitMap element of 2^31-1 × 2^31-1 pixels.
    let mut data = b"$SP,\"\",BI=1$\n\0".to_vec();
    let mut elem = vec![23u8];
    for v in [0i32, 0, i32::MAX, i32::MAX] {
        elem.extend_from_slice(&v.to_le_bytes());
    }
    elem.push(0);
    for v in [1u32, 0, elem.len() as u32, 1] {
        data.extend_from_slice(&v.to_le_bytes());
    }
    data.extend_from_slice(&elem);
    let mut host = Host::open("sprite.DD", data, Limits::default(), None);
    host.explore_all();
    assert!(host.session.work_done() < 5_000);
    let text = host.render();
    assert!(text.contains("BitMap") || text.contains("[0]"), "{text}");
}
