//! The second probe phase (`formats::DeepProbe`) and the node name it may
//! use as a tie-breaker: a bare 768-byte Photoshop colour table is
//! recognised only by its `.act` name, and only at the node's own
//! detection step.

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

fn table() -> Vec<u8> {
    (0..768).map(|i| (i / 3) as u8).collect()
}

fn root_format(name: &str, data: Vec<u8>) -> Option<&'static str> {
    let mut host = Host::named(name, data, Limits::default());
    host.session.expand(host.root, 10);
    host.run();
    host.session
        .interpretation(host.root)
        .and_then(|i| i.format)
        .map(|f| f.name)
}

#[test]
fn a_768_byte_colour_table_is_identified_by_its_name() {
    assert_eq!(
        root_format("palette.ACT", table()),
        Some("photoshop-color-table")
    );
    // The same bytes under another name, or one byte longer, are not.
    assert_eq!(root_format("palette.bin", table()), None);
    assert_eq!(root_format(".act", table()), None);
    let mut longer = table();
    longer.push(0);
    assert_eq!(root_format("palette.act", longer), None);
}

#[test]
fn the_name_does_not_override_a_signature() {
    // A PNG named .act stays a PNG; the second phase runs only for
    // content nothing recognised.
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.resize(768, 0);
    assert_eq!(root_format("palette.act", png), Some("png"));
}
