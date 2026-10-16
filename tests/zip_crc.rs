//! ZIP members' CRC-32s are verified when their content is decoded, not
//! when the archive is listed: a corrupted member shows the mismatch on
//! its content once that is expanded, and listing (or expanding a member's
//! headers) decodes nothing.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::Host;
use fillyfoal::{DiagKind, Limits, NodeId};

/// `mixed.zip`: `dir/notes.txt` (deflate, central header at 0x6c3, data
/// at 0x85+0x37) and `x.tar.gz` (stored, data at 0x2eb+0x349).
fn mixed() -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/external/zip/mixed.zip",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn expand(host: &mut Host, id: NodeId) {
    host.session.expand(id, 1000);
    host.run();
}

/// Opens `data` and expands the central directory: the listing.
fn listed(data: Vec<u8>) -> (Host, NodeId) {
    let mut host = Host::named("mixed.zip", data, Limits::default());
    let root = host.root;
    expand(&mut host, root);
    let directory = host.child(root, "Central Directory").unwrap();
    expand(&mut host, directory);
    (host, directory)
}

/// Expands member `name` and its content; the content's warnings and the
/// central header's CRC-32 field as rendered.
fn content_warnings(host: &mut Host, directory: NodeId, name: &str) -> Vec<String> {
    let member = host.child(directory, name).unwrap();
    expand(host, member);
    let content = host.child(member, "Content").unwrap();
    expand(host, content);
    host.session
        .node(content)
        .unwrap()
        .diagnostics
        .iter()
        .filter(|d| d.kind == DiagKind::Warning)
        .map(|d| d.message.clone())
        .collect()
}

fn crc_field(host: &mut Host, directory: NodeId, name: &str) -> String {
    let member = host.child(directory, name).unwrap();
    expand(host, member);
    let header = host.child(member, "Central Directory Header").unwrap();
    expand(host, header);
    let field = host.child(header, "CRC-32").unwrap();
    fillyfoal::render::value(host.session.node(field).unwrap().value.as_ref().unwrap())
}

#[test]
fn intact_members_check_clean() {
    let (mut host, directory) = listed(mixed());
    assert_eq!(
        crc_field(&mut host, directory, "dir/notes.txt"),
        "0xdf323ca2 (CRC-32, skipped: checked when decoded)"
    );
    assert!(content_warnings(&mut host, directory, "dir/notes.txt").is_empty());
    assert!(content_warnings(&mut host, directory, "x.tar.gz").is_empty());
}

#[test]
fn a_corrupted_stored_member_shows_the_mismatch_on_expansion() {
    let mut data = mixed();
    data[0x2eb + 0x100] ^= 0x01;
    let (mut host, directory) = listed(data);
    let warnings = content_warnings(&mut host, directory, "x.tar.gz");
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(
        warnings[0].starts_with("CRC-32 mismatch: stored 0x"),
        "{warnings:?}"
    );
}

#[test]
fn a_wrong_crc_shows_on_the_decompressed_content() {
    let mut data = mixed();
    // The central header's CRC-32 of `dir/notes.txt`, which the content is
    // checked against.
    data[0x6c3 + 16] ^= 0x80;
    let (mut host, directory) = listed(data);
    let warnings = content_warnings(&mut host, directory, "dir/notes.txt");
    assert_eq!(
        warnings,
        ["CRC-32 mismatch: stored 0xdf323c22, computed 0xdf323ca2"]
    );
}

#[test]
fn listing_decodes_nothing() {
    let (mut host, directory) = listed(mixed());
    assert_eq!(host.session.derived_bytes(), 0);
    // A member's headers show without decoding its content either.
    let member = host.child(directory, "dir/notes.txt").unwrap();
    expand(&mut host, member);
    let header = host.child(member, "Central Directory Header").unwrap();
    expand(&mut host, header);
    assert_eq!(host.session.derived_bytes(), 0);
    // Expanding the content decodes it (and checks it).
    let content = host.child(member, "Content").unwrap();
    expand(&mut host, content);
    assert_eq!(host.session.derived_bytes(), 4800);
}
