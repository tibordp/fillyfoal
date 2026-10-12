//! Forensic disk images assemble the media they hold: the chunks of EWF1
//! (`.E01`) and EWF2 (`.Ex01`) segments and the map and image streams of
//! AFF4 volumes read back as the imaged volume (checked against the MD5
//! ewfacquire recorded and against pyaff4's own reading); and a large chunk
//! table is not read until the media is opened.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::Host;
use fillyfoal::codec::crypto::hash::{Hash, Md5};
use fillyfoal::{Limits, NodeId, Span};

fn host(path: &str) -> Host {
    let full = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
    let name = full.file_name().unwrap().to_string_lossy().into_owned();
    Host::named(&name, common::fixture_bytes(&full), Limits::default())
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

/// The first `len` bytes of the source a node's children were dissected
/// from (the assembled media).
fn media(host: &mut Host, id: NodeId, len: u64) -> Vec<u8> {
    let first = host.session.children(id).unwrap().ids[0];
    let source = host.session.node(first).unwrap().span.unwrap().source;
    let span = Span::new(source, 0, len);
    loop {
        match host.session.read(span) {
            Ok(bytes) => return bytes,
            Err(requests) => host.supply(requests),
        }
    }
}

fn md5_hex(data: &[u8]) -> String {
    Md5::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// What ewfverify reported for the volume imaged into the EWF fixtures.
const EWF_MD5: &str = "c1a3423c3c98b2b6c6584fb344189b1f";

#[test]
fn ewf_media_matches_the_recorded_hash() {
    for path in [
        "tests/fixtures/external/ewf2/fat-deflate.Ex01",
        "tests/fixtures/external/ewf2/fat-stored.Ex01",
        "tests/fixtures/external/ewf/fat-libewf.E01",
    ] {
        let mut host = host(path);
        let id = open(&mut host, &["Media"]);
        let data = media(&mut host, id, 98304);
        assert_eq!(data.len(), 98304, "{path}");
        assert_eq!(md5_hex(&data), EWF_MD5, "{path}");
    }
}

#[test]
fn aff4_data_matches_pyaff4() {
    // pyaff4 read both back as the source volume, the second with zeros
    // where its map has a hole (16 to 32 KiB).
    for (path, want) in [
        (
            "tests/fixtures/external/aff4/fat-zlib.aff4",
            "24dc3d6b6d787a8235fdeccf6d9cea7a",
        ),
        (
            "tests/fixtures/external/aff4/fat-snappy-hole.aff4",
            "22b673a9644b1ea2bad0a48d382de884",
        ),
    ] {
        let mut host = host(path);
        let images = open(&mut host, &["Images"]);
        let image = host.session.children(images).unwrap().ids[0];
        host.session.expand_more(image, 100);
        host.run();
        let data_node = host.child(image, "Data").unwrap();
        host.session.expand_more(data_node, 100);
        host.run();
        let data = media(&mut host, data_node, 98304);
        assert_eq!(md5_hex(&data), want, "{path}");
    }
    // The logical volume's ImageStream file is the same volume.
    let mut host = host("tests/fixtures/external/aff4/logical.aff4");
    let id = open(&mut host, &["Images", "disk/fat.img", "Data"]);
    let data = media(&mut host, id, 98304);
    assert_eq!(md5_hex(&data), "24dc3d6b6d787a8235fdeccf6d9cea7a");
}

/// An EWF2 segment: the file header, then each section's data followed by
/// its descriptor (previous offset, data size, Adler-32 of the first 60
/// bytes).
fn ewf2_segment(sections: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut out = b"EVF2\r\n\x81\x00\x02\x01\x01\x00\x01\x00\x00\x00".to_vec();
    out.resize(32, 0);
    let mut previous = 0u64;
    for (kind, data) in sections {
        out.extend_from_slice(data);
        let at = out.len() as u64;
        let mut d = Vec::new();
        d.extend_from_slice(&kind.to_le_bytes());
        d.extend_from_slice(&0u32.to_le_bytes());
        d.extend_from_slice(&previous.to_le_bytes());
        d.extend_from_slice(&(data.len() as u64).to_le_bytes());
        d.extend_from_slice(&64u32.to_le_bytes());
        d.extend_from_slice(&0u32.to_le_bytes());
        d.resize(60, 0);
        let sum = fillyfoal::codec::adler32(&d);
        d.extend_from_slice(&sum.to_le_bytes());
        out.extend_from_slice(&d);
        previous = at;
    }
    out
}

#[test]
fn a_large_ewf2_sector_table_is_read_only_for_the_media() {
    // 200,000 pattern-fill chunks (3.2 MB of table, 6.1 GiB of media).
    let n = 200_000u32;
    let mut table = Vec::new();
    table.extend_from_slice(&0u64.to_le_bytes());
    table.extend_from_slice(&n.to_le_bytes());
    table.resize(32, 0);
    for i in 0..n {
        table.extend_from_slice(&u64::from(i % 3 == 0).to_le_bytes());
        table.extend_from_slice(&8u32.to_le_bytes());
        table.extend_from_slice(&5u32.to_le_bytes());
    }
    table.resize(table.len() + 16, 0);
    let data = ewf2_segment(&[(4, table), (0x0f, Vec::new())]);
    let len = data.len() as u64;
    let mut host = Host::named("big.Ex01", data, Limits::default());
    let root = host.root;
    host.session.expand_more(root, 100);
    host.run();
    assert!(
        host.child(root, "Sector table").is_some(),
        "{}",
        host.render()
    );
    // The listing reads the head (for identification) and the
    // descriptors, a few 64 KiB read chunks, not the table.
    assert!(
        host.bytes_supplied < 256 * 1024,
        "{} of {len} bytes read",
        host.bytes_supplied
    );
    let before = host.session.work_done();
    let media_node = host.child(root, "Media").unwrap();
    host.session.expand_more(media_node, 100);
    host.run();
    let work = host.session.work_done() - before;
    // One read of the table and a pass over it; well under the limit.
    assert!(work < Limits::default().max_work / 4, "{work} units");
    let first = host.session.children(media_node).unwrap();
    assert!(!first.ids.is_empty(), "{}", host.render());
}
