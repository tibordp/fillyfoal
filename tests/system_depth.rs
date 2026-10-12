//! Content the system dissectors rebuild from their containers: the image
//! an Android sparse file describes, read back against what simg2img
//! writes, and its cost on a sparse file describing a huge fill.

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

fn fixture(path: &str) -> Vec<u8> {
    common::fixture_bytes(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
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

fn read(host: &mut Host, span: Span) -> Vec<u8> {
    loop {
        match host.session.read(span) {
            Ok(bytes) => return bytes,
            Err(requests) => host.supply(requests),
        }
    }
}

/// The source an expanded node's children were dissected from.
fn child_source(host: &Host, id: NodeId) -> Span {
    let children = host.session.children(id).unwrap();
    children
        .ids
        .iter()
        .find_map(|&c| host.session.node(c).unwrap().span)
        .unwrap_or_else(|| panic!("no spans under:\n{}", host.render()))
}

#[test]
fn sparse_image_expands_to_what_simg2img_writes() {
    let data = fixture("tests/fixtures/external/android-sparse/ext4.simg");
    let mut host = Host::named("ext4.simg", data, Limits::default());
    let id = open(&mut host, &["Expanded image"]);
    let source = child_source(&host, id).source;
    let image = read(&mut host, Span::new(source, 0, 2 << 20));
    assert_eq!(image.len(), 2 << 20);
    // CRC-32 of the ext4 image simg2img rebuilt from this file
    // (tests/data/android-sparse/inside.sh).
    assert_eq!(fillyfoal::codec::crc32(&image), 0xd159_787d);
}

/// A sparse header for `blocks` 4 KiB blocks and its chunk headers.
fn sparse(blocks: u32, chunks: &[(u16, u32, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(0xed26_ff3au32.to_le_bytes());
    out.extend(1u16.to_le_bytes());
    out.extend(0u16.to_le_bytes());
    out.extend(28u16.to_le_bytes());
    out.extend(12u16.to_le_bytes());
    out.extend(4096u32.to_le_bytes());
    out.extend(blocks.to_le_bytes());
    out.extend(u32::try_from(chunks.len()).unwrap().to_le_bytes());
    out.extend(0u32.to_le_bytes());
    for (kind, n, body) in chunks {
        out.extend(kind.to_le_bytes());
        out.extend(0u16.to_le_bytes());
        out.extend(n.to_le_bytes());
        out.extend((12 + u32::try_from(body.len()).unwrap()).to_le_bytes());
        out.extend(*body);
    }
    out
}

#[test]
fn huge_sparse_fills_cost_little() {
    // 16 TiB: a non-zero fill of 8 TiB, then 8 TiB of "don't care". The
    // fill maps onto repeats of one derived 1 MiB pattern, capped at a
    // million pieces; the hole is one piece.
    let half = 1u32 << 31;
    let data = sparse(
        u32::MAX,
        &[(0xcac2, half, &[0xff; 4]), (0xcac3, half - 1, &[])],
    );
    let mut host = Host::named("huge.simg", data, Limits::default());
    let id = open(&mut host, &["Expanded image"]);
    let work = host.session.work_done();
    assert!(work < 200_000, "{work} units");
    let source = child_source(&host, id);
    let head = read(&mut host, Span::new(source.source, 0, 64));
    assert!(head.iter().all(|&b| b == 0xff), "{head:x?}");
    let kinds = common::diagnostic_kinds(&host);
    assert!(
        kinds.contains(&fillyfoal::DiagKind::Limit),
        "{kinds:?}\n{}",
        host.render()
    );
}
