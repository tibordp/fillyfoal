//! ntfsclone special images: the volume is the command stream decoded on
//! demand, so a far read costs work in proportion to the clusters it walks,
//! a bounded step at a time with progress, checkpoints make the next far
//! read cheap, and damage is reported rather than fatal.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::Host;
use fillyfoal::{Limits, NodeId, ReadProgress, Span};

const CS: usize = 4096;

/// An ntfsclone 10.1 image header for `clusters` clusters of `CS` bytes on
/// a device of `device` bytes, `in_use` of them in use.
fn header(clusters: u64, device: u64, in_use: u64) -> Vec<u8> {
    let mut h = b"\0ntfsclone-image".to_vec();
    h.extend_from_slice(&[10, 1]);
    h.extend_from_slice(&(CS as u32).to_le_bytes());
    h.extend_from_slice(&device.to_le_bytes());
    h.extend_from_slice(&(clusters as i64).to_le_bytes());
    h.extend_from_slice(&in_use.to_le_bytes());
    h.extend_from_slice(&56u32.to_le_bytes());
    h.resize(56, 0);
    h
}

fn gap(out: &mut Vec<u8>, n: u64) {
    out.push(0);
    out.extend_from_slice(&(n as i64).to_le_bytes());
}

/// A data command whose cluster is filled with `fill` and starts with
/// `label`.
fn data(out: &mut Vec<u8>, fill: u8, label: &[u8]) {
    out.push(1);
    let at = out.len();
    out.resize(at + CS, fill);
    out[at..at + label.len()].copy_from_slice(label);
}

/// Clusters in the large image: a 1 GiB volume.
const BIG: u64 = 1 << 18;

/// A mostly empty 1 GiB volume: data in clusters 0 and `BIG - 1` (and the
/// backup boot sector's cluster `BIG`), nothing in between. About 12 KiB.
fn big_image() -> Vec<u8> {
    let mut img = header(BIG, (BIG + 1) * CS as u64, 2);
    data(&mut img, 0x11, b"first cluster");
    gap(&mut img, BIG - 2);
    data(&mut img, 0x22, b"last cluster");
    data(&mut img, 0x33, b"backup boot sector");
    img
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

/// The decoded volume, from the first child of an expanded "Volume".
fn volume_span(host: &mut Host, volume: NodeId) -> Span {
    let first = host.session.children(volume).unwrap().ids[0];
    let source = host.session.node(first).unwrap().span.unwrap().source;
    Span::new(source, 0, host.session.source_len(source))
}

/// Reads `span` in steps of `budget` units; returns the bytes and how far
/// the volume's decoding front moved at each step.
fn read_in_steps(host: &mut Host, span: Span, budget: u64) -> (Vec<u8>, Vec<u64>) {
    let mut fronts = Vec::new();
    loop {
        match host.session.read_step(span, budget) {
            ReadProgress::Done(bytes) => return (bytes, fronts),
            ReadProgress::NeedBytes(requests) => host.supply(requests),
            ReadProgress::Yielded => {
                let chain = host.session.read_activity();
                let inner = chain.last().expect("a yielded read reports its decoding");
                assert_eq!(inner.codec, "ntfsclone");
                let (done, total) = inner.estimate().unwrap();
                assert_eq!(total, span.end());
                fronts.push(done);
                assert!(fronts.len() < 10_000_000);
            }
        }
    }
}

/// Reading the last cluster of a 1 GiB mostly empty volume walks it: the
/// work is in proportion to the clusters produced, every step is bounded by
/// the host's budget, and progress rises step by step. A checkpoint then
/// makes another far read cheap.
#[test]
fn far_reads_are_bounded_and_checkpointed() {
    let mut host = Host::named("big.img", big_image(), Limits::default());
    let volume = open(&mut host, &["Volume"]);
    let vol = volume_span(&mut host, volume);
    assert_eq!(vol.len, (BIG + 1) * CS as u64);
    assert!(
        !host.render().contains("last cluster"),
        "expanding the volume reads only its head"
    );

    const BUDGET: u64 = 500;
    let last = vol.sub((BIG - 1) * CS as u64, 16);
    let (bytes, fronts) = read_in_steps(&mut host, last, BUDGET);
    assert_eq!(&bytes[..12], b"last cluster");
    // About a unit per 4 KiB cluster: BIG units in BUDGET-unit steps.
    let steps = fronts.len() as u64;
    assert!(
        (BIG / BUDGET / 2..=2 * BIG / BUDGET + 2).contains(&steps),
        "{steps} steps"
    );
    // Each step moves the front by a bounded amount, and it only rises.
    let per_step = 2 * BUDGET * CS as u64;
    let mut prev = 0;
    for &f in &fronts {
        assert!(f >= prev && f - prev <= per_step, "{prev} -> {f}");
        prev = f;
    }

    // Back to the start (released long ago: decoded again from the start),
    // then far again: a checkpoint near the end spares the walk.
    let first = vol.sub(0, 13);
    let (bytes, _) = read_in_steps(&mut host, first, BUDGET);
    assert_eq!(bytes, b"first cluster");
    let near_end = vol.sub((BIG - 2) * CS as u64, CS as u64 + 16);
    let (bytes, fronts) = read_in_steps(&mut host, near_end, BUDGET);
    assert!(bytes[..CS].iter().all(|&b| b == 0));
    assert_eq!(&bytes[CS..CS + 12], b"last cluster");
    assert!(fronts.len() <= 2, "{} steps", fronts.len());

    let tail = vol.sub(BIG * CS as u64, 18);
    let (bytes, _) = read_in_steps(&mut host, tail, BUDGET);
    assert_eq!(bytes, b"backup boot sector");
}

/// The command listing of the large image is a few nodes, and costs work
/// in proportion to the commands, not the clusters.
#[test]
fn listing_coalesces_runs() {
    let mut host = Host::named("big.img", big_image(), Limits::default());
    let id = open(&mut host, &["Commands"]);
    let names: Vec<String> = host
        .session
        .children(id)
        .unwrap()
        .ids
        .iter()
        .map(|&c| host.session.node(c).unwrap().name.to_string())
        .collect();
    assert_eq!(
        names,
        [
            "Cluster 0",
            format!("Clusters 1–{}", BIG - 2).as_str(),
            format!("Clusters {}–{}", BIG - 1, BIG).as_str()
        ]
    );
    assert!(
        host.session.work_done() < 10_000,
        "{}",
        host.session.work_done()
    );
    assert!(!host.render().contains("!"), "{}", host.render());
}

/// A gzip member of stored DEFLATE blocks holding `data`.
fn gzip_stored(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
    let mut chunks = data.chunks(0xffff).peekable();
    while let Some(c) = chunks.next() {
        out.push(u8::from(chunks.peek().is_none()));
        out.extend_from_slice(&(c.len() as u16).to_le_bytes());
        out.extend_from_slice(&(!(c.len() as u16)).to_le_bytes());
        out.extend_from_slice(c);
    }
    out.extend_from_slice(&fillyfoal::codec::crc32(data).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

/// An image piped through gzip: the volume decodes on demand through both
/// stages, so opening it reads only the start of the gzip stream.
#[test]
fn gzipped_images_decode_lazily() {
    // 4 MiB of saved clusters, so that the gzip content is decoded lazily.
    const SAVED: u64 = 1024;
    const CLUSTERS: u64 = 4 * SAVED;
    let mut img = header(CLUSTERS, (CLUSTERS + 1) * CS as u64, SAVED);
    for i in 0..SAVED {
        data(&mut img, 0x40, format!("saved cluster {i:05}").as_bytes());
        gap(&mut img, 3);
    }
    data(&mut img, 0x44, b"backup boot sector");
    let gz = gzip_stored(&img);
    let len = gz.len() as u64;
    let mut host = Host::named("big.img.gz", gz, Limits::default());
    let volume = open(&mut host, &["Content", "Volume"]);
    assert!(
        host.bytes_supplied < len / 4,
        "{} of {len} bytes read",
        host.bytes_supplied
    );
    let vol = volume_span(&mut host, volume);
    let far = vol.sub((CLUSTERS - 4) * CS as u64, 19);
    let (bytes, _) = read_in_steps(&mut host, far, 1000);
    assert_eq!(bytes, b"saved cluster 01023");
}

/// The volume decoded from the real-tool fixture is what `ntfsclone
/// --restore-image` writes (length and CRC-32 printed by
/// `tests/data/ntfsclone/inner.sh`).
#[test]
fn decoded_volume_matches_ntfsclone_restore() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/external/ntfsclone/ntfsclone.img.raw.zst");
    let mut host = Host::named(
        "ntfsclone.img",
        common::fixture_bytes(&path),
        Limits::default(),
    );
    let volume = open(&mut host, &["Volume"]);
    let vol = volume_span(&mut host, volume);
    let bytes = loop {
        match host.session.read(vol) {
            Ok(bytes) => break bytes,
            Err(requests) => host.supply(requests),
        }
    };
    assert_eq!(bytes.len(), 2_098_688);
    assert_eq!(fillyfoal::codec::crc32(&bytes), 0x890e_b059);
}

/// A cut image: the listing says where it ends, reads past the cut fail
/// with the reason, and what was saved before it is still there.
#[test]
fn truncated_images_report() {
    let mut img = header(8, 9 * CS as u64, 3);
    data(&mut img, 0x11, b"zero");
    gap(&mut img, 2);
    data(&mut img, 0x22, b"three");
    data(&mut img, 0x33, b"four");
    img.truncate(img.len() - 100);
    let mut host = Host::named("cut.img", img, Limits::default());
    let commands = open(&mut host, &["Commands"]);
    let tree = host.render();
    assert!(
        tree.contains("truncated: the image ends inside cluster 4"),
        "{tree}"
    );
    // The volume (whose head cannot be read whole: its expansion fails,
    // saying why), from where the listing points.
    let first = host.session.children(commands).unwrap().ids[0];
    let source = host.session.node(first).unwrap().target.unwrap().source;
    let vol = Span::new(source, 0, 9 * CS as u64);
    open(&mut host, &["Volume"]);
    let tree = host.render();
    assert!(
        tree.contains("decoding stopped: ntfsclone image ends inside cluster 4"),
        "{tree}"
    );
    let (bytes, _) = read_in_steps(&mut host, vol.sub(3 * CS as u64, 5), 1000);
    assert_eq!(bytes, b"three");
    let short = loop {
        match host.session.read(vol.sub(4 * CS as u64, CS as u64)) {
            Ok(bytes) => break bytes,
            Err(requests) => host.supply(requests),
        }
    };
    assert_eq!(short.len(), CS - 100);
}

/// Damage inside the stream is a diagnostic where the walk finds it.
#[test]
fn damaged_streams_report() {
    let mut img = header(8, 9 * CS as u64, 1);
    data(&mut img, 0x11, b"zero");
    img.push(0x07);
    let mut host = Host::named("bad.img", img, Limits::default());
    open(&mut host, &["Commands"]);
    let tree = host.render();
    assert!(tree.contains("unknown command 0x07"), "{tree}");

    // More clusters in use than saved; bytes after the last cluster.
    let mut img = header(2, 3 * CS as u64, 5);
    data(&mut img, 0x11, b"zero");
    gap(&mut img, 1);
    data(&mut img, 0x22, b"backup");
    img.extend_from_slice(b"extra");
    let mut host = Host::named("extra.img", img, Limits::default());
    open(&mut host, &["Commands"]);
    let tree = host.render();
    assert!(tree.contains("Trailing data"), "{tree}");
    assert!(tree.contains("5 bytes after the last cluster"), "{tree}");
    assert!(
        tree.contains("1 cluster saved before the backup boot sector; the header says 5 in use"),
        "{tree}"
    );
}
