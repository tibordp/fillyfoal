//! FSArchiver: the top level lists one node per filesystem (or one for the
//! directories of a `savedir` archive) without walking the data, each
//! section finds its start by walking the ones before it, and a section's
//! listing resumes from marks.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::Host;
use fillyfoal::{Limits, NodeId};

/// FSArchiver's Fletcher-32 (sums reduced every 360 bytes).
fn fletcher(data: &[u8]) -> u32 {
    let (mut a, mut b) = (0xffffu32, 0xffffu32);
    for chunk in data.chunks(360) {
        for &v in chunk {
            a = a.wrapping_add(u32::from(v));
            b = b.wrapping_add(a);
        }
        a = (a & 0xffff) + (a >> 16);
        b = (b & 0xffff) + (b >> 16);
    }
    let a = (a & 0xffff) + (a >> 16);
    let b = (b & 0xffff) + (b >> 16);
    (b << 16) | (a & 0xffff)
}

enum Item<'a> {
    Int(u16, u64),
    Str(u16, &'a str),
}

fn header(out: &mut Vec<u8>, magic: &[u8; 4], fs: u16, items: &[Item]) {
    let mut dico = (items.len() as u16).to_le_bytes().to_vec();
    for item in items {
        let (kind, key, data) = match item {
            Item::Int(key, v) => (4u8, *key, v.to_le_bytes().to_vec()),
            Item::Str(key, s) => (6u8, *key, [s.as_bytes(), b"\0"].concat()),
        };
        dico.extend_from_slice(&[kind, 0]);
        dico.extend_from_slice(&key.to_le_bytes());
        dico.extend_from_slice(&(data.len() as u16).to_le_bytes());
        dico.extend_from_slice(&data);
    }
    out.extend_from_slice(magic);
    out.extend_from_slice(&0x1234_5678u32.to_le_bytes());
    out.extend_from_slice(&fs.to_le_bytes());
    out.extend_from_slice(&(dico.len() as u32).to_le_bytes());
    out.extend_from_slice(&dico);
    out.extend_from_slice(&fletcher(&dico).to_le_bytes());
}

/// A savefs archive of two filesystems holding `n` and 3 directories.
fn archive(n: u32) -> Vec<u8> {
    let mut out = Vec::new();
    header(
        &mut out,
        b"FsA0",
        0xffff,
        &[Item::Int(0, 0), Item::Str(2, "FsArCh_002")],
    );
    header(
        &mut out,
        b"ArCh",
        0xffff,
        &[Item::Int(6, 1), Item::Int(8, 7), Item::Int(7, 2)],
    );
    for label in ["first", "second"] {
        header(
            &mut out,
            b"FsIn",
            0xffff,
            &[Item::Str(1, "ext4"), Item::Str(5, label)],
        );
    }
    for (fs, count) in [(0u16, n), (1, 3)] {
        header(&mut out, b"FsYs", fs, &[]);
        for i in 0..count {
            let path = format!("/dir{i:05}");
            header(
                &mut out,
                b"ObJt",
                fs,
                &[
                    Item::Int(1, u64::from(i)),
                    Item::Str(2, &path),
                    Item::Int(3, 1),
                    Item::Int(7, 0o40755),
                ],
            );
        }
        header(&mut out, b"DaEn", fs, &[]);
    }
    header(
        &mut out,
        b"FsAE",
        0xffff,
        &[Item::Int(0, 0), Item::Int(2, 1)],
    );
    out
}

fn host(data: Vec<u8>) -> Host {
    let mut host = Host::named(
        "test.fsa",
        data,
        Limits {
            chunk_size: 4096,
            ..Limits::default()
        },
    );
    host.max_polls = 10_000_000;
    host
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

const N: u32 = 20_000;

/// The top level is the headers, one node per filesystem and the footer,
/// read from the start and the end only.
#[test]
fn top_level_is_one_node_per_filesystem() {
    let data = archive(N);
    let len = data.len() as u64;
    let mut h = host(data);
    h.session.expand(h.root, 100);
    h.run();
    assert_eq!(
        names(&h, h.root),
        [
            "Volume header",
            "Archive header",
            "Filesystem 0",
            "Filesystem 1",
            "Volume footer"
        ],
        "{}",
        h.render()
    );
    // Identification reads the first 66 KiB and the last 1 KiB.
    assert!(
        h.bytes_supplied < 80 * 1024,
        "read {} of {len} bytes for the top level",
        h.bytes_supplied
    );

    // The second filesystem's start is found by walking the first's
    // headers; its listing is its own.
    let second = h.child(h.root, "Filesystem 1").unwrap();
    h.session.expand(second, 100);
    h.run();
    assert_eq!(
        names(&h, second),
        [
            "Filesystem info",
            "Filesystem start",
            "/dir00000",
            "/dir00001",
            "/dir00002",
            "Data end"
        ]
    );
}

/// Seeking back in a long filesystem listing restarts from a mark, with
/// the children a fresh walk gives.
#[test]
fn filesystem_listing_resumes() {
    let data = archive(N);
    let mut h = host(data.clone());
    h.session.expand(h.root, 100);
    h.run();
    let first = h.child(h.root, "Filesystem 0").unwrap();
    h.session.expand(first, 10);
    h.run();
    let before = h.session.work_done();
    h.session.seek(first, 18_000, 5);
    h.run();
    let forward = h.session.work_done() - before;
    let before = h.session.work_done();
    h.session.seek(first, 9_000, 5);
    h.run();
    let back = h.session.work_done() - before;
    assert!(
        back * 4 < forward,
        "seeking back took {back} work units, walking forward {forward}"
    );
    let resumed = names(&h, first);
    // Info and start come first: child 9000 is object 8998.
    assert_eq!(resumed[0], "/dir08998");

    let mut fresh = host(data);
    fresh.session.expand(fresh.root, 100);
    fresh.run();
    let id = fresh.child(fresh.root, "Filesystem 0").unwrap();
    fresh.session.seek(id, 9_000, 5);
    fresh.run();
    assert_eq!(names(&fresh, id), resumed);
}
