//! NTFS volumes written by Windows 11 (fixed VHDs from DiskPart, see
//! `tests/fixtures/external/SOURCES.md`): WOF (XPRESS4K/8K/16K, LZX) and
//! LZNT1 compressed files decompress to exactly the text the generator
//! wrote, and attribute lists (resident and non-resident, from named
//! streams and from hard links) bring every attribute back.

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
        .join("tests/fixtures/external/vhd")
        .join(format!("{name}.raw.zst"));
    Host::named(name, common::fixture_bytes(&path), Limits::default())
}

const VOLUME: [&str; 4] = ["Virtual disk", "Partition 1", "Volume", "Root directory"];

fn open(host: &mut Host, path: &[&str]) -> NodeId {
    let mut id = host.root;
    for name in VOLUME.iter().chain(path) {
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

fn names(host: &Host, id: NodeId) -> Vec<String> {
    host.session
        .children(id)
        .unwrap()
        .ids
        .iter()
        .map(|&c| host.session.node(c).unwrap().name.to_string())
        .collect()
}

fn read(host: &mut Host, span: Span) -> Vec<u8> {
    loop {
        match host.session.read(span) {
            Ok(bytes) => return bytes,
            Err(requests) => host.supply(requests),
        }
    }
}

/// The text `tests/data/windows/ntfs/build.ps1` (`New-SyntheticText`)
/// wrote: numbered lines, cut to 320 KiB.
fn synthetic(tag: &str) -> Vec<u8> {
    let mut text = String::new();
    let mut i = 0u32;
    while text.len() < 320 * 1024 {
        text.push_str(&format!(
            "fillyfoal test {tag} line {i:06}: lorem ipsum dolor sit amet, consectetur adipiscing elit, value {}\r\n",
            (i * 7919) % 1000
        ));
        i += 1;
    }
    text.truncate(320 * 1024);
    text.into_bytes()
}

fn content(host: &mut Host, path: &[&str]) -> Vec<u8> {
    let file = open(host, path);
    let content = host
        .child(file, "Content")
        .unwrap_or_else(|| panic!("no content under:\n{}", host.render()));
    let span = host.session.node(content).unwrap().span.unwrap();
    // Compressed content is dissected from a derived source: read that
    // one whole (its children's source), not the encoded span.
    host.session.expand_more(content, 10);
    host.run();
    let source = host
        .session
        .children(content)
        .and_then(|c| c.ids.first().copied())
        .and_then(|c| host.session.node(c).and_then(|n| n.span))
        .map_or(span.source, |s| s.source);
    if source == span.source {
        return read(host, span);
    }
    let len = host.session.source_len(source);
    read(host, Span::new(source, 0, len))
}

#[test]
fn wof_files_decompress_to_what_was_written() {
    let mut host = host("ntfs-wof.vhd");
    for algorithm in ["xpress4k", "xpress8k", "xpress16k", "lzx"] {
        let name = format!("wof-{algorithm}.txt");
        let got = content(&mut host, &[name.as_str()]);
        assert!(
            got == synthetic(&format!("wof-{algorithm}")),
            "{name}: {} bytes differ",
            got.len()
        );
    }
    let got = content(&mut host, &["uncompressed-control.txt"]);
    assert!(got == synthetic("uncompressed"));
}

#[test]
fn lznt1_files_decompress_to_what_was_written() {
    let mut host = host("ntfs-lznt1.vhd");
    assert!(content(&mut host, &["lznt1-file.txt"]) == synthetic("lznt1-file"));
    assert!(
        content(&mut host, &["lznt1-dir", "inside-compressed-dir.txt"]) == synthetic("lznt1-dir")
    );
}

#[test]
fn attribute_lists_bring_back_every_attribute() {
    let mut host = host("ntfs-attrlist.vhd");
    let streams = |host: &Host, id| {
        names(host, id)
            .into_iter()
            .filter(|n| n.starts_with("$DATA:stream"))
            .count()
    };
    let id = open(&mut host, &["attrlist-resident.txt"]);
    assert_eq!(streams(&host, id), 6);
    let id = open(&mut host, &["attrlist-nonresident.txt"]);
    assert_eq!(streams(&host, id), 60);
    for (dir, links) in [
        ("attrlist-resident-hardlinks", 7),
        ("attrlist-nonresident-hardlinks", 11),
    ] {
        let id = open(&mut host, &[dir, "target.txt"]);
        let file_names = names(&host, id)
            .into_iter()
            .filter(|n| n == "$FILE_NAME")
            .count();
        // Each link has a Win32 name and, being long, a DOS name.
        assert!(file_names >= links, "{dir}: {file_names} names");
        assert!(content(&mut host, &[dir, "target.txt"]) == b"fillyfoal test hard link target\r\n");
    }
}
