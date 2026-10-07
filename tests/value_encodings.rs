//! Binary value encodings without a magic number (MessagePack, UBJSON,
//! BSON): their probes must not claim other formats' fixtures, and data
//! the probes deliberately leave alone is still dissected when the format
//! is chosen by extension ("inspect as").

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use std::path::{Path, PathBuf};

use common::Host;
use fillyfoal::formats::{self, HEAD_LEN, Head, Probe, TAIL_LEN};

const MAGICLESS: [&str; 3] = ["msgpack", "ubjson", "bson"];

fn probe(name: &str, data: &[u8]) -> bool {
    let format = formats::by_name(name).unwrap();
    let head = Head {
        data: &data[..data.len().min(HEAD_LEN as usize)],
        tail: &data[data.len().saturating_sub(TAIL_LEN as usize)..],
        len: data.len() as u64,
    };
    match &format.probe {
        Probe::Custom(f) => f(&head),
        Probe::Magic(_) | Probe::Never => panic!("{name} has no custom probe"),
    }
}

fn fixtures() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut out = Vec::new();
    for tree in ["external", "synthetic"] {
        for dir in std::fs::read_dir(root.join(tree)).unwrap().flatten() {
            if dir.path().is_dir() {
                out.extend(std::fs::read_dir(dir.path()).unwrap().flatten().map(|e| e.path()));
            }
        }
    }
    out.sort();
    out
}

/// Whatever comes first in probe order, these probes must not match any
/// other format's fixture: they would claim such files where they are
/// tried first (for example inside containers) and lie to mime sniffing.
#[test]
fn magicless_probes_claim_only_their_own_fixtures() {
    let mut wrong = Vec::new();
    for path in fixtures() {
        let data = std::fs::read(&path).unwrap();
        let dir = path.parent().unwrap().file_name().unwrap().to_string_lossy().into_owned();
        for name in MAGICLESS {
            if probe(name, &data) != (dir == name) {
                wrong.push(format!("{}: {name} probe says {}", path.display(), dir != name));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn magicless_probes_reject_lookalikes() {
    // JSON text, an empty map/object, a lone small map, data after a value.
    for data in [
        &b"{\"a\": 1}"[..],
        b"{}",
        b"\x80",
        b"\x82\xa1a\x01\xa1b\x02\x00",
        b"{U\x01ai\x01}garbage",
        b"\x05\x00\x00\x00\x00",
    ] {
        for name in MAGICLESS {
            assert!(!probe(name, data), "{name} claims {data:?}");
        }
    }
    // A sequence of MessagePack values or a top-level array: by extension only.
    let stream = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/msgpack/stream.msgpack")).unwrap();
    assert!(!probe("msgpack", &stream));
    let array = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/ubjson/array.ubj")).unwrap();
    assert!(!probe("ubjson", &array));
}

/// Opens `file` (under tests/data) as the format its extension names and
/// renders the whole tree.
fn open_as(file: &str, extension: &str, format: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data").join(file);
    let data = std::fs::read(path).unwrap();
    assert!(formats::by_extension(extension).iter().any(|f| f.name == format));
    let len = data.len() as u64;
    let mut host = Host::with_chunk(data, 64);
    let root = host.session.open_as(file.to_owned(), len, formats::by_name(format).unwrap());
    host.explore(root, 8, 100);
    fillyfoal::render::tree(&host.session, root)
}

#[test]
fn msgpack_stream_by_extension() {
    let tree = open_as("msgpack/stream.msgpack", "msgpack", "msgpack");
    for line in [
        "MessagePack, first value: array, 3 elements",
        "[1]: \"second value\"",
        "tags — array, 2 elements",
        "timestamp extension, 8 bytes: 1970-01-01 00:00:00.000000001 UTC",
        "[4] — nil",
    ] {
        assert!(tree.contains(line), "{line:?} missing from\n{tree}");
    }
    assert!(!tree.contains("! "), "diagnostics in\n{tree}");
}

#[test]
fn ubjson_array_by_extension() {
    let tree = open_as("ubjson/array.ubj", "ubj", "ubjson");
    for line in ["UBJSON array, 4 elements", "[1]: \"two\"", "three: 3", "uint8 array, 1 byte"] {
        assert!(tree.contains(line), "{line:?} missing from\n{tree}");
    }
    assert!(!tree.contains("! "), "diagnostics in\n{tree}");
}

/// Deep nesting, huge counts and unterminated containers, opened as each
/// format: every expansion settles, without internal errors or runaway
/// work.
#[test]
fn pathological_inputs_settle() {
    let mut cases: Vec<(&str, Vec<u8>)> = vec![
        ("msgpack", [&b"\x81\xa1a"[..], &[0x91; 100_000], b"\x01"].concat()),
        ("msgpack", b"\x82\xa1a\xdd\xff\xff\xff\xff\x01\xa1b\x02".to_vec()),
        ("ubjson", [&b"{U\x01a[$Z#L"[..], &(1u64 << 62).to_be_bytes(), b"}"].concat()),
        ("ubjson", [vec![b'['; 100_000], vec![b']'; 100_000]].concat()),
        ("smile", [&b":)\n\x03"[..], &[0xf8; 100_000]].concat()),
        ("smile", [&b":)\n\x03\xfa"[..], &[0x40; 1000]].concat()),
        ("ion-text", [&b"$ion_1_0 "[..], &[b'['; 100_000]].concat()),
        // Annotation wrappers nested in each other.
        ("ion", [&b"\xe0\x01\x00\xea"[..], &[0xbe, 0x8f, 0xbe, 0x8c, 0xbe, 0x89, 0xbe, 0x86, 0xbe, 0x83, 0xbe, 0x80]].concat()),
    ];
    // BSON documents nested 1,000 deep.
    let mut doc = b"\x05\x00\x00\x00\x00".to_vec();
    for _ in 0..1000 {
        let mut outer = vec![0, 0, 0, 0, 0x03, b'a', 0];
        outer.extend(&doc);
        outer.push(0);
        let len = outer.len() as u32;
        outer[..4].copy_from_slice(&len.to_le_bytes());
        doc = outer;
    }
    cases.push(("bson", doc));
    for (format, data) in cases {
        let len = data.len() as u64;
        let mut host = Host::new(
            data,
            fillyfoal::Limits {
                chunk_size: 4096,
                max_work: 5_000_000,
                ..fillyfoal::Limits::default()
            },
        );
        host.max_polls = 200_000;
        host.max_nodes = 20_000;
        let root = host.session.open_as("case", len, formats::by_name(format).unwrap());
        host.explore(root, 300, 1000);
        let tree = fillyfoal::render::tree(&host.session, root);
        assert!(!tree.contains("internal"), "{format}: {tree}");
        assert!(!tree.contains("units of work"), "{format}: runaway\n{tree}");
    }
}
