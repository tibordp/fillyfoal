//! RedSea (TempleOS) volumes: the tree against the files the generator
//! packed, bounded work on hostile directories, and (with
//! `TEMPLEOS_ISO=<TempleOS.ISO>:<manifest.tsv>`) every file of the real
//! distribution ISO.

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

fn expand(host: &mut Host, id: NodeId) -> Vec<NodeId> {
    host.session.expand_more(id, 1 << 20);
    host.run();
    let children = host.session.children(id).unwrap();
    if let Some(e) = children.error {
        panic!("{}: {e}", host.session.node(id).unwrap().name);
    }
    children.ids.to_vec()
}

fn name(host: &Host, id: NodeId) -> String {
    host.session.node(id).unwrap().name.to_string()
}

fn child(host: &mut Host, id: NodeId, wanted: &str) -> NodeId {
    expand(host, id)
        .into_iter()
        .find(|&c| name(host, c) == wanted)
        .unwrap_or_else(|| panic!("no {wanted:?}"))
}

/// Files found under directory node `dir` (path, node), recursively.
fn walk(host: &mut Host, dir: NodeId, path: &str, out: &mut Vec<(String, NodeId, bool)>) {
    for c in expand(host, dir) {
        let n = name(host, c);
        if n == "." || n == ".." {
            continue;
        }
        let summary = host
            .session
            .node(c)
            .unwrap()
            .summary
            .clone()
            .unwrap_or_default();
        let p = format!("{path}/{n}");
        if summary.starts_with("directory") {
            out.push((p.clone(), c, true));
            walk(host, c, &p, out);
        } else {
            out.push((p, c, false));
        }
    }
}

/// Opens the RedSea root directory of `data` (bare, or inside a TempleOS
/// ISO) and lists every entry.
fn list(host: &mut Host) -> Vec<(String, NodeId, bool)> {
    let mut vol = host.root;
    let top = expand(host, vol);
    if let Some(&v) = top.iter().find(|&&c| name(host, c) == "RedSea file system") {
        vol = v;
    }
    let root = child(host, vol, "Root directory");
    let mut out = Vec::new();
    walk(host, root, "", &mut out);
    out
}

/// Expands a file node and its `.Z` content down to the expanded data,
/// checking that nothing on the way reports damage.
fn check_file(host: &mut Host, path: &str, file: NodeId) {
    let content = child(host, file, "Content");
    if !path.ends_with(".Z") {
        return;
    }
    let expanded = child(host, content, "Expanded");
    expand(host, expanded);
    let mut stack = vec![file];
    while let Some(id) = stack.pop() {
        let node = host.session.node(id).unwrap();
        for d in &node.diagnostics {
            assert!(
                !matches!(
                    d.kind,
                    DiagKind::Malformed | DiagKind::Truncated | DiagKind::Internal
                ),
                "{path}: {d}"
            );
        }
        stack.extend(host.session.children(id).unwrap().ids.iter().copied());
    }
}

fn fixture(rel: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel);
    common::fixture_bytes(&path)
}

/// The generator's tree, bare, in an MBR partition and in an ISO; every
/// file's content dissects without damage.
#[test]
fn generated_images() {
    for (rel, deleted) in [
        ("synthetic/redsea/templeos.img.gz", true),
        ("synthetic/mbr/templeos-redsea.img.gz", true),
        ("synthetic/templeos-iso/templeos.iso.gz", false),
    ] {
        let mut host = Host::named("t", fixture(rel), Limits::default());
        if rel.contains("mbr") {
            // MBR → partition 1 → its volume.
            let root = host.root;
            let top = expand(&mut host, root);
            let part = top
                .into_iter()
                .find(|&c| name(&host, c).starts_with("Partition 1"))
                .unwrap();
            let vol = child(&mut host, part, "Volume");
            host.root = vol;
        }
        let entries = list(&mut host);
        let mut paths: Vec<&str> = entries.iter().map(|(p, _, _)| p.as_str()).collect();
        paths.sort();
        let mut want = vec![
            "/DateTime.HC",
            "/Demo",
            "/Demo/DateTime.HC.Z",
            "/Doc",
            "/Doc/FileLowLevel.DD.Z",
        ];
        if deleted {
            want.push("/Doc/Old.DD.Z");
        }
        assert_eq!(paths, want, "{rel}");
        for (path, id, dir) in &entries {
            if !dir {
                check_file(&mut host, path, *id);
            }
        }
    }
}

/// The ISO TempleOS wrote itself (`RedSeaISO` in QEMU).
#[test]
fn templeos_written_iso() {
    let mut host = Host::named(
        "t.iso",
        fixture("external/templeos-iso/templeos-redseaiso.iso.gz"),
        Limits::default(),
    );
    let entries = list(&mut host);
    let paths: Vec<&str> = entries.iter().map(|(p, _, _)| p.as_str()).collect();
    assert_eq!(paths, ["/Doc", "/Doc/FileLowLevel.DD.Z", "/DateTime.HC.Z"]);
    for (path, id, dir) in &entries {
        if !dir {
            check_file(&mut host, path, *id);
        }
    }
}

fn put_i64(img: &mut [u8], at: usize, v: i64) {
    img[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

/// A directory that claims to be huge is listed up to a bound, one that
/// contains its ancestor is not followed, and the work stays small.
#[test]
fn hostile_directories_are_bounded() {
    let mut img = fixture("synthetic/redsea/templeos.img.gz");
    // Root directory (block 2): "." claims 2^40 bytes.
    put_i64(&mut img, 2 * 512 + 48, 1 << 40);
    // /Doc/FileLowLevel.DD.Z (Doc at block 5, third entry) becomes a
    // directory pointing back at the root.
    let e = 5 * 512 + 2 * 64;
    img[e..e + 2].copy_from_slice(&0x810u16.to_le_bytes());
    put_i64(&mut img, e + 40, 2);
    let mut host = Host::named("t.img", img, Limits::default());
    let entries = list(&mut host);
    assert!(
        entries
            .iter()
            .any(|(p, _, _)| p == "/Doc/FileLowLevel.DD.Z")
    );
    let kinds = common::diagnostic_kinds(&host);
    assert!(kinds.contains(&DiagKind::Limit), "{kinds:?}");
    assert!(kinds.contains(&DiagKind::Malformed), "{kinds:?}");
    let work = host.session.work_done();
    assert!(work < 200_000, "{work}");
}

/// A `.Z` file whose header claims far more than its codes can make (so
/// the probe declines it; it is opened as `templeos-z`) stops
/// where the codes end, with bounded work.
#[test]
fn compressed_size_claims_are_bounded() {
    let mut z = fixture("external/templeos-z/DateTime.HC.Z");
    z[8..16].copy_from_slice(&(1u64 << 28).to_le_bytes());
    let format = fillyfoal::formats::by_name("templeos-z").unwrap();
    let mut host = Host::open("t.HC.Z", z, Limits::default(), Some(format));
    host.explore_all();
    let kinds = common::diagnostic_kinds(&host);
    assert!(
        kinds.contains(&DiagKind::Malformed) || kinds.contains(&DiagKind::Limit),
        "{kinds:?}\n{}",
        host.render()
    );
    let work = host.session.work_done();
    assert!(work < 200_000, "{work}");
}

/// The real TempleOS V5.03 ISO: every file `tests/data/redsea/extract.py`
/// lists is in the tree with its size, and every `.Z` file expands.
#[test]
fn templeos_iso() {
    let Ok(spec) = std::env::var("TEMPLEOS_ISO") else {
        return;
    };
    let (iso, manifest) = spec.split_once(':').unwrap();
    let data = std::fs::read(iso).unwrap();
    let mut host = Host::named("TempleOS.ISO", data, Limits::default());
    let entries = list(&mut host);
    let root = host.root;
    let format = host.session.interpretation(root).unwrap().format;
    assert_eq!(format.map(|f| f.name), Some("templeos-iso"));
    let manifest = std::fs::read_to_string(manifest).unwrap();
    let mut want: Vec<(String, bool)> = manifest
        .lines()
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            let attr = u16::from_str_radix(f[1].trim_start_matches("0x"), 16).unwrap();
            (f[0].to_owned(), attr & 0x10 != 0)
        })
        .collect();
    let mut got: Vec<(String, bool)> = entries.iter().map(|(p, _, d)| (p.clone(), *d)).collect();
    want.sort();
    got.sort();
    assert_eq!(got, want);
    let files: Vec<_> = entries.into_iter().filter(|e| !e.2).collect();
    for (path, id, _) in &files {
        check_file(&mut host, path, *id);
    }
    eprintln!("{} files, {} entries", files.len(), want.len());
}

/// A TempleOS ISO is `templeos-iso`, its `CISOPriDesc` fields read as
/// TempleOS writes them; the same bytes without the RedSea volume fall
/// through to `iso9660`, as an ordinary but damaged ISO that warns.
#[test]
fn templeos_iso_needs_redsea() {
    let iso = fixture("external/templeos-iso/templeos-redseaiso.iso.gz");
    let tree = common::explore("t.iso", &iso);
    assert!(
        tree.contains("TempleOS RedSea ISO, 48 KiB, El Torito"),
        "{tree}"
    );
    assert!(tree.contains("publisher_id: \"TempleOS RedSea\""), "{tree}");
    assert!(!tree.contains("warning"), "{tree}");
    let mut plain = iso;
    plain[0xb000..0xb200].fill(0);
    let tree = common::explore("t.iso", &plain);
    assert!(!tree.contains("TempleOS RedSea ISO"), "{tree}");
    assert!(tree.contains("ISO 9660 image"), "{tree}");
    assert!(tree.contains("copies differ"), "{tree}");
    assert!(tree.contains("Path table (optional M)"), "{tree}");
}
