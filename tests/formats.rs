//! Every file under `tests/fixtures/{external,synthetic}/<format>/` is fully
//! explored and snapshotted, then truncated and mutated many ways to check
//! robustness. Adding a fixture file is all it takes to cover a new format.
//!
//! `external/` holds files written by other implementations (each listed in
//! `external/SOURCES.md`); `synthetic/` holds files we generated or wrote by
//! hand. Snapshots are named `formats__<format>__<file>` either way.
//!
//! `FIXTURE=substring cargo test --test formats` restricts the run.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The two fixture trees: files from other implementations, and our own.
const TREES: [&str; 2] = ["external", "synthetic"];

/// Documentation kept at the root of each tree, not fixtures.
const TREE_DOCS: [&str; 2] = ["SOURCES.md", "README.md"];

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn sorted_entries(dir: &Path) -> Vec<PathBuf> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    entries
}

/// Every fixture of one tree, as `<tree>/<format>/<file>` paths.
fn tree_fixtures(tree: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for format in sorted_entries(&fixtures_root().join(tree)) {
        if format.is_dir() {
            out.extend(sorted_entries(&format));
        }
    }
    out
}

fn fixtures() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = TREES.iter().flat_map(|tree| tree_fixtures(tree)).collect();
    // Same order as a single tree: by format, then file.
    out.sort_by_key(|p| snapshot_name(p));
    let filter = std::env::var("FIXTURE").unwrap_or_default();
    out.retain(|p| p.to_string_lossy().contains(&filter));
    out
}

/// Fixture bytes. Large, mostly-empty images (disk images identified by
/// their exact size) are stored gzip-compressed as `*.gz` outside
/// `fixtures/gzip/`; they are decompressed with our own inflate.
fn load(path: &Path) -> Vec<u8> {
    let data = std::fs::read(path).unwrap();
    let in_gzip_dir = path
        .parent()
        .and_then(|p| p.file_name())
        .is_some_and(|n| n == "gzip");
    if path.extension().is_some_and(|e| e == "gz") && !in_gzip_dir {
        assert_eq!(
            data[3] & 0x1e,
            0,
            "{}: write fixtures with `gzip -n`",
            path.display()
        );
        return fillyfoal::codec::inflate::inflate(&data[10..], 64 << 20).unwrap();
    }
    data
}

fn display_name(path: &Path) -> String {
    let name = path.file_name().unwrap().to_string_lossy().into_owned();
    let in_gzip_dir = path
        .parent()
        .and_then(|p| p.file_name())
        .is_some_and(|n| n == "gzip");
    match name.strip_suffix(".gz") {
        Some(stem) if !in_gzip_dir => stem.to_owned(),
        _ => name,
    }
}

/// `<format>__<file>`: the tree a fixture lives in is not part of its name,
/// so moving a fixture between trees leaves its snapshot alone.
fn snapshot_name(path: &Path) -> String {
    let rel = path.strip_prefix(fixtures_root()).unwrap();
    let mut parts = rel.components();
    parts.next(); // the tree
    parts.as_path().to_string_lossy().replace(['/', '\\'], "__")
}

#[test]
fn fixtures_snapshot() {
    for path in fixtures() {
        let data = load(&path);
        insta::assert_snapshot!(
            snapshot_name(&path),
            common::explore(&display_name(&path), &data)
        );
    }
}

#[test]
fn fixtures_are_robust() {
    // Fixtures are independent; sweep them on all cores.
    let paths = fixtures();
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let next = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(path) = paths.get(i) else { break };
                    let data = load(path);
                    common::robustness(&snapshot_name(path), &data);
                }
            });
        }
    });
}

/// The directory a fixture lives in names the format it must be identified
/// as. This catches probes that are too greedy (or too strict) as formats
/// accumulate.
#[test]
fn fixtures_are_identified_correctly() {
    use fillyfoal::formats::{HEAD_LEN, Head, TAIL_LEN, identify};
    let mut wrong = Vec::new();
    for path in fixtures() {
        let data = load(&path);
        let expected = path
            .parent()
            .and_then(|p| p.file_name())
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let head = &data[..data.len().min(HEAD_LEN as usize)];
        let tail = &data[data.len().saturating_sub(TAIL_LEN as usize)..];
        let probe = Head {
            data: head,
            tail,
            len: data.len() as u64,
        };
        let found = identify(&probe).map(|f| f.name);
        if found != Some(expected.as_str()) {
            wrong.push(format!(
                "{}: expected {expected}, got {found:?}",
                snapshot_name(&path)
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "misidentified fixtures:\n{}",
        wrong.join("\n")
    );
}

/// Every fixture is either external or synthetic (never both, never
/// neither), sits at `<tree>/<format>/<file>`, and every external one is
/// accounted for in `external/SOURCES.md` (whose entries must all exist).
#[test]
fn fixtures_are_classified() {
    let root = fixtures_root();
    let mut problems = Vec::new();

    for entry in sorted_entries(&root) {
        let name = entry.file_name().unwrap().to_string_lossy().into_owned();
        if !(entry.is_dir() && TREES.contains(&name.as_str())) {
            problems.push(format!(
                "tests/fixtures/{name}: fixtures go in external/ or synthetic/"
            ));
        }
    }

    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut external: BTreeSet<String> = BTreeSet::new();
    for tree in TREES {
        for entry in sorted_entries(&root.join(tree)) {
            let name = entry.file_name().unwrap().to_string_lossy().into_owned();
            if entry.is_dir() {
                for file in sorted_entries(&entry) {
                    if file.is_dir() {
                        problems.push(format!(
                            "{tree}/{name}/{}: nested directory (use <format>/<file>)",
                            file.file_name().unwrap().to_string_lossy()
                        ));
                    }
                }
            } else if !TREE_DOCS.contains(&name.as_str()) {
                problems.push(format!("{tree}/{name}: not in a <format>/ directory"));
            }
        }
        for path in tree_fixtures(tree) {
            if path.is_dir() {
                continue;
            }
            let rel = path
                .strip_prefix(root.join(tree))
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if !seen.insert(rel.clone()) {
                problems.push(format!(
                    "{rel}: in both trees (snapshot names would collide)"
                ));
            }
            if tree == "external" {
                external.insert(rel);
            }
        }
    }

    // SOURCES.md lists fixtures as table rows: | `<format>/<file>` | ... |,
    // or `<format>/` for a whole directory with one producer.
    let sources = std::fs::read_to_string(root.join("external/SOURCES.md")).unwrap();
    let mut listed_files = BTreeSet::new();
    let mut listed_dirs = BTreeSet::new();
    for line in sources.lines() {
        let Some(rest) = line.trim_start().strip_prefix("| `") else {
            continue;
        };
        let Some(end) = rest.find('`') else { continue };
        let entry = rest.get(..end).unwrap_or_default().to_owned();
        if let Some(dir) = entry.strip_suffix('/') {
            if !external.iter().any(|f| f.starts_with(&entry)) {
                problems.push(format!(
                    "SOURCES.md lists {entry}, which has no external fixtures"
                ));
            }
            listed_dirs.insert(dir.to_owned());
        } else {
            if !external.contains(&entry) {
                problems.push(format!(
                    "SOURCES.md lists {entry}, which is not an external fixture"
                ));
            }
            listed_files.insert(entry);
        }
    }
    for rel in &external {
        let dir = rel.split('/').next().unwrap_or_default();
        if !listed_files.contains(rel) && !listed_dirs.contains(dir) {
            problems.push(format!("external/{rel}: not listed in external/SOURCES.md"));
        }
    }

    assert!(
        problems.is_empty(),
        "fixture classification:\n{}",
        problems.join("\n")
    );
}

#[test]
fn format_names_are_unique() {
    let mut names: Vec<&str> = fillyfoal::formats::FORMATS.iter().map(|f| f.name).collect();
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(before, names.len(), "duplicate format names");
}
