//! Every file under `tests/fixtures/<format>/` is fully explored and
//! snapshotted, then truncated and mutated many ways to check robustness.
//! Adding a fixture file is all it takes to cover a new format.
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

use std::path::{Path, PathBuf};

fn fixtures() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push(path);
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut out = Vec::new();
    walk(&root, &mut out);
    let filter = std::env::var("FIXTURE").unwrap_or_default();
    out.retain(|p| p.to_string_lossy().contains(&filter));
    out
}

/// Fixture bytes. Large, mostly-empty images (disk images identified by
/// their exact size) are stored gzip-compressed as `*.gz` outside
/// `fixtures/gzip/`; they are decompressed with our own inflate.
fn load(path: &Path) -> Vec<u8> {
    let data = std::fs::read(path).unwrap();
    let in_gzip_dir = path.parent().and_then(|p| p.file_name()).is_some_and(|n| n == "gzip");
    if path.extension().is_some_and(|e| e == "gz") && !in_gzip_dir {
        assert_eq!(data[3] & 0x1e, 0, "{}: write fixtures with `gzip -n`", path.display());
        return fillyfoal::codec::inflate::inflate(&data[10..], 64 << 20).unwrap();
    }
    data
}

fn display_name(path: &Path) -> String {
    let name = path.file_name().unwrap().to_string_lossy().into_owned();
    let in_gzip_dir = path.parent().and_then(|p| p.file_name()).is_some_and(|n| n == "gzip");
    match name.strip_suffix(".gz") {
        Some(stem) if !in_gzip_dir => stem.to_owned(),
        _ => name,
    }
}

fn snapshot_name(path: &Path) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    path.strip_prefix(root)
        .unwrap()
        .to_string_lossy()
        .replace(['/', '\\'], "__")
}

#[test]
fn fixtures_snapshot() {
    for path in fixtures() {
        let data = load(&path);
        insta::assert_snapshot!(snapshot_name(&path), common::explore(&display_name(&path), &data));
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
            scope.spawn(|| loop {
                let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let Some(path) = paths.get(i) else { break };
                let data = load(path);
                common::robustness(&snapshot_name(path), &data);
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

#[test]
fn format_names_are_unique() {
    let mut names: Vec<&str> = fillyfoal::formats::FORMATS.iter().map(|f| f.name).collect();
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(before, names.len(), "duplicate format names");
}
