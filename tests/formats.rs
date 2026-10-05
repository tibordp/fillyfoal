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
        let data = std::fs::read(&path).unwrap();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        insta::assert_snapshot!(snapshot_name(&path), common::explore(&name, &data));
    }
}

#[test]
fn fixtures_are_robust() {
    for path in fixtures() {
        let data = std::fs::read(&path).unwrap();
        common::robustness(&snapshot_name(&path), &data);
    }
}
