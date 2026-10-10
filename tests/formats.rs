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

/// Fixture bytes. Large, mostly-empty disk images are stored compressed
/// (`*.raw.zst`, or `*.gz` outside `fixtures/gzip/`) and decompressed here;
/// see `common::fixture_bytes`. Their snapshots keep the stored file name.
fn load(path: &Path) -> Vec<u8> {
    common::fixture_bytes(path)
}

fn display_name(path: &Path) -> String {
    common::fixture_name(path)
}

/// `<format>__<file>`: the tree a fixture lives in is not part of its name,
/// so moving a fixture between trees leaves its snapshot alone.
fn snapshot_name(path: &Path) -> String {
    let rel = path.strip_prefix(fixtures_root()).unwrap();
    let mut parts = rel.components();
    parts.next(); // the tree
    parts.as_path().to_string_lossy().replace(['/', '\\'], "__")
}

/// The format a fixture is dissected as without identification: the one
/// its directory names, if that format is never identified by content
/// (`Probe::Never`; such formats are chosen by extension or by hand).
fn chosen_format(path: &Path) -> Option<&'static fillyfoal::formats::Format> {
    let dir = path.parent()?.file_name()?.to_str()?;
    fillyfoal::formats::by_name(dir).filter(|f| matches!(f.probe, fillyfoal::formats::Probe::Never))
}

#[test]
fn fixtures_snapshot() {
    for path in fixtures() {
        let data = load(&path);
        // Two calls, so the expression recorded in existing snapshots
        // stays the same.
        match chosen_format(&path) {
            Some(format) => insta::assert_snapshot!(
                snapshot_name(&path),
                common::explore_as(&display_name(&path), &data, Some(format))
            ),
            None => insta::assert_snapshot!(
                snapshot_name(&path),
                common::explore(&display_name(&path), &data)
            ),
        }
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
                    common::robustness_as(&snapshot_name(path), &data, chosen_format(path));
                }
            });
        }
    });
}

/// Tiny chunks, tiny budgets, short pages and little derived memory change
/// how often expansions suspend, restart and re-decode, never what they
/// produce. Slow; run on demand: `cargo test --test formats -- --ignored`.
#[test]
#[ignore]
fn fixtures_are_invariant_under_host_pressure() {
    let paths = fixtures();
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let next = std::sync::atomic::AtomicUsize::new(0);
    let failures = std::sync::Mutex::new(Vec::new());
    let compared = std::sync::atomic::AtomicUsize::new(0);
    let polls = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(path) = paths.get(i) else { break };
                    let data = load(path);
                    if data.len() > common::LARGE_FIXTURE {
                        continue;
                    }
                    let name = display_name(path);
                    let expected = common::explore_as(&name, &data, chosen_format(path));
                    let mut host = common::Host::open(
                        &name,
                        data,
                        fillyfoal::Limits {
                            chunk_size: std::env::var("PRESSURE_CHUNK")
                                .ok()
                                .and_then(|v| v.parse().ok())
                                .unwrap_or(512),
                            max_derived: std::env::var("PRESSURE_DERIVED")
                                .ok()
                                .and_then(|v| v.parse().ok())
                                .unwrap_or(64 << 20),
                            ..fillyfoal::Limits::default()
                        },
                        chosen_format(path),
                    );
                    host.budget = std::env::var("PRESSURE_BUDGET")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(37);
                    host.max_polls = 50_000_000;
                    host.explore(
                        host.root,
                        24,
                        std::env::var("PRESSURE_PAGE")
                            .ok()
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(7),
                    );
                    let got = host.render();
                    compared.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    polls.fetch_add(host.polls as usize, std::sync::atomic::Ordering::Relaxed);
                    if got != expected {
                        let diff: Vec<String> = expected
                            .lines()
                            .zip(got.lines())
                            .filter(|(a, b)| a != b)
                            .take(3)
                            .map(|(a, b)| format!("- {a}\n+ {b}"))
                            .collect();
                        failures.lock().unwrap().push(format!(
                            "{}:\n{}",
                            snapshot_name(path),
                            diff.join("\n")
                        ));
                    }
                }
            });
        }
    });
    let failures = failures.into_inner().unwrap();
    eprintln!(
        "compared {} fixtures, {} polls",
        compared.into_inner(),
        polls.into_inner()
    );
    assert!(
        failures.is_empty(),
        "{} fixtures differ:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Random host behaviour (expanding, seeking windows back and forth,
/// collapsing, trimming, polling single nodes) must keep every child at
/// its index and leave a session that explores to the same tree. Slow; run
/// on demand: `cargo test --test formats -- --ignored`.
#[test]
#[ignore]
fn fixtures_survive_random_host_behaviour() {
    let paths: Vec<_> = fixtures()
        .into_iter()
        .step_by(
            std::env::var("FUZZ_STEP")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(7),
        )
        .collect();
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let next = std::sync::atomic::AtomicUsize::new(0);
    let failures = std::sync::Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(path) = paths.get(i) else { break };
                    let data = load(path);
                    if data.len() > common::LARGE_FIXTURE {
                        continue;
                    }
                    let name = display_name(path);
                    let expected = common::explore_as(&name, &data, chosen_format(path));
                    let mut host = common::Host::open(
                        &name,
                        data,
                        fillyfoal::Limits {
                            chunk_size: 64,
                            ..fillyfoal::Limits::default()
                        },
                        chosen_format(path),
                    );
                    host.budget = 200;
                    let mut rng = common::Rng(0x9e37_79b9_7f4a_7c15 ^ i as u64);
                    if let Err(e) = random_walk(
                        &mut host,
                        &mut rng,
                        std::env::var("FUZZ_STEPS")
                            .ok()
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(300),
                    ) {
                        failures
                            .lock()
                            .unwrap()
                            .push(format!("{}: {e}", snapshot_name(path)));
                        continue;
                    }
                    // Back to a clean slate: everything must come out the same.
                    host.session.collapse(host.root);
                    host.explore(host.root, 24, 1000);
                    // Derived sources are numbered in the order they were
                    // made, which depends on the walk; compare them by order
                    // of appearance.
                    let got = renumber_sources(&host.render());
                    let expected = renumber_sources(&expected);
                    if got != expected {
                        if let Ok(dir) = std::env::var("FUZZ_DUMP") {
                            std::fs::write(format!("{dir}/expected.txt"), &expected).unwrap();
                            std::fs::write(format!("{dir}/got.txt"), &got).unwrap();
                        }
                        let diff: Vec<String> = expected
                            .lines()
                            .zip(got.lines())
                            .filter(|(a, b)| a != b)
                            .take(2)
                            .map(|(a, b)| format!("- {a}\n+ {b}"))
                            .collect();
                        failures.lock().unwrap().push(format!(
                            "{}: differs after random walk ({} vs {} lines)\n{}",
                            snapshot_name(path),
                            expected.lines().count(),
                            got.lines().count(),
                            diff.join("\n")
                        ));
                    }
                }
            });
        }
    });
    let failures = failures.into_inner().unwrap();
    assert!(
        failures.is_empty(),
        "{} fixtures failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Renumbers `#N:` source references in order of first appearance.
fn renumber_sources(render: &str) -> String {
    let mut map = std::collections::HashMap::new();
    let mut out = String::with_capacity(render.len());
    let mut rest = render;
    while let Some(at) = rest.find('#') {
        out.push_str(&rest[..at]);
        let tail = &rest[at + 1..];
        let digits = tail.bytes().take_while(u8::is_ascii_digit).count();
        if digits > 0 && tail[digits..].starts_with(":0x") {
            let next = map.len() + 1;
            let n = *map.entry(&tail[..digits]).or_insert(next);
            out.push_str(&format!("#{n}"));
            rest = &tail[digits..];
        } else {
            out.push('#');
            rest = tail;
        }
    }
    out.push_str(rest);
    out
}

fn random_walk(host: &mut common::Host, rng: &mut common::Rng, steps: usize) -> Result<(), String> {
    use fillyfoal::{ChildState, Progress};
    let mut known = vec![host.root];
    for _ in 0..steps {
        known.retain(|&id| host.session.node(id).is_some());
        if known.is_empty() {
            known.push(host.root);
        }
        let id = known[(rng.next() as usize) % known.len()];
        match rng.next() % 8 {
            0 | 1 => host.session.expand_more(id, 1 + rng.next() % 50),
            2 => {
                let start = rng.next() % 200;
                host.session.seek(id, start, 1 + rng.next() % 50);
            }
            3 => host.session.collapse(id),
            4 => host.session.trim(rng.next() as usize % 200, &[]),
            5 => {
                for _ in 0..(rng.next() % 20) {
                    match host.session.poll_node(id, 1 + rng.next() % 500) {
                        Progress::NeedBytes(requests) => host.supply(requests),
                        Progress::Idle => break,
                        _ => {}
                    }
                }
            }
            _ => host.run(),
        }
        // Every materialised child sits at its index.
        let Some(children) = host.session.children(id) else {
            continue;
        };
        let first = children.first;
        let ids = children.ids.to_vec();
        for (k, child) in ids.iter().enumerate() {
            let Some((_, path)) = host.session.address(*child) else {
                return Err("live child without an address".into());
            };
            if path.last() != Some(&(first + k as u64)) {
                return Err(format!(
                    "child {k} of the window at {first} has index {:?}",
                    path.last()
                ));
            }
            if rng.next().is_multiple_of(4) {
                known.push(*child);
            }
        }
        if matches!(children.state, ChildState::Running(_)) && rng.next().is_multiple_of(3) {
            host.run();
        }
    }
    host.run();
    Ok(())
}

/// The directory a fixture lives in names the format it must be identified
/// as. This catches probes that are too greedy (or too strict) as formats
/// accumulate. Fixtures of formats that are never identified by content
/// must not be claimed by any format.
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
            len_known: true,
        };
        let found = identify(&probe).map(|f| f.name);
        let wanted = match chosen_format(&path) {
            Some(_) => None,
            None => Some(expected.as_str()),
        };
        if found != wanted {
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

/// Cargo reads every `Cargo.toml` in the repository when a dependent crate
/// looks for this package, and warns about malformed ones on every command
/// in that crate: fixtures must not use the name.
#[test]
fn no_fixture_is_a_cargo_manifest() {
    fn walk(dir: &std::path::Path, found: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, found);
            } else if path.file_name().is_some_and(|n| n == "Cargo.toml") {
                found.push(path);
            }
        }
    }
    let mut found = Vec::new();
    walk(
        std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests")),
        &mut found,
    );
    assert!(found.is_empty(), "rename these fixtures: {found:?}");
}
