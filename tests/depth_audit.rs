//! How much of each fixture the dissection explains (run on demand):
//!
//!   DEPTH_AUDIT=report.csv cargo test --test depth_audit -- --ignored
//!
//! With `DEPTH_GAPS=1`, the gap and container-only runs of each fixture are
//! also written next to the report (`<report>.<tree>.<dir>.<file>.gaps`).
//!
//! Every fixture is explored completely and each byte of the file is
//! classified by the most specific node covering it: a decoded field (a
//! node with a value), a payload explained by what it decodes to (a
//! container whose children are on a derived source), an opaque leaf (a
//! span with neither value nor children), only a container (inside a node
//! whose children leave it unexplained), or a gap (no node at all). Spans
//! of piecewise sources (fragmented files, CFB streams) are resolved back
//! to the file. Gaps and container-only bytes
//! are the signal of shallow parsing; opaque leaves are often legitimate
//! payloads (pixel data, compressed streams) and need reading case by case.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::cast_possible_truncation
)]

mod common;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use common::Host;
use fillyfoal::{Limits, SourceId};

fn fixtures() -> Vec<(String, PathBuf)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let filter = std::env::var("FIXTURE").unwrap_or_default();
    let mut out = Vec::new();
    for tree in ["external", "synthetic"] {
        let mut dirs: Vec<_> = std::fs::read_dir(root.join(tree))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.is_dir())
            .collect();
        dirs.sort();
        for dir in dirs {
            let mut files: Vec<_> = std::fs::read_dir(&dir)
                .unwrap()
                .map(|e| e.unwrap().path())
                .filter(|p| p.is_file())
                .collect();
            files.sort();
            for f in files {
                if f.to_string_lossy().contains(&filter) {
                    out.push((tree.to_owned(), f));
                }
            }
        }
    }
    out
}

const GAP: u8 = 0;
const CONTAINER: u8 = 1;
const OPAQUE: u8 = 2;
/// A container whose children are on another source: its bytes are
/// explained by what they decode to (a compressed or encrypted payload).
const DECODED: u8 = 3;
const FIELD: u8 = 4;

#[test]
#[ignore = "an on-demand report, not a check"]
fn depth_audit() {
    let Ok(report) = std::env::var("DEPTH_AUDIT") else {
        return;
    };
    let mut csv = String::from(
        "tree,dir,file,format,size,nodes,field_pct,decoded_pct,opaque_pct,container_pct,gap_pct,largest_opaque_pct\n",
    );
    for (tree, path) in fixtures() {
        let data = common::fixture_bytes(&path);
        let size = data.len();
        if size == 0 {
            continue;
        }
        let name = common::fixture_name(&path);
        let dir = path
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let explored = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut host = Host::named(
                &name,
                data.clone(),
                Limits {
                    chunk_size: 4096,
                    ..Limits::default()
                },
            );
            host.max_nodes = 300_000;
            host.max_polls = 2_000_000;
            host.explore(host.root, 32, 1000);
            let format = host
                .session
                .interpretation(host.root)
                .and_then(|i| i.format)
                .map_or("-", |f| f.name)
                .to_owned();
            let mut class = vec![GAP; size];
            let mut largest_opaque = 0u64;
            let mut nodes = 0u64;
            let mut stack: Vec<_> = host.session.children(host.root).unwrap().ids.to_vec();
            while let Some(id) = stack.pop() {
                nodes += 1;
                let node = host.session.node(id).unwrap();
                let children = host.session.children(id).unwrap();
                stack.extend(children.ids.iter().copied());
                let Some(span) = node.span else { continue };
                let decoded = children.ids.iter().any(|&c| {
                    host.session
                        .node(c)
                        .and_then(|n| n.span)
                        .is_some_and(|s| s.source != span.source)
                });
                let kind = if node.value.is_some() {
                    FIELD
                } else if children.ids.is_empty() && !node.has_children() {
                    OPAQUE
                } else if decoded {
                    DECODED
                } else {
                    CONTAINER
                };
                for piece in host.session.resolve(span) {
                    if piece.source != SourceId::default_host() {
                        continue;
                    }
                    if kind == OPAQUE {
                        largest_opaque = largest_opaque.max(piece.len);
                    }
                    let start = (piece.offset as usize).min(size);
                    let end = (piece.offset.saturating_add(piece.len) as usize).min(size);
                    for c in &mut class[start..end] {
                        *c = (*c).max(kind);
                    }
                }
            }
            (format, nodes, class, largest_opaque)
        }));
        let Ok((format, nodes, class, largest_opaque)) = explored else {
            writeln!(csv, "{tree},{dir},{name},PANIC,{size},0,0,0,0,0,100,0").unwrap();
            continue;
        };
        if std::env::var_os("DEPTH_GAPS").is_some() {
            // Gap and container-only runs of 16 bytes or more, for finding
            // what a dissector leaves unexplained.
            let mut runs = String::new();
            let mut at = 0usize;
            while at < size {
                let kind = class[at];
                let start = at;
                while at < size && class[at] == kind {
                    at += 1;
                }
                if (kind == GAP || kind == CONTAINER) && at - start >= 16 {
                    let what = if kind == GAP { "gap" } else { "container" };
                    writeln!(runs, "{what},{start:#x},{:#x}", at - start).unwrap();
                }
            }
            std::fs::write(format!("{report}.{tree}.{dir}.{name}.gaps"), runs).unwrap();
        }
        let pct = |k: u8| 100.0 * class.iter().filter(|&&c| c == k).count() as f64 / size as f64;
        writeln!(
            csv,
            "{tree},{dir},{name},{format},{size},{nodes},{:.1},{:.1},{:.1},{:.1},{:.1},{:.1}",
            pct(FIELD),
            pct(DECODED),
            pct(OPAQUE),
            pct(CONTAINER),
            pct(GAP),
            100.0 * largest_opaque as f64 / size as f64,
        )
        .unwrap();
    }
    std::fs::write(report, csv).unwrap();
}
