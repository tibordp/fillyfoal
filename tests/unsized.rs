//! Dissecting a file whose length is unknown (the decoded content of a
//! stream that records no size, decoded on demand with a provisional
//! length) must give the same tree as dissecting it with its length known:
//! nothing may identify, count or estimate from the provisional length.
//!
//! Fixtures over `common::LARGE_FIXTURE` (whole disk images, tens of MiB
//! decompressed) are skipped: the unsized stream can only be decoded
//! forwards, so every read near the end of a large image re-decodes
//! everything before it in 64-byte chunks, and a filesystem's scattered
//! metadata reads make that take tens of minutes per image. The property
//! being tested does not depend on size; the small fixtures of the same
//! formats cover it. Set `UNSIZED_LARGE=1` to include them anyway.

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
use fillyfoal::codec::Codec;
use fillyfoal::formats::{self, Input};
use fillyfoal::{Cx, Limits, Node, Result, SourceId, Span};

fn fixtures() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let filter = std::env::var("FIXTURE").unwrap_or_default();
    let mut out = Vec::new();
    for tree in ["external", "synthetic"] {
        let mut formats: Vec<_> = std::fs::read_dir(root.join(tree))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.is_dir())
            .collect();
        formats.sort();
        for dir in formats {
            let mut files: Vec<_> = std::fs::read_dir(&dir)
                .unwrap()
                .map(|e| e.unwrap().path())
                .collect();
            files.sort();
            out.extend(
                files
                    .into_iter()
                    .filter(|p| p.to_string_lossy().contains(&filter)),
            );
        }
    }
    out
}

/// A zstd frame of raw blocks with no content size.
fn zstd_unsized(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x58];
    let chunks: Vec<&[u8]> = data.chunks(128 * 1024).collect();
    if chunks.is_empty() {
        out.extend_from_slice(&[1, 0, 0]);
    }
    for (i, chunk) in chunks.iter().enumerate() {
        let last = u32::from(i + 1 == chunks.len());
        let header = last | ((chunk.len() as u32) << 3);
        out.extend_from_slice(&header.to_le_bytes()[..3]);
        out.extend_from_slice(chunk);
    }
    out
}

async fn unsized_root(cx: Cx, file: Span) -> Result<()> {
    let content = cx.decode_lazy_unsized(file, &Codec::Zstd)?;
    formats::dissect_unsized(cx, Input::root(content)).await
}

/// The tree below the root line, with source numbers dropped.
fn body(tree: &str, bound: Option<(u64, u64)>) -> Vec<String> {
    tree.lines()
        .skip(1)
        .map(|line| {
            let mut line = line.to_owned();
            // "#3:0x10" -> "0x10"
            let mut from = 0;
            while let Some(at) = line[from..].find('#').map(|i| i + from) {
                let digits = line[at + 1..]
                    .chars()
                    .take_while(char::is_ascii_digit)
                    .count();
                if digits > 0 && line[at + 1 + digits..].starts_with(':') {
                    line.replace_range(at..at + 2 + digits, "");
                    from = at;
                } else {
                    from = at + 1;
                }
            }
            if let Some((bound, len)) = bound {
                line = line.replace(&format!("{bound:#x}"), &format!("{len:#x}"));
            }
            line
        })
        .collect()
}

#[test]
fn unknown_length_does_not_change_the_tree() {
    let limits = || Limits {
        chunk_size: 64,
        ..Limits::default()
    };
    let mut differing = Vec::new();
    let all = fixtures();
    std::panic::set_hook(Box::new(|_| {}));
    for path in &all {
        // Disk images stored as `.raw.zst` are tested decompressed. Other
        // fixtures, `.gz` ones included, are tested as stored: several
        // formats kept gzipped are recognized by their exact size, which an
        // unsized stream cannot know.
        let (data, name) = if common::stored_compressed(path) == Some(".raw.zst") {
            (common::fixture_bytes(path), common::fixture_name(path))
        } else {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            (std::fs::read(path).unwrap(), name)
        };
        if data.len() > common::LARGE_FIXTURE && std::env::var_os("UNSIZED_LARGE").is_none() {
            continue;
        }

        let mut plain = Host::named(&name, data.clone(), limits());
        plain.explore(plain.root, 24, 1000);
        let expected = body(&plain.render(), None);

        let wrapped = zstd_unsized(&data);
        let bound = (wrapped.len() as u64).saturating_mul(Codec::Zstd.max_ratio());
        let explored = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let file = Span::new(SourceId::default_host(), 0, wrapped.len() as u64);
            let mut host = Host::named(&name, wrapped.clone(), limits());
            host.max_polls = 200_000;
            let root = host
                .session
                .add_root(Node::new(name.clone()).lazy(unsized_root, file));
            host.root = root;
            host.explore(root, 24, 1000);
            host.render()
        }));
        let got = match explored {
            Ok(tree) => body(&tree, Some((bound, data.len() as u64))),
            Err(_) => vec!["<did not settle>".to_owned()],
        };

        // Unrecognized content is "unsupported" at a root and a data leaf
        // when nested (as the unsized content is here): the same thing.
        let unrecognized = expected.len() == 1
            && got.len() == 1
            && expected[0]
                .trim()
                .starts_with("! unsupported: unrecognized format")
            && got[0].trim().starts_with("Data ");
        if got != expected && !unrecognized {
            let first = expected
                .iter()
                .zip(&got)
                .position(|(a, b)| a != b)
                .unwrap_or(expected.len().min(got.len()));
            differing.push(format!(
                "{}\n    known:   {}\n    unknown: {}",
                path.strip_prefix(env!("CARGO_MANIFEST_DIR"))
                    .unwrap()
                    .display(),
                expected.get(first).map_or("<end>", String::as_str).trim(),
                got.get(first).map_or("<end>", String::as_str).trim(),
            ));
        }
    }
    if let Ok(report) = std::env::var("UNSIZED_REPORT") {
        std::fs::write(report, differing.join("\n")).unwrap();
    }
    assert!(
        differing.is_empty(),
        "{} of {} fixtures differ with their length unknown:\n{}",
        differing.len(),
        all.len(),
        differing
            .iter()
            .take(40)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
