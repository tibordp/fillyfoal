//! Checksum lists as written by `md5sum`, `sha256sum` (and friends) or in
//! BSD style (`SHA256 (file) = hash`).

use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::{Format, Head, Input, Probe};
use crate::span::Span;

use super::encoding::prepare;
use super::piece::Piece;
use super::scan::Lines;
use super::{plural, probe, text_node};

pub static FORMAT: Format = Format {
    name: "checksums",
    title: "Checksum list",
    extensions: &[
        "md5",
        "sha1",
        "sha256",
        "sha512",
        "md5sum",
        "sha256sum",
        "sums",
    ],
    mime: "text/plain",
    probe: Probe::Custom(probe_sums),
    dissect: crate::expander!(dissect: Input),
};

/// The usual algorithm for a hex digest of `len` digits.
fn algorithm(len: usize) -> Option<&'static str> {
    Some(match len {
        32 => "MD5",
        40 => "SHA-1",
        56 => "SHA-224",
        64 => "SHA-256",
        96 => "SHA-384",
        128 => "SHA-512",
        _ => return None,
    })
}

/// A checksum line: (algorithm, hash, file name).
struct Entry<'a> {
    algorithm: String,
    hash: Piece<'a>,
    file: Piece<'a>,
    binary: bool,
}

fn parse(line: Piece<'_>) -> Option<Entry<'_>> {
    let t = line.trim();
    // BSD style: `SHA256 (file) = hash`.
    if let Some(open) = t.find_seq(b" (")
        && let Some(close) = t.rfind(b')')
        && t.from(close).starts_with(b") = ")
    {
        let algo = t.to(open);
        let hash = t.from(close.saturating_add(4)).trim();
        if algo
            .bytes()
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
            && hash.bytes().iter().all(u8::is_ascii_hexdigit)
            && !hash.is_empty()
        {
            return Some(Entry {
                algorithm: algo.text(),
                hash,
                file: t.slice(open.saturating_add(2), close),
                binary: false,
            });
        }
    }
    // GNU style: `hash  file` or `hash *file`.
    let (hash, rest) = t.split_once(b' ')?;
    let algo = algorithm(hash.len())?;
    if !hash.bytes().iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let binary = rest.first() == Some(b'*');
    let file = if rest.first() == Some(b' ') || binary {
        rest.from(1)
    } else {
        rest
    };
    (!file.is_empty()).then(|| Entry {
        algorithm: algo.to_owned(),
        hash,
        file,
        binary,
    })
}

fn probe_sums(h: &Head<'_>) -> bool {
    let head = probe::head(h);
    let span = Span::new(crate::span::SourceId(0), 0, 0);
    let (mut good, mut bad) = (0usize, 0usize);
    for line in probe::significant(&head, &[b"#", b";"]).take(20) {
        if parse(Piece::new(line, span)).is_some() {
            good = good.saturating_add(1);
        } else {
            bad = bad.saturating_add(1);
        }
    }
    // The first line must be one; a stray line among many is tolerated.
    let first_ok = probe::significant(&head, &[b"#", b";"])
        .next()
        .is_some_and(|l| parse(Piece::new(l, span)).is_some());
    first_ok && (bad == 0 || (good >= 2 && bad.saturating_mul(3) <= good)) && probe::is_text(h)
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let prepared = prepare(&cx, input).await?;
    let mut lines = Lines::new(&cx, prepared.span);
    let mut count = 0u64;
    let mut algorithms: Vec<String> = Vec::new();
    while let Some(line) = lines.next().await? {
        let p = line.piece();
        let t = p.trim();
        if t.is_empty() || matches!(t.first(), Some(b'#' | b';')) {
            continue;
        }
        let Some(e) = parse(p) else {
            cx.push(
                text_node(format!("Line {}", line.number), line.span, &t.text())
                    .diag(Diagnostic::malformed("not a checksum line")),
            )
            .await;
            continue;
        };
        count = count.saturating_add(1);
        if !algorithms.contains(&e.algorithm) {
            algorithms.push(e.algorithm.clone());
        }
        let mut summary = e.algorithm.clone();
        if e.binary {
            summary.push_str(", binary mode");
        }
        cx.push(
            text_node(
                e.file.text(),
                e.hash.span(),
                &e.hash.text().to_ascii_lowercase(),
            )
            .summary(summary),
        )
        .await;
    }
    cx.annotate(format!(
        "{} checksums, {}",
        algorithms.join("/"),
        plural(count, "file", "files")
    ));
    Ok(())
}
