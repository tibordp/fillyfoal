//! Credential stores, key files and backups.

use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::{Codec, Input, Probe, content};
use crate::node::Node;
use crate::value::{EnumTable, Value, lookup};

const BE: Endian = Endian::Big;

// KeePass lives in its own module; re-exported for the format table.
pub use super::keepass::{KDB, KDBX};

// ---------------------------------------------------------------------------
// GnuPG keybox

fn keybox_probe(h: &crate::formats::Head<'_>) -> bool {
    h.at(8, b"KBXf")
}

declare_format!(pub KEYBOX = "keybox", "GnuPG keybox", ["kbx"], "application/x-gnupg-keybox",
    Probe::Custom(keybox_probe), keybox);

const KEYBOX_TYPES: EnumTable = &[(0, "empty"), (1, "header"), (2, "OpenPGP"), (3, "X.509")];

async fn keybox(cx: Cx, input: Input) -> Result<()> {
    let mut cur = Cursor::new(&cx, input.span, BE);
    let mut counts = [0u32; 4];
    while cur.remaining() >= 5 {
        let start = cur.pos();
        let len = cur.u32().await?;
        let kind = cur.u8().await?;
        if len < 5 {
            cx.diag(Diagnostic::malformed("blob shorter than its header").at(cur.since(start)));
            break;
        }
        cur.seek(start.saturating_add(len.into()));
        if let Some(c) = counts.get_mut(usize::from(kind)) {
            *c = c.saturating_add(1);
        }
        let name = lookup(KEYBOX_TYPES, kind.into()).unwrap_or("unknown");
        cx.progress_in(input.span, input.span.offset.saturating_add(start));
        cx.push(
            Node::new(format!("{name} blob"))
                .span(cur.since(start))
                .summary(format!("{len} bytes")),
        )
        .await;
    }
    cx.annotate(format!(
        "{} OpenPGP and {} X.509 blob(s)",
        counts[2], counts[3]
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Android backup (adb backup)

declare_format!(pub ANDROID_BACKUP = "android-backup", "Android backup", ["ab"], "application/x-android-backup",
    Probe::Magic(&[(0, b"ANDROID BACKUP\n")]), android_backup);

async fn android_backup(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 1024)).await?;
    let mut pos = 0u64;
    let mut lines = Vec::new();
    for (i, line) in head.split(|&b| b == b'\n').take(4).enumerate() {
        let len = crate::bytes::to_u64(line.len()).saturating_add(1);
        let label = ["Magic", "Version", "Compressed", "Encryption"]
            .get(i)
            .copied()
            .unwrap_or("Line");
        let text = String::from_utf8_lossy(line).into_owned();
        cx.emit(
            Node::new(label)
                .span(file.sub(pos, len))
                .value(Value::Text(text.clone())),
        );
        lines.push(text);
        pos = pos.saturating_add(len);
    }
    let compressed = lines.get(2).is_some_and(|l| l == "1");
    let encryption = lines.get(3).cloned().unwrap_or_default();
    let body = file.tail(pos);
    if encryption == "none" {
        // The payload is a (zlib-compressed) tar archive.
        let codec = if compressed {
            Codec::Zlib
        } else {
            Codec::Stored
        };
        cx.emit(content("Payload (tar)", input, body, codec, None));
    } else {
        cx.emit(
            Node::new("Payload")
                .span(body)
                .diag(Diagnostic::note(format!("encrypted ({encryption})"))),
        );
    }
    cx.annotate(format!(
        "Android backup v{}, {}{}",
        lines.get(1).cloned().unwrap_or_default(),
        if compressed {
            "compressed"
        } else {
            "uncompressed"
        },
        if encryption == "none" {
            String::new()
        } else {
            format!(", {encryption}")
        }
    ));
    Ok(())
}
