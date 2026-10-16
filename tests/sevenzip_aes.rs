//! 7-Zip AES-256 (7zAES): one password prompt per archive, a wrong
//! password asked again, a declined one leaving the content encrypted, and
//! the key derivation's work bounded.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::Host;
use fillyfoal::secret::Secret;
use fillyfoal::{ChildState, Limits, NodeId, Progress};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/external/7z/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn explored(name: &str, passwords: &[&str], limits: Limits) -> Host {
    let mut host = Host::named(name, fixture(name), limits);
    host.passwords = passwords.iter().map(|p| p.to_string()).collect();
    host.explore_all();
    host
}

fn attempts(host: &Host) -> Vec<u32> {
    host.secret_requests.iter().map(|r| r.attempt).collect()
}

fn messages(host: &Host) -> Vec<String> {
    common::diagnostics(host)
        .into_iter()
        .map(|d| d.message)
        .collect()
}

#[test]
fn one_prompt_serves_the_header_and_the_data() {
    let host = explored("aes-header-lzma2.7z", &["fillyfoal"], Limits::default());
    assert_eq!(attempts(&host), [0]);
    let render = host.render();
    assert!(render.contains("The quick brown fox"), "{render}");
    assert!(render.contains("CRC32: 0xfecb6a91 — valid"), "{render}");
    assert!(messages(&host).is_empty(), "{:?}", messages(&host));
}

#[test]
fn a_wrong_password_is_asked_again() {
    for name in [
        "aes-header-lzma2.7z",
        "aes-data-lzma-solid.7z",
        "aes-bcj-lzma2.7z",
    ] {
        let host = explored(name, &["wrong", "fillyfoal"], Limits::default());
        assert_eq!(attempts(&host), [0, 1], "{name}");
        assert!(messages(&host).is_empty(), "{name}: {:?}", messages(&host));
        assert!(host.render().contains("— valid"), "{name}");
    }
}

#[test]
fn a_declined_prompt_leaves_the_content_encrypted() {
    // Header encryption: the file list itself stays encrypted.
    let host = explored("aes-header-lzma2.7z", &[], Limits::default());
    assert_eq!(attempts(&host), [0]);
    let files = host.child(host.root, "Files").unwrap();
    let error = host.session.children(files).unwrap().error.unwrap();
    assert_eq!(error.message, "encrypted (no password)");
    // Data encryption only: the files are listed, their contents are not.
    let host = explored("aes-data-lzma-solid.7z", &[], Limits::default());
    let render = host.render();
    assert!(render.contains("notes/lorem.txt — 2.6 KiB"), "{render}");
    assert!(!render.contains("lorem ipsum"), "{render}");
    assert!(
        messages(&host)
            .iter()
            .any(|m| m == "encrypted (no password)")
    );
    // Wrong, then declined.
    let host = explored("aes-data-lzma-solid.7z", &["wrong"], Limits::default());
    assert_eq!(attempts(&host), [0, 1]);
    assert!(
        messages(&host)
            .iter()
            .any(|m| m == "encrypted (wrong password)")
    );
}

/// Stored (`-mx0`) folders are AES + Copy: no decompressor rejects a
/// wrong key, and their first file is larger than the start a compressed
/// folder is checked on. The key is checked on the folder's padding or
/// the first file's CRC instead, folder by folder.
#[test]
fn a_wrong_password_for_stored_folders_is_asked_again() {
    for (name, valid) in [("aes-stored.7z", 1), ("aes-stored-two.7z", 2)] {
        let host = explored(name, &["wrong", "fillyfoal"], Limits::default());
        assert_eq!(attempts(&host), [0, 1], "{name}");
        assert!(messages(&host).is_empty(), "{name}: {:?}", messages(&host));
        let render = host.render();
        assert!(render.contains("sierra echo romeo oscar bravo"), "{name}");
        // Each file's content checks out.
        assert_eq!(render.matches("— valid").count(), valid, "{name}: {render}");
        assert!(!render.contains("mismatch"), "{name}: {render}");
    }
}

/// The second folder of `aes-stored-two.7z` alone: 6 bytes, checked on
/// its 10 bytes of zero padding before its CRC.
#[test]
fn a_stored_folder_is_checked_on_its_padding() {
    let mut host = Host::named(
        "aes-stored-two.7z",
        fixture("aes-stored-two.7z"),
        Limits::default(),
    );
    host.passwords = vec!["wrong".into(), "fillyfoal".into()];
    host.session.expand(host.root, 100);
    host.run();
    let files = host.child(host.root, "Files").unwrap();
    host.session.expand(files, 100);
    host.run();
    let file = host.child(files, "small.txt").unwrap();
    host.session.expand(file, 100);
    host.run();
    let node = host.child(file, "Content").unwrap();
    host.session.expand(node, 100);
    host.run();
    assert_eq!(attempts(&host), [0, 1]);
    let crc = host.child(node, "CRC32").unwrap();
    let crc = host.session.node(crc).unwrap();
    assert_eq!(crc.summary.as_deref(), Some("valid"), "{crc:?}");
}

#[test]
fn a_stored_folder_shows_no_garbage_without_the_password() {
    for name in ["aes-stored.7z", "aes-stored-two.7z"] {
        // Declined.
        let host = explored(name, &[], Limits::default());
        assert_eq!(attempts(&host), [0], "{name}");
        let render = host.render();
        assert!(!render.contains("sierra"), "{name}: {render}");
        assert!(!render.contains("— valid"), "{name}: {render}");
        assert!(!render.contains("mismatch"), "{name}: {render}");
        assert!(
            messages(&host)
                .iter()
                .all(|m| m == "encrypted (no password)"),
            "{name}: {:?}",
            messages(&host)
        );
        // Wrong, then declined: never taken for the key.
        let host = explored(name, &["wrong"], Limits::default());
        assert_eq!(attempts(&host), [0, 1], "{name}");
        let render = host.render();
        assert!(!render.contains("— valid"), "{name}: {render}");
        assert!(!render.contains("mismatch"), "{name}: {render}");
        assert!(
            messages(&host)
                .iter()
                .all(|m| m == "encrypted (wrong password)"),
            "{name}: {:?}",
            messages(&host)
        );
    }
}

#[test]
fn the_empty_password_unlocks() {
    let host = explored("aes-empty-password.7z", &[""], Limits::default());
    assert_eq!(attempts(&host), [0]);
    assert!(host.render().contains("The quick brown fox"));
    assert!(messages(&host).is_empty(), "{:?}", messages(&host));
}

/// `aes-bcj-lzma2.7z` (whose header is plain) with its AES coder's
/// key derivation rounds set to 2^`cycles`, and the header CRCs fixed.
fn with_cycles(cycles: u8) -> Vec<u8> {
    let mut data = fixture("aes-bcj-lzma2.7z");
    let off = u64::from_le_bytes(data[12..20].try_into().unwrap()) as usize;
    let size = u64::from_le_bytes(data[20..28].try_into().unwrap()) as usize;
    let header = 32 + off..32 + off + size;
    assert_eq!(data[header.start], 0x01, "a plain header");
    let at = header.start
        + data[header.clone()]
            .windows(4)
            .position(|w| w == [0x06, 0xf1, 0x07, 0x01])
            .unwrap();
    // The coder ID, the property size, then the first property byte.
    assert_eq!(data[at + 5] & 0x3f, 19);
    data[at + 5] = (data[at + 5] & 0xc0) | cycles;
    let crc = fillyfoal::codec::crc32(&data[header]);
    data[28..32].copy_from_slice(&crc.to_le_bytes());
    let crc = fillyfoal::codec::crc32(&data[12..32]);
    data[8..12].copy_from_slice(&crc.to_le_bytes());
    data
}

/// The archive's `Files/code.bin/Content` node, listed but not expanded.
fn content(host: &mut Host) -> NodeId {
    host.session.expand(host.root, 100);
    host.run();
    let files = host.child(host.root, "Files").unwrap();
    host.session.expand(files, 100);
    host.run();
    let file = host.child(files, "code.bin").unwrap();
    host.session.expand(file, 100);
    host.run();
    host.child(file, "Content").unwrap()
}

#[test]
fn more_rounds_than_7zip_allows_are_refused() {
    let mut host = Host::named("x.7z", with_cycles(62), Limits::default());
    let node = content(&mut host);
    host.session.expand(node, 100);
    host.run();
    let error = host.session.children(node).unwrap().error.unwrap();
    assert!(
        error.message.contains("2^62 key derivation rounds"),
        "{error:?}"
    );
    assert!(host.secret_requests.is_empty());
}

#[test]
fn a_derivation_beyond_the_work_limit_is_refused() {
    let limits = Limits {
        max_work: Some(1_000_000),
        ..Limits::default()
    };
    let mut host = Host::named("x.7z", with_cycles(24), limits);
    let node = content(&mut host);
    host.session.expand(node, 100);
    host.run();
    let children = host.session.children(node).unwrap();
    assert_eq!(children.state, ChildState::Failed);
    let error = children.error.unwrap();
    assert!(error.message.contains("too expensive"), "{error:?}");
    assert!(host.secret_requests.is_empty());
}

#[test]
fn without_a_limit_the_derivation_runs_in_budgeted_steps() {
    let mut host = Host::named("x.7z", with_cycles(24), Limits::default());
    let node = content(&mut host);
    host.session.expand(node, 100);
    let mut reported = Vec::new();
    for _ in 0..30 {
        match host.session.poll_node(node, 5_000) {
            Progress::Yielded => {
                if let Some(p) = host.session.progress(node) {
                    reported.push(p);
                }
            }
            Progress::NeedBytes(requests) => host.supply(requests),
            Progress::NeedSecret(requests) => {
                for r in requests {
                    host.session
                        .answer_secret(&r, Some(Secret::password("fillyfoal")));
                }
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    assert!(matches!(
        host.session.children(node).unwrap().state,
        ChildState::Running(_)
    ));
    // 2^24 rounds of one unit each; the progress rises with every poll.
    assert!(reported.len() >= 20, "{reported:?}");
    assert!(reported.iter().all(|&(_, total)| total == 1 << 24));
    assert!(reported.windows(2).all(|w| w[1].0 > w[0].0), "{reported:?}");
}
