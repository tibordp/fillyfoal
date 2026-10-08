//! Key derivations whose cost the file controls run in budgeted steps: a
//! hostile iteration count makes the expansion yield again and again (and
//! `Limits::max_work` stops it), instead of stalling one poll.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use std::time::{Duration, Instant};

use common::Host;
use fillyfoal::codec::crypto::{self, Pbkdf2, Sha1};
use fillyfoal::{ChildState, Cx, Limits, Node, Progress, Result, Value};

/// PBKDF2-HMAC-SHA1 with the largest iteration count a file can ask for.
async fn huge_pbkdf2(cx: Cx, (): ()) -> Result<()> {
    let mut kdf = Pbkdf2::<Sha1>::new(b"fillyfoal", b"salt", u32::MAX, 20);
    crypto::run(&cx, &mut kdf).await;
    cx.emit(Node::new("key").value(Value::Bytes(kdf.finish())));
    Ok(())
}

#[test]
fn huge_pbkdf2_yields_in_bounded_steps() {
    let mut host = Host::new(Vec::new(), Limits::default());
    let root = host
        .session
        .add_root(Node::new("kdf").lazy(huge_pbkdf2, ()));
    host.session.expand(root, 10);
    for _ in 0..20 {
        let start = Instant::now();
        assert_eq!(host.session.poll_node(root, 2_000), Progress::Yielded);
        // 2000 units are about a millisecond; allow for a slow machine.
        assert!(start.elapsed() < Duration::from_millis(500));
    }
    let children = host.session.children(root).unwrap();
    assert!(children.ids.is_empty());
    assert!(
        matches!(children.state, ChildState::Running(_)),
        "{:?}",
        children.state
    );
}

#[test]
fn huge_pbkdf2_stops_at_the_work_limit() {
    let limits = Limits {
        max_work: 200_000,
        ..Limits::default()
    };
    let mut host = Host::new(Vec::new(), limits);
    host.budget = 10_000;
    let root = host
        .session
        .add_root(Node::new("kdf").lazy(huge_pbkdf2, ()));
    host.session.expand(root, 10);
    host.run();
    let children = host.session.children(root).unwrap();
    assert_eq!(children.state, ChildState::Failed);
    assert!(
        children
            .error
            .is_some_and(|e| e.message.contains("units of work")),
        "{:?}",
        children.error
    );
}

/// The PBES2 fixture (PBKDF2-HMAC-SHA256, AES-256-CBC, 2048 iterations)
/// with its iteration count raised to 10 million, the most we accept.
fn huge_pbes2() -> Vec<u8> {
    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/external/pkcs8-encrypted/pbes2-aes256.p8"
    ))
    .unwrap();
    // INTEGER 2048 at 0x33 becomes INTEGER 10000000: two bytes longer, and
    // so is every enclosing SEQUENCE (lengths at 0x2, 0x4, 0x11, 0x13, 0x20).
    assert_eq!(&data[0x33..0x37], &[0x02, 0x02, 0x08, 0x00]);
    let mut out = data[..0x33].to_vec();
    out.extend_from_slice(&[0x02, 0x04, 0x00, 0x98, 0x96, 0x80]);
    out.extend_from_slice(&data[0x37..]);
    for at in [0x2, 0x4, 0x11, 0x13, 0x20] {
        out[at] += 2;
    }
    out
}

#[test]
fn pkcs8_with_ten_million_iterations_yields_while_deriving() {
    let mut host = Host::named("huge.p8", huge_pbes2(), Limits::default());
    host.session.expand(host.root, 100);
    host.run();
    let key = host
        .child(host.root, "Decrypted key")
        .expect("a Decrypted key node");
    host.session.expand(key, 100);
    let mut yields = 0;
    for _ in 0..50 {
        let start = Instant::now();
        match host.session.poll_node(key, 2_000) {
            Progress::Yielded => yields += 1,
            Progress::NeedBytes(requests) => {
                for r in requests {
                    let start = r.offset as usize;
                    let end = (start + r.len as usize).min(host.data.len());
                    let bytes = host.data[start..end].to_vec();
                    host.session.supply(r.source, r.offset, &bytes);
                }
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(start.elapsed() < Duration::from_millis(500));
    }
    assert!(yields >= 40, "{yields} yields");
    assert!(matches!(
        host.session.children(key).unwrap().state,
        ChildState::Running(_)
    ));
}
