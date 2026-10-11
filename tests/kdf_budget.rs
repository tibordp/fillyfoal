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

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use common::Host;
use fillyfoal::codec::crypto::{self, Pbkdf2, Sha1, Stepped};
use fillyfoal::{ChildState, Cx, Limits, Node, Progress, Result, Value};

/// A key derivation that counts the units of work it has done (for
/// PBKDF2, HMAC iterations), so a test can bound the work of each poll
/// deterministically instead of timing it.
struct Counted<K> {
    kdf: K,
    done: Arc<AtomicU64>,
}

impl<K: Stepped> Stepped for Counted<K> {
    fn advance(&mut self, units: u32) -> u32 {
        let used = self.kdf.advance(units);
        self.done.fetch_add(u64::from(used), Ordering::Relaxed);
        used
    }

    fn done(&self) -> bool {
        self.kdf.done()
    }
}

/// PBKDF2-HMAC-SHA1 with the largest iteration count a file can ask for;
/// the iterations done so far are counted in `done`.
async fn huge_pbkdf2(cx: Cx, done: Arc<AtomicU64>) -> Result<()> {
    let mut kdf = Counted {
        kdf: Pbkdf2::<Sha1>::new(b"fillyfoal", b"salt", u32::MAX, 20),
        done,
    };
    crypto::run(&cx, &mut kdf).await;
    cx.emit(Node::new("key").value(Value::Bytes(kdf.kdf.finish())));
    Ok(())
}

#[test]
fn huge_pbkdf2_yields_in_bounded_steps() {
    let done = Arc::new(AtomicU64::new(0));
    let mut host = Host::new(Vec::new(), Limits::default());
    let root = host
        .session
        .add_root(Node::new("kdf").lazy(huge_pbkdf2, Arc::clone(&done)));
    host.session.expand(root, 10);
    let budget = 2_000;
    for _ in 0..20 {
        let before = done.load(Ordering::Relaxed);
        assert_eq!(host.session.poll_node(root, budget), Progress::Yielded);
        // Each poll does about its budget of iterations: at most one more
        // chunk than the budget allows, and some progress.
        let used = done.load(Ordering::Relaxed) - before;
        assert!(
            used > 0 && used <= budget + u64::from(crypto::CHUNK),
            "{used} iterations in one poll"
        );
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
        .add_root(Node::new("kdf").lazy(huge_pbkdf2, Arc::new(AtomicU64::new(0))));
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
    // Deriving the key takes ten million HMAC iterations, each charged as
    // a unit of work: if the derivation were not budgeted, the first polls
    // would finish it. Instead every poll yields and 50 polls of 2000
    // units (about 100k iterations) leave it running.
    let mut yields = 0;
    for _ in 0..50 {
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
    }
    assert!(yields >= 40, "{yields} yields");
    assert!(matches!(
        host.session.children(key).unwrap().state,
        ChildState::Running(_)
    ));
}

#[test]
fn jceks_key_derivation_is_charged_per_iteration() {
    // keytool protects JCEKS keys with PBEWithMD5AndTripleDES at 200,000
    // iterations for each half of the key: 400,000 MD5 rounds per key, each
    // a unit of work (it was one unit per 1024 rounds, so a 2000-unit poll
    // could run two million MD5 rounds).
    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/external/jks/keytool.jceks"
    ))
    .unwrap();
    let mut host = Host::named("keytool.jceks", data, Limits::default());
    host.explore_all();
    let work = host.session.work_done();
    assert!(work >= 400_000, "{work} units");
}
