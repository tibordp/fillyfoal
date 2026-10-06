//! Core behaviour not tied to a particular format.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::Host;
use fillyfoal::{Cx, Limits, Node, Origin, Result, Span, Value};

/// Reassembles "fragments" of the input in a scrambled order and emits the
/// reassembled text, plus a piecewise source built on top of the first one.
async fn reassemble(cx: Cx, file: Span) -> Result<()> {
    let at = |offset, len| Span::new(file.source, offset, len);
    let first = cx.add_pieces(
        Origin {
            parent: file,
            transform: "test-chain",
        },
        vec![at(10, 5), at(0, 5), at(20, 6), at(5, 5)],
    )?;
    let text = cx.read(first).await?;
    cx.emit(
        Node::new("first")
            .span(first)
            .value(Value::Text(String::from_utf8(text).unwrap())),
    );
    // Pieces of a piecewise source.
    let second = cx.add_pieces(
        Origin {
            parent: first,
            transform: "test-nested",
        },
        vec![first.sub(15, 6), first.sub(0, 5)],
    )?;
    let text = cx.read(second).await?;
    cx.emit(
        Node::new("second")
            .span(second)
            .value(Value::Text(String::from_utf8(text).unwrap())),
    );
    Ok(())
}

#[test]
fn piecewise_sources_reassemble_and_resolve() {
    let data = b"HELLO, wor_ld! ____ IGNORE_this_".to_vec();
    for chunk in [1, 3, 64] {
        let mut host = Host::with_chunk(data.clone(), chunk);
        let file = Span::new(fillyfoal::SourceId::default_host(), 0, data.len() as u64);
        let root = host
            .session
            .add_root(Node::new("test").lazy(reassemble, file));
        host.session.expand(root, 10);
        host.run();
        let children = host.session.children(root).unwrap();
        assert!(children.error.is_none(), "{:?}", children.error);
        let values: Vec<_> = children
            .ids
            .iter()
            .map(|&id| host.session.node(id).unwrap().value.clone().unwrap())
            .collect();
        // data[10..15] + data[0..5] + data[20..26] + data[5..10]
        assert_eq!(
            values[0],
            Value::Text("_ld! HELLOIGNORE, wor".into()),
            "chunk {chunk}"
        );
        // first[15..21] + first[0..5]
        assert_eq!(
            values[1],
            Value::Text("E, wor_ld! ".into()),
            "chunk {chunk}"
        );

        // Provenance: bytes 3..8 of the nested source come from two places.
        let second = host.session.node(children.ids[1]).unwrap().span.unwrap();
        let resolved = host.session.resolve(Span::new(second.source, 3, 5));
        assert_eq!(
            resolved,
            vec![Span::new(file.source, 7, 3), Span::new(file.source, 10, 2)]
        );
    }
    let _ = Limits::default();
}

/// A sparse stream: data, a hole, data.
async fn sparse(cx: Cx, file: Span) -> Result<()> {
    let s = cx.add_pieces(
        Origin {
            parent: file,
            transform: "test-sparse",
        },
        vec![
            Span::new(file.source, 0, 2),
            Span::zeros(3),
            Span::new(file.source, 2, 2),
        ],
    )?;
    let bytes = cx.read(s).await?;
    cx.emit(Node::new("sparse").span(s).value(Value::Bytes(bytes)));
    Ok(())
}

#[test]
fn holes_read_as_zeros_and_resolve_to_nothing() {
    let data = b"ABCD".to_vec();
    let mut host = Host::with_chunk(data, 1);
    let file = Span::new(fillyfoal::SourceId::default_host(), 0, 4);
    let root = host.session.add_root(Node::new("test").lazy(sparse, file));
    host.session.expand(root, 10);
    host.run();
    let children = host.session.children(root).unwrap();
    let node = host.session.node(children.ids[0]).unwrap();
    assert_eq!(node.value, Some(Value::Bytes(b"AB\0\0\0CD".to_vec())));
    let span = node.span.unwrap();
    assert_eq!(span.len, 7);
    assert_eq!(
        host.session.resolve(span),
        vec![Span::new(file.source, 0, 2), Span::new(file.source, 2, 2)]
    );
}

/// A tarball whose middle member is 2 MiB of zeros: listing the first entry
/// must not decompress the whole stream.
#[test]
fn large_members_are_decompressed_lazily() {
    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/gzip/large-member.tar.gz"
    ))
    .unwrap();
    let mut host = Host::with_chunk(data, 4096);
    host.session.expand(host.root, 100);
    host.run();
    let content = host.child(host.root, "Content").expect("content node");
    host.session.expand(content, 1);
    host.run();
    let decoded = host.session.derived_bytes();
    assert!(
        decoded < 512 << 10,
        "decoded {decoded} bytes to show one entry"
    );
    let rendered = host.render();
    assert!(rendered.contains("a.txt"), "{rendered}");
    // Paging through everything does reach the end.
    host.explore(content, 4, 100);
    assert!(host.render().contains("z.txt"));
}

/// Two "entries" of one encrypted container, each unlocked with the same
/// realm: the host is asked once per attempt, not once per entry.
async fn locked(cx: Cx, file: Span) -> Result<()> {
    for name in ["first", "second"] {
        let secret = cx.unlock(file, "Password for the test container", |s| s.expose() == b"fillyfoal").await;
        let value = match secret {
            Some(_) => Value::Text(format!("{name}: unlocked")),
            None => Value::Text(format!("{name}: locked")),
        };
        cx.emit(Node::new(name).span(file).value(value));
    }
    Ok(())
}

fn run_locked(passwords: &[&str]) -> (Vec<Value>, Vec<fillyfoal::SecretRequest>) {
    let data = b"ciphertext".to_vec();
    let mut host = Host::with_chunk(data, 4);
    host.passwords = passwords.iter().map(|p| p.to_string()).collect();
    let file = Span::new(fillyfoal::SourceId::default_host(), 0, 10);
    let root = host.session.add_root(Node::new("test").lazy(locked, file));
    host.session.expand(root, 10);
    host.run();
    let children = host.session.children(root).unwrap();
    let values = children.ids.iter().map(|&id| host.session.node(id).unwrap().value.clone().unwrap()).collect();
    (values, host.secret_requests)
}

#[test]
fn secrets_are_requested_once_per_realm_and_attempt() {
    let (values, requests) = run_locked(&["fillyfoal"]);
    assert_eq!(values, vec![Value::Text("first: unlocked".into()), Value::Text("second: unlocked".into())]);
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].attempt, 0);

    // A wrong password leads to a second request, then success.
    let (values, requests) = run_locked(&["wrong", "fillyfoal"]);
    assert_eq!(values[1], Value::Text("second: unlocked".into()));
    assert_eq!(requests.iter().map(|r| r.attempt).collect::<Vec<_>>(), vec![0, 1]);

    // Declining keeps the content locked, without asking again.
    let (values, requests) = run_locked(&[]);
    assert_eq!(values, vec![Value::Text("first: locked".into()), Value::Text("second: locked".into())]);
    assert_eq!(requests.len(), 1);

    // Wrong every time: bounded attempts.
    let (_, requests) = run_locked(&["a", "b", "c", "d"]);
    assert_eq!(requests.len(), fillyfoal::secret::MAX_ATTEMPTS as usize);
}

/// A zlib stream with one stored block holding `data`.
fn zlib_stored(data: &[u8]) -> Vec<u8> {
    let len = data.len() as u16;
    let mut out = vec![0x78, 0x01, 0x01];
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&(!len).to_le_bytes());
    out.extend_from_slice(data);
    out.extend_from_slice(&fillyfoal::codec::adler32(data).to_be_bytes());
    out
}

/// Feeds `input` one byte at a time, as a lazy source would in the worst case.
fn trickle(codec: &fillyfoal::codec::Codec, input: &[u8]) -> Vec<u8> {
    use fillyfoal::codec::pipeline::Status;
    let mut decoder = codec.decoder().unwrap();
    let mut out = Vec::new();
    let mut fed = 0;
    loop {
        let eof = fed == input.len();
        match decoder.decode(&input[..fed], eof, &mut out, 3, 1 << 20).unwrap() {
            Status::Done => return out,
            Status::More => {}
            Status::NeedInput => {
                assert!(!eof, "decoder wants input after the end");
                fed += 1;
            }
        }
    }
}

#[test]
fn decoders_resume_across_input_shortages_and_chain() {
    use fillyfoal::codec::Codec;
    let inner = zlib_stored(b"hello, pipeline");
    assert_eq!(trickle(&Codec::Zlib, &inner), b"hello, pipeline");
    // zlib inside zlib: a two-stage chain.
    let outer = zlib_stored(&inner);
    let chain = Codec::chain("zlib+zlib", "zlib+zlib (lazy)", vec![Codec::Zlib, Codec::Zlib]);
    assert_eq!(trickle(&chain, &outer), b"hello, pipeline");
    // A corrupted checksum is a warning, not an error.
    let mut bad = inner.clone();
    *bad.last_mut().unwrap() ^= 1;
    let mut decoder = Codec::Zlib.decoder().unwrap();
    let out = fillyfoal::codec::pipeline::decode_all(decoder.as_mut(), &bad, 1 << 20).unwrap();
    assert!(decoder.warning(&out).is_some());
}

fn render_zip(name: &str, passwords: &[&str]) -> (String, usize) {
    let path = format!("{}/tests/fixtures/zip/{name}", env!("CARGO_MANIFEST_DIR"));
    let data = std::fs::read(path).unwrap();
    let mut host = Host::named(name, data, Limits::default());
    host.passwords = passwords.iter().map(|p| p.to_string()).collect();
    host.explore_all();
    (host.render(), host.secret_requests.len())
}

#[test]
fn encrypted_zip_entries_unlock_once_and_stay_locked_on_wrong_passwords() {
    for name in ["zipcrypto.zip", "winzip-aes.zip"] {
        let (text, asked) = render_zip(name, &["fillyfoal"]);
        assert!(text.contains("secret text inside the archive"), "{name}");
        assert_eq!(asked, 1, "{name}: one prompt for the whole archive");

        let (text, asked) = render_zip(name, &["wrong", "fillyfoal"]);
        assert!(text.contains("secret text inside the archive"), "{name}");
        assert_eq!(asked, 2, "{name}: a retry after the wrong password");

        let (text, asked) = render_zip(name, &[]);
        assert!(!text.contains("secret text"), "{name}");
        assert!(text.contains("no password, or a wrong one"), "{name}");
        assert_eq!(asked, 1, "{name}: declining is remembered");
    }
}

#[test]
fn encrypted_pdfs_ask_only_when_needed() {
    let read = |name: &str| std::fs::read(format!("{}/tests/fixtures/pdf/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap();
    // Empty user password: decrypted without asking.
    let mut host = Host::named("a.pdf", read("encrypted-empty-aes-256.pdf"), Limits::default());
    host.passwords.clear();
    host.explore_all();
    assert!(host.render().contains("Hello encrypted world"));
    assert!(host.secret_requests.is_empty());
    // A user password: asked once, then everything decrypts.
    let mut host = Host::named("b.pdf", read("encrypted-password-rc4-128.pdf"), Limits::default());
    host.explore_all();
    assert!(host.render().contains("Hello encrypted world"));
    assert_eq!(host.secret_requests.len(), 1);
    // Declined: streams stay encrypted, and the user is not asked again.
    let mut host = Host::named("c.pdf", read("encrypted-password-aes-256.pdf"), Limits::default());
    host.passwords.clear();
    host.explore_all();
    let text = host.render();
    assert!(!text.contains("Hello encrypted world"));
    assert!(text.contains("password required"));
    assert_eq!(host.secret_requests.len(), 1);
}

#[test]
fn pkcs12_without_the_password_lists_nothing_secret() {
    let data = std::fs::read(format!("{}/tests/fixtures/pkcs12/modern-aes.p12", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let mut host = Host::named("k.p12", data.clone(), Limits::default());
    host.passwords.clear();
    host.explore_all();
    let text = host.render();
    assert!(text.contains("no password, or a wrong one"));
    assert!(!text.contains("CN=fillyfoal p12 test"));
    // The empty-password store needs no prompt at all.
    let data = std::fs::read(format!("{}/tests/fixtures/pkcs12/empty-password.p12", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let mut host = Host::named("e.p12", data, Limits::default());
    host.passwords.clear();
    host.explore_all();
    assert!(host.render().contains("CN=fillyfoal p12 test"));
    assert!(host.secret_requests.is_empty());
}

fn lzma_text() -> Vec<u8> {
    (0..2000).map(|i: u32| format!("line {i}: the quick brown fox {}\n", i * 7919 % 1000)).collect::<String>().into_bytes()
}

fn lzma_code() -> Vec<u8> {
    let mut x: u32 = 12345;
    (0..40000)
        .map(|_| {
            x = x.wrapping_mul(1103515245).wrapping_add(12345) & 0x7fff_ffff;
            let r = ((x >> 16) & 0xff) as u8;
            if r < 40 { 0xe8 } else { r }
        })
        .collect()
}

#[test]
fn lzma_family_decodes_python_output() {
    use fillyfoal::codec::Codec;
    let read = |name: &str| std::fs::read(format!("{}/tests/data/lzma/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let decode = |codec: Codec, data: &[u8]| {
        let mut d = codec.decoder().unwrap();
        fillyfoal::codec::pipeline::decode_all(d.as_mut(), data, 1 << 26).unwrap()
    };
    let text = lzma_text();
    for name in ["text.xz", "text-crc32.xz", "text-sha256.xz", "text-two-streams.xz"] {
        assert!(decode(Codec::Xz, &read(name)) == text, "{name}");
    }
    for name in ["text.lzma", "text-pb0lc0.lzma"] {
        assert!(decode(Codec::LzmaAlone, &read(name)) == text, "{name}");
    }
    let code = lzma_code();
    for name in ["code-x86.xz", "code-delta.xz", "code-arm.xz", "code-arm64.xz", "code-x86-delta.xz"] {
        assert!(decode(Codec::Xz, &read(name)) == code, "{name}");
    }
    let random: Vec<u8> = (0..70000u32).map(|i| ((i * 131 + (i >> 3)) & 0xff) as u8).collect();
    assert!(decode(Codec::Xz, &read("random.xz")) == random);
}
