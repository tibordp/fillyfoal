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
use fillyfoal::{Cx, Limits, Node, Origin, Result, Span, Value, formats};

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
    // The same tarball through gzip, xz and zstd (real `gzip`/`xz`/`zstd`).
    for (path, node) in [
        ("gzip/large-member.tar.gz", "Content"),
        ("xz/large-member.tar.xz", "Decompressed"),
        ("zstd/large-member.tar.zst", "Decompressed"),
    ] {
        large_member_is_decompressed_lazily(path, node);
    }
}

fn large_member_is_decompressed_lazily(path: &str, node: &str) {
    let data = std::fs::read(format!(
        "{}/tests/fixtures/external/{path}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let mut host = Host::with_chunk(data, 4096);
    host.session.expand(host.root, 100);
    host.run();
    let content = host.child(host.root, node).expect("content node");
    host.session.expand(content, 1);
    host.run();
    let decoded = host.session.derived_bytes();
    assert!(
        decoded < 512 << 10,
        "{path}: decoded {decoded} bytes to show one entry"
    );
    let rendered = host.render();
    assert!(rendered.contains("a.txt"), "{rendered}");
    // Paging through everything does reach the end.
    host.explore(content, 4, 100);
    assert!(host.render().contains("z.txt"));
}

/// The "Content" node of a tar member (beside its "Header").
fn member_content(host: &mut Host, archive: fillyfoal::NodeId, name: &str) -> fillyfoal::NodeId {
    let member = host.child(archive, name).expect("member");
    host.session.expand(member, 100);
    host.run();
    let content = host.child(member, "Content").expect("member content");
    host.session.expand(content, 100);
    host.run();
    content
}

fn interpretation(host: &Host, id: fillyfoal::NodeId) -> Option<(&'static str, bool)> {
    let i = host.session.interpretation(id)?;
    Some((i.format.map_or("-", |f| f.name), i.forced))
}

/// Opens the zstd-compressed tarball and expands its "Decompressed" node.
fn decompressed_tarball() -> (Host, fillyfoal::NodeId) {
    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/external/zstd/large-member.tar.zst"
    ))
    .unwrap();
    let mut host = Host::with_chunk(data, 4096);
    host.session.expand(host.root, 100);
    host.run();
    let content = host.child(host.root, "Decompressed").expect("content node");
    host.session.expand(content, 100);
    host.run();
    (host, content)
}

/// "Inspect as" on nested content: the forced format replaces
/// identification of the decoded bytes (which are not decoded again), only
/// for that node, and `None` restores identification.
#[test]
fn nested_content_can_be_reinterpreted() {
    let (mut host, content) = decompressed_tarball();
    assert_eq!(interpretation(&host, host.root), Some(("zstd", false)));
    assert_eq!(interpretation(&host, content), Some(("tar", false)));
    let derived = host.session.derived_bytes();

    let text = formats::by_name("text").unwrap();
    assert!(host.session.reinterpret(content, Some(text)));
    assert!(host.session.children(content).unwrap().ids.is_empty());
    assert_eq!(interpretation(&host, content), None);
    host.session.expand(content, 100);
    host.run();
    assert_eq!(interpretation(&host, content), Some(("text", true)));
    assert!(host.child(content, "Lines").is_some(), "{}", host.render());
    assert!(host.child(content, "a.txt").is_none());
    assert_eq!(host.session.derived_bytes(), derived, "decoded again");

    // Forcing what identification found still marks it as forced; members
    // inside are identified as usual.
    let tar = formats::by_name("tar").unwrap();
    host.session.reinterpret(content, Some(tar));
    host.session.expand(content, 100);
    host.run();
    assert_eq!(interpretation(&host, content), Some(("tar", true)));
    let member = member_content(&mut host, content, "a.txt");
    assert_eq!(interpretation(&host, member), Some(("text", false)));

    host.session.reinterpret(content, None);
    host.session.expand(content, 100);
    host.run();
    assert_eq!(interpretation(&host, content), Some(("tar", false)));
}

/// Forced formats are kept by position, so they outlive the nodes: after an
/// ancestor is collapsed and expanded again, the re-created node gets the
/// same format. Reinterpreting a node drops what was forced below it.
#[test]
fn reinterpretation_survives_collapse_and_is_dropped_below() {
    let (mut host, content) = decompressed_tarball();
    let text = formats::by_name("text").unwrap();
    let der = formats::by_name("der").unwrap();
    let member = member_content(&mut host, content, "a.txt");
    assert!(host.session.reinterpret(member, Some(der)));

    host.session.collapse(host.root);
    let (mut host, content) = {
        host.session.expand(host.root, 100);
        host.run();
        let content = host.child(host.root, "Decompressed").unwrap();
        host.session.expand(content, 100);
        host.run();
        (host, content)
    };
    let member = member_content(&mut host, content, "a.txt");
    assert_eq!(interpretation(&host, member), Some(("der", true)));

    // Trimming re-creates the member too.
    host.session.trim(0, &[]);
    host.session.expand(content, 100);
    host.run();
    let member = member_content(&mut host, content, "a.txt");
    assert_eq!(interpretation(&host, member), Some(("der", true)));

    // Reinterpreting the container forgets the member's format: under a
    // different reading, "the first member" no longer means the same thing.
    host.session.reinterpret(content, Some(text));
    host.session.reinterpret(content, None);
    host.session.expand(content, 100);
    host.run();
    let member = member_content(&mut host, content, "a.txt");
    assert_eq!(interpretation(&host, member), Some(("text", false)));
}

/// Nodes without children cannot be reinterpreted; structural nodes can be,
/// but never reach a detection step, so nothing changes.
#[test]
fn reinterpreting_fields_has_no_effect() {
    let (mut host, _) = decompressed_tarball();
    let text = formats::by_name("text").unwrap();
    let frame = host.child(host.root, "Frame 0").unwrap();
    host.session.expand(frame, 100);
    host.run();
    let magic = host.child(frame, "Magic").unwrap();
    assert!(!host.session.reinterpret(magic, Some(text)));
    let before = host.render();
    assert!(host.session.reinterpret(frame, Some(text)));
    host.session.expand(frame, 100);
    host.run();
    assert_eq!(interpretation(&host, frame), None);
    assert_eq!(host.render(), before);
}

/// The same tarball, corrupted halfway through its DEFLATE stream: paging
/// to the end reports why the lazily decoded data stopped, instead of a bare
/// truncation.
#[test]
fn lazy_decode_errors_are_reported() {
    let mut data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/external/gzip/large-member.tar.gz"
    ))
    .unwrap();
    let mid = data.len() / 2;
    for b in &mut data[mid..mid + 16] {
        *b = 0xff;
    }
    let mut host = Host::with_chunk(data, 4096);
    host.session.expand(host.root, 100);
    host.run();
    let content = host.child(host.root, "Content").expect("content node");
    host.explore(content, 4, 100);
    let messages: Vec<String> = common::diagnostics(&host)
        .iter()
        .map(|d| d.message.clone())
        .collect();
    assert!(
        messages.iter().any(|m| m.starts_with("decoding stopped")),
        "{messages:?}"
    );
}

/// Two "entries" of one encrypted container, each unlocked with the same
/// realm: the host is asked once per attempt, not once per entry.
async fn locked(cx: Cx, file: Span) -> Result<()> {
    for name in ["first", "second"] {
        let secret = cx
            .unlock(file, "Password for the test container", |s| {
                s.expose() == b"fillyfoal"
            })
            .await;
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
    let values = children
        .ids
        .iter()
        .map(|&id| host.session.node(id).unwrap().value.clone().unwrap())
        .collect();
    (values, host.secret_requests)
}

#[test]
fn secrets_are_requested_once_per_realm_and_attempt() {
    let (values, requests) = run_locked(&["fillyfoal"]);
    assert_eq!(
        values,
        vec![
            Value::Text("first: unlocked".into()),
            Value::Text("second: unlocked".into())
        ]
    );
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].attempt, 0);

    // A wrong password leads to a second request, then success.
    let (values, requests) = run_locked(&["wrong", "fillyfoal"]);
    assert_eq!(values[1], Value::Text("second: unlocked".into()));
    assert_eq!(
        requests.iter().map(|r| r.attempt).collect::<Vec<_>>(),
        vec![0, 1]
    );

    // Declining keeps the content locked, without asking again.
    let (values, requests) = run_locked(&[]);
    assert_eq!(
        values,
        vec![
            Value::Text("first: locked".into()),
            Value::Text("second: locked".into())
        ]
    );
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
        match decoder
            .decode(&input[..fed], eof, &mut out, 3, 1 << 20)
            .unwrap()
        {
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
    let chain = Codec::chain(
        "zlib+zlib",
        "zlib+zlib (lazy)",
        vec![Codec::Zlib, Codec::Zlib],
    );
    assert_eq!(trickle(&chain, &outer), b"hello, pipeline");
    // A corrupted checksum is a warning, not an error.
    let mut bad = inner.clone();
    *bad.last_mut().unwrap() ^= 1;
    let mut decoder = Codec::Zlib.decoder().unwrap();
    let out = fillyfoal::codec::pipeline::decode_all(decoder.as_mut(), &bad, 1 << 20).unwrap();
    assert!(decoder.warning(&out).is_some());
}

fn render_zip(name: &str, passwords: &[&str]) -> (String, usize) {
    let path = format!(
        "{}/tests/fixtures/external/zip/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
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
    let read = |name: &str| {
        std::fs::read(format!(
            "{}/tests/fixtures/external/pdf/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    };
    // Empty user password: decrypted without asking.
    let mut host = Host::named(
        "a.pdf",
        read("encrypted-empty-aes-256.pdf"),
        Limits::default(),
    );
    host.passwords.clear();
    host.explore_all();
    assert!(host.render().contains("Hello encrypted world"));
    assert!(host.secret_requests.is_empty());
    // A user password: asked once, then everything decrypts.
    let mut host = Host::named(
        "b.pdf",
        read("encrypted-password-rc4-128.pdf"),
        Limits::default(),
    );
    host.explore_all();
    assert!(host.render().contains("Hello encrypted world"));
    assert_eq!(host.secret_requests.len(), 1);
    // Declined: streams stay encrypted, and the user is not asked again.
    let mut host = Host::named(
        "c.pdf",
        read("encrypted-password-aes-256.pdf"),
        Limits::default(),
    );
    host.passwords.clear();
    host.explore_all();
    let text = host.render();
    assert!(!text.contains("Hello encrypted world"));
    assert!(text.contains("password required"));
    assert_eq!(host.secret_requests.len(), 1);
}

#[test]
fn pkcs12_without_the_password_lists_nothing_secret() {
    let data = std::fs::read(format!(
        "{}/tests/fixtures/external/pkcs12/modern-aes.p12",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let mut host = Host::named("k.p12", data.clone(), Limits::default());
    host.passwords.clear();
    host.explore_all();
    let text = host.render();
    assert!(text.contains("no password, or a wrong one"));
    assert!(!text.contains("CN=fillyfoal p12 test"));
    // The empty-password store needs no prompt at all.
    let data = std::fs::read(format!(
        "{}/tests/fixtures/external/pkcs12/empty-password.p12",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let mut host = Host::named("e.p12", data, Limits::default());
    host.passwords.clear();
    host.explore_all();
    assert!(host.render().contains("CN=fillyfoal p12 test"));
    assert!(host.secret_requests.is_empty());
}

fn lzma_text() -> Vec<u8> {
    (0..2000)
        .map(|i: u32| format!("line {i}: the quick brown fox {}\n", i * 7919 % 1000))
        .collect::<String>()
        .into_bytes()
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
    let read = |name: &str| {
        std::fs::read(format!(
            "{}/tests/data/lzma/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    };
    let decode = |codec: Codec, data: &[u8]| {
        let mut d = codec.decoder().unwrap();
        fillyfoal::codec::pipeline::decode_all(d.as_mut(), data, 1 << 26).unwrap()
    };
    let text = lzma_text();
    for name in [
        "text.xz",
        "text-crc32.xz",
        "text-sha256.xz",
        "text-two-streams.xz",
    ] {
        assert!(decode(Codec::Xz, &read(name)) == text, "{name}");
    }
    for name in ["text.lzma", "text-pb0lc0.lzma"] {
        assert!(decode(Codec::LzmaAlone, &read(name)) == text, "{name}");
    }
    let code = lzma_code();
    for name in [
        "code-x86.xz",
        "code-delta.xz",
        "code-arm.xz",
        "code-arm64.xz",
        "code-x86-delta.xz",
    ] {
        assert!(decode(Codec::Xz, &read(name)) == code, "{name}");
    }
    let random: Vec<u8> = (0..70000u32)
        .map(|i| ((i * 131 + (i >> 3)) & 0xff) as u8)
        .collect();
    assert!(decode(Codec::Xz, &read("random.xz")) == random);
}

#[test]
fn zstd_decodes_python_output() {
    use fillyfoal::codec::Codec;
    let read = |name: &str| {
        std::fs::read(format!(
            "{}/tests/data/zstd/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    };
    let decode = |data: &[u8]| {
        let mut d = Codec::Zstd.decoder().unwrap();
        fillyfoal::codec::pipeline::decode_all(d.as_mut(), data, 1 << 26)
    };
    let text = lzma_text();
    for name in [
        "text-1.zst",
        "text-3.zst",
        "text-9.zst",
        "text-19.zst",
        "text-checksum.zst",
        "text-two-frames.zst",
    ] {
        assert!(decode(&read(name)).unwrap() == text, "{name}");
    }
    assert!(decode(&read("code-19.zst")).unwrap() == lzma_code());
    let random: Vec<u8> = (0..70000u32)
        .map(|i| ((i * 131 + (i >> 3)) & 0xff) as u8)
        .collect();
    assert!(decode(&read("random.zst")).unwrap() == random);
    assert!(decode(&read("zeros.zst")).unwrap() == vec![0u8; 300000]);
    assert!(decode(&read("big-text.zst")).unwrap() == text.repeat(40));
}

#[test]
fn unix_compress_decodes_real_output() {
    use fillyfoal::codec::Codec;
    let read = |name: &str| {
        std::fs::read(format!(
            "{}/tests/data/compress/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    };
    let decode = |data: &[u8]| {
        let mut d = Codec::UnixCompress.decoder().unwrap();
        fillyfoal::codec::pipeline::decode_all(d.as_mut(), data, 1 << 26).unwrap()
    };
    assert!(decode(&read("text.Z")) == lzma_text());
    assert!(decode(&read("text12.Z")) == lzma_text());
    let random: Vec<u8> = (0..70000u32)
        .map(|i| ((i * 131 + (i >> 3)) & 0xff) as u8)
        .collect();
    assert!(decode(&read("rnd.Z")) == random);
    let words = decode(&read("words.Z"));
    assert_eq!(words.len(), 2_493_885);
    assert!(words.starts_with(b"A\na\naa\naal\n"));
}

#[test]
fn lzfse_decodes_apple_output() {
    use fillyfoal::codec::Codec;
    let read = |name: &str| {
        std::fs::read(format!(
            "{}/tests/data/lzfse/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    };
    let decode = |data: &[u8]| {
        let mut d = Codec::Lzfse.decoder().unwrap();
        fillyfoal::codec::pipeline::decode_all(d.as_mut(), data, 1 << 26).unwrap()
    };
    assert!(decode(&read("text.lzfse")) == lzma_text());
    let random: Vec<u8> = (0..70000u32)
        .map(|i| ((i * 131 + (i >> 3)) & 0xff) as u8)
        .collect();
    assert!(decode(&read("rnd.lzfse")) == random);
    assert_eq!(
        decode(&read("small.lzfse")),
        b"hello lzvn hello lzvn hello lzvn small input\n"
    );
    let words = decode(&read("words.lzfse"));
    assert_eq!(words.len(), 2_493_885);
    assert!(words.starts_with(b"A\na\naa\naal\n"));
}

/// Streams from the `brotli` 1.2.0 CLI, except `transforms.br`: hand-made
/// (one meta-block per dictionary reference, all 121 transforms on words of
/// every length) and checked against `brotli -d`'s output.
#[test]
fn brotli_decodes_reference_output() {
    use fillyfoal::codec::{Codec, crc32};
    let read = |name: &str| {
        std::fs::read(format!(
            "{}/tests/data/brotli/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    };
    let decode = |name: &str| {
        let mut d = Codec::Brotli.decoder().unwrap();
        fillyfoal::codec::pipeline::decode_all(d.as_mut(), &read(name), 1 << 26).unwrap()
    };
    // Qualities 0-11 and window sizes 2^16 and the default 2^22.
    for name in [
        "text.q0.br",
        "text.q1.br",
        "text.q5.br",
        "text.q9.br",
        "text.q11.br",
        "text.w16.br",
    ] {
        assert!(decode(name) == lzma_text(), "{name}");
    }
    let random: Vec<u8> = (0..70000u32)
        .map(|i| ((i * 131 + (i >> 3)) & 0xff) as u8)
        .collect();
    assert!(decode("rnd.br") == random);
    assert!(decode("zeros.br") == vec![0u8; 100_000]);
    assert!(decode("empty.br").is_empty());
    let check = |name: &str, len: usize, crc: u32| {
        let out = decode(name);
        assert_eq!((out.len(), crc32(&out)), (len, crc), "{name}");
        out
    };
    // English-like text with UTF-8 and HTML (dictionary hits; 2^10 window).
    for name in ["prose.q0.br", "prose.q11.br", "prose.w10.br"] {
        check(name, 32656, 0xd184_6982);
    }
    // Transformed dictionary words, at quality 11 (113 of the transforms).
    check("dict.q11.br", 101_373, 0xa334_44cb);
    check("transforms.br", 39876, 0x0a24_e342);
    // Binary records: signed context mode, NPOSTFIX 3 and NDIRECT 120.
    check("struct.q11.br", 30000, 0x3c0f_27cd);
    // Incompressible: uncompressed meta-blocks.
    check("noise.br", 20000, 0x1716_a644);
    // Several meta-blocks (quality 1, 2^16 window).
    let words = check("words.q1.br", 300_000, 0xe11b_b7a0);
    assert!(words.starts_with(b"A\na\naa\naal\n"));
    // Truncation and corruption are errors, not panics.
    let text = read("text.q11.br");
    for cut in [0, 1, 10, text.len() / 2, text.len() - 1] {
        let mut d = Codec::Brotli.decoder().unwrap();
        assert!(fillyfoal::codec::pipeline::decode_all(d.as_mut(), &text[..cut], 1 << 26).is_err());
    }
    for i in (0..text.len()).step_by(97) {
        let mut bad = text.clone();
        bad[i] ^= 0x5a;
        let mut d = Codec::Brotli.decoder().unwrap();
        let _ = fillyfoal::codec::pipeline::decode_all(d.as_mut(), &bad, 1 << 26);
    }
    // The output limit holds.
    let mut d = Codec::Brotli.decoder().unwrap();
    assert!(fillyfoal::codec::pipeline::decode_all(d.as_mut(), &read("zeros.br"), 1000).is_err());
}

#[test]
fn xca_codecs_decode_reference_output() {
    // LZNT1 from the `lznt1` PyPI encoder; Plain LZ77 and LZ77+Huffman from
    // encoders written to [MS-XCA] 2.3.4 / 2.1 (no packaged encoder exists),
    // all checked against dissect.util's decompressors when generated.
    use fillyfoal::codec::Codec;
    let read = |name: &str| {
        std::fs::read(format!(
            "{}/tests/data/xca/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    };
    let decode = |codec: Codec, data: &[u8]| {
        let mut d = codec.decoder().unwrap();
        fillyfoal::codec::pipeline::decode_all(d.as_mut(), data, 1 << 26).unwrap()
    };
    let lcg = |n: usize| {
        let mut x: u32 = 12345;
        (0..n)
            .map(|_| {
                x = x.wrapping_mul(1103515245).wrapping_add(12345) & 0x7fff_ffff;
                ((x >> 16) & 0xff) as u8
            })
            .collect::<Vec<u8>>()
    };
    let inputs = [
        ("text", lzma_text()),
        (
            "rnd",
            (0..70000u32)
                .map(|i| ((i * 131 + (i >> 3)) & 0xff) as u8)
                .collect(),
        ),
        ("zeros", vec![0u8; 150_000]),
        ("noise", lcg(9000)),
    ];
    for (name, data) in inputs {
        let size = data.len() as u64;
        assert!(
            decode(Codec::Lznt1 { size: None }, &read(&format!("{name}.lznt1"))) == data,
            "{name}.lznt1"
        );
        assert!(
            decode(
                Codec::Xpress { size: None },
                &read(&format!("{name}.xpress"))
            ) == data,
            "{name}.xpress"
        );
        assert!(
            decode(
                Codec::Xpress { size: Some(size) },
                &read(&format!("{name}.xpress"))
            ) == data,
            "{name}.xpress"
        );
        assert!(
            decode(
                Codec::XpressHuffman { size },
                &read(&format!("{name}.xpressh"))
            ) == data,
            "{name}.xpressh"
        );
    }
    // Corrupt and truncated input fails cleanly (no panics, bounded output).
    let mut rng = common::Rng(0x8ca);
    for ext in ["lznt1", "xpress", "xpressh"] {
        let good = read(&format!("text.{ext}"));
        for i in 0..64 {
            let mut bad = good.clone();
            if i % 2 == 0 {
                bad.truncate(rng.below(good.len()));
            } else {
                for _ in 0..8 {
                    let at = rng.below(bad.len());
                    bad[at] = rng.next() as u8;
                }
            }
            for codec in [
                Codec::Lznt1 { size: None },
                Codec::Xpress { size: None },
                Codec::XpressHuffman { size: 68670 },
            ] {
                let mut d = codec.decoder().unwrap();
                if let Ok(out) = fillyfoal::codec::pipeline::decode_all(d.as_mut(), &bad, 1 << 20) {
                    assert!(out.len() <= 1 << 20);
                }
            }
        }
    }
}

fn legacy_noise(n: usize) -> Vec<u8> {
    let mut x: u32 = 12345;
    (0..n)
        .map(|_| {
            x = x.wrapping_mul(1103515245).wrapping_add(12345) & 0x7fff_ffff;
            ((x >> 16) & 0xff) as u8
        })
        .collect()
}

/// `text[..20000] + noise(9000) + text[..30000]`, as the generators write.
fn legacy_mixed() -> Vec<u8> {
    let text = lzma_text();
    [&text[..20000], &legacy_noise(9000), &text[..30000]].concat()
}

fn legacy_read(dir: &str, name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/data/{dir}/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn legacy_decode_bytes(
    codec: &fillyfoal::codec::Codec,
    data: &[u8],
    limit: usize,
) -> fillyfoal::error::Result<Vec<u8>> {
    let mut d = codec.decoder().unwrap();
    fillyfoal::codec::pipeline::decode_all(d.as_mut(), data, limit)
}

fn legacy_decode(codec: fillyfoal::codec::Codec, dir: &str, name: &str) -> Vec<u8> {
    legacy_decode_bytes(&codec, &legacy_read(dir, name), 1 << 26).unwrap()
}

#[test]
fn lzo_decodes_liblzo_output() {
    // Raw streams from liblzo2 2.10; lzop containers built around them.
    use fillyfoal::codec::Codec;
    assert!(legacy_decode(Codec::Lzo1x, "lzo", "text.lzo1x_1") == lzma_text());
    assert!(legacy_decode(Codec::Lzo1x, "lzo", "text.lzo1x_999") == lzma_text());
    assert!(legacy_decode(Codec::Lzo1x, "lzo", "mixed.lzo1x_1_15") == legacy_mixed());
    assert!(legacy_decode(Codec::Lzo1x, "lzo", "empty.lzo1x_1").is_empty());
    assert!(legacy_decode(Codec::Lzop, "lzo", "text.lzo") == lzma_text());
    assert!(legacy_decode(Codec::Lzop, "lzo", "mixed.lzo") == legacy_mixed());
    // A small output limit, truncation and corruption fail cleanly.
    let data = legacy_read("lzo", "text.lzo");
    assert!(legacy_decode_bytes(&Codec::Lzop, &data, 1000).is_err());
    assert!(legacy_decode_bytes(&Codec::Lzop, &data[..data.len() / 2], 1 << 26).is_err());
    let mut bad = data.clone();
    let at = bad.len() - 10;
    bad[at] ^= 0x55;
    assert!(legacy_decode_bytes(&Codec::Lzop, &bad, 1 << 26).is_err());
    let raw = legacy_read("lzo", "text.lzo1x_1");
    for cut in [1, 2, 100, raw.len() / 2, raw.len() - 1] {
        assert!(legacy_decode_bytes(&Codec::Lzo1x, &raw[..cut], 1 << 26).is_err());
    }
}

#[test]
fn lzf_decodes_liblzf_output() {
    use fillyfoal::codec::Codec;
    assert!(legacy_decode(Codec::Lzf, "lzf", "text.lzf") == lzma_text());
    let framed = legacy_decode(Codec::LzfFramed, "lzf", "mixed.zv");
    assert!(framed == [legacy_mixed(), lzma_text()].concat());
}

#[test]
fn adc_decodes_hdiutil_chunks() {
    // ADC chunks of a UDCO image made by hdiutil; the expected sectors come
    // from the same image converted to a raw (UDTO) one.
    use fillyfoal::codec::Codec;
    let text = legacy_decode(Codec::Adc, "adc", "text.adc");
    assert_eq!(text.len(), 69632);
    let expected = lzma_text();
    assert!(text[..expected.len()] == expected[..]);
    assert!(text[expected.len()..].iter().all(|&b| b == 0));
    assert!(legacy_decode(Codec::Adc, "adc", "gpt.adc") == legacy_read("adc", "gpt.bin"));
}

#[test]
fn implode_decodes_method_6() {
    // Written by an APPNOTE-based encoder (no real PKZIP 1.x encoder is at
    // hand) and checked with 7-Zip's independent implode decoder.
    use fillyfoal::codec::Codec;
    use fillyfoal::codec::implode::Implode;
    let text = lzma_text();
    let mixed = legacy_mixed();
    let runs = [vec![b'A'; 5000], text[..3000].repeat(4), vec![0; 2000]].concat();
    let cases: [(&str, bool, bool, &[u8]); 5] = [
        ("text_8k_lit", true, true, &text),
        ("text_4k", false, false, &text),
        ("mixed_8k", true, false, &mixed),
        ("mixed_4k_lit", false, true, &mixed[..30000]),
        ("runs_4k_lit", false, true, &runs),
    ];
    for (name, large_window, literal_tree, expected) in cases {
        let file = format!("{name}.imploded");
        let params = Implode {
            large_window,
            literal_tree,
            size: Some(expected.len() as u64),
        };
        assert!(
            legacy_decode(Codec::Implode(params), "implode", &file) == expected,
            "{name}"
        );
        // Without a size, decoding runs to the end of the input (padding
        // bits may decode as one more literal).
        let out = legacy_decode(
            Codec::Implode(Implode {
                size: None,
                ..params
            }),
            "implode",
            &file,
        );
        assert!(
            out.starts_with(expected) && out.len() <= expected.len() + 1,
            "{name}"
        );
    }
}

#[test]
fn legacy_codecs_survive_corruption() {
    use fillyfoal::codec::Codec;
    use fillyfoal::codec::implode::Implode;
    let implode = Codec::Implode(Implode {
        large_window: false,
        literal_tree: true,
        size: Some(19000),
    });
    let cases = [
        (Codec::Lzo1x, "lzo", "text.lzo1x_999"),
        (Codec::Lzop, "lzo", "mixed.lzo"),
        (Codec::Lzf, "lzf", "text.lzf"),
        (Codec::LzfFramed, "lzf", "mixed.zv"),
        (Codec::Adc, "adc", "gpt.adc"),
        (implode, "implode", "runs_4k_lit.imploded"),
        (Codec::DclImplode, "dcl", "text_binary2k.pk"),
    ];
    for (codec, dir, name) in cases {
        let data = legacy_read(dir, name);
        for cut in [0, 1, 2, 3, 7, data.len() / 3, data.len() - 1] {
            let _ = legacy_decode_bytes(&codec, &data[..cut], 1 << 22);
        }
        for i in (0..data.len()).step_by(data.len() / 50 + 1) {
            let mut bad = data.clone();
            bad[i] ^= 0xa5;
            let _ = legacy_decode_bytes(&codec, &bad, 1 << 22);
        }
        assert!(
            legacy_decode_bytes(&codec, &data, 100).is_err(),
            "{name}: limit"
        );
    }
}

#[test]
fn dcl_implode_decodes_pklib_output() {
    // From the dclimplode package (StormLib's pklib implode, checked there
    // against zlib's blast): ASCII (coded literals) and binary modes, 1-4 KiB
    // dictionaries.
    use fillyfoal::codec::Codec;
    let text = lzma_text();
    assert!(legacy_decode(Codec::DclImplode, "dcl", "text_ascii4k.pk") == text);
    assert!(legacy_decode(Codec::DclImplode, "dcl", "text_binary2k.pk") == text[..5000]);
    assert!(legacy_decode(Codec::DclImplode, "dcl", "mixed_binary1k.pk") == legacy_mixed());
}

/// A cabinet's folders: compression type and the span of their data blocks.
fn cab_folders(cab: &[u8]) -> Vec<(u16, std::ops::Range<usize>)> {
    let u16le = |o: usize| u16::from_le_bytes([cab[o], cab[o + 1]]);
    let u32le = |o: usize| u32::from_le_bytes(cab[o..o + 4].try_into().unwrap()) as usize;
    (0..usize::from(u16le(26)))
        .map(|i| {
            let at = 36 + 8 * i;
            let start = u32le(at);
            let mut end = start;
            for _ in 0..u16le(at + 4) {
                end += 8 + usize::from(u16le(end + 4));
            }
            (u16le(at + 6), start..end)
        })
        .collect()
}

/// MSZIP comes from zlib; LZX and Quantum from the test encoders in
/// `tests/data/cab/make.py`, whose output 7-Zip extracts to the same bytes.
#[test]
fn cab_folders_decode_7zip_checked_cabinets() {
    use fillyfoal::codec::{Codec, cab::Folder};
    let read = |name: &str| {
        std::fs::read(format!(
            "{}/tests/data/cab/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    };
    let (text, code) = (lzma_text(), lzma_code());
    let small = b"hello cabinet ".repeat(40);
    let cases = [
        ("mszip.cab", vec![[text.as_slice(), &small].concat()]),
        (
            "lzx16.cab",
            vec![[code.as_slice(), &text[..40000]].concat()],
        ),
        ("lzx21.cab", vec![text.clone(), small.clone()]),
        (
            "quantum.cab",
            vec![[text.as_slice(), &code[..20000]].concat()],
        ),
    ];
    for (name, expected) in cases {
        let cab = read(name);
        let folders = cab_folders(&cab);
        assert_eq!(folders.len(), expected.len());
        for ((kind, range), expected) in folders.into_iter().zip(expected) {
            let codec = Codec::CabFolder(Folder {
                kind,
                data_reserve: 0,
            });
            let mut d = codec.decoder().unwrap();
            let out =
                fillyfoal::codec::pipeline::decode_all(d.as_mut(), &cab[range.clone()], 1 << 26)
                    .unwrap();
            assert!(out == expected, "{name}: folder {kind:#x}");
            assert!(
                trickle(&codec, &cab[range]) == expected,
                "{name}: folder {kind:#x}, trickled"
            );
        }
    }
}

/// The test CHM's LZX section: the content stream, window bits, reset
/// interval (frames), decoded length (from the reset table) and the files.
type Section1 = (Vec<u8>, u8, u32, u64, Vec<(String, u64, u64)>);

fn chm_section1(chm: &[u8]) -> Section1 {
    let u32le = |d: &[u8], o: usize| u32::from_le_bytes(d[o..o + 4].try_into().unwrap());
    let u64le = |d: &[u8], o: usize| u64::from_le_bytes(d[o..o + 8].try_into().unwrap());
    let content_at = u64le(chm, 0x58) as usize;
    let dir = u64le(chm, 0x48) as usize + 0x54;
    let pmgl = &chm[dir..dir + 0x1000];
    let end = 0x1000 - u32le(pmgl, 4) as usize;
    let encint = |at: &mut usize| {
        let mut v = 0u64;
        loop {
            let b = pmgl[*at];
            *at += 1;
            v = v << 7 | u64::from(b & 0x7f);
            if b & 0x80 == 0 {
                return v;
            }
        }
    };
    let (mut at, mut files, mut sec0) = (20, Vec::new(), std::collections::HashMap::new());
    while at < end {
        let len = encint(&mut at) as usize;
        let name = String::from_utf8(pmgl[at..at + len].to_vec()).unwrap();
        at += len;
        let (section, offset, length) = (encint(&mut at), encint(&mut at), encint(&mut at));
        if section == 1 {
            files.push((name, offset, length));
        } else {
            sec0.insert(
                name,
                &chm[content_at + offset as usize..content_at + (offset + length) as usize],
            );
        }
    }
    let base = "::DataSpace/Storage/MSCompressed/";
    let control = sec0[&format!("{base}ControlData")];
    assert_eq!(&control[4..8], b"LZXC");
    let window_bits = (u32le(control, 16) * 32768).trailing_zeros() as u8;
    let reset = sec0[&format!(
        "{base}Transform/{{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}}/InstanceData/ResetTable"
    )];
    let content = sec0[&format!("{base}Content")].to_vec();
    (
        content,
        window_bits,
        u32le(control, 12),
        u64le(reset, 16),
        files,
    )
}

/// The CHM's LZX section resets every two frames and uses E8 translation;
/// 7-Zip extracts the same files from it. Also a WIM-style chunk (short
/// block sizes, no E8 header): self-consistency with the test encoder only.
#[test]
fn lzx_decodes_chm_sections_and_wim_chunks() {
    use fillyfoal::codec::{Codec, lzx};
    let dir = format!("{}/tests/data/cab", env!("CARGO_MANIFEST_DIR"));
    let chm = std::fs::read(format!("{dir}/lzx.chm")).unwrap();
    let (content, window_bits, reset_interval, len, files) = chm_section1(&chm);
    assert_eq!((window_bits, reset_interval), (16, 2));
    let codec = Codec::Lzx(lzx::Params {
        window_bits,
        reset_interval,
        variant: lzx::Variant::Cab,
        len: Some(len),
    });
    let mut d = codec.decoder().unwrap();
    let out = fillyfoal::codec::pipeline::decode_all(d.as_mut(), &content, 1 << 26).unwrap();
    assert_eq!(out.len() as u64, len);
    assert!(trickle(&codec, &content) == out);
    let (text, code) = (lzma_text(), lzma_code());
    let small = [
        b"<html>".as_slice(),
        &b"hello cabinet ".repeat(40),
        b"</html>",
    ]
    .concat();
    for (name, offset, length) in files {
        let expected = match name.as_str() {
            "/text.txt" => text.clone(),
            "/code.bin" => code[..30000].to_vec(),
            "/small.html" => small.clone(),
            _ => panic!("{name}"),
        };
        assert!(
            out[offset as usize..(offset + length) as usize] == expected,
            "{name}"
        );
    }

    let chunk = std::fs::read(format!("{dir}/wim-chunk.lzx")).unwrap();
    let mut d = Codec::Lzx(lzx::Params::wim_chunk(32768)).decoder().unwrap();
    let out = fillyfoal::codec::pipeline::decode_all(d.as_mut(), &chunk, 1 << 20).unwrap();
    assert!(out == [&code[..6000], &text[..32768 - 6000]].concat());
}

/// Files in compressed CAB folders and in the CHM's LZX section are
/// dissected like stored ones.
#[test]
fn cab_and_chm_show_compressed_files() {
    for name in [
        "mszip.cab",
        "lzx16.cab",
        "lzx21.cab",
        "quantum.cab",
        "lzx.chm",
    ] {
        let data = std::fs::read(format!(
            "{}/tests/data/cab/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let mut host = Host::named(name, data, Limits::default());
        host.explore(host.root, 6, 40);
        let tree = host.render();
        // (The text sniffs as YAML, which has complaints of its own.)
        for line in tree
            .lines()
            .filter(|l| !l.contains("expected `key: value`"))
        {
            for bad in ["! malformed", "! truncated", "! limit", "! internal"] {
                assert!(!line.contains(bad), "{name}: {line}");
            }
        }
        assert!(
            tree.contains("\"the quick brown fox 919\""),
            "{name}\n{tree}"
        );
        if !["lzx16.cab", "quantum.cab"].contains(&name) {
            assert!(
                tree.contains("hello cabinet hello cabinet"),
                "{name}\n{tree}"
            );
        }
    }
}

/// Corrupted and truncated folders fail (or decode to something) without
/// panicking or looping.
#[test]
fn cab_folder_decoders_survive_corruption() {
    use fillyfoal::codec::{Codec, cab::Folder};
    for name in ["mszip.cab", "lzx16.cab", "quantum.cab"] {
        let cab = std::fs::read(format!(
            "{}/tests/data/cab/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let (kind, range) = cab_folders(&cab).remove(0);
        let codec = Codec::CabFolder(Folder {
            kind,
            data_reserve: 0,
        });
        let data = &cab[range];
        for i in 0..64usize {
            let at = 8 + (i * 7919) % (data.len() - 8);
            let mut bad = data.to_vec();
            bad[at] ^= 1 << (i % 8);
            let mut d = codec.decoder().unwrap();
            let _ = fillyfoal::codec::pipeline::decode_all(d.as_mut(), &bad, 1 << 26);
            let mut d = codec.decoder().unwrap();
            let _ = fillyfoal::codec::pipeline::decode_all(d.as_mut(), &data[..at], 1 << 26);
        }
        // The output limit holds.
        let mut d = codec.decoder().unwrap();
        assert!(fillyfoal::codec::pipeline::decode_all(d.as_mut(), data, 40000).is_err());
    }
}

#[test]
fn charsets_match_python() {
    use fillyfoal::codec::charset::Charset;
    let all: Vec<u8> = (0..=255u8).collect();
    for &cs in Charset::ALL {
        let path = format!(
            "{}/tests/data/charset/{}.txt",
            env!("CARGO_MANIFEST_DIR"),
            cs.name().replace(' ', "_")
        );
        let python: Vec<char> = std::fs::read_to_string(&path).unwrap().chars().collect();
        let ours: Vec<char> = cs.decode(&all).chars().collect();
        assert_eq!(python.len(), 256, "{path}");
        assert_eq!(ours.len(), 256);
        for (b, (p, o)) in python.iter().zip(&ours).enumerate() {
            // Undefined bytes: Python replaces them; Windows code pages
            // pass them through as C1 controls (as browsers do).
            let windows = cs.name().starts_with("Windows-");
            let ok = p == o || (*p == '\u{fffd}' && windows && *o as u32 == b as u32);
            assert!(ok, "{}: byte {b:#04x}: python {p:?}, ours {o:?}", cs.name());
        }
    }
}

/// Explores `data` as file `name`; returns the host, every node's summary
/// and diagnostics, and the bytes of each derived source by transform.
fn explore_decoded(name: &str, data: Vec<u8>) -> (Vec<String>, Vec<(&'static str, Vec<u8>)>) {
    let mut host = Host::named(name, data, Limits::default());
    host.explore_all();
    let mut texts = Vec::new();
    let mut sources = Vec::new();
    let mut stack = vec![host.root];
    while let Some(id) = stack.pop() {
        let node = host.session.node(id).unwrap();
        texts.push(format!(
            "{}: {}",
            node.name,
            node.summary.clone().unwrap_or_default()
        ));
        for d in &node.diagnostics {
            texts.push(format!("diag {:?}: {}", d.kind, d.message));
        }
        if let Some(span) = node.span
            && !sources.contains(&span.source)
        {
            sources.push(span.source);
        }
        if let Some(c) = host.session.children(id) {
            stack.extend(c.ids.iter().copied());
        }
    }
    let derived = sources
        .into_iter()
        .filter_map(|s| {
            Some((
                host.session.origin(s)?.transform,
                host.session.derived_data(s)?.to_vec(),
            ))
        })
        .collect();
    (texts, derived)
}

fn test_data(path: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/data/{path}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

#[test]
fn uuencode_and_xxencode_decode_real_output() {
    // `uu/*.uue` come from /usr/bin/uuencode; `uu/*.xxe` are the same
    // output re-spelled in the xxencode alphabet.
    let text = lzma_text()[..16000].to_vec();
    let rnd: Vec<u8> = (0..5000u32)
        .map(|i| ((i * 131 + (i >> 3)) & 0xff) as u8)
        .collect();
    for (file, transform, want) in [
        ("uu/text.uue", "uudecode", &text),
        ("uu/rnd.uue", "uudecode", &rnd),
        ("uu/text.xxe", "xxdecode", &text),
        ("uu/rnd.xxe", "xxdecode", &rnd),
    ] {
        let (texts, derived) = explore_decoded(file, test_data(file));
        let got: Vec<_> = derived.iter().filter(|(t, _)| *t == transform).collect();
        assert_eq!(got.len(), 1, "{file}: {texts:?}");
        assert!(got[0].1 == *want, "{file}");
        assert!(
            !texts.iter().any(|t| t.starts_with("diag")),
            "{file}: {texts:?}"
        );
    }
}

#[test]
fn yenc_decodes_real_encoder_output() {
    // Bodies from sabyenc3 (a real yEnc encoder); headers per yEnc 1.3.
    let rnd: Vec<u8> = (0..20000u32)
        .map(|i| ((i * 131 + (i >> 3)) & 0xff) as u8)
        .collect();
    let (texts, derived) = explore_decoded("rnd.yenc", test_data("yenc/rnd.yenc"));
    assert!(
        derived.iter().any(|(t, d)| *t == "ydecode" && *d == rnd),
        "{texts:?}"
    );
    assert!(
        texts.iter().any(|t| t == "CRC-32: matches the trailer"),
        "{texts:?}"
    );
    assert!(!texts.iter().any(|t| t.starts_with("diag")), "{texts:?}");

    // Three parts, joined: the joined file's size and CRC-32 are checked.
    let text = lzma_text();
    let (texts, derived) = explore_decoded("text.yenc", test_data("yenc/text.yenc"));
    let parts: Vec<u8> = derived
        .iter()
        .filter(|(t, _)| *t == "ydecode")
        .flat_map(|(_, d)| d.clone())
        .collect();
    assert_eq!(parts.len(), text.len());
    assert!(
        texts
            .iter()
            .any(|t| t.starts_with("Joined: lzma text.txt") && t.contains("3 parts of 3")),
        "{texts:?}"
    );
    assert_eq!(
        texts
            .iter()
            .filter(|t| *t == "CRC-32: matches the trailer")
            .count(),
        4,
        "{texts:?}"
    );
    assert!(!texts.iter().any(|t| t.starts_with("diag")), "{texts:?}");

    // A corrupted byte fails the CRC.
    let mut bad = test_data("yenc/rnd.yenc");
    let at = bad.len() / 2;
    bad[at] = bad[at].wrapping_add(if bad[at] == b'=' - 1 { 2 } else { 1 });
    let (texts, _) = explore_decoded("bad.yenc", bad);
    assert!(
        texts
            .iter()
            .any(|t| t.starts_with("diag Malformed: CRC-32")),
        "{texts:?}"
    );
}

/// A collection of `n` numbered children; with `marks`, the walker records
/// resume marks (its next index) and counts in the summary where it
/// started, so tests can see whether a restart used one.
async fn numbers(cx: Cx, (n, marks): (u64, bool)) -> Result<()> {
    let mut i = cx.resume::<u64>().unwrap_or(0);
    cx.diag(fillyfoal::Diagnostic::note(format!("started at {i}")));
    cx.set_count(fillyfoal::Count::Exact(n));
    while i < n {
        if marks {
            let at = i;
            cx.mark(move || at);
        }
        cx.push(Node::new(format!("n{i}")).value(Value::Text(i.to_string())))
            .await;
        i += 1;
    }
    Ok(())
}

fn window(host: &Host, id: fillyfoal::NodeId) -> (u64, Vec<String>) {
    let c = host.session.children(id).unwrap();
    (
        c.first,
        c.ids
            .iter()
            .map(|&i| host.session.node(i).unwrap().name.to_string())
            .collect(),
    )
}

fn started(host: &Host, id: fillyfoal::NodeId) -> Vec<String> {
    host.session
        .node(id)
        .unwrap()
        .diagnostics
        .iter()
        .map(|d| d.message.clone())
        .collect()
}

#[test]
fn windows_seek_and_resume_from_marks() {
    for marks in [true, false] {
        let mut host = Host::with_chunk(Vec::new(), 4);
        let root = host
            .session
            .add_root(Node::new("numbers").lazy(numbers, (10_000u64, marks)));
        // Page through the start.
        host.session.expand(root, 50);
        host.run();
        assert_eq!(window(&host, root).1.len(), 50);
        // Jump far ahead: only the window is materialised.
        host.session.seek(root, 5_000, 20);
        host.run();
        let (first, names) = window(&host, root);
        assert_eq!(first, 5_000);
        assert_eq!(
            names,
            (5_000..5_020).map(|i| format!("n{i}")).collect::<Vec<_>>()
        );
        assert!(
            host.session.live_nodes() < 100,
            "{} live nodes",
            host.session.live_nodes()
        );
        // Back to the middle: a restart, from a mark when there are marks.
        host.session.seek(root, 1_000, 10);
        host.run();
        let (first, names) = window(&host, root);
        assert_eq!(first, 1_000);
        assert_eq!(
            names,
            (1_000..1_010).map(|i| format!("n{i}")).collect::<Vec<_>>()
        );
        let notes = started(&host, root);
        assert_eq!(
            notes.len(),
            1,
            "diagnostics of the restarted run only: {notes:?}"
        );
        if marks {
            assert_ne!(notes[0], "started at 0", "restart did not use a mark");
        } else {
            assert_eq!(notes[0], "started at 0");
        }
        // Forward again within reach, then to the end.
        host.session.seek(root, 9_990, 100);
        host.run();
        let (first, names) = window(&host, root);
        assert_eq!((first, names.len()), (9_990, 10));
        assert_eq!(
            host.session.children(root).unwrap().state,
            fillyfoal::ChildState::Complete
        );
        assert_eq!(
            host.session.children(root).unwrap().count,
            fillyfoal::Count::Exact(10_000)
        );
        // Collapsing and expanding again starts from scratch with one note.
        host.session.collapse(root);
        host.session.expand(root, 5);
        host.run();
        assert_eq!(
            window(&host, root),
            (0, (0..5).map(|i| format!("n{i}")).collect())
        );
        assert_eq!(started(&host, root), vec!["started at 0".to_owned()]);
    }
}

/// A zlib stream of stored blocks holding `data` (any size).
fn zlib_stored_big(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x78, 0x01];
    let blocks: Vec<&[u8]> = data.chunks(65_535).collect();
    for (i, block) in blocks.iter().enumerate() {
        out.push(u8::from(i + 1 == blocks.len()));
        let len = block.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(block);
    }
    out.extend_from_slice(&fillyfoal::codec::adler32(data).to_be_bytes());
    out
}

/// Decodes each stream eagerly, then the first one again, emitting each
/// stream's last bytes.
async fn decode_streams(cx: Cx, streams: Vec<Span>) -> Result<()> {
    let order: Vec<usize> = (0..streams.len()).chain([0]).collect();
    for i in order {
        let decoded =
            fillyfoal::codec::decode_span(&cx, streams[i], &fillyfoal::codec::Codec::Zlib, None)
                .await?;
        let tail = cx.read(decoded.span.tail(decoded.span.len - 8)).await?;
        cx.emit(Node::new(format!("stream {i}")).value(Value::Bytes(tail)));
    }
    Ok(())
}

#[test]
fn decoded_sources_are_evicted_and_decoded_again() {
    let parts: Vec<Vec<u8>> = (0..3u8)
        .map(|k| {
            (0..400_000u32)
                .map(|i| (i as u8) ^ k.wrapping_mul(37))
                .collect()
        })
        .collect();
    let mut file = Vec::new();
    let mut spans = Vec::new();
    for p in &parts {
        let z = zlib_stored_big(p);
        spans.push(Span::new(
            fillyfoal::SourceId::default_host(),
            file.len() as u64,
            z.len() as u64,
        ));
        file.extend_from_slice(&z);
    }
    let run = |max_derived: u64| {
        let limits = fillyfoal::Limits {
            max_derived,
            chunk_size: 4096,
            ..fillyfoal::Limits::default()
        };
        let mut host = Host::new(file.clone(), limits);
        let root = host
            .session
            .add_root(Node::new("streams").lazy(decode_streams, spans.clone()));
        host.session.expand(root, 10);
        host.run();
        let c = host.session.children(root).unwrap();
        assert!(c.error.is_none(), "{:?}", c.error);
        let values: Vec<_> = c
            .ids
            .iter()
            .map(|&id| host.session.node(id).unwrap().value.clone().unwrap())
            .collect();
        (values, host.session.derived_bytes())
    };
    let (roomy, _) = run(1 << 30);
    let (tight, held) = run(1 << 20);
    assert_eq!(roomy, tight);
    assert_eq!(tight.len(), 4);
    assert_eq!(
        tight[0],
        Value::Bytes(parts[0][parts[0].len() - 8..].to_vec())
    );
    assert!(held <= 1 << 20, "{held} derived bytes held");
}

/// Reads a 64 MiB lazily decoded stream at its end, its start and its
/// middle, emitting 16 bytes from each.
async fn read_far(cx: Cx, file: Span) -> Result<()> {
    let len = 64u64 << 20;
    let s = cx.decode_lazy(file, &fillyfoal::codec::Codec::Zlib, len)?;
    for at in [len - 16, 0, len / 2, len - 16] {
        let bytes = cx.read(s.sub(at, 16)).await?;
        cx.emit(Node::new(format!("at {at}")).value(Value::Bytes(bytes)));
    }
    Ok(())
}

/// A stream sixteen times larger than the decoded-data budget can be read
/// anywhere: the source keeps a window and decodes again from the start for
/// reads behind it.
#[test]
fn lazy_sources_slide_over_streams_larger_than_the_budget() {
    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/lazy/big.zlib"
    ))
    .unwrap();
    let file = Span::new(fillyfoal::SourceId::default_host(), 0, data.len() as u64);
    let limits = fillyfoal::Limits {
        max_derived: 4 << 20,
        ..fillyfoal::Limits::default()
    };
    let mut host = Host::new(data, limits);
    host.max_polls = 10_000_000;
    let root = host.session.add_root(Node::new("far").lazy(read_far, file));
    host.session.expand(root, 10);
    host.run();
    let c = host.session.children(root).unwrap();
    assert!(c.error.is_none(), "{:?}", c.error);
    let expect = |i: u64| -> Vec<u8> { (i..i + 16).map(|i| ((i * 7) + (i >> 12)) as u8).collect() };
    let len = 64u64 << 20;
    let got: Vec<Value> = c
        .ids
        .iter()
        .map(|&id| host.session.node(id).unwrap().value.clone().unwrap())
        .collect();
    let want: Vec<Value> = [len - 16, 0, len / 2, len - 16]
        .iter()
        .map(|&at| Value::Bytes(expect(at)))
        .collect();
    assert_eq!(got, want);
    assert!(
        host.session.derived_bytes() <= 4 << 20,
        "{} bytes held",
        host.session.derived_bytes()
    );
}

/// Seeking around the lines of a large text file, forward and back (the
/// line walker records resume marks), gives the right lines.
#[test]
fn text_lines_seek() {
    let text: String = (1..=100_000).map(|i| format!("row {i}\n")).collect();
    let mut host = Host::with_chunk(text.into_bytes(), 65_536);
    host.max_polls = 10_000_000;
    host.session.expand(host.root, 10);
    host.run();
    let lines = host.child(host.root, "Lines").expect("lines node");
    for (start, first_name, first_text) in [
        (90_000, "Line 90001", "row 90001"),
        (50_000, "Line 50001", "row 50001"),
        (99_998, "Line 99999", "row 99999"),
    ] {
        host.session.seek(lines, start, 5);
        host.run();
        let c = host.session.children(lines).unwrap();
        assert_eq!(c.first, start);
        let node = host.session.node(c.ids[0]).unwrap();
        assert_eq!(node.name, first_name);
        assert_eq!(node.value, Some(Value::Text(first_text.into())));
    }
    assert!(
        host.session.live_nodes() < 50,
        "{} live nodes",
        host.session.live_nodes()
    );
}

/// "Inspect as": formats by extension, and dissecting bytes as a chosen
/// format whatever identification says.
#[test]
fn open_as_a_chosen_format() {
    use fillyfoal::formats;
    let names = |ext: &str| {
        formats::by_extension(ext)
            .iter()
            .map(|f| f.name)
            .collect::<Vec<_>>()
    };
    assert!(names("BR").contains(&"brotli"));
    // Probe order: ZIP-based formats that also use `.zip` come first.
    assert!(names(".zip").contains(&"zip"));
    assert!(names("no-such-extension").is_empty());

    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/external/brotli/page.html.br"
    ))
    .unwrap();
    let len = data.len() as u64;
    let mut host = Host::with_chunk(data, 4096);
    // As Brotli: decoded and dissected.
    let br = host
        .session
        .open_as("page.html.br", len, formats::by_name("brotli").unwrap());
    host.explore(br, 2, 100);
    let children = host.session.children(br).unwrap();
    let names: Vec<String> = children
        .ids
        .iter()
        .map(|&id| host.session.node(id).unwrap().name.to_string())
        .collect();
    assert!(names.iter().any(|n| n == "Decompressed"), "{names:?}");
    // As ZIP: not a ZIP, so the dissector reports why, without panicking.
    let zip = host
        .session
        .open_as("page.html.br", len, formats::by_name("zip").unwrap());
    host.explore(zip, 2, 100);
    let c = host.session.children(zip).unwrap();
    assert!(c.error.is_some() || !host.session.node(zip).unwrap().diagnostics.is_empty());
}

/// The G-code blocks of libbgcode's binary fixtures, decoded with our
/// codecs (zlib, Heatshrink 11/4 and 12/4, MeatPack), are exactly the
/// G-code libbgcode's `from_binary_to_ascii` writes for them (see
/// `tests/data/bgcode/make_bgcode.py`).
#[test]
fn bgcode_gcode_blocks_match_libbgcode() {
    use fillyfoal::codec::Codec;
    let root = env!("CARGO_MANIFEST_DIR");
    for name in [
        "plain",
        "deflate",
        "heatshrink-11",
        "heatshrink-12",
        "meatpack",
    ] {
        let data = std::fs::read(format!(
            "{root}/tests/fixtures/external/bgcode/{name}.bgcode"
        ))
        .unwrap();
        let reference =
            std::fs::read(format!("{root}/tests/data/bgcode/{name}.ref.gcode")).unwrap();
        let checksum = u16::from_le_bytes([data[8], data[9]]) as usize * 4;
        let mut pos = 10;
        let mut gcode = Vec::new();
        let mut blocks = 0;
        while pos < data.len() {
            let u16_at = |at: usize| u16::from_le_bytes([data[at], data[at + 1]]);
            let u32_at =
                |at: usize| u32::from_le_bytes(data[at..at + 4].try_into().unwrap()) as usize;
            let (kind, compression, size) = (u16_at(pos), u16_at(pos + 2), u32_at(pos + 4));
            let (header, stored) = if compression == 0 {
                (8, size)
            } else {
                (12, u32_at(pos + 8))
            };
            let params = if kind == 5 { 6 } else { 2 };
            let body = &data[pos + header + params..pos + header + params + stored];
            if kind == 1 {
                let base = match compression {
                    0 => None,
                    1 => Some(Codec::Zlib),
                    2 => Some(Codec::Heatshrink {
                        window: 11,
                        lookahead: 4,
                    }),
                    _ => Some(Codec::Heatshrink {
                        window: 12,
                        lookahead: 4,
                    }),
                };
                let mut bytes = match base {
                    Some(c) => fillyfoal::codec::pipeline::decode_all(
                        c.decoder().unwrap().as_mut(),
                        body,
                        1 << 24,
                    )
                    .unwrap(),
                    None => body.to_vec(),
                };
                assert_eq!(bytes.len(), size, "{name}: decoded size");
                if u16_at(pos + header) != 0 {
                    let mut d = Codec::MeatPack.decoder().unwrap();
                    bytes = fillyfoal::codec::pipeline::decode_all(d.as_mut(), &bytes, 1 << 24)
                        .unwrap();
                }
                // `from_binary_to_ascii` drops blank and empty-comment lines
                // of each block (`remove_empty_lines` in convert.cpp).
                let trim = |l: &[u8]| -> Vec<u8> {
                    let s = l
                        .iter()
                        .position(|b| *b != b' ' && *b != b'\t')
                        .unwrap_or(l.len());
                    let e = l
                        .iter()
                        .rposition(|b| *b != b' ' && *b != b'\t')
                        .map_or(s, |e| e + 1);
                    l[s..e.max(s)].to_vec()
                };
                for line in bytes.split(|&b| b == b'\n') {
                    let t = trim(line);
                    let reduced = if t.first() == Some(&b';') {
                        trim(&t[1..])
                    } else {
                        t
                    };
                    if !reduced.is_empty() {
                        gcode.extend_from_slice(line);
                        gcode.push(b'\n');
                    }
                }
                blocks += 1;
            }
            pos += header + params + stored + checksum;
        }
        assert!(blocks > 0, "{name}");
        let found = reference
            .windows(gcode.len())
            .any(|w| w == gcode.as_slice());
        assert!(found, "{name}: decoded G-code differs from libbgcode's");
    }
}

/// Schemaless wire encodings have no signature: they are offered by
/// extension, and the ones without a probe never identify anything.
#[test]
fn wire_encodings_are_offered_by_extension() {
    use fillyfoal::formats::{self, Probe};
    let names = |ext: &str| {
        formats::by_extension(ext)
            .iter()
            .map(|f| f.name)
            .collect::<Vec<_>>()
    };
    assert!(names("pb").contains(&"protobuf"));
    assert!(names("binpb").contains(&"protobuf"));
    assert!(names("fb").contains(&"flatbuffers"));
    let bin = names("bin");
    for name in [
        "flatbuffers",
        "thrift-binary",
        "thrift-compact",
        "capnp",
        "capnp-packed",
    ] {
        assert!(bin.contains(&name), "{name} missing from {bin:?}");
    }
    for name in [
        "protobuf",
        "flatbuffers",
        "thrift-binary",
        "thrift-compact",
        "capnp-packed",
    ] {
        assert!(
            matches!(formats::by_name(name).unwrap().probe, Probe::Never),
            "{name}"
        );
    }
}

/// Compressed `.blend` files (zstd from Blender 3.0 on, gzip before) are
/// identified by their compression; the Blender file inside is recognised,
/// and opening one as Blender explicitly decompresses it too (see
/// `tests/data/blend/make_blend.py` for how the files were made).
#[test]
fn compressed_blend_files() {
    for (file, wrapper) in [
        ("scene.blend.zst", "Decompressed"),
        ("scene.blend.gz", "Gzip stream"),
    ] {
        let path = format!("{}/tests/data/blend/{file}", env!("CARGO_MANIFEST_DIR"));
        let data = std::fs::read(path).unwrap();
        // Identified by content: the compression format, the scene inside.
        let tree = common::explore(file, &data);
        assert!(tree.contains("OB Cube"), "{file}:\n{tree}");
        // Opened as Blender: the dissector offers the decompressed file.
        let len = data.len() as u64;
        let mut host = Host::with_chunk(data, 4096);
        let id = host
            .session
            .open_as(file, len, formats::by_name("blend").unwrap());
        host.explore(id, 8, 100);
        let tree = fillyfoal::render::tree(&host.session, id);
        assert!(tree.contains(wrapper), "{file}:\n{tree}");
        assert!(tree.contains("OB Cube"), "{file}:\n{tree}");
    }
}

#[test]
fn keepass_retries_the_password_and_hides_secrets() {
    let read = |p: &str| {
        std::fs::read(format!("{}/tests/fixtures/{p}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    };
    for (name, path) in [
        ("a.kdbx", "external/kdbx/argon2d-chacha20.kdbx"),
        ("b.kdbx", "external/kdbx/kdbx3.kdbx"),
        ("c.kdb", "synthetic/kdb/twofish.kdb"),
    ] {
        let mut host = Host::named(name, read(path), Limits::default());
        host.passwords = vec!["wrong".into(), "fillyfoal".into()];
        host.explore_all();
        let text = host.render();
        assert_eq!(host.secret_requests.len(), 2, "{name}");
        assert!(text.contains("Router"), "{name}: not unlocked\n{text}");
        for secret in ["hunter2", "correct horse", "s3cret"] {
            assert!(!text.contains(secret), "{name}: {secret} leaked");
        }
        // Without a password, nothing beyond the header.
        let mut host = Host::named(name, read(path), Limits::default());
        host.passwords.clear();
        host.explore_all();
        let text = host.render();
        assert!(text.contains("no password, or a wrong one"), "{name}");
        assert!(!text.contains("Router"), "{name}");
    }
}

#[test]
fn keepass_refuses_runaway_key_derivations() {
    // AES-KDF rounds patched to 2^40 in the KDBX 3.1 fixture: refused up
    // front instead of running into the work limit.
    let mut data = std::fs::read(format!(
        "{}/tests/fixtures/external/kdbx/kdbx3.kdbx",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    data[0x6f..0x77].copy_from_slice(&(1u64 << 40).to_le_bytes());
    let mut host = Host::named("x.kdbx", data, Limits::default());
    host.explore_all();
    let text = host.render();
    assert!(text.contains("key derivation too expensive"), "{text}");
}

/// `text(n, seed)` of `tests/data/lzh/make.py`.
fn lzh_text(n: usize, seed: u64) -> Vec<u8> {
    let words: Vec<&str> = "the quick brown fox jumps over lazy dogs while old archivers \
         squeeze bytes into tiny floppy disks and bulletin boards"
        .split_whitespace()
        .collect();
    let mut out: Vec<String> = Vec::new();
    let (mut x, mut i) = (seed, 0u64);
    while out.iter().map(|w| w.len() + 1).sum::<usize>() < n {
        x = (x * 1103515245 + 12345) & 0x7FFF_FFFF;
        out.push(words[((x >> 16) as usize) % words.len()].to_owned());
        i += 1;
        if i % 12 == 0 {
            out.push(format!("{i}\r\n"));
        }
    }
    let mut joined = out.join(" ").into_bytes();
    joined.truncate(n);
    joined
}

/// `binary(n, seed)` of `tests/data/lzh/make.py`.
fn lzh_binary(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed;
    (0..n)
        .map(|i| {
            x = (x * 1103515245 + 12345) & 0x7FFF_FFFF;
            let r = ((x >> 16) & 0xff) as u8;
            if r < 160 { r } else { (i & 0x0f) as u8 }
        })
        .collect()
}

/// The LHA, ARJ, ZOO, SZDD, KWAJ and PSARC fixtures of
/// `tests/data/lzh/make.py` decode to the generator's input, with matching
/// CRCs. 7-Zip extracts the same bytes from the LHA -lh4- to -lh7-, ARJ and
/// SZDD streams (libarchive and lhafile from -lh5- to -lh7-); the other
/// methods are checked against our own test encoders only.
#[test]
fn lzh_family_fixtures_decode_to_the_generator_input() {
    let t = lzh_text;
    let b = lzh_binary;
    let psarc = vec![
        t(9000, 61),
        [b(4096, 9), (0..=255u8).chain(0..=255u8).collect()].concat(),
        b"short text member\n".to_vec(),
        b"/docs/readme.txt\n/data/noise.bin\n/data/tail.txt".to_vec(),
    ];
    let cases: Vec<(&str, &str, Vec<Vec<u8>>)> = vec![
        (
            "lha",
            "methods.lzh",
            vec![
                t(3000, 11),
                [t(2500, 12), b(500, 7)].concat(),
                t(3000, 13),
                [b(1500, 3), t(1500, 14)].concat(),
                [b(256, 4), t(20000, 15), b(256, 4)].concat(),
                t(1500, 16),
                t(1500, 17),
            ],
        ),
        (
            "arj",
            "methods.arj",
            vec![
                t(3000, 21),
                [b(800, 5), t(1200, 22)].concat(),
                t(2000, 23),
                t(3000, 24),
            ],
        ),
        ("zoo", "methods.zoo", vec![t(9000, 31), t(3000, 32)]),
        ("szdd", "lzss.tx_", vec![t(3000, 41)]),
        ("kwaj", "lzss.tx_", vec![t(3000, 51)]),
        ("kwaj", "mszip.tx_", vec![t(40000, 52)]),
        ("psarc", "zlib.psarc", psarc.clone()),
        ("psarc", "lzma.psarc", psarc),
    ];
    for (format, name, expected) in cases {
        let data = std::fs::read(format!(
            "{}/tests/fixtures/synthetic/{format}/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let (texts, derived) = explore_decoded(name, data);
        for line in &texts {
            assert!(
                !line.starts_with("diag") || line.starts_with("diag Note"),
                "{format}/{name}: {line}"
            );
        }
        let outputs: Vec<&Vec<u8>> = derived
            .iter()
            .filter(|(transform, _)| ["lzh", "psarc"].contains(transform))
            .map(|(_, d)| d)
            .collect();
        for (i, want) in expected.iter().enumerate() {
            assert!(
                outputs.contains(&want),
                "{format}/{name}: expected output {i} ({} bytes) missing",
                want.len()
            );
        }
    }
}

/// The LZH codecs decode one byte of input at a time (rolling back short
/// steps) to the same output, and survive corruption and truncation.
#[test]
fn lzh_codecs_trickle_and_survive_corruption() {
    use fillyfoal::codec::{Codec, lzh};
    let lha = std::fs::read(format!(
        "{}/tests/fixtures/synthetic/lha/methods.lzh",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    // Level 0 headers: size, checksum, method, packed and original sizes.
    let mut at = 0;
    let mut streams = Vec::new();
    while lha[at] != 0 {
        let size = lha[at] as usize + 2;
        let method = std::str::from_utf8(&lha[at + 2..at + 7])
            .unwrap()
            .to_owned();
        let packed = u32::from_le_bytes(lha[at + 7..at + 11].try_into().unwrap()) as usize;
        let original = u32::from_le_bytes(lha[at + 11..at + 15].try_into().unwrap()) as u64;
        streams.push((
            method,
            lha[at + size..at + size + packed].to_vec(),
            original,
        ));
        at += size + packed;
    }
    for (method, data, original) in streams {
        let m = match method.as_str() {
            "-lh1-" => lzh::Method::Lh1,
            "-lh4-" => lzh::Method::Lh { dict_bits: 12 },
            "-lh5-" => lzh::Method::Lh { dict_bits: 13 },
            "-lh6-" => lzh::Method::Lh { dict_bits: 15 },
            "-lh7-" => lzh::Method::Lh { dict_bits: 16 },
            "-lzs-" => lzh::Method::Lzs,
            "-lz5-" => lzh::Method::Lz5,
            _ => continue,
        };
        let codec = Codec::Lzh(lzh::Params::new(m, Some(original), lzh::Check::None));
        let mut d = codec.decoder().unwrap();
        let whole = fillyfoal::codec::pipeline::decode_all(d.as_mut(), &data, 1 << 20).unwrap();
        assert_eq!(whole.len() as u64, original, "{method}");
        assert!(trickle(&codec, &data) == whole, "{method}: trickled");
        for i in 0..48usize {
            let mut bad = data.clone();
            let at = (i * 7919) % bad.len();
            bad[at] ^= 1 << (i % 8);
            let mut d = codec.decoder().unwrap();
            let _ = fillyfoal::codec::pipeline::decode_all(d.as_mut(), &bad, 1 << 20);
            let mut d = codec.decoder().unwrap();
            let _ = fillyfoal::codec::pipeline::decode_all(d.as_mut(), &data[..at], 1 << 20);
        }
    }
}
