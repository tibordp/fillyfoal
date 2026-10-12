//! Content the system dissectors rebuild from their containers: the image
//! an Android sparse file describes, read back against what simg2img
//! writes, and its cost on a sparse file describing a huge fill; git
//! objects rebuilt from ofs-delta chains, checked against their object
//! IDs (SHA-1 and SHA-256 repositories); and record walkers resumed from
//! marks.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::Host;
use fillyfoal::codec::crypto::Hash;
use fillyfoal::{Limits, NodeId, Span};

fn fixture(path: &str) -> Vec<u8> {
    common::fixture_bytes(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
}

fn open(host: &mut Host, path: &[&str]) -> NodeId {
    let mut id = host.root;
    for name in path {
        host.session.expand_more(id, 10_000);
        host.run();
        id = host
            .child(id, name)
            .unwrap_or_else(|| panic!("no {name:?} under:\n{}", host.render()));
    }
    host.session.expand_more(id, 10_000);
    host.run();
    id
}

fn read(host: &mut Host, span: Span) -> Vec<u8> {
    loop {
        match host.session.read(span) {
            Ok(bytes) => return bytes,
            Err(requests) => host.supply(requests),
        }
    }
}

/// The source an expanded node's children were dissected from.
fn child_source(host: &Host, id: NodeId) -> Span {
    let children = host.session.children(id).unwrap();
    children
        .ids
        .iter()
        .find_map(|&c| host.session.node(c).unwrap().span)
        .unwrap_or_else(|| panic!("no spans under:\n{}", host.render()))
}

#[test]
fn sparse_image_expands_to_what_simg2img_writes() {
    let data = fixture("tests/fixtures/external/android-sparse/ext4.simg");
    let mut host = Host::named("ext4.simg", data, Limits::default());
    let id = open(&mut host, &["Expanded image"]);
    let source = child_source(&host, id).source;
    let image = read(&mut host, Span::new(source, 0, 2 << 20));
    assert_eq!(image.len(), 2 << 20);
    // CRC-32 of the ext4 image simg2img rebuilt from this file
    // (tests/data/android-sparse/inside.sh).
    assert_eq!(fillyfoal::codec::crc32(&image), 0xd159_787d);
}

/// A sparse header for `blocks` 4 KiB blocks and its chunk headers.
fn sparse(blocks: u32, chunks: &[(u16, u32, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(0xed26_ff3au32.to_le_bytes());
    out.extend(1u16.to_le_bytes());
    out.extend(0u16.to_le_bytes());
    out.extend(28u16.to_le_bytes());
    out.extend(12u16.to_le_bytes());
    out.extend(4096u32.to_le_bytes());
    out.extend(blocks.to_le_bytes());
    out.extend(u32::try_from(chunks.len()).unwrap().to_le_bytes());
    out.extend(0u32.to_le_bytes());
    for (kind, n, body) in chunks {
        out.extend(kind.to_le_bytes());
        out.extend(0u16.to_le_bytes());
        out.extend(n.to_le_bytes());
        out.extend((12 + u32::try_from(body.len()).unwrap()).to_le_bytes());
        out.extend(*body);
    }
    out
}

#[test]
fn huge_sparse_fills_cost_little() {
    // 16 TiB: a non-zero fill of 8 TiB, then 8 TiB of "don't care". The
    // fill maps onto repeats of one derived 1 MiB pattern, capped at a
    // million pieces; the hole is one piece.
    let half = 1u32 << 31;
    let data = sparse(
        u32::MAX,
        &[(0xcac2, half, &[0xff; 4]), (0xcac3, half - 1, &[])],
    );
    let mut host = Host::named("huge.simg", data, Limits::default());
    let id = open(&mut host, &["Expanded image"]);
    let work = host.session.work_done();
    assert!(work < 200_000, "{work} units");
    let source = child_source(&host, id);
    let head = read(&mut host, Span::new(source.source, 0, 64));
    assert!(head.iter().all(|&b| b == 0xff), "{head:x?}");
    let kinds = common::diagnostic_kinds(&host);
    assert!(
        kinds.contains(&fillyfoal::DiagKind::Limit),
        "{kinds:?}\n{}",
        host.render()
    );
}

/// The object ID of the object an ofs-delta at `offset` rebuilds: the
/// hash of `"<type> <size>\0"` and the content, as git computes it.
fn rebuilt_id<H: fillyfoal::codec::crypto::Hash>(pack: &str, offset: u64, kind: &str) -> String {
    let data = fixture(&format!("tests/fixtures/external/git-pack/{pack}"));
    let mut host = Host::named(pack, data, Limits::default());
    let id = open(
        &mut host,
        &[&format!("ofs-delta at {offset:#x}"), "Resolved object"],
    );
    let node = host
        .child(id, "Object")
        .unwrap_or_else(|| panic!("no object under:\n{}", host.render()));
    let span = host.session.node(node).unwrap().span.unwrap();
    let bytes = read(&mut host, span);
    let mut h = H::new();
    h.update(format!("{kind} {}\0", bytes.len()).as_bytes());
    h.update(&bytes);
    h.finish().iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn ofs_deltas_rebuild_their_objects() {
    use fillyfoal::codec::crypto::{Sha1, Sha256};
    // `git verify-pack -v` of signed.pack: a commit delta, and two blobs
    // at chain depth 2 sharing their base.
    assert_eq!(
        rebuilt_id::<Sha1>("signed.pack", 0x2e4, "commit"),
        "9e877340816015914be6c72f372e68539686152d"
    );
    assert_eq!(
        rebuilt_id::<Sha1>("signed.pack", 0x7fe, "blob"),
        "02237bf456da8784f6d16a80a9239b0ed90cab8b"
    );
    assert_eq!(
        rebuilt_id::<Sha1>("signed.pack", 0x80f, "blob"),
        "9d904a0e65bceeb68066d4987ae4a1cb77d3dbdc"
    );
    // A SHA-256 repository (tests/data/git-pack/inside-sha256.sh).
    assert_eq!(
        rebuilt_id::<Sha256>("sha256.pack", 0x495, "blob"),
        "68508f7647e94e8c38de36a704fe1d3ab3d5340b0f9b26dc5a6f940cb8041eac"
    );
    assert_eq!(
        rebuilt_id::<Sha256>("sha256.pack", 0x50f, "blob"),
        "5a4abaa40b063a557620b4face82b7ebe661e7f09faedf90274dc75e9f960c6b"
    );
}

/// What a window of children shows: names, summaries, spans.
fn window(host: &Host, id: NodeId) -> (u64, Vec<String>) {
    let c = host.session.children(id).unwrap();
    let rows = c
        .ids
        .iter()
        .map(|&i| {
            let n = host.session.node(i).unwrap();
            format!("{} — {:?} {:?}", n.name, n.summary, n.span)
        })
        .collect();
    (c.first, rows)
}

/// Opens `path` under a host dissecting `data` as `format`.
fn walker(format: &str, data: &[u8], path: &[&str]) -> (Host, NodeId) {
    let format = fillyfoal::formats::by_name(format).unwrap();
    let mut host = Host::open("walk", data.to_vec(), Limits::default(), Some(format));
    let mut id = host.root;
    for name in path {
        host.session.expand_more(id, 10_000);
        host.run();
        id = host
            .child(id, name)
            .unwrap_or_else(|| panic!("no {name:?} under:\n{}", host.render()));
    }
    (host, id)
}

/// A walk resumed from a mark (after paging to `far`, a seek back to
/// `mid`) shows the same window as a fresh walk to `mid`.
fn assert_resumes(format: &str, data: &[u8], path: &[&str], far: u64, mid: u64) {
    let (mut fresh, id) = walker(format, data, path);
    fresh.session.seek(id, mid, 10);
    fresh.run();
    let expected = window(&fresh, id);
    assert_eq!(expected.0, mid, "{format}: fresh window");
    assert_eq!(expected.1.len(), 10, "{format}: fresh window");
    let (mut host, id) = walker(format, data, path);
    host.session.expand(id, 50);
    host.run();
    host.session.seek(id, far, 10);
    host.run();
    host.session.seek(id, mid, 10);
    host.run();
    assert_eq!(window(&host, id), expected, "{format}: resumed window");
}

#[test]
fn record_walkers_resume_from_marks() {
    // Intel HEX: data records with an extended linear address record in
    // the middle (the walker carries the base address).
    let mut ihex = String::new();
    for i in 0..3000u32 {
        if i == 1500 {
            ihex.push_str(":020000040001F9\n");
        }
        let addr = (i * 4) as u16;
        let bytes = [4u8, (addr >> 8) as u8, addr as u8, 0, 1, 2, 3, 4];
        let sum = bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        ihex.push(':');
        for b in bytes.iter().chain([&0u8.wrapping_sub(sum)]) {
            ihex.push_str(&format!("{b:02X}"));
        }
        ihex.push('\n');
    }
    ihex.push_str(":00000001FF\n");
    assert_resumes("ihex", ihex.as_bytes(), &[], 2600, 1700);

    // HPROF: header fields, then UTF-8 string records.
    let mut hprof = b"JAVA PROFILE 1.0.2\0".to_vec();
    hprof.extend(4u32.to_be_bytes());
    hprof.extend(0u64.to_be_bytes());
    for i in 0..3000u32 {
        let s = format!("string {i}");
        hprof.push(0x01);
        hprof.extend(0u32.to_be_bytes());
        hprof.extend((4 + s.len() as u32).to_be_bytes());
        hprof.extend(i.to_be_bytes());
        hprof.extend(s.as_bytes());
    }
    assert_resumes("hprof", &hprof, &[], 2600, 1700);

    // Subversion dump: node records.
    let mut svn = String::from("SVN-fs-dump-format-version: 2\n\n");
    for i in 0..3000 {
        svn.push_str(&format!(
            "Node-path: file{i}\nNode-kind: file\nNode-action: add\nContent-length: 0\n\n"
        ));
    }
    assert_resumes("svn-dump", svn.as_bytes(), &[], 2600, 1700);

    // TFRecord: framed records with masked CRC-32C.
    let mut tf = Vec::new();
    for i in 0..3000u32 {
        let body = format!("record {i}").into_bytes();
        let len = (body.len() as u64).to_le_bytes();
        tf.extend(len);
        tf.extend(fillyfoal::codec::crc::crc32c_masked(&len).to_le_bytes());
        tf.extend(&body);
        tf.extend(fillyfoal::codec::crc::crc32c_masked(&body).to_le_bytes());
    }
    assert_resumes("tfrecord", &tf, &[], 2600, 1700);

    // Android sparse chunks: alternating raw and fill chunks.
    let raw = [0x55u8; 4096];
    let chunks: Vec<(u16, u32, &[u8])> = (0..3000)
        .map(|i| {
            if i % 2 == 0 {
                (0xcac1, 1, &raw[..])
            } else {
                (0xcac2, 1, &[1u8, 2, 3, 4][..])
            }
        })
        .collect();
    assert_resumes(
        "android-sparse",
        &sparse(3000, &chunks),
        &["Chunks"],
        2600,
        1700,
    );

    // vbmeta descriptors: property descriptors.
    let mut descriptors = Vec::new();
    for i in 0..3000 {
        let key = format!("key.{i:04}");
        let value = format!("value {i}");
        let mut body = Vec::new();
        body.extend((key.len() as u64).to_be_bytes());
        body.extend((value.len() as u64).to_be_bytes());
        body.extend(key.as_bytes());
        body.push(0);
        body.extend(value.as_bytes());
        body.push(0);
        body.resize(body.len().next_multiple_of(8), 0);
        descriptors.extend(0u64.to_be_bytes());
        descriptors.extend((body.len() as u64).to_be_bytes());
        descriptors.extend(body);
    }
    let mut vbmeta = vec![0u8; 256];
    vbmeta[..4].copy_from_slice(b"AVB0");
    vbmeta[4..8].copy_from_slice(&1u32.to_be_bytes());
    vbmeta[20..28].copy_from_slice(&(descriptors.len() as u64).to_be_bytes());
    vbmeta[104..112].copy_from_slice(&(descriptors.len() as u64).to_be_bytes());
    vbmeta.extend(&descriptors);
    assert_resumes("vbmeta", &vbmeta, &["Descriptors"], 2600, 1700);

    // Git pack: blobs in stored zlib streams, after the header and
    // checksum emitted before the objects.
    let mut pack = b"PACK\0\0\0\x02".to_vec();
    pack.extend(3000u32.to_be_bytes());
    for i in 0..3000u32 {
        let body = format!("blob {i}\n").into_bytes();
        pack.push(0x30 | body.len() as u8);
        pack.extend(zlib_stored(&body));
    }
    pack.extend(fillyfoal::codec::crypto::Sha1::digest(&pack));
    assert_resumes("git-pack", &pack, &[], 2600, 1700);

    // Git index v4: paths compressed against the previous one.
    let mut index = b"DIRC\0\0\0\x04".to_vec();
    index.extend(3000u32.to_be_bytes());
    let mut prev = String::new();
    for i in 0..3000u32 {
        let path = format!("dir/file{i:05}");
        let common = prev
            .bytes()
            .zip(path.bytes())
            .take_while(|(a, b)| a == b)
            .count();
        let mut entry = vec![0u8; 62];
        entry[24..28].copy_from_slice(&0o100644u32.to_be_bytes());
        entry[60..62].copy_from_slice(&(path.len() as u16).to_be_bytes());
        index.extend(entry);
        index.push((prev.len() - common) as u8);
        index.extend(&path.as_bytes()[common..]);
        index.push(0);
        prev = path;
    }
    index.extend(fillyfoal::codec::crypto::Sha1::digest(&index));
    assert_resumes("git-index", &index, &["Entries"], 2600, 1700);
}

/// A zlib stream of one stored block.
fn zlib_stored(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x78, 0x01, 0x01];
    let len = data.len() as u16;
    out.extend(len.to_le_bytes());
    out.extend((!len).to_le_bytes());
    out.extend(data);
    out.extend(fillyfoal::codec::adler32(data).to_be_bytes());
    out
}
