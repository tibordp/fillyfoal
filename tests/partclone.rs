//! Partclone images: the volume is the block area decoded on demand, with
//! resume points from the bitmap, so a far read costs a bounded amount of
//! work wherever it lands; the volumes decoded from real-tool images are
//! what `partclone.restore` writes; compressed images decode lazily; damage
//! is reported rather than fatal.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::Host;
use fillyfoal::codec::crc::crc32_update;
use fillyfoal::{Limits, NodeId, ReadProgress, Span};

const BS: usize = 4096;

/// A format 0002 image of `blocks` blocks of `BS` bytes, those in `used`
/// stored (filled with their index's low byte, starting with `label(b)`),
/// with a CRC32 check value every `every` stored blocks.
fn image(blocks: u64, used: &[u64], every: u32, label: impl Fn(u64) -> Vec<u8>) -> Vec<u8> {
    let mut h = b"partclone-image\0".to_vec();
    h.extend_from_slice(b"0.3.36\0\0\0\0\0\0\0\0");
    h.extend_from_slice(b"0002");
    h.extend_from_slice(&0xc0deu16.to_le_bytes());
    let mut fs = b"EXTFS".to_vec();
    fs.resize(16, 0);
    h.extend_from_slice(&fs);
    h.extend_from_slice(&(blocks * BS as u64).to_le_bytes());
    h.extend_from_slice(&blocks.to_le_bytes());
    h.extend_from_slice(&(used.len() as u64).to_le_bytes());
    h.extend_from_slice(&(used.len() as u64).to_le_bytes());
    h.extend_from_slice(&(BS as u32).to_le_bytes());
    h.extend_from_slice(&18u32.to_le_bytes());
    h.extend_from_slice(&2u16.to_le_bytes());
    h.extend_from_slice(&64u16.to_le_bytes());
    h.extend_from_slice(&0x20u16.to_le_bytes());
    h.extend_from_slice(&4u16.to_le_bytes());
    h.extend_from_slice(&every.to_le_bytes());
    h.extend_from_slice(&[1, 1]);
    let crc = crc32_update(0xffff_ffff, &h);
    h.extend_from_slice(&crc.to_le_bytes());
    assert_eq!(h.len(), 110);
    let mut bitmap = vec![0u8; blocks.div_ceil(8) as usize];
    for &b in used {
        bitmap[(b / 8) as usize] |= 1 << (b % 8);
    }
    h.extend_from_slice(&bitmap);
    h.extend_from_slice(&crc32_update(0xffff_ffff, &bitmap).to_le_bytes());
    let mut crc = 0xffff_ffffu32;
    for (i, &b) in used.iter().enumerate() {
        let mut block = vec![b as u8; BS];
        let l = label(b);
        block[..l.len()].copy_from_slice(&l);
        crc = crc32_update(crc, &block);
        h.extend_from_slice(&block);
        if (i + 1) % every as usize == 0 || i + 1 == used.len() {
            h.extend_from_slice(&crc.to_le_bytes());
            crc = 0xffff_ffff;
        }
    }
    h
}

/// Blocks in the large image: a 1 GiB volume.
const BIG: u64 = 1 << 18;

/// A mostly empty 1 GiB volume: blocks 0 and `BIG - 1` in use. About 40
/// KiB (most of it the bitmap).
fn big_image() -> Vec<u8> {
    image(BIG, &[0, BIG - 1], 1024, |b| {
        format!("block {b}").into_bytes()
    })
}

fn expand(host: &mut Host, id: NodeId) {
    host.session.expand_more(id, 10_000);
    host.run();
}

fn open(host: &mut Host, path: &[&str]) -> NodeId {
    let mut id = host.root;
    for name in path {
        expand(host, id);
        id = host
            .child(id, name)
            .unwrap_or_else(|| panic!("no {name:?} under:\n{}", host.render()));
    }
    expand(host, id);
    id
}

/// The volume, from where the block listing points.
fn volume_span(host: &mut Host, len: u64) -> Span {
    let blocks = open(host, &["Blocks"]);
    let first = host.session.children(blocks).unwrap().ids[0];
    let source = host.session.node(first).unwrap().target.unwrap().source;
    Span::new(source, 0, len)
}

fn read(host: &mut Host, span: Span) -> Vec<u8> {
    loop {
        match host.session.read(span) {
            Ok(bytes) => break bytes,
            Err(requests) => host.supply(requests),
        }
    }
}

/// Reads `span` in steps of `budget` units; returns the bytes and the steps.
fn read_in_steps(host: &mut Host, span: Span, budget: u64) -> (Vec<u8>, u64) {
    let mut steps = 0;
    loop {
        match host.session.read_step(span, budget) {
            ReadProgress::Done(bytes) => return (bytes, steps),
            ReadProgress::NeedBytes(requests) => host.supply(requests),
            ReadProgress::Yielded => {
                steps += 1;
                assert!(steps < 10_000_000);
            }
        }
    }
}

/// Reading the last block of a 1 GiB mostly empty volume starts from the
/// nearest resume point: a few MiB of zeros at most, not the whole volume.
#[test]
fn far_reads_start_from_the_bitmap() {
    let mut host = Host::named("big.img", big_image(), Limits::default());
    open(&mut host, &["Volume"]);
    let vol = volume_span(&mut host, BIG * BS as u64);
    let (bytes, steps) = read_in_steps(&mut host, vol.sub((BIG - 1) * BS as u64, 16), 500);
    assert_eq!(&bytes[..12], b"block 262143");
    // A 4 MiB spacing: about a thousand units, a few steps of 500, against
    // a quarter million to walk the whole volume. (Read steps are not
    // counted in `work_done`, which totals expansions.)
    assert!(steps < 20, "{steps} steps");
    let (bytes, _) = read_in_steps(&mut host, vol.sub(0, 7), 500);
    assert_eq!(bytes, b"block 0");
}

/// Free blocks are skipped rather than written out: a far read starts from
/// the nearest resume point and then costs a few units, not a unit per 4
/// KiB of free space up to it; reads in free space the decoding has passed
/// are zeros at once; reads across free and used blocks return the right
/// bytes; reads behind the front decode again.
#[test]
fn free_space_is_skipped() {
    let mut host = Host::named("big.img", big_image(), Limits::default());
    open(&mut host, &["Volume"]);
    let len = BIG * BS as u64;
    let vol = volume_span(&mut host, len);
    // In steps of one unit: a few, against about a thousand to write the 4
    // MiB of zeros from the nearest resume point.
    let (bytes, steps) = read_in_steps(&mut host, vol.sub((BIG - 1) * BS as u64, 16), 1);
    assert_eq!(&bytes[..12], b"block 262143");
    assert!(steps < 20, "{steps} steps");
    for at in [len - (1 << 20) - BS as u64, len - (3 << 20)] {
        match host.session.read_step(vol.sub(at, 1 << 20), 1) {
            ReadProgress::Done(bytes) => {
                assert_eq!(bytes.len(), 1 << 20);
                assert!(bytes.iter().all(|&b| b == 0), "{at:#x}");
            }
            _ => panic!("a read in known free space at {at:#x} decodes"),
        }
    }
    let across = vol.sub((BIG - 2) * BS as u64, 2 * BS as u64);
    let (bytes, steps) = read_in_steps(&mut host, across, 1);
    assert!(bytes[..BS].iter().all(|&b| b == 0));
    assert_eq!(&bytes[BS..BS + 12], b"block 262143");
    assert!(steps < 20, "{steps} steps");
    let (bytes, steps) = read_in_steps(&mut host, vol.sub(0, 2 * BS as u64), 1);
    assert_eq!(&bytes[..7], b"block 0");
    assert!(bytes[BS..].iter().all(|&b| b == 0));
    assert!(steps < 20, "{steps} steps");
    // A read in the middle, from its resume point (seeds still work).
    let (bytes, steps) = read_in_steps(&mut host, vol.sub(len / 2, 1 << 16), 1);
    assert!(bytes.iter().all(|&b| b == 0));
    assert!(steps < 20, "{steps} steps");
}

/// The block listing of the large image is a few nodes, and costs work in
/// proportion to the bitmap, not the volume.
#[test]
fn listing_coalesces_runs() {
    let mut host = Host::named("big.img", big_image(), Limits::default());
    let id = open(&mut host, &["Blocks"]);
    let names: Vec<String> = host
        .session
        .children(id)
        .unwrap()
        .ids
        .iter()
        .map(|&c| host.session.node(c).unwrap().name.to_string())
        .collect();
    let expected = [
        "Block 0".to_string(),
        "Blocks 1–65536".to_string(),
        "Blocks 65537–131072".to_string(),
        "Blocks 131073–196608".to_string(),
        "Blocks 196609–262142".to_string(),
        "Block 262143".to_string(),
        "Check value".to_string(),
    ];
    assert_eq!(names, expected);
    assert!(
        host.session.work_done() < 20_000,
        "{}",
        host.session.work_done()
    );
    assert!(!host.render().contains("!"), "{}", host.render());
}

/// A gzip member of stored DEFLATE blocks holding `data`.
fn gzip_stored(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
    let mut chunks = data.chunks(0xffff).peekable();
    while let Some(c) = chunks.next() {
        out.push(u8::from(chunks.peek().is_none()));
        out.extend_from_slice(&(c.len() as u16).to_le_bytes());
        out.extend_from_slice(&(!(c.len() as u16)).to_le_bytes());
        out.extend_from_slice(c);
    }
    out.extend_from_slice(&fillyfoal::codec::crc32(data).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

/// An image piped through gzip: the volume decodes on demand through both
/// stages, so opening it reads only the start of the gzip stream.
#[test]
fn gzipped_images_decode_lazily() {
    // 4 MiB of stored blocks, every fourth block of the volume.
    const STORED: u64 = 1024;
    let used: Vec<u64> = (0..STORED).map(|i| i * 4).collect();
    let img = image(STORED * 4, &used, 64, |b| {
        format!("stored block {b:05}").into_bytes()
    });
    let gz = gzip_stored(&img);
    let len = gz.len() as u64;
    let mut host = Host::named("big.img.gz", gz, Limits::default());
    let volume = open(&mut host, &["Content", "Volume"]);
    assert!(
        host.bytes_supplied < len / 4,
        "{} of {len} bytes read",
        host.bytes_supplied
    );
    let first = host.session.children(volume).unwrap().ids[0];
    let source = host.session.node(first).unwrap().span.unwrap().source;
    let vol = Span::new(source, 0, STORED * 4 * BS as u64);
    let far = vol.sub((STORED - 1) * 4 * BS as u64, 18);
    let (bytes, _) = read_in_steps(&mut host, far, 1000);
    assert_eq!(bytes, b"stored block 04092");
}

/// The volumes decoded from the real-tool fixtures are what
/// `partclone.restore` writes (lengths and CRC-32s printed by
/// `tests/data/partclone/inner.sh` and `inner-v1.sh`).
#[test]
fn decoded_volumes_match_partclone_restore() {
    for (file, len, crc) in [
        ("fat16.img.raw.zst", 4_194_304, 0x6ec4_9a4a),
        ("fat16-v1.img.raw.zst", 4_194_304, 0xbec0_8f4d),
        ("ext2-k8-noreseed.img.raw.zst", 1_048_576, 0x0159_bc1d),
        ("ext2-nocrc.img.raw.zst", 1_048_576, 0x0159_bc1d),
        ("ext4-far.img.raw.zst", 33_554_432, 0x6dc9_deb4),
    ] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/external/partclone")
            .join(file);
        let mut host = Host::named(file, common::fixture_bytes(&path), Limits::default());
        let vol = volume_span(&mut host, len);
        let bytes = read(&mut host, vol);
        assert_eq!(bytes.len() as u64, len, "{file}");
        assert_eq!(fillyfoal::codec::crc32(&bytes), crc, "{file}");
    }
}

/// On a real image whose data runs 13 MiB in (`tests/data/partclone/
/// inner-far.sh`), a read of the last file's data (block 12362, printed by
/// debugfs) starts from the nearest resume point: a fraction of the work
/// (budgeted read steps) of decoding the volume up to it.
#[test]
fn far_reads_on_a_real_image() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/external/partclone/ext4-far.img.raw.zst");
    let data = common::fixture_bytes(&path);
    let far = 12_362 * 1024;
    let want = b"fillyfoal far file, after 12 MiB of data\n";
    let work = |seeded: bool| {
        // The image in one chunk, so that the steps count decoding only
        // (a step also ends where the host must supply more bytes).
        let limits = Limits {
            chunk_size: 32 << 20,
            ..Limits::default()
        };
        let mut host = Host::named("ext4-far.img", data.clone(), limits);
        let vol = volume_span(&mut host, 32 << 20);
        let mut steps = 0;
        if !seeded {
            // Everything before it, then it: what a walk from the start costs.
            steps += read_in_steps(&mut host, vol.sub(0, far), 100).1;
        }
        let (bytes, n) = read_in_steps(&mut host, vol.sub(far, want.len() as u64), 100);
        assert_eq!(bytes, want);
        steps + n
    };
    let (seeded, walked) = (work(true), work(false));
    assert!(
        seeded * 4 < walked,
        "far read in {seeded} steps, from the start {walked}"
    );
}

/// A damaged block is reported by its check value, when the user expands
/// it; a cut image says where it ends, and what was saved
/// before the cut is still there.
#[test]
fn damage_is_reported() {
    let used = [0, 1, 2, 5];
    let label = |b: u64| format!("block {b}").into_bytes();
    let mut img = image(8, &used, 2, label);
    // A byte of block 1 (the second stored block).
    let at = img.len() - 2 * 4 - 3 * BS;
    img[at] ^= 0x40;
    let mut host = Host::named("bad.img", img, Limits::default());
    let blocks = open(&mut host, &["Blocks"]);
    let checks: Vec<NodeId> = host
        .session
        .children(blocks)
        .unwrap()
        .ids
        .iter()
        .copied()
        .filter(|&c| host.session.node(c).unwrap().name == "Check value")
        .collect();
    assert_eq!(checks.len(), 2);
    for &c in &checks {
        expand(&mut host, c);
    }
    let tree = host.render();
    assert_eq!(
        tree.matches("warning: CRC-32 (not inverted) mismatch")
            .count(),
        1,
        "{tree}"
    );
    assert!(tree.contains("Checked"), "{tree}");

    let mut img = image(8, &used, 2, label);
    img.truncate(img.len() - BS);
    let mut host = Host::named("cut.img", img, Limits::default());
    let vol = volume_span(&mut host, 8 * BS as u64);
    let tree = host.render();
    assert!(
        tree.contains("truncated: the image ends 4096 bytes before the last block in use"),
        "{tree}"
    );
    let (bytes, _) = read_in_steps(&mut host, vol.sub(2 * BS as u64, 7), 1000);
    assert_eq!(bytes, b"block 2");
}

/// A device larger than its blocks cover (a file system smaller than its
/// partition) is pointed out on the file system node.
#[test]
fn device_larger_than_the_blocks() {
    let mut img = image(8, &[0], 8, |b| format!("block {b}").into_bytes());
    img[0x34..0x3c].copy_from_slice(&(16 * BS as u64).to_le_bytes());
    // The header checksum covers it.
    let crc = fillyfoal::codec::crc::crc32_update(0xffff_ffff, &img[..106]);
    img[106..110].copy_from_slice(&crc.to_le_bytes());
    let mut host = Host::named("dev.img", img, Limits::default());
    let root = host.root;
    expand(&mut host, root);
    let tree = host.render();
    assert!(
        tree.contains("note: the device is 64 KiB; its 8 blocks cover 32 KiB, the volume shown"),
        "{tree}"
    );
}
