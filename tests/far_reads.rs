//! Large compressed disk images: a single-frame zstd stream that records
//! its content size is decoded on demand with that size (no walk over the
//! stream first, no decode to its end), a GPT inside it shows its primary
//! structures at once, and the backup header at the end of the disk is a
//! node read on request. Also: no work limit unless the host sets one.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::Host;
use fillyfoal::codec::crc32;
use fillyfoal::{ChildState, Cx, Limits, Node, NodeId, Progress, Result};

const SECTOR: usize = 512;
/// Disk size: 128 MiB, so decoding all of it costs about 32k units.
const DISK: usize = 128 << 20;
/// Units decoding the whole disk costs (one per 4 KiB of output).
const FULL_DECODE: u64 = (DISK >> 12) as u64;

fn put_u32(d: &mut [u8], at: usize, v: u32) {
    d[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u64(d: &mut [u8], at: usize, v: u64) {
    d[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

/// A GPT header for `my_lba`, its array at `entries_lba`.
fn gpt_header(
    my: u64,
    alternate: u64,
    entries_lba: u64,
    last_usable: u64,
    array_crc: u32,
) -> Vec<u8> {
    let mut h = vec![0u8; SECTOR];
    h[..8].copy_from_slice(b"EFI PART");
    put_u32(&mut h, 8, 0x0001_0000);
    put_u32(&mut h, 12, 92);
    put_u64(&mut h, 24, my);
    put_u64(&mut h, 32, alternate);
    put_u64(&mut h, 40, 34);
    put_u64(&mut h, 48, last_usable);
    h[56..72].copy_from_slice(&[0x11; 16]);
    put_u64(&mut h, 72, entries_lba);
    put_u32(&mut h, 80, 128);
    put_u32(&mut h, 84, 128);
    put_u32(&mut h, 88, array_crc);
    let crc = crc32(&h[..92]);
    put_u32(&mut h, 16, crc);
    h
}

/// A GPT disk of [`DISK`] bytes with one partition, primary and backup
/// structures, zeros but for 1.5 MiB of pseudo-random data in the
/// partition (so the compressed file is larger than 1 MiB).
fn gpt_disk() -> Vec<u8> {
    let mut d = vec![0u8; DISK];
    let lbas = (DISK / SECTOR) as u64;
    // Protective MBR.
    d[446 + 4] = 0xee;
    put_u32(&mut d, 446 + 8, 1);
    put_u32(&mut d, 446 + 12, (lbas - 1) as u32);
    d[510] = 0x55;
    d[511] = 0xaa;
    // One partition entry (Linux filesystem data), LBAs 2048..=10239.
    let mut array = vec![0u8; 128 * 128];
    array[..16].copy_from_slice(&[
        0xaf, 0x3d, 0xc6, 0x0f, 0x83, 0x84, 0x72, 0x47, 0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d,
        0xe4,
    ]);
    array[16..32].copy_from_slice(&[0x22; 16]);
    put_u64(&mut array, 32, 2048);
    put_u64(&mut array, 40, 10239);
    for (i, c) in "data".encode_utf16().enumerate() {
        array[56 + 2 * i..58 + 2 * i].copy_from_slice(&c.to_le_bytes());
    }
    let array_crc = crc32(&array);
    let last_usable = lbas - 34;
    let primary = gpt_header(1, lbas - 1, 2, last_usable, array_crc);
    let backup = gpt_header(lbas - 1, 1, lbas - 33, last_usable, array_crc);
    d[SECTOR..2 * SECTOR].copy_from_slice(&primary);
    d[2 * SECTOR..2 * SECTOR + array.len()].copy_from_slice(&array);
    let backup_array = (lbas as usize - 33) * SECTOR;
    d[backup_array..backup_array + array.len()].copy_from_slice(&array);
    d[DISK - SECTOR..].copy_from_slice(&backup);
    let mut x = 0x2545_f491_4f6c_dd1du64;
    for b in &mut d[2048 * SECTOR..2048 * SECTOR + (3 << 19)] {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = x as u8;
    }
    d
}

/// A zstd frame of `data` recording its content size (8-byte field, with
/// a window descriptor): RLE blocks for runs of one byte, raw blocks for
/// the rest, 128 KiB each.
fn zstd_frame(data: &[u8]) -> Vec<u8> {
    let mut out = 0xfd2f_b528u32.to_le_bytes().to_vec();
    out.push(0xc0); // FCS_8, window descriptor follows
    out.push(0x58); // 2 MiB window
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    let chunks: Vec<&[u8]> = data.chunks(128 * 1024).collect();
    for (i, chunk) in chunks.iter().enumerate() {
        let last = u32::from(i + 1 == chunks.len());
        let rle = chunk.iter().all(|&b| b == chunk[0]);
        let header = last | (u32::from(rle) << 1) | ((chunk.len() as u32) << 3);
        out.extend_from_slice(&header.to_le_bytes()[..3]);
        if rle {
            out.push(chunk[0]);
        } else {
            out.extend_from_slice(chunk);
        }
    }
    out
}

fn name(host: &Host, id: NodeId) -> String {
    host.session.node(id).unwrap().name.to_string()
}

fn child(host: &Host, id: NodeId, wanted: &str) -> NodeId {
    host.child(id, wanted)
        .unwrap_or_else(|| panic!("no {wanted} in\n{}", host.render()))
}

/// Polls only `id` until it is idle (or `done` holds), answering byte
/// requests; the work it took.
fn poll_until(host: &mut Host, id: NodeId, done: impl Fn(&Host) -> bool) -> u64 {
    poll_with(host, id, 2_000, done)
}

/// [`poll_until`] with `budget` units per poll.
fn poll_with(host: &mut Host, id: NodeId, budget: u64, done: impl Fn(&Host) -> bool) -> u64 {
    let before = host.session.work_done();
    for _ in 0..1_000_000 {
        if done(host) {
            break;
        }
        match host.session.poll_node(id, budget) {
            Progress::Idle => break,
            Progress::NeedBytes(requests) => host.supply(requests),
            Progress::Yielded => {}
            Progress::NeedSecret(_) => panic!("no secrets here"),
        }
    }
    host.session.work_done() - before
}

/// Expands the root of `data` just until its Decompressed node exists (the
/// listing of frames goes on in the background, unpolled), then the
/// content; returns the content node and the work its expansion took.
fn open_content(host: &mut Host) -> (NodeId, u64) {
    let root = host.root;
    host.session.expand(root, 1);
    poll_until(host, root, |h| {
        h.session.children(root).is_some_and(|c| !c.ids.is_empty())
    });
    let content = host.session.children(root).unwrap().ids[0];
    assert_eq!(name(host, content), "Decompressed");
    host.session.expand(content, 100);
    let work = poll_until(host, content, |_| false);
    (content, work)
}

#[test]
fn a_large_single_frame_disk_shows_its_gpt_at_once() {
    let disk = gpt_disk();
    let data = zstd_frame(&disk);
    assert!(data.len() > 1 << 20, "{} bytes", data.len());
    let mut host = Host::named("disk.img.zst", data, Limits::default());
    let (content, work) = open_content(&mut host);
    let c = host.session.children(content).unwrap();
    assert_eq!(c.state, ChildState::Complete, "{:?}", c.error);
    let node = host.session.node(content).unwrap();
    assert!(
        node.summary.as_deref().unwrap_or("").contains("GPT disk"),
        "{:?}",
        node.summary
    );
    // The primary header and array are near the start: nothing like the
    // whole disk was decoded to show them.
    assert!(work < FULL_DECODE / 8, "{work} units of {FULL_DECODE}");
    child(&host, content, "GPT header");
    child(&host, content, "Partition entries");
    assert!(host.child(content, "Backup partition entries").is_none());

    // The backup header waits at the end of the disk, until asked for.
    let backup = child(&host, content, "Backup GPT header");
    let summary = host.session.node(backup).unwrap().summary.clone().unwrap();
    assert!(summary.contains("not read yet"), "{summary}");
    assert_eq!(
        host.session.children(backup).unwrap().state,
        ChildState::NotRequested
    );
    host.session.expand(backup, 100);
    let work = poll_until(&mut host, backup, |_| false);
    assert!(work >= FULL_DECODE, "{work} units");
    let c = host.session.children(backup).unwrap();
    assert_eq!(c.state, ChildState::Complete, "{:?}", c.error);
    let node = host.session.node(backup).unwrap();
    assert!(node.diagnostics.is_empty(), "{:?}", node.diagnostics);
    child(&host, backup, "Signature");
    let array = child(&host, backup, "Backup partition entries");
    assert_eq!(
        host.session.node(array).unwrap().summary.as_deref(),
        Some("identical to the primary array")
    );
}

#[test]
fn a_damaged_backup_is_reported_when_read() {
    let mut disk = gpt_disk();
    // The backup header's disk GUID no longer mirrors the primary.
    disk[DISK - SECTOR + 56] ^= 1;
    let mut host = Host::named("disk.img.zst", zstd_frame(&disk), Limits::default());
    let (content, _) = open_content(&mut host);
    let backup = child(&host, content, "Backup GPT header");
    host.session.expand(backup, 100);
    poll_until(&mut host, backup, |_| false);
    let messages: Vec<String> = host
        .session
        .node(backup)
        .unwrap()
        .diagnostics
        .iter()
        .map(|d| d.message.clone())
        .collect();
    assert!(
        messages.iter().any(|m| m.contains("CRC mismatch")),
        "{messages:?}"
    );
    assert!(
        messages.iter().any(|m| m.contains("does not mirror")),
        "{messages:?}"
    );
}

#[test]
fn a_stream_with_more_frames_than_the_first_is_not_cut_short_silently() {
    // The disk in one frame, then a second frame: the content's length is
    // the first frame's, and reading up to it finds that more follows.
    let disk = gpt_disk();
    let mut data = zstd_frame(&disk);
    data.extend(zstd_frame(b"more content after the first frame"));
    let mut host = Host::named("disk.img.zst", data, Limits::default());
    let (content, work) = open_content(&mut host);
    assert!(work < FULL_DECODE / 8, "{work} units of {FULL_DECODE}");
    let summary = host.session.node(content).unwrap().summary.clone().unwrap();
    assert!(summary.contains("GPT disk"), "{summary}");
    let backup = child(&host, content, "Backup GPT header");
    host.session.expand(backup, 100);
    poll_until(&mut host, backup, |_| false);
    let node = host.session.node(backup).unwrap();
    assert!(
        node.diagnostics
            .iter()
            .any(|d| d.message.contains("continues past")),
        "{:?}\n{}",
        node.diagnostics,
        host.render()
    );
    // The listing of frames, polled to its end, shows the second frame.
    let root = host.root;
    host.session.expand(root, 100);
    poll_until(&mut host, root, |_| false);
    let names: Vec<String> = host
        .session
        .children(root)
        .unwrap()
        .ids
        .iter()
        .map(|&c| name(&host, c))
        .collect();
    assert_eq!(names, ["Decompressed", "Frame 0", "Frame 1"]);
}

/// Charges `units` of work in steps of a million.
async fn long_work(cx: Cx, units: u64) -> Result<()> {
    for _ in 0..units / 1_000_000 {
        cx.charge(1_000_000).await;
    }
    cx.emit(Node::new("done"));
    Ok(())
}

#[test]
fn work_is_unlimited_unless_the_host_sets_a_limit() {
    assert_eq!(Limits::default().max_work, None);
    // Twice the old default limit: completes.
    let mut host = Host::new(Vec::new(), Limits::default());
    let root = host
        .session
        .add_root(Node::new("long").lazy(long_work, 200_000_000u64));
    host.session.expand(root, 10);
    poll_with(&mut host, root, 5_000_000, |_| false);
    let c = host.session.children(root).unwrap();
    assert_eq!(c.state, ChildState::Complete, "{:?}", c.error);

    // With a limit, the same expansion stops at it.
    let limits = Limits {
        max_work: Some(100_000_000),
        ..Limits::default()
    };
    let mut host = Host::new(Vec::new(), limits);
    let root = host
        .session
        .add_root(Node::new("long").lazy(long_work, 200_000_000u64));
    host.session.expand(root, 10);
    poll_with(&mut host, root, 5_000_000, |_| false);
    let c = host.session.children(root).unwrap();
    assert_eq!(c.state, ChildState::Failed);
    assert!(
        c.error.is_some_and(|e| e.message.contains("units of work")),
        "{:?}",
        c.error
    );
}
