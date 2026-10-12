//! Audio: checksums are charged (a large TTA frame is hashed in paced
//! steps, not in one poll), and files behind an ID3v2 tag too long for the
//! probes to see past are still dissected as their own format.

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
use fillyfoal::{Limits, NodeId, Progress};

/// Expands `id` and polls it with `budget` units at a time until it
/// settles, answering byte requests; returns how many polls yielded.
fn yields_expanding(host: &mut Host, id: NodeId, budget: u64) -> u32 {
    host.session.expand(id, 100);
    let mut yields = 0;
    for _ in 0..100_000 {
        match host.session.poll_node(id, budget) {
            Progress::Idle => return yields,
            Progress::Yielded => yields += 1,
            Progress::NeedSecret(_) => panic!("unexpected secret request"),
            Progress::NeedBytes(requests) => host.supply(requests),
        }
    }
    panic!("did not settle");
}

/// A TTA file of one frame of `frame` bytes (CRC included).
fn tta_one_frame(frame: u32) -> Vec<u8> {
    let rate = 44_100u32;
    let samples = rate * 256 / 245; // exactly one frame
    let mut h = b"TTA1".to_vec();
    h.extend(1u16.to_le_bytes());
    h.extend(2u16.to_le_bytes());
    h.extend(16u16.to_le_bytes());
    h.extend(rate.to_le_bytes());
    h.extend(samples.to_le_bytes());
    let crc = crc32(&h);
    h.extend(crc.to_le_bytes());
    let seek = frame.to_le_bytes();
    h.extend(seek);
    h.extend(crc32(&seek).to_le_bytes());
    let body: Vec<u8> = (0..frame - 4).map(|i| (i % 251) as u8).collect();
    let crc = crc32(&body);
    h.extend(body);
    h.extend(crc.to_le_bytes());
    h
}

#[test]
fn tta_frame_crc_is_hashed_in_steps() {
    let mut host = Host::named("big.tta", tta_one_frame(1 << 20), Limits::default());
    let root = host.root;
    host.explore(root, 1, 100);
    let frames = host.child(root, "Frames").expect("frames");
    host.explore(frames, 1, 100);
    let frame = host.child(frames, "Frame 0").expect("frame");
    // Reading the MiB costs about 256 units; hashing it about 1024 more.
    let yields = yields_expanding(&mut host, frame, 300);
    assert!(yields >= 3, "{yields} yields");
    let crc = host.child(frame, "CRC").expect("crc");
    assert_eq!(
        host.session.node(crc).unwrap().summary.as_deref(),
        Some("valid")
    );
}

/// An ID3v2.3 tag of `len` bytes: a title frame, then padding.
fn id3_tag(len: usize) -> Vec<u8> {
    let mut frames = b"TIT2".to_vec();
    frames.extend(5u32.to_be_bytes());
    frames.extend([0, 0, 0]);
    frames.extend(b"Tone");
    frames.resize(len - 10, 0);
    let n = frames.len() as u32;
    let mut tag = b"ID3\x03\x00\x00".to_vec();
    tag.extend([
        (n >> 21) as u8 & 0x7f,
        (n >> 14) as u8 & 0x7f,
        (n >> 7) as u8 & 0x7f,
        n as u8 & 0x7f,
    ]);
    tag.extend(frames);
    tag
}

#[test]
fn audio_behind_a_long_id3_tag_is_dissected_as_itself() {
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    for (path, annotation, format) in [
        ("external/flac/tone.flac", "FLAC, ", "flac"),
        ("external/aac/tone.aac", "AAC LC, ", "aac"),
        ("external/ac3/tone.ac3", "AC-3, ", "ac3"),
        ("external/ac3/tone.eac3", "E-AC-3, ", "ac3"),
        ("external/dts/surround.dts", "DTS core, ", "dts"),
        ("external/tta/tone.tta", "TTA 16-bit", "tta"),
        ("external/wavpack/tone.wv", "WavPack 16-bit", "wavpack"),
        ("synthetic/ape/tone.ape", "Monkey's Audio", "ape"),
        ("synthetic/musepack/tone.mpc", "Musepack SV8", "musepack"),
        ("external/mp3/layer2.mp2", "MPEG-2 Layer II", "mp3"),
    ] {
        // Longer than the probes' head, as cover art often makes it.
        let mut data = id3_tag(100_000);
        data.extend(std::fs::read(fixtures.join(path)).unwrap());
        let mut host = Host::named("tagged", data, Limits::default());
        let root = host.root;
        host.explore(root, 1, 100);
        let node = host.session.node(root).unwrap();
        let summary = node.summary.clone().unwrap_or_default();
        assert!(summary.starts_with(annotation), "{path}: {summary}");
        assert!(host.child(root, "ID3v2 tag").is_some(), "{path}");
        assert!(host.child(root, "Data").is_none(), "{path}");
        assert!(
            common::diagnostics(&host).is_empty(),
            "{path}: {:?}",
            common::diagnostics(&host)
        );
        // The probes claimed it as MP3; the MP3 dissector handed it off, so
        // the host sees the real format.
        let interpretation = host.session.interpretation(root).unwrap();
        assert_eq!(
            interpretation.format.map(|f| f.name),
            Some(format),
            "{path}"
        );
        assert!(!interpretation.forced);
    }
}

#[test]
fn a_forced_mp3_is_not_handed_off() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/external/flac/tone.flac");
    let mut data = id3_tag(100_000);
    data.extend(std::fs::read(path).unwrap());
    let mp3 = fillyfoal::formats::by_name("mp3").unwrap();
    // "Inspect as MP3" after identification.
    let mut host = Host::named("tagged", data, Limits::default());
    host.explore(host.root, 1, 100);
    let flac = host.session.interpretation(host.root).unwrap();
    assert_eq!(flac.format.map(|f| f.name), Some("flac"));
    let summary = |host: &Host| host.session.node(host.root).unwrap().summary.clone();
    assert!(summary(&host).unwrap().starts_with("FLAC, "));
    assert!(host.session.reinterpret(host.root, Some(mp3)));
    // The FLAC annotation described the old interpretation.
    assert_eq!(summary(&host), None);
    host.explore(host.root, 1, 100);
    let forced = host.session.interpretation(host.root).unwrap();
    assert_eq!(forced.format.map(|f| f.name), Some("mp3"));
    assert!(forced.forced);
    assert!(!summary(&host).unwrap_or_default().starts_with("FLAC"));
    // The MP3 dissector ran: it looked for frames after the tag.
    assert!(host.child(host.root, "Data").is_some(), "{}", host.render());
    // Back to identification, and to the FLAC annotation.
    assert!(host.session.reinterpret(host.root, None));
    host.explore(host.root, 1, 100);
    assert!(summary(&host).unwrap().starts_with("FLAC, "));
}

/// `Session::open_as` forces the format, as "inspect as" does: the MP3
/// dissector carries on as itself instead of handing the FLAC stream
/// behind the long tag over, and `None` returns to identification.
#[test]
fn open_as_mp3_is_not_handed_off() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/external/flac/tone.flac");
    let mut data = id3_tag(100_000);
    data.extend(std::fs::read(path).unwrap());
    let mp3 = fillyfoal::formats::by_name("mp3").unwrap();
    let mut host = Host::open("tagged", data, Limits::default(), Some(mp3));
    host.explore(host.root, 1, 100);
    let forced = host.session.interpretation(host.root).unwrap();
    assert_eq!(forced.format.map(|f| f.name), Some("mp3"));
    assert!(forced.forced);
    assert!(host.child(host.root, "Data").is_some(), "{}", host.render());
    assert!(host.session.reinterpret(host.root, None));
    host.explore(host.root, 1, 100);
    let identified = host.session.interpretation(host.root).unwrap();
    assert_eq!(identified.format.map(|f| f.name), Some("flac"));
    assert!(!identified.forced);
}

/// One Ogg page holding `packet` whole (it must be under 64 KiB).
fn ogg_page(serial: u32, sequence: u32, flags: u8, granule: u64, packet: &[u8]) -> Vec<u8> {
    let mut lacing = vec![255u8; packet.len() / 255];
    lacing.push((packet.len() % 255) as u8);
    let mut page = b"OggS\0".to_vec();
    page.push(flags);
    page.extend(granule.to_le_bytes());
    page.extend(serial.to_le_bytes());
    page.extend(sequence.to_le_bytes());
    page.extend([0; 4]);
    page.push(lacing.len() as u8);
    page.extend(lacing);
    page.extend(packet);
    let crc = fillyfoal::codec::crc::CRC32_OGG.checksum(&page) as u32;
    page[22..26].copy_from_slice(&crc.to_le_bytes());
    page
}

/// An Opus stream of `packets` 20 ms packets, one per page.
fn opus_link(serial: u32, packets: u32) -> Vec<u8> {
    let mut head = b"OpusHead\x01\x01".to_vec();
    head.extend(312u16.to_le_bytes());
    head.extend(48_000u32.to_le_bytes());
    head.extend([0, 0, 0]);
    let mut out = ogg_page(serial, 0, 2, 0, &head);
    out.extend(ogg_page(serial, 1, 0, 0, b"OpusTags\0\0\0\0\0\0\0\0"));
    for i in 0..packets {
        let flags = if i + 1 == packets { 4 } else { 0 };
        let granule = u64::from(i + 1) * 960;
        out.extend(ogg_page(serial, i + 2, flags, granule, &[0xfc; 200]));
    }
    out
}

#[test]
fn chained_ogg_links_are_all_found() {
    // A first link far longer than the 64 KiB looked at for durations,
    // then two short ones.
    let mut data = opus_link(1, 20_000);
    data.extend(opus_link(2, 50));
    data.extend(opus_link(3, 50));
    let len = data.len();
    let mut host = Host::named("chained.opus", data, Limits::default());
    let root = host.root;
    host.explore(root, 1, 100);
    let summary = host.session.node(root).unwrap().summary.clone().unwrap();
    assert!(
        summary.starts_with("Ogg, 3 chained links: Opus, 48000 Hz, 1 ch; Opus"),
        "{summary}"
    );
    // 400 s + 1 s + 1 s, less the pre-skip of each link.
    let kbps = format!(", 6:41, {:.0} kbps", len as f64 * 8.0 / 401.9805 / 1000.0);
    assert!(summary.ends_with(&kbps), "{summary} vs {kbps}");
    let streams: Vec<String> = host.session.children(root).unwrap().ids[..3]
        .iter()
        .map(|&id| host.session.node(id).unwrap().summary.clone().unwrap())
        .collect();
    assert!(
        streams[0].starts_with("link 1, serial 0x00000001") && streams[0].ends_with(", 6:39"),
        "{streams:?}"
    );
    assert!(
        streams[2].starts_with("link 3, serial 0x00000003") && streams[2].ends_with(" ms"),
        "{streams:?}"
    );
    // Finding the links bisects: far less than the whole file is read.
    assert!(
        host.bytes_supplied < len as u64 / 2,
        "{} of {len}",
        host.bytes_supplied
    );
}
