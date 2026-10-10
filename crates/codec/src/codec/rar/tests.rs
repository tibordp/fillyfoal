#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

use super::*;
use crate::codec::pipeline::decode_all;

/// Decodes the streams in `RAR_CASES` (written by the test encoder:
/// `<name>.bin` the group's packed data, `<name>.txt` "dict" then one
/// "algorithm packed unpacked" line per member, `<name>.out` the expected
/// output). Run with `RAR_CASES=dir cargo test rar_cases -- --ignored`.
#[test]
#[ignore]
fn rar_cases() {
    let Ok(dir) = std::env::var("RAR_CASES") else {
        return;
    };
    let mut names: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.ok()?.path();
            (p.extension()? == "txt").then(|| p.with_extension(""))
        })
        .collect();
    names.sort();
    let mut fails = 0;
    for base in &names {
        let desc = std::fs::read_to_string(base.with_extension("txt")).unwrap();
        let mut lines = desc.lines();
        let dict: u64 = lines.next().unwrap().trim().parse().unwrap();
        let members: Vec<Member> = lines
            .map(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                Member {
                    algorithm: match f[0] {
                        "29" => Algorithm::V29,
                        "50" => Algorithm::V50,
                        _ => Algorithm::V70,
                    },
                    packed: f[1].parse().unwrap(),
                    unpacked: f[2].parse().unwrap(),
                }
            })
            .collect();
        let input = std::fs::read(base.with_extension("bin")).unwrap();
        let want = std::fs::read(base.with_extension("out")).unwrap();
        let mut d = Stream::new(Params {
            dict,
            members: members.into(),
        });
        // Feed the input in growing pieces, as a lazy reader would.
        let mut out = Vec::new();
        let mut fed = 0usize;
        let mut result = Ok(());
        loop {
            let eof = fed >= input.len();
            match d.decode(&input[..fed], eof, &mut out, 4096, 1 << 30) {
                Ok(Status::Done) => break,
                Ok(Status::More) => {}
                Ok(Status::NeedInput) => {
                    if eof {
                        result = Err("needs input at eof".to_owned());
                        break;
                    }
                    fed = (fed + 100_000).min(input.len());
                }
                Err(e) => {
                    result = Err(format!("{e:?}"));
                    break;
                }
            }
        }
        if result.is_err() || out != want {
            fails += 1;
            let first = out.iter().zip(&want).position(|(a, b)| a != b);
            eprintln!(
                "FAIL {}: {:?} got {} want {} first diff {:?}",
                base.display(),
                result,
                out.len(),
                want.len(),
                first
            );
        }
    }
    eprintln!("{} of {} ok", names.len() - fails, names.len());
    assert_eq!(fails, 0);
}

/// The PPMd model against 7-Zip's encoder (`tests/data/rar/ppmd.py`).
#[test]
fn ppmd_matches_7zip() {
    let want = include_bytes!("../testdata/words.txt");
    let cases: [(&[u8], u32, u32); 4] = [
        (
            include_bytes!("../testdata/ppmd7-6-1048576.bin"),
            6,
            1 << 20,
        ),
        (
            include_bytes!("../testdata/ppmd7-16-65536.bin"),
            16,
            1 << 16,
        ),
        (
            include_bytes!("../testdata/ppmd7-64-1048576.bin"),
            64,
            1 << 20,
        ),
        (include_bytes!("../testdata/ppmd7-2-65536.bin"), 2, 1 << 16),
    ];
    for (data, order, mem) in cases {
        let (got, _) = ppmd::Ppm::decode_7z(data, order, mem, want.len(), false)
            .unwrap_or_else(|| panic!("order {order}: corrupt"));
        let first = got.iter().zip(want.iter()).position(|(a, b)| a != b);
        assert_eq!(first, None, "order {order} mem {mem}");
        assert_eq!(got.len(), want.len());
    }
}

/// RAR's carry-less range encoder (Subbotin), for re-encoding a traced 7z
/// PPMd stream as a RAR one.
fn rar_range_encode(trace: &[(u32, u32, u32)]) -> Vec<u8> {
    const TOP: u32 = 1 << 24;
    const BOT: u32 = 1 << 15;
    let (mut low, mut range) = (0u32, u32::MAX);
    let mut out = Vec::new();
    for &(start, size, total) in trace {
        range /= total;
        low = low.wrapping_add(start.wrapping_mul(range));
        range = range.wrapping_mul(size);
        loop {
            if (low ^ low.wrapping_add(range)) >= TOP {
                if range >= BOT {
                    break;
                }
                range = low.wrapping_neg() & (BOT - 1);
            }
            out.push((low >> 24) as u8);
            low <<= 8;
            range <<= 8;
        }
    }
    for _ in 0..4 {
        out.push((low >> 24) as u8);
        low <<= 8;
    }
    out
}

/// Re-encodes a 7z PPMd stream (from pyppmd) as the range-coded part of a
/// RAR 3 PPMd block: `RAR_PPMD=in.bin,symbols,order,mem,out.bin`. Used by
/// `tests/data/rar/make.py`.
#[test]
#[ignore]
fn ppmd_rar_stream() {
    let Ok(spec) = std::env::var("RAR_PPMD") else {
        return;
    };
    let f: Vec<&str> = spec.split(',').collect();
    let data = std::fs::read(f[0]).unwrap();
    let n: usize = f[1].parse().unwrap();
    let order: u32 = f[2].parse().unwrap();
    let mem: u32 = f[3].parse().unwrap();
    let (_, trace) = ppmd::Ppm::decode_7z(&data, order, mem, n, true).unwrap();
    std::fs::write(f[4], rar_range_encode(&trace)).unwrap();
}

#[test]
fn empty_group() {
    let mut d = Stream::new(Params {
        dict: 1 << 20,
        members: Vec::new().into(),
    });
    assert_eq!(decode_all(&mut d, &[], 100).unwrap(), b"");
}

/// A RAR 5 variable-length integer at `*at`.
fn vint(data: &[u8], at: &mut usize) -> u64 {
    let mut v = 0u64;
    for shift in (0..).step_by(7) {
        let b = data[*at];
        *at += 1;
        v |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            break;
        }
    }
    v
}

/// The compressed streams in one of the test encoder's archives (the
/// header layouts `tests/data/rar/rarenc.py` writes): each file's packed
/// data on its own, a solid group's concatenated, stored files skipped.
fn streams(archive: &[u8]) -> Vec<(Params, Vec<u8>)> {
    let u16le = |o: usize| usize::from(u16::from_le_bytes([archive[o], archive[o + 1]]));
    let u32le = |o: usize| u32::from_le_bytes(archive[o..o + 4].try_into().unwrap()) as usize;
    // (algorithm, dictionary, solid, packed data, unpacked size) per file.
    let mut files = Vec::new();
    if archive.starts_with(b"Rar!\x1a\x07\x00") {
        let mut pos = 7;
        while pos + 7 <= archive.len() {
            let (kind, flags, size) = (archive[pos + 2], u16le(pos + 3), u16le(pos + 5));
            let mut next = pos + size;
            if kind == 0x74 {
                let (packed, unpacked, method) =
                    (u32le(pos + 7), u32le(pos + 11), archive[pos + 25]);
                if method != 0x30 {
                    files.push((
                        Algorithm::V29,
                        (64u64 << 10) << (flags >> 5 & 7),
                        flags & 0x10 != 0,
                        archive[next..next + packed].to_vec(),
                        unpacked as u64,
                    ));
                }
                next += packed;
            }
            pos = next;
        }
    } else {
        assert!(archive.starts_with(b"Rar!\x1a\x07\x01\x00"));
        let mut pos = 8;
        while pos + 4 < archive.len() {
            let mut at = pos + 4;
            let size = vint(archive, &mut at) as usize;
            let end = at + size;
            let kind = vint(archive, &mut at);
            let flags = vint(archive, &mut at);
            if flags & 1 != 0 {
                vint(archive, &mut at);
            }
            let data = if flags & 2 != 0 {
                vint(archive, &mut at) as usize
            } else {
                0
            };
            if kind == 2 {
                let file_flags = vint(archive, &mut at);
                let unpacked = vint(archive, &mut at);
                vint(archive, &mut at);
                at += 4 * usize::from(file_flags & 2 != 0) + 4 * usize::from(file_flags & 4 != 0);
                let info = vint(archive, &mut at);
                if info >> 7 & 7 != 0 {
                    files.push((
                        Algorithm::V50,
                        (128u64 << 10) << (info >> 10 & 31),
                        info & 0x40 != 0,
                        archive[end..end + data].to_vec(),
                        unpacked,
                    ));
                }
            }
            pos = end + data;
        }
    }
    let mut groups: Vec<(Params, Vec<u8>)> = Vec::new();
    for (algorithm, dict, solid, packed, unpacked) in files {
        let member = Member {
            packed: packed.len() as u64,
            unpacked,
            algorithm,
        };
        match groups.last_mut() {
            Some((params, data)) if solid => {
                params.members = [&params.members[..], &[member]].concat().into();
                data.extend_from_slice(&packed);
            }
            _ => groups.push((
                Params {
                    dict,
                    members: vec![member].into(),
                },
                packed,
            )),
        }
    }
    groups
}

/// The fixtures (`tests/data/rar/make.py`): RAR 5 and RAR 2.9 LZ with
/// filters, solid groups and PPMd. Their output is smaller than the
/// history kept, so checkpoints hold all of it.
#[test]
fn checkpoints_resume_mid_stream() {
    for name in [
        "v5-normal.rar",
        "v5-solid.rar",
        "v4-normal.rar",
        "v4-solid.rar",
        "v4-ppmd.rar",
    ] {
        let archive = std::fs::read(format!(
            "{}/../../tests/fixtures/synthetic/rar/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let groups = streams(&archive);
        assert!(!groups.is_empty(), "{name}");
        for (params, input) in groups {
            let total: u64 = params.members.iter().map(|m| m.unpacked).sum();
            let (checked, largest) = crate::codec::pipeline::verify_checkpoints(
                || Box::new(Stream::new(params.clone())),
                &input,
                256,
                1,
            )
            .unwrap();
            assert!(checked > 0, "{name}");
            assert!(
                largest >= total as usize / 4 && largest < total as usize + (1 << 20),
                "{name}: {largest} for {total}"
            );
        }
    }
}

/// 5,200,000 bytes of RAR 5 (`tests/data/rar/big.py`): checkpoints past
/// 4 MiB keep the last 4 MiB of history. (A step decodes a batch of 32K
/// symbols, and the first 5 MB are long matches, so the checkpoints are
/// in the text at the end.)
#[test]
fn checkpoints_keep_four_mib() {
    let input = include_bytes!("../testdata/rar5-text-5m.bin");
    let params = Params {
        dict: 4 << 20,
        members: vec![Member {
            packed: input.len() as u64,
            unpacked: 5_200_000,
            algorithm: Algorithm::V50,
        }]
        .into(),
    };
    let (checked, largest) = crate::codec::pipeline::verify_checkpoints(
        || Box::new(Stream::new(params.clone())),
        input,
        4096,
        1,
    )
    .unwrap();
    assert!(checked >= 2, "{checked}");
    assert!(
        (4 << 20..(4 << 20) + (1 << 16)).contains(&largest),
        "{largest}"
    );
}
