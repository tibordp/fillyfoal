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
