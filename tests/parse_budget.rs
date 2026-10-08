//! Parsers and decryptors whose work grows with the input run in budgeted
//! steps: a large input makes the expansion yield again and again instead
//! of stalling one poll.

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
use fillyfoal::codec::crypto::{Aes, Hash, Sha256};
use fillyfoal::{Limits, NodeId, Progress, Secret, formats};

/// Polls `id` with small budgets until it settles, answering byte and
/// password requests; returns how many polls yielded. Every poll must
/// return quickly.
fn poll_stepped(host: &mut Host, id: NodeId) -> u32 {
    let mut yields = 0;
    for _ in 0..1_000_000 {
        let start = Instant::now();
        match host.session.poll_node(id, 2_000) {
            Progress::Idle => return yields,
            Progress::Yielded => yields += 1,
            Progress::NeedSecret(requests) => {
                for r in requests {
                    let answer = host
                        .passwords
                        .get(r.attempt as usize)
                        .map(|p| Secret::password(p));
                    host.session.answer_secret(&r, answer);
                }
            }
            Progress::NeedBytes(requests) => {
                for r in requests {
                    let start = r.offset as usize;
                    let end = (start + r.len as usize).min(host.data.len());
                    let bytes = host.data[start..end].to_vec();
                    host.session.supply(r.source, r.offset, &bytes);
                }
            }
        }
        // 2000 units are about a millisecond; allow for a slow machine.
        assert!(start.elapsed() < Duration::from_millis(500));
    }
    panic!("did not settle");
}

/// Thrift compact: a struct whose field 1 is a list of `n` i32 zeros.
fn thrift_list(n: usize) -> Vec<u8> {
    let mut data = vec![0x19, 0xf5];
    let mut len = n;
    while len >= 0x80 {
        data.push((len & 0x7f) as u8 | 0x80);
        len >>= 7;
    }
    data.push(len as u8);
    data.extend(std::iter::repeat_n(0u8, n));
    data.push(0);
    data
}

#[test]
fn thrift_skips_a_large_list_in_steps() {
    let data = thrift_list(4 << 20);
    let format = formats::by_name("thrift-compact").unwrap();
    let mut host = Host::open("big.bin", data, Limits::default(), Some(format));
    host.session.expand(host.root, 10);
    let root = host.root;
    let yields = poll_stepped(&mut host, root);
    assert!(yields >= 4, "{yields} yields");
    let field = host.child(host.root, "field 1").expect("field 1");
    let rendered = host.render();
    assert!(rendered.contains("4194304 elements"), "{rendered}");
    host.session.expand(field, 10);
    poll_stepped(&mut host, field);
}

#[test]
fn nrbf_parses_a_large_array_in_steps() {
    // Header (root #1, version 1.0), an ArraySingleObject of `n` nulls,
    // MessageEnd.
    let n = 400_000u32;
    let mut data = vec![0];
    for word in [1i32, -1, 1, 0] {
        data.extend_from_slice(&word.to_le_bytes());
    }
    data.push(16);
    data.extend_from_slice(&1i32.to_le_bytes());
    data.extend_from_slice(&n.to_le_bytes());
    data.extend(std::iter::repeat_n(10u8, n as usize));
    data.push(11);
    let mut host = Host::named("big.nrbf", data, Limits::default());
    host.session.expand(host.root, 10);
    let root = host.root;
    let yields = poll_stepped(&mut host, root);
    assert!(yields >= 2, "{yields} yields");
    let rendered = host.render();
    // The header, the array, its nulls and MessageEnd.
    assert!(rendered.contains("400003 records"), "{rendered}");
}

/// A KeePass 1 database (AES) holding `plain` (no groups or entries),
/// with the password "fillyfoal".
fn kdb(plain: &[u8]) -> Vec<u8> {
    let (master_seed, iv, transform_seed, rounds) = ([1u8; 16], [2u8; 16], [3u8; 32], 10u32);
    let composite = Sha256::digest(b"fillyfoal");
    let transform = Aes::new(&transform_seed).unwrap();
    let mut a: [u8; 16] = composite[..16].try_into().unwrap();
    let mut b: [u8; 16] = composite[16..].try_into().unwrap();
    for _ in 0..rounds {
        transform.encrypt_block(&mut a);
        transform.encrypt_block(&mut b);
    }
    let transformed = Sha256::digest(&[a, b].concat());
    let key = Sha256::digest(&[&master_seed[..], &transformed].concat());
    let aes = Aes::new(&key).unwrap();
    let mut padded = plain.to_vec();
    let pad = 16 - plain.len() % 16;
    padded.extend(std::iter::repeat_n(pad as u8, pad));
    let mut prev = iv;
    let mut cipher_text = Vec::new();
    for chunk in padded.chunks(16) {
        let mut block: [u8; 16] = chunk.try_into().unwrap();
        for (x, p) in block.iter_mut().zip(prev) {
            *x ^= p;
        }
        aes.encrypt_block(&mut block);
        cipher_text.extend_from_slice(&block);
        prev = block;
    }
    let mut out = Vec::new();
    for word in [0x9AA2_D903u32, 0xB54B_FB65, 2, 0x0003_0004] {
        out.extend_from_slice(&word.to_le_bytes());
    }
    out.extend_from_slice(&master_seed);
    out.extend_from_slice(&iv);
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(&Sha256::digest(plain));
    out.extend_from_slice(&transform_seed);
    out.extend_from_slice(&rounds.to_le_bytes());
    out.extend_from_slice(&cipher_text);
    out
}

#[test]
fn kdb_decrypts_and_hashes_in_steps() {
    // Several chunks, CBC chained across them, ending in a partial one.
    let plain: Vec<u8> = (0..(2 << 20) + 1000).map(|i| (i % 251) as u8).collect();
    let mut host = Host::named("big.kdb", kdb(&plain), Limits::default());
    host.session.expand(host.root, 10);
    host.run();
    let payload = host.child(host.root, "Payload").expect("Payload");
    host.session.expand(payload, 10);
    let yields = poll_stepped(&mut host, payload);
    assert!(yields >= 4, "{yields} yields");
    let rendered = host.render();
    assert!(rendered.contains("contents hash verified"), "{rendered}");
}

#[test]
fn toml_parses_a_large_array_in_steps() {
    // `a = [1,1,...]`: one value of 2Mi elements.
    let n = 2usize << 20;
    let mut data = b"a = [".to_vec();
    for _ in 0..n {
        data.extend_from_slice(b"1,");
    }
    data.extend_from_slice(b"]\n");
    let format = formats::by_name("toml").unwrap();
    let mut host = Host::open("big.toml", data, Limits::default(), Some(format));
    host.session.expand(host.root, 10);
    let root = host.root;
    let yields = poll_stepped(&mut host, root);
    // Reading the 4 MiB costs about 1k units; the elements about 8k.
    assert!(yields >= 3, "{yields} yields");
    let rendered = host.render();
    assert!(rendered.contains("2,097,152 elements"), "{rendered}");
}

/// LLVM bitcode bits, least significant first.
struct Bits {
    data: Vec<u8>,
    len: usize,
}

impl Bits {
    fn put(&mut self, value: u64, width: u32) {
        for i in 0..width {
            if self.len.is_multiple_of(8) {
                self.data.push(0);
            }
            if (value >> i) & 1 != 0 {
                *self.data.last_mut().unwrap() |= 1 << (self.len % 8);
            }
            self.len += 1;
        }
    }

    fn vbr(&mut self, mut value: u64, width: u32) {
        let payload = width - 1;
        loop {
            let chunk = value & ((1 << payload) - 1);
            value >>= payload;
            if value == 0 {
                self.put(chunk, width);
                return;
            }
            self.put(chunk | (1 << payload), width);
        }
    }
}

#[test]
fn bitcode_reads_a_long_record_in_steps() {
    // One unabbreviated record of 16Mi operands (12 MiB) at the top level.
    let n = 16u64 << 20;
    let mut b = Bits {
        data: Vec::new(),
        len: 0,
    };
    b.put(u64::from(u32::from_le_bytes(*b"BC\xc0\xde")), 32);
    b.put(3, 2);
    b.vbr(1, 6);
    b.vbr(n, 6);
    for _ in 0..n {
        b.put(0, 6);
    }
    b.put(0, 2);
    let format = formats::by_name("llvm-bitcode").unwrap();
    let mut host = Host::open("big.bc", b.data, Limits::default(), Some(format));
    host.session.expand(host.root, 10);
    let root = host.root;
    let yields = poll_stepped(&mut host, root);
    // Reading 12 MiB costs about 3k units; the operands about 4k more.
    assert!(yields >= 3, "{yields} yields");
}
