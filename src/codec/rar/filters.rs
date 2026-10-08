//! The RAR post-processing filters, applied to a block of decoded data
//! once it is complete.
//!
//! RAR 3 declares a filter as a RarVM program; like libarchive, only the
//! standard programs are supported, recognised by their length and CRC32
//! (DELTA, E8, E8E9, RGB, AUDIO; libarchive's `execute_filter_*`, with its
//! size limits). RAR 5 names its filter by type (DELTA, E8, E8E9, ARM;
//! libarchive's `run_*_filter`). Neither libarchive reader implements the
//! RAR 3 ITANIUM program, and neither does this one. See [`super`] for
//! provenance.

use super::bad;
use crate::error::Result;

/// The x86 filters' address range.
const FILE_SIZE: u32 = 0x100_0000;
/// RarVM memory sizes (libarchive's `VM_MEMORY_SIZE`, `PROGRAM_WORK_SIZE`):
/// the limits on what the RAR 3 standard filters may process.
pub const VM_MEMORY: u64 = 0x4_0000;
const WORK: usize = 0x3_c000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Filter {
    /// Bytes stored as differences, channel by channel.
    Delta { channels: u32 },
    /// x86 CALL (and with `e9` JMP) targets stored as absolute addresses.
    E8 { e9: bool },
    /// ARM BL targets stored as absolute addresses (RAR 5).
    Arm,
    /// RAR 3 RGB image predictor: row `stride`, and where the colour
    /// differences start.
    Rgb { stride: u32, byte_offset: u32 },
    /// RAR 3 adaptive audio predictor.
    Audio { channels: u32 },
}

/// A filter and the format that declared it.
#[derive(Clone, Debug)]
pub struct Kind {
    pub filter: Filter,
    pub rar3: bool,
}

impl Kind {
    /// RAR 3 runs a further filter declared on the same block over the
    /// output of the one before.
    pub fn chains(&self) -> bool {
        self.rar3
    }
}

/// The RAR 3 standard program with this fingerprint (CRC32 of the byte
/// code, and its length), as libarchive's `execute_filter` tells them
/// apart. `regs` are the program's initial registers r0–r6.
pub fn standard(crc: u32, len: usize, regs: &[u32; 7]) -> Option<Filter> {
    Some(match (crc, len) {
        (0x0e06_077d, 0x1d) => Filter::Delta { channels: regs[0] },
        (0xad57_6887, 0x35) => Filter::E8 { e9: false },
        (0x3cd7_e57e, 0x39) => Filter::E8 { e9: true },
        (0x1c2c_5dc8, 0x95) => Filter::Rgb {
            stride: regs[0],
            byte_offset: regs[1],
        },
        (0xbc85_e701, 0xd8) => Filter::Audio { channels: regs[0] },
        _ => return None,
    })
}

/// Applies `kind` to `data` (a block starting `offset` bytes into the
/// file).
pub fn apply(kind: &Kind, data: &mut Vec<u8>, offset: u64) -> Result<()> {
    let len = data.len();
    if kind.rar3 && len as u64 > VM_MEMORY {
        return Err(bad("filter block larger than the RarVM memory"));
    }
    let channel_limit = if kind.rar3 { 128 } else { 32 };
    match kind.filter {
        Filter::Delta { channels } => {
            if channels == 0 || channels > channel_limit || (kind.rar3 && len > WORK / 2) {
                return Err(bad("invalid DELTA filter"));
            }
            *data = delta(data, channels as usize);
        }
        Filter::E8 { e9 } => {
            if kind.rar3 && (len > WORK || len <= 4) {
                return Err(bad("invalid E8 filter"));
            }
            e8(data, offset, e9, kind.rar3);
        }
        Filter::Arm => arm(data, offset),
        Filter::Rgb {
            stride,
            byte_offset,
        } => {
            let stride = stride as usize;
            if len > WORK / 2 || stride > len || len < 3 || byte_offset > 2 {
                return Err(bad("invalid RGB filter"));
            }
            *data = rgb(data, stride, byte_offset as usize);
        }
        Filter::Audio { channels } => {
            if channels == 0 || channels > 128 || len > WORK / 2 {
                return Err(bad("invalid AUDIO filter"));
            }
            *data = audio(data, channels as usize);
        }
    }
    Ok(())
}

fn get(d: &[u8], i: usize) -> u8 {
    d.get(i).copied().unwrap_or(0)
}

fn set(d: &mut [u8], i: usize, v: u8) {
    if let Some(b) = d.get_mut(i) {
        *b = v;
    }
}

fn le32(d: &[u8], i: usize) -> u32 {
    let mut v = 0u32;
    for k in (0..4).rev() {
        v = v << 8 | u32::from(get(d, i.saturating_add(k)));
    }
    v
}

fn put32(d: &mut [u8], i: usize, v: u32) {
    for (k, b) in v.to_le_bytes().into_iter().enumerate() {
        set(d, i.saturating_add(k), b);
    }
}

/// Channel `c` holds input bytes in sequence; output byte `c + k * n` is
/// the running difference.
fn delta(src: &[u8], channels: usize) -> Vec<u8> {
    let len = src.len();
    let mut out = vec![0u8; len];
    let mut input = src.iter().copied();
    for c in 0..channels {
        let mut prev = 0u8;
        let mut i = c;
        while i < len {
            prev = prev.wrapping_sub(input.next().unwrap_or(0));
            set(&mut out, i, prev);
            i = i.saturating_add(channels);
        }
    }
    out
}

/// The x86 filters. RAR 3 counts positions from the file start as is,
/// RAR 5 modulo 16 MiB (and tests the ranges by sign bits), as libarchive.
fn e8(d: &mut [u8], offset: u64, e9: bool, rar3: bool) {
    let len = d.len();
    let mut i = 0usize;
    while i.saturating_add(4) < len {
        let b = get(d, i);
        i = i.saturating_add(1);
        if b != 0xe8 && !(e9 && b == 0xe9) {
            continue;
        }
        let pos = offset.wrapping_add(i as u64);
        let addr = le32(d, i);
        if rar3 {
            let cur = pos as u32;
            let signed = addr as i32;
            if signed < 0 && cur >= addr.wrapping_neg() {
                put32(d, i, addr.wrapping_add(FILE_SIZE));
            } else if signed >= 0 && addr < FILE_SIZE {
                put32(d, i, addr.wrapping_sub(cur));
            }
        } else {
            let cur = (pos & u64::from(FILE_SIZE - 1)) as u32;
            if addr & 0x8000_0000 != 0 {
                if addr.wrapping_add(cur) & 0x8000_0000 == 0 {
                    put32(d, i, addr.wrapping_add(FILE_SIZE));
                }
            } else if addr.wrapping_sub(FILE_SIZE) & 0x8000_0000 != 0 {
                put32(d, i, addr.wrapping_sub(cur));
            }
        }
        i = i.saturating_add(4);
    }
}

/// ARM BL: a 24-bit word offset in the low bytes of each aligned word whose
/// top byte is 0xEB.
fn arm(d: &mut [u8], offset: u64) {
    let len = d.len();
    let mut i = 0usize;
    while i.saturating_add(3) < len {
        if get(d, i.saturating_add(3)) == 0xeb {
            let v = le32(d, i) & 0xff_ffff;
            let at = (offset.wrapping_add(i as u64) >> 2) as u32;
            let v = v.wrapping_sub(at) & 0xff_ffff | 0xeb00_0000;
            put32(d, i, v);
        }
        i = i.saturating_add(4);
    }
}

fn rgb(src: &[u8], stride: usize, byte_offset: usize) -> Vec<u8> {
    let len = src.len();
    let mut out = vec![0u8; len];
    let mut input = src.iter().copied();
    for c in 0..3usize {
        let mut byte = 0u8;
        let mut j = c;
        while j < len {
            if let Some(up_left) = j.checked_sub(stride) {
                let a = i32::from(get(&out, up_left.saturating_add(3)));
                let b = i32::from(get(&out, up_left));
                let p = i32::from(byte);
                let d1 = a.wrapping_sub(b).wrapping_abs();
                let d2 = p.wrapping_sub(b).wrapping_abs();
                let d3 = a
                    .wrapping_sub(b)
                    .wrapping_add(p)
                    .wrapping_sub(b)
                    .wrapping_abs();
                if d1 > d2 || d1 > d3 {
                    byte = if d2 <= d3 { a as u8 } else { b as u8 };
                }
            }
            byte = byte.wrapping_sub(input.next().unwrap_or(0));
            set(&mut out, j, byte);
            j = j.saturating_add(3);
        }
    }
    let mut i = byte_offset;
    while i.saturating_add(2) < len {
        let g = get(&out, i.saturating_add(1));
        let v = get(&out, i).wrapping_add(g);
        set(&mut out, i, v);
        let k = i.saturating_add(2);
        let v = get(&out, k).wrapping_add(g);
        set(&mut out, k, v);
        i = i.saturating_add(3);
    }
    out
}

fn audio(src: &[u8], channels: usize) -> Vec<u8> {
    let len = src.len();
    let mut out = vec![0u8; len];
    let mut input = src.iter().copied();
    for c in 0..channels {
        let mut weight = [0i32; 3];
        let mut deltas = [0i32; 3];
        let mut last_delta = 0i32;
        let mut last_byte = 0u8;
        let mut error = [0i32; 7];
        let mut count = 0u32;
        let mut j = c;
        while j < len {
            let d = i32::from(input.next().unwrap_or(0) as i8);
            deltas[2] = deltas[1];
            deltas[1] = last_delta.wrapping_sub(deltas[0]);
            deltas[0] = last_delta;
            let sum = i32::from(last_byte)
                .wrapping_mul(8)
                .wrapping_add(weight[0].wrapping_mul(deltas[0]))
                .wrapping_add(weight[1].wrapping_mul(deltas[1]))
                .wrapping_add(weight[2].wrapping_mul(deltas[2]));
            let predicted = (sum >> 3) as u8;
            let byte = predicted.wrapping_sub(d as u8);
            let e = d.wrapping_mul(8);
            let terms = [
                e,
                e.wrapping_sub(deltas[0]),
                e.wrapping_add(deltas[0]),
                e.wrapping_sub(deltas[1]),
                e.wrapping_add(deltas[1]),
                e.wrapping_sub(deltas[2]),
                e.wrapping_add(deltas[2]),
            ];
            for (acc, t) in error.iter_mut().zip(terms) {
                *acc = acc.wrapping_add(t.wrapping_abs());
            }
            last_delta = i32::from(byte.wrapping_sub(last_byte) as i8);
            last_byte = byte;
            set(&mut out, j, byte);
            if count & 0x1f == 0 {
                let mut best = 0usize;
                for k in 1..error.len() {
                    if error.get(k) < error.get(best) {
                        best = k;
                    }
                }
                error = [0; 7];
                let w = best.saturating_sub(1) / 2;
                if let Some(wt) = weight.get_mut(w)
                    && best > 0
                {
                    if best % 2 == 1 {
                        if *wt >= -16 {
                            *wt = wt.wrapping_sub(1);
                        }
                    } else if *wt < 16 {
                        *wt = wt.wrapping_add(1);
                    }
                }
            }
            count = count.wrapping_add(1);
            j = j.saturating_add(channels);
        }
    }
    out
}
