//! RAR filters: RAR 5's DELTA, E8, E8E9 and ARM, and the standard RarVM
//! programs of RAR 3 (E8, E8E9, ITANIUM, DELTA, RGB, AUDIO), recognised by
//! the checksum of their byte code as modern unrar does; other byte code
//! is not run (there is no general VM here).

use crate::bytes::{to_u64, u32_le};
use crate::error::Result;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    /// RAR 5 filters.
    Delta5 {
        channels: u32,
    },
    E8_5 {
        e9: bool,
    },
    Arm5,
    /// RAR 3 standard filters; `r` holds the initial VM registers R0–R6.
    E8_3 {
        e9: bool,
        r: [u32; 7],
    },
    Itanium {
        r: [u32; 7],
    },
    Delta3 {
        r: [u32; 7],
    },
    Rgb {
        r: [u32; 7],
    },
    Audio {
        r: [u32; 7],
    },
    /// Byte code that is not a standard filter.
    Unknown,
}

impl Kind {
    /// Whether a further RAR 3 filter on the same block applies to the
    /// output of the one before.
    pub fn chains(&self) -> bool {
        !matches!(self, Kind::Delta5 { .. } | Kind::E8_5 { .. } | Kind::Arm5)
    }
}

/// RarVM memory: filter blocks larger than this fail.
const VM_MEMSIZE: u64 = 0x40000;

/// Applies `kind` to `data` in place; `offset` is the block's position in
/// its file.
pub(super) fn apply(kind: &Kind, data: &mut [u8], offset: u64) -> Result<()> {
    let off = u32::try_from(offset & 0xffff_ffff).unwrap_or(0);
    match kind {
        Kind::Delta5 { channels } => delta(data, *channels),
        Kind::E8_5 { e9 } => e8(data, off, *e9, true),
        Kind::Arm5 => arm(data, off),
        Kind::Unknown => {
            return Err(crate::error::Diagnostic::unsupported(
                "RAR 3 filter with non-standard RarVM code",
            ));
        }
        Kind::E8_3 { e9, r } => {
            // R4 is the block size; RAR 3 passes the file offset in R6.
            if vm_size_ok(data, r) && data.len() >= 4 {
                e8(data, off, *e9, false);
            }
        }
        Kind::Itanium { r } => {
            if vm_size_ok(data, r) && data.len() >= 21 {
                itanium(data, off);
            }
        }
        Kind::Delta3 { r } => {
            let channels = r[0];
            if vm_size_ok(data, r)
                && to_u64(data.len()) <= VM_MEMSIZE / 2
                && (1..=1024).contains(&channels)
            {
                delta(data, channels);
            }
        }
        Kind::Rgb { r } => {
            let width = r[0].wrapping_sub(3);
            let pos_r = r[1];
            let n = data.len();
            if vm_size_ok(data, r)
                && to_u64(n) <= VM_MEMSIZE / 2
                && n >= 3
                && (width as usize) <= n
                && pos_r <= 2
            {
                rgb(data, width as usize, pos_r as usize);
            }
        }
        Kind::Audio { r } => {
            let channels = r[0];
            if vm_size_ok(data, r)
                && to_u64(data.len()) <= VM_MEMSIZE / 2
                && (1..=128).contains(&channels)
            {
                audio(data, channels as usize);
            }
        }
    }
    Ok(())
}

/// The block fits RarVM memory and R4 (the size the program sees) is the
/// block's length; otherwise unrar outputs the data unfiltered (or, for an
/// overridden R4, something else entirely, which is not reproduced).
fn vm_size_ok(data: &[u8], r: &[u32; 7]) -> bool {
    to_u64(data.len()) <= VM_MEMSIZE && u64::from(r[4]) == to_u64(data.len())
}

fn delta(data: &mut [u8], channels: u32) {
    let n = data.len();
    let channels = (channels as usize).max(1);
    let src = data.to_vec();
    let mut s = 0usize;
    for ch in 0..channels {
        let mut prev = 0u8;
        let mut d = ch;
        while d < n {
            prev = prev.wrapping_sub(src.get(s).copied().unwrap_or(0));
            if let Some(o) = data.get_mut(d) {
                *o = prev;
            }
            s = s.saturating_add(1);
            d = d.saturating_add(channels);
        }
    }
}

/// x86 CALL (and JMP) address translation. RAR 5 takes the position
/// modulo 16 MiB; RAR 3 does not.
fn e8(data: &mut [u8], file_offset: u32, e9: bool, rar5: bool) {
    const FILE_SIZE: u32 = 0x100_0000;
    let n = data.len();
    let mut cur = 0usize;
    while cur.saturating_add(4) < n {
        let b = data.get(cur).copied().unwrap_or(0);
        cur = cur.saturating_add(1);
        if b == 0xe8 || (e9 && b == 0xe9) {
            let mut offset = u32::try_from(cur).unwrap_or(0).wrapping_add(file_offset);
            if rar5 {
                offset %= FILE_SIZE;
            }
            let addr = u32_le(data, cur).unwrap_or(0);
            let new = if addr & 0x8000_0000 != 0 {
                (addr.wrapping_add(offset) & 0x8000_0000 == 0).then(|| addr.wrapping_add(FILE_SIZE))
            } else {
                (addr.wrapping_sub(FILE_SIZE) & 0x8000_0000 != 0).then(|| addr.wrapping_sub(offset))
            };
            if let (Some(v), Some(slot)) = (new, data.get_mut(cur..cur.saturating_add(4))) {
                slot.copy_from_slice(&v.to_le_bytes());
            }
            cur = cur.saturating_add(4);
        }
    }
}

fn arm(data: &mut [u8], file_offset: u32) {
    let n = data.len();
    let mut cur = 0usize;
    while cur.saturating_add(3) < n {
        if let Some(d) = data.get_mut(cur..cur.saturating_add(4))
            && let Ok(word) = <[u8; 4]>::try_from(&*d)
            && word[3] == 0xeb
        {
            let v = u32::from_le_bytes(word) & 0xff_ffff;
            let pos = file_offset.wrapping_add(u32::try_from(cur).unwrap_or(0)) / 4;
            let v = (v.wrapping_sub(pos) & 0xff_ffff) | 0xeb00_0000;
            d.copy_from_slice(&v.to_le_bytes());
        }
        cur = cur.saturating_add(4);
    }
}

fn itanium_get(data: &[u8], bit: usize, count: u32) -> u32 {
    let at = bit / 8;
    let mut v = 0u32;
    for i in 0..4usize {
        v |= u32::from(data.get(at.saturating_add(i)).copied().unwrap_or(0)) << (i << 3);
    }
    v >>= bit & 7;
    v & (u32::MAX >> 32u32.saturating_sub(count))
}

fn itanium_set(data: &mut [u8], value: u32, bit: usize, count: u32) {
    let at = bit / 8;
    let shift = (bit & 7) as u32;
    let mut and_mask = !((u32::MAX >> 32u32.saturating_sub(count)) << shift);
    let mut value = value << shift;
    for i in 0..4usize {
        if let Some(b) = data.get_mut(at.saturating_add(i)) {
            *b &= and_mask as u8;
            *b |= value as u8;
        }
        and_mask = (and_mask >> 8) | 0xff00_0000;
        value >>= 8;
    }
}

fn itanium(data: &mut [u8], file_offset: u32) {
    const MASKS: [u8; 16] = [4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0];
    let n = data.len();
    let mut file_offset = file_offset >> 4;
    let mut cur = 0usize;
    while cur.saturating_add(21) < n {
        let b = data.get(cur).copied().unwrap_or(0) & 0x1f;
        if let Some(b) = usize::from(b).checked_sub(0x10) {
            let mask = MASKS.get(b).copied().unwrap_or(0);
            if mask != 0 {
                let block = data.get_mut(cur..).unwrap_or_default();
                for i in 0..=2usize {
                    if mask & (1 << i) == 0 {
                        continue;
                    }
                    let start = i.saturating_mul(41).saturating_add(5);
                    if itanium_get(block, start.saturating_add(37), 4) == 5 {
                        let offset = itanium_get(block, start.saturating_add(13), 20);
                        itanium_set(
                            block,
                            offset.wrapping_sub(file_offset) & 0xfffff,
                            start.saturating_add(13),
                            20,
                        );
                    }
                }
            }
        }
        cur = cur.saturating_add(16);
        file_offset = file_offset.wrapping_add(1);
    }
}

fn rgb(data: &mut [u8], width: usize, pos_r: usize) {
    let n = data.len();
    let src = data.to_vec();
    let mut s = 0usize;
    for ch in 0..3usize {
        let mut prev = 0u32;
        let mut i = ch;
        while i < n {
            let predicted = if i >= width.saturating_add(3) {
                let upper = u32::from(data.get(i.wrapping_sub(width)).copied().unwrap_or(0));
                let upper_left = u32::from(
                    data.get(i.wrapping_sub(width).wrapping_sub(3))
                        .copied()
                        .unwrap_or(0),
                );
                let p = prev.wrapping_add(upper).wrapping_sub(upper_left);
                let pa = (p.wrapping_sub(prev) as i32).unsigned_abs();
                let pb = (p.wrapping_sub(upper) as i32).unsigned_abs();
                let pc = (p.wrapping_sub(upper_left) as i32).unsigned_abs();
                if pa <= pb && pa <= pc {
                    prev
                } else if pb <= pc {
                    upper
                } else {
                    upper_left
                }
            } else {
                prev
            };
            let v = (predicted as u8).wrapping_sub(src.get(s).copied().unwrap_or(0));
            s = s.saturating_add(1);
            if let Some(o) = data.get_mut(i) {
                *o = v;
            }
            prev = u32::from(v);
            i = i.saturating_add(3);
        }
    }
    let mut i = pos_r;
    while i.saturating_add(2) < n {
        let g = data.get(i.saturating_add(1)).copied().unwrap_or(0);
        if let Some(o) = data.get_mut(i) {
            *o = o.wrapping_add(g);
        }
        if let Some(o) = data.get_mut(i.saturating_add(2)) {
            *o = o.wrapping_add(g);
        }
        i = i.saturating_add(3);
    }
}

fn audio(data: &mut [u8], channels: usize) {
    let n = data.len();
    let src = data.to_vec();
    let mut s = 0usize;
    for ch in 0..channels {
        let mut prev_byte = 0u32;
        let mut prev_delta = 0i32;
        let mut dif = [0u32; 7];
        let (mut d1, mut d2) = (0i32, 0i32);
        let (mut k1, mut k2, mut k3) = (0i32, 0i32, 0i32);
        let mut i = ch;
        let mut count = 0u32;
        while i < n {
            let d3 = d2;
            d2 = prev_delta.wrapping_sub(d1);
            d1 = prev_delta;
            let predicted = (8u32.wrapping_mul(prev_byte))
                .wrapping_add(k1.wrapping_mul(d1) as u32)
                .wrapping_add(k2.wrapping_mul(d2) as u32)
                .wrapping_add(k3.wrapping_mul(d3) as u32);
            let predicted = (predicted >> 3) & 0xff;
            let cur = u32::from(src.get(s).copied().unwrap_or(0));
            s = s.saturating_add(1);
            let predicted = predicted.wrapping_sub(cur);
            if let Some(o) = data.get_mut(i) {
                *o = predicted as u8;
            }
            prev_delta = i32::from(predicted.wrapping_sub(prev_byte) as u8 as i8);
            prev_byte = predicted;
            let d = i32::from(cur as u8 as i8).wrapping_mul(8);
            let terms = [
                d,
                d.wrapping_sub(d1),
                d.wrapping_add(d1),
                d.wrapping_sub(d2),
                d.wrapping_add(d2),
                d.wrapping_sub(d3),
                d.wrapping_add(d3),
            ];
            for (acc, t) in dif.iter_mut().zip(terms) {
                *acc = acc.wrapping_add(t.unsigned_abs());
            }
            if count & 0x1f == 0 {
                let mut min = dif[0];
                let mut which = 0usize;
                dif[0] = 0;
                for j in 1..dif.len() {
                    let v = dif.get(j).copied().unwrap_or(0);
                    if v < min {
                        min = v;
                        which = j;
                    }
                    if let Some(x) = dif.get_mut(j) {
                        *x = 0;
                    }
                }
                match which {
                    1 if k1 >= -16 => k1 = k1.wrapping_sub(1),
                    2 if k1 < 16 => k1 = k1.wrapping_add(1),
                    3 if k2 >= -16 => k2 = k2.wrapping_sub(1),
                    4 if k2 < 16 => k2 = k2.wrapping_add(1),
                    5 if k3 >= -16 => k3 = k3.wrapping_sub(1),
                    6 if k3 < 16 => k3 = k3.wrapping_add(1),
                    _ => {}
                }
            }
            count = count.wrapping_add(1);
            i = i.saturating_add(channels);
        }
    }
}

/// The standard RarVM programs, by byte code length and CRC32.
/// Builds a filter from its initial registers.
pub(super) type MakeFilter = fn([u32; 7]) -> Kind;

pub(super) fn standard(code: &[u8]) -> Option<MakeFilter> {
    let (first, rest) = code.split_first()?;
    if rest.iter().fold(0u8, |x, &b| x ^ b) != *first {
        return None;
    }
    let crc = crate::codec::crc32(code);
    let table: [(usize, u32, MakeFilter); 6] = [
        (53, 0xad57_6887, |r| Kind::E8_3 { e9: false, r }),
        (57, 0x3cd7_e57e, |r| Kind::E8_3 { e9: true, r }),
        (120, 0x3769_893f, |r| Kind::Itanium { r }),
        (29, 0x0e06_077d, |r| Kind::Delta3 { r }),
        (149, 0x1c2c_5dc8, |r| Kind::Rgb { r }),
        (216, 0xbc85_e701, |r| Kind::Audio { r }),
    ];
    table
        .iter()
        .find(|(len, c, _)| *len == code.len() && *c == crc)
        .map(|(_, _, f)| *f)
}
