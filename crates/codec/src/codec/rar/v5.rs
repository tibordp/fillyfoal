//! RAR 5.0 streams (algorithm version 0): blocks, each with a small header
//! giving its exact size in bits, of LZ77 symbols under four prefix codes,
//! with filter declarations.
//!
//! Follows libarchive's `archive_read_support_format_rar5.c` by Grzegorz
//! Antoniak (`parse_block_header`, `parse_tables`, `do_uncompress_block`,
//! `decode_code_length`, `parse_filter`). RAR 7.0 streams (algorithm
//! version 1), which libarchive does not read, are refused. See [`super`]
//! for provenance.

use super::bits::Bits;
use super::filters::{Filter, Kind};
use super::huffman::{Code, read_lengths};
use super::{Algorithm, BATCH, Member, Pending, Stream, Unit, bad};
use crate::error::Result;

/// Alphabet sizes: main (literals, commands, length slots), distance
/// slots, low distance bits, length slots of repeated distances.
const MAIN: usize = 306;
const DIST: usize = 64;
const LOW: usize = 16;
const REP: usize = 44;
const TABLES: usize = MAIN + DIST + LOW + REP;

#[derive(Clone)]
struct Codes {
    main: Code,
    dist: Code,
    low: Code,
    rep: Code,
}

/// The block being decoded: where its symbols end (in bits), where the
/// next block header starts, and whether it is the member's last.
#[derive(Clone, Copy)]
struct Block {
    end: u64,
    next: u64,
    last: bool,
}

#[derive(Clone, Default)]
pub struct State {
    codes: Option<Codes>,
    block: Option<Block>,
    /// The last four distances, most recent first.
    cache: [u64; 4],
    last_len: u64,
    /// Where the last filter declared in this member ends.
    filter_end: Option<u64>,
}

impl State {
    /// Heap bytes a clone copies (the prefix codes).
    pub fn heap_size(&self) -> usize {
        self.codes.as_ref().map_or(0, |c| {
            [&c.main, &c.dist, &c.low, &c.rep]
                .iter()
                .map(|code| code.heap_size())
                .fold(0, usize::saturating_add)
        })
    }
}

/// A length from its slot: slots 0–7 are lengths 2–9, then four slots per
/// number of extra bits (libarchive's `decode_code_length`).
fn length(bits: &mut Bits<'_>, slot: u16) -> u64 {
    let slot = u32::from(slot);
    if slot < 8 {
        return u64::from(slot).saturating_add(2);
    }
    let nbits = (slot / 4).saturating_sub(1);
    let base = u64::from(4 | slot & 3) << nbits;
    base.saturating_add(2)
        .saturating_add(u64::from(bits.read(nbits)))
}

/// A filter parameter: 2 bits giving the byte count - 1, then the bytes,
/// least significant first.
fn filter_number(bits: &mut Bits<'_>) -> u64 {
    let n = bits.read(2);
    let mut v = 0u64;
    for i in 0..=n {
        v |= u64::from(bits.read(8)) << i.saturating_mul(8);
    }
    v
}

impl Stream {
    /// Decodes RAR 5 symbols of member `m` until the input position reaches
    /// byte `stop` (of the member) or a batch is done.
    pub(super) fn run5(&mut self, mut bits: Bits<'_>, m: Member, stop: u64) -> Result<Unit> {
        if m.algorithm == Algorithm::V70 {
            return Err(bad(
                "RAR 7.0 compression (algorithm version 1) is not supported",
            ));
        }
        if !self.started {
            self.started = true;
            self.v5.block = None;
            self.v5.filter_end = None;
        }
        let end = bits.end();
        let mut unit = Unit::More;
        // At least one unit per call (the driver keeps a margin of input
        // beyond `stop`), so that every call makes progress.
        for n in 0..BATCH {
            if n > 0 && bits.pos >> 3 >= stop {
                break;
            }
            match self.v5.block {
                None => {
                    if bits.pos >= end {
                        unit = Unit::End;
                        break;
                    }
                    self.block_header(&mut bits)?;
                }
                Some(b) if bits.pos >= b.end => {
                    self.v5.block = None;
                    bits.pos = b.next;
                    if b.last {
                        unit = Unit::End;
                        break;
                    }
                }
                Some(_) => self.symbol(&mut bits)?,
            }
        }
        self.bitpos = bits.pos;
        Ok(unit)
    }

    /// A block header: flags (bit 7 tables follow, bit 6 last block, bits
    /// 3–5 size bytes - 1, bits 0–2 bits used in the last byte - 1), a check
    /// byte (0x5A XOR the flags and size bytes), the size (little-endian);
    /// then the tables if flagged.
    fn block_header(&mut self, bits: &mut Bits<'_>) -> Result<()> {
        bits.align();
        let flags = bits.get_byte();
        let check = bits.get_byte();
        let count = (flags >> 3) & 7;
        if count > 2 {
            return Err(bad("block size of more than 3 bytes"));
        }
        let mut size = 0u64;
        let mut sum = 0x5a ^ flags;
        for i in 0..=count {
            let b = bits.get_byte();
            sum ^= b;
            size |= u64::from(b) << u32::from(i).saturating_mul(8);
        }
        if sum != check {
            return Err(bad("block header checksum mismatch"));
        }
        let start = bits.pos;
        let used = u64::from(flags & 7).saturating_add(1);
        let end = match size.checked_sub(1) {
            Some(n) => start
                .saturating_add(n.saturating_mul(8))
                .saturating_add(used),
            None => start,
        };
        self.v5.block = Some(Block {
            end,
            next: start.saturating_add(size.saturating_mul(8)),
            last: flags & 0x40 != 0,
        });
        if flags & 0x80 != 0 {
            let mut lengths = [0u8; TABLES];
            read_lengths(bits, &mut lengths, false)?;
            let (main, rest) = lengths.split_at(MAIN);
            let (dist, rest) = rest.split_at(DIST);
            let (low, rep) = rest.split_at(LOW);
            self.v5.codes = Some(Codes {
                main: Code::new(main)?,
                dist: Code::new(dist)?,
                low: Code::new(low)?,
                rep: Code::new(rep)?,
            });
        } else if self.v5.codes.is_none() {
            return Err(bad("block without tables"));
        }
        Ok(())
    }

    /// One symbol (libarchive's `do_uncompress_block`).
    fn symbol(&mut self, bits: &mut Bits<'_>) -> Result<()> {
        let st = &mut self.v5;
        let codes = st.codes.as_ref().ok_or_else(|| bad("no tables"))?;
        let sym = codes.main.decode(bits)?;
        let (dist, len) = match sym {
            0..=255 => {
                self.win.put(sym as u8);
                return Ok(());
            }
            256 => return self.read_filter5(bits),
            257 => {
                if st.last_len == 0 {
                    return Ok(());
                }
                (st.cache[0], st.last_len)
            }
            258..=261 => {
                let idx = usize::from(sym.saturating_sub(258));
                let dist = st.cache.get(idx).copied().unwrap_or(0);
                for k in (1..=idx).rev() {
                    if let Some(v) = st.cache.get(k.saturating_sub(1)).copied()
                        && let Some(c) = st.cache.get_mut(k)
                    {
                        *c = v;
                    }
                }
                st.cache[0] = dist;
                let slot = codes.rep.decode(bits)?;
                let len = length(bits, slot);
                st.last_len = len;
                (dist, len)
            }
            _ => {
                let mut len = length(bits, sym.saturating_sub(262));
                let slot = u32::from(codes.dist.decode(bits)?);
                let mut dist = 1u64;
                if slot < 4 {
                    dist = dist.saturating_add(u64::from(slot));
                } else {
                    let nbits = (slot / 2).saturating_sub(1);
                    dist = dist.saturating_add(u64::from(2 | slot & 1) << nbits);
                    if nbits >= 4 {
                        if nbits > 4 {
                            let high = u64::from(bits.read(nbits.saturating_sub(4)));
                            dist = dist.saturating_add(high << 4);
                        }
                        dist = dist.saturating_add(u64::from(codes.low.decode(bits)?));
                    } else {
                        dist = dist.saturating_add(u64::from(bits.read(nbits)));
                    }
                }
                if dist > 0x100 {
                    len = len.saturating_add(1);
                }
                if dist > 0x2000 {
                    len = len.saturating_add(1);
                }
                if dist > 0x4_0000 {
                    len = len.saturating_add(1);
                }
                st.cache = [dist, st.cache[0], st.cache[1], st.cache[2]];
                st.last_len = len;
                (dist, len)
            }
        };
        self.win.copy(dist, len)
    }

    /// Symbol 256: block start (relative to the current position) and
    /// length, type (3 bits), and for DELTA the channel count - 1 (5 bits).
    /// Checked as libarchive's `parse_filter` does.
    fn read_filter5(&mut self, bits: &mut Bits<'_>) -> Result<()> {
        let rel = filter_number(bits);
        let len = filter_number(bits);
        let kind = bits.read(3);
        let start = self.win.pos().saturating_add(rel);
        let half_dict = self.params.dict / 2;
        if !(4..=0x40_0000).contains(&len)
            || self.v5.filter_end.is_some_and(|e| start < e)
            || (half_dict > 0 && len > half_dict)
        {
            return Err(bad("invalid filter"));
        }
        let filter = match kind {
            0 => Filter::Delta {
                channels: bits.read(5).saturating_add(1),
            },
            1 => Filter::E8 { e9: false },
            2 => Filter::E8 { e9: true },
            3 => Filter::Arm,
            _ => return Err(bad(&format!("unsupported filter type {kind}"))),
        };
        self.v5.filter_end = Some(start.saturating_add(len));
        self.pending.push(Pending {
            start,
            len,
            kind: Kind {
                filter,
                rar3: false,
            },
        });
        Ok(())
    }
}
