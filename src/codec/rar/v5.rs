//! RAR 5.0/7.0 LZ decoding (unrar's `Unpack5`): byte-aligned blocks with
//! a checksummed header, optional Huffman tables (pre-code, then main,
//! distance, low-distance and repeat-length codes), and filters.

use super::bits::{Bits, Huff, read_bit_lengths, read_lengths};
use super::filters::Kind;
use super::{Algorithm, BATCH, Member, Pending, Stream, Unit, bad};
use crate::error::Result;

const NC: usize = 306;
const DC5: usize = 64;
const DC7: usize = 80;
const LDC: usize = 16;
const RC: usize = 44;
/// Largest filter block (larger ones are ignored).
const MAX_FILTER_BLOCK: u64 = 0x40_0000;
const MAX_FILTERS: usize = 8192;

#[derive(Clone)]
struct Tables {
    ld: Huff,
    dd: Huff,
    ldd: Huff,
    rd: Huff,
}

/// Decoder state kept across the files of a solid group.
#[derive(Default)]
pub(super) struct State {
    tables: Option<Tables>,
    old_dist: [u64; 4],
    last_len: u64,
    /// The current block: end (in bits from the member start), last flag.
    block_end: u64,
    last_block: bool,
}

impl Stream {
    /// Decodes up to [`BATCH`] symbols of a RAR 5 member, stopping before
    /// byte `stop` of its data.
    pub(super) fn run5(&mut self, mut bits: Bits<'_>, m: Member, stop: u64) -> Result<Unit> {
        let extra = m.algorithm == Algorithm::V70;
        if !self.started {
            if self.member == 0 {
                self.v5 = State::default();
            }
            self.started = true;
            if !self.block5(&mut bits, extra)? {
                self.bitpos = bits.pos;
                return Ok(Unit::End);
            }
        }
        let result = self.symbols5(&mut bits, extra, stop);
        self.bitpos = bits.pos;
        result
    }

    /// Reads a block header (and its tables); `false` at the end of the
    /// member's data.
    fn block5(&mut self, bits: &mut Bits<'_>, extra: bool) -> Result<bool> {
        bits.align();
        if bits.exhausted() {
            return Ok(false);
        }
        let flags = bits.read(8);
        let checksum = bits.read(8);
        let count = ((flags >> 3) & 3).saturating_add(1);
        if count == 4 {
            return Err(bad("block header size field of 4 bytes"));
        }
        let mut size = 0u32;
        for i in 0..count {
            size |= bits.read(8) << (i << 3);
        }
        let check = 0x5a ^ flags ^ size ^ (size >> 8) ^ (size >> 16);
        if check & 0xff != checksum {
            return Err(bad("block header checksum mismatch"));
        }
        if bits.overrun() {
            return Ok(false);
        }
        let start = bits.byte_pos();
        let bit_size = u64::from((flags & 7).saturating_add(1));
        self.v5.block_end = start
            .saturating_add(u64::from(size))
            .saturating_mul(8)
            .saturating_sub(8)
            .saturating_add(bit_size);
        self.v5.last_block = flags & 0x40 != 0;
        if flags & 0x80 != 0 {
            self.tables5(bits, extra)?;
        } else if self.v5.tables.is_none() {
            return Err(bad("block without Huffman tables"));
        }
        Ok(true)
    }

    fn tables5(&mut self, bits: &mut Bits<'_>, extra: bool) -> Result<()> {
        let bc = Huff::new(&read_bit_lengths(bits), 7);
        let dc = if extra { DC7 } else { DC5 };
        let mut table = vec![0u8; dc.saturating_add(NC + LDC + RC)];
        read_lengths(bits, &bc, &mut table, None).ok_or_else(|| bad("invalid Huffman tables"))?;
        if bits.overrun() {
            return Err(bad("Huffman tables run past the data"));
        }
        let (ld, rest) = table.split_at(NC);
        let (dd, rest) = rest.split_at(dc);
        let (ldd, rd) = rest.split_at(LDC);
        self.v5.tables = Some(Tables {
            ld: Huff::new(ld, 10),
            dd: Huff::new(dd, 7),
            ldd: Huff::new(ldd, 7),
            rd: Huff::new(rd, 7),
        });
        Ok(())
    }

    fn symbols5(&mut self, bits: &mut Bits<'_>, extra: bool, stop: u64) -> Result<Unit> {
        for _ in 0..BATCH {
            while bits.pos >= self.v5.block_end {
                if self.v5.last_block {
                    return Ok(Unit::End);
                }
                if !self.block5(bits, extra)? {
                    return Ok(Unit::End);
                }
            }
            if bits.exhausted() {
                return Ok(Unit::End);
            }
            if bits.byte_pos() >= stop {
                return Ok(Unit::More);
            }
            let t = self
                .v5
                .tables
                .as_ref()
                .ok_or_else(|| bad("no Huffman tables"))?;
            let slot = t.ld.decode(bits);
            if slot < 256 {
                self.win.put(slot as u8);
                continue;
            }
            if slot >= 262 {
                let mut len = slot_to_length(bits, slot.saturating_sub(262));
                let dslot = t.dd.decode(bits);
                let mut dist = 1u64;
                let dbits;
                if dslot < 4 {
                    dbits = 0;
                    dist = dist.saturating_add(u64::from(dslot));
                } else {
                    dbits = (dslot / 2).saturating_sub(1);
                    dist = dist
                        .saturating_add(u64::from(2 | (dslot & 1)).checked_shl(dbits).unwrap_or(0));
                }
                if dbits > 0 {
                    if dbits >= 4 {
                        if dbits > 4 {
                            dist =
                                dist.saturating_add(bits.read_long(dbits.saturating_sub(4)) << 4);
                        }
                        dist = dist.saturating_add(u64::from(t.ldd.decode(bits)));
                    } else {
                        dist = dist.saturating_add(u64::from(bits.read(dbits)));
                    }
                }
                if dist > 0x100 {
                    len = len.saturating_add(1);
                    if dist > 0x2000 {
                        len = len.saturating_add(1);
                        if dist > 0x40000 {
                            len = len.saturating_add(1);
                        }
                    }
                }
                self.v5.old_dist = [
                    dist,
                    self.v5.old_dist[0],
                    self.v5.old_dist[1],
                    self.v5.old_dist[2],
                ];
                self.v5.last_len = len;
                self.win.copy(dist, len)?;
                continue;
            }
            if slot == 256 {
                self.filter5(bits)?;
                continue;
            }
            if slot == 257 {
                if self.v5.last_len != 0 {
                    self.win.copy(self.v5.old_dist[0], self.v5.last_len)?;
                }
                continue;
            }
            // 258..261: a repeated distance.
            let n = (slot.saturating_sub(258) as usize).min(3);
            let dist = self.v5.old_dist.get(n).copied().unwrap_or(0);
            let mut i = n;
            while i > 0 {
                let prev = self
                    .v5
                    .old_dist
                    .get(i.saturating_sub(1))
                    .copied()
                    .unwrap_or(0);
                if let Some(d) = self.v5.old_dist.get_mut(i) {
                    *d = prev;
                }
                i = i.saturating_sub(1);
            }
            self.v5.old_dist[0] = dist;
            let lslot = t.rd.decode(bits);
            let len = slot_to_length(bits, lslot);
            self.v5.last_len = len;
            self.win.copy(dist, len)?;
        }
        Ok(Unit::More)
    }

    fn filter5(&mut self, bits: &mut Bits<'_>) -> Result<()> {
        let start = filter_data(bits);
        let mut len = filter_data(bits);
        if len > MAX_FILTER_BLOCK {
            len = 0;
        }
        let kind = match bits.read(3) {
            0 => Kind::Delta5 {
                channels: bits.read(5).saturating_add(1),
            },
            1 => Kind::E8_5 { e9: false },
            2 => Kind::E8_5 { e9: true },
            3 => Kind::Arm5,
            _ => return Err(bad("unknown filter type")),
        };
        if self.pending.len() >= MAX_FILTERS {
            self.pending.clear();
        }
        self.pending.push(Pending {
            start: self.win.pos().saturating_add(start),
            len,
            kind,
        });
        Ok(())
    }
}

fn slot_to_length(bits: &mut Bits<'_>, slot: u32) -> u64 {
    let (lbits, base) = if slot < 8 {
        (0, 2u64.saturating_add(u64::from(slot)))
    } else {
        let lbits = (slot / 4).saturating_sub(1);
        (
            lbits,
            2u64.saturating_add(u64::from(4 | (slot & 3)).checked_shl(lbits).unwrap_or(0)),
        )
    };
    base.saturating_add(u64::from(bits.read(lbits)))
}

/// A filter's start or length: 2 bits of byte count, then that many bytes
/// (little-endian).
fn filter_data(bits: &mut Bits<'_>) -> u64 {
    let count = bits.read(2).saturating_add(1);
    let mut v = 0u64;
    for i in 0..count {
        v |= u64::from(bits.read(8)) << (i << 3);
    }
    v
}
