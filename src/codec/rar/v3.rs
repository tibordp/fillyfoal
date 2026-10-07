//! RAR 2.9/3.x decoding (unrar's `Unpack29`): LZ blocks with Huffman
//! tables coded as deltas against the previous ones, PPMd variant H blocks,
//! and RarVM filters.

use super::bits::{Bits, Huff, read_bit_lengths, read_lengths};
use super::filters::{Kind, standard};
use super::ppmd::Ppm;
use super::{BATCH, Pending, Stream, Unit, bad};
use crate::error::Result;

const NC: usize = 299;
const DC: usize = 60;
const LDC: usize = 17;
const RC: usize = 28;
const TABLE: usize = NC + DC + LDC + RC;
const MAX_FILTERS: usize = 8192;

const LDECODE: [u8; 28] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128,
    160, 192, 224,
];
const LBITS: [u8; 28] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5,
];
const SDDECODE: [u8; 8] = [0, 4, 8, 16, 32, 64, 128, 192];
const SDBITS: [u8; 8] = [2, 2, 3, 4, 5, 6, 6, 6];

/// Distance slots: 4 of 0 extra bits, two each of 1..=15, 14 of 16 and 12
/// of 18 (unrar's `DBitLengthCounts`).
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
const fn dist_tables() -> ([u32; DC], [u8; DC]) {
    const COUNTS: [u8; 19] = [4, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 14, 0, 12];
    let mut base = [0u32; DC];
    let mut bits = [0u8; DC];
    let mut dist = 0u32;
    let mut slot = 0usize;
    let mut i = 0usize;
    while i < COUNTS.len() {
        let mut j = 0;
        while j < COUNTS[i] {
            base[slot] = dist;
            bits[slot] = i as u8;
            dist += 1 << i;
            slot += 1;
            j += 1;
        }
        i += 1;
    }
    (base, bits)
}

const DIST: ([u32; DC], [u8; DC]) = dist_tables();

fn ldecode(i: usize) -> u32 {
    u32::from(LDECODE.get(i).copied().unwrap_or(0))
}

fn lbits(i: usize) -> u32 {
    u32::from(LBITS.get(i).copied().unwrap_or(0))
}

#[derive(Clone)]
struct Tables {
    ld: Huff,
    dd: Huff,
    ldd: Huff,
    rd: Huff,
}

/// A filter's byte code, once seen.
#[derive(Clone)]
struct FilterDef {
    make: Option<fn([u32; 7]) -> Kind>,
    /// The block length of its last use.
    last_len: u32,
}

/// Decoder state kept across the files of a solid group.
pub(super) struct State {
    tables_read: bool,
    old_table: [u8; TABLE],
    tables: Option<Tables>,
    ppm_block: bool,
    esc: u8,
    old_dist: [u32; 4],
    last_len: u32,
    prev_low_dist: u32,
    low_dist_rep: u32,
    defs: Vec<FilterDef>,
    last_filter: usize,
    ppm: Option<Box<Ppm>>,
}

impl Default for State {
    fn default() -> Self {
        State {
            tables_read: false,
            old_table: [0; TABLE],
            tables: None,
            ppm_block: false,
            esc: 2,
            old_dist: [0; 4],
            last_len: 0,
            prev_low_dist: 0,
            low_dist_rep: 0,
            defs: Vec::new(),
            last_filter: 0,
            ppm: None,
        }
    }
}

/// unrar's `RarVM::ReadData`: a 2-bit size class, then 4, 8, 16 or 32 bits.
fn vm_data(bits: &mut Bits<'_>) -> u32 {
    let field = bits.peek16();
    match field & 0xc000 {
        0 => {
            bits.skip(6);
            (field >> 10) & 0xf
        }
        0x4000 => {
            if field & 0x3c00 == 0 {
                bits.skip(14);
                0xffff_ff00 | ((field >> 2) & 0xff)
            } else {
                bits.skip(10);
                (field >> 6) & 0xff
            }
        }
        0x8000 => {
            bits.skip(2);
            bits.read(16)
        }
        _ => {
            bits.skip(2);
            bits.read(32)
        }
    }
}

impl Stream {
    /// Decodes up to [`BATCH`] symbols of a RAR 3 member, stopping before
    /// byte `stop` of its data.
    pub(super) fn run3(&mut self, mut bits: Bits<'_>, stop: u64) -> Result<Unit> {
        if !self.started {
            if self.member == 0 {
                self.v3 = State::default();
            }
            self.started = true;
            if (self.member == 0 || !self.v3.tables_read) && !self.tables3(&mut bits)? {
                self.bitpos = bits.pos;
                return Ok(Unit::End);
            }
        }
        let result = self.symbols3(&mut bits, stop);
        self.bitpos = bits.pos;
        result
    }

    /// unrar's `ReadTables30`: a PPMd block header or LZ tables. `false` at
    /// the end of the data.
    fn tables3(&mut self, bits: &mut Bits<'_>) -> Result<bool> {
        bits.align();
        if bits.exhausted() {
            return Ok(false);
        }
        let field = bits.peek16();
        if field & 0x8000 != 0 {
            self.v3.ppm_block = true;
            let ppm = self.v3.ppm.get_or_insert_with(|| Box::new(Ppm::new()));
            ppm.init(bits, &mut self.v3.esc)?;
            return Ok(true);
        }
        self.v3.ppm_block = false;
        self.v3.prev_low_dist = 0;
        self.v3.low_dist_rep = 0;
        if field & 0x4000 == 0 {
            self.v3.old_table = [0; TABLE];
        }
        bits.skip(2);
        let bc = Huff::new(&read_bit_lengths(bits), 7);
        let mut table = [0u8; TABLE];
        read_lengths(bits, &bc, &mut table, Some(&self.v3.old_table))
            .ok_or_else(|| bad("invalid Huffman tables"))?;
        if bits.overrun() {
            return Err(bad("Huffman tables run past the data"));
        }
        self.v3.tables_read = true;
        let (ld, rest) = table.split_at(NC);
        let (dd, rest) = rest.split_at(DC);
        let (ldd, rd) = rest.split_at(LDC);
        self.v3.tables = Some(Tables {
            ld: Huff::new(ld, 10),
            dd: Huff::new(dd, 7),
            ldd: Huff::new(ldd, 7),
            rd: Huff::new(rd, 7),
        });
        self.v3.old_table = table;
        Ok(true)
    }

    fn insert_dist3(&mut self, dist: u32) {
        let d = &mut self.v3.old_dist;
        *d = [dist, d[0], d[1], d[2]];
    }

    fn symbols3(&mut self, bits: &mut Bits<'_>, stop: u64) -> Result<Unit> {
        for _ in 0..BATCH {
            if bits.overrun() || bits.exhausted() && !self.v3.ppm_block {
                return Ok(Unit::End);
            }
            if bits.byte_pos() >= stop {
                return Ok(Unit::More);
            }
            if self.v3.ppm_block {
                if let Unit::End = self.ppm_symbol(bits)? {
                    return Ok(Unit::End);
                }
                continue;
            }
            let t = self
                .v3
                .tables
                .as_ref()
                .ok_or_else(|| bad("no Huffman tables"))?;
            let n = t.ld.decode(bits);
            if n < 256 {
                self.win.put(n as u8);
                continue;
            }
            if n >= 271 {
                let i = (n as usize).saturating_sub(271);
                let mut len = ldecode(i).saturating_add(3);
                len = len.saturating_add(bits.read(lbits(i)));
                let ds = t.dd.decode(bits) as usize;
                let mut dist = DIST.0.get(ds).copied().unwrap_or(0).saturating_add(1);
                let db = u32::from(DIST.1.get(ds).copied().unwrap_or(0));
                if db > 0 {
                    if ds > 9 {
                        if db > 4 {
                            dist = dist.saturating_add(bits.read(db.saturating_sub(4)) << 4);
                        }
                        if self.v3.low_dist_rep > 0 {
                            self.v3.low_dist_rep = self.v3.low_dist_rep.saturating_sub(1);
                            dist = dist.saturating_add(self.v3.prev_low_dist);
                        } else {
                            let low = t.ldd.decode(bits);
                            if low == 16 {
                                self.v3.low_dist_rep = 15;
                                dist = dist.saturating_add(self.v3.prev_low_dist);
                            } else {
                                dist = dist.saturating_add(low);
                                self.v3.prev_low_dist = low;
                            }
                        }
                    } else {
                        dist = dist.saturating_add(bits.read(db));
                    }
                }
                if dist >= 0x2000 {
                    len = len.saturating_add(1);
                    if dist >= 0x40000 {
                        len = len.saturating_add(1);
                    }
                }
                self.insert_dist3(dist);
                self.v3.last_len = len;
                self.win.copy(dist.into(), len.into())?;
                continue;
            }
            match n {
                256 => {
                    // End of block: a new table, or the end of the file.
                    let field = bits.peek16();
                    let (new_table, new_file) = if field & 0x8000 != 0 {
                        bits.skip(1);
                        (true, false)
                    } else {
                        bits.skip(2);
                        (field & 0x4000 != 0, true)
                    };
                    self.v3.tables_read = !new_table;
                    if new_file {
                        return Ok(Unit::End);
                    }
                    if !self.tables3(bits)? {
                        return Ok(Unit::End);
                    }
                }
                257 => {
                    let first = bits.read(8);
                    let mut len = (first & 7).saturating_add(1);
                    if len == 7 {
                        len = bits.read(8).saturating_add(7);
                    } else if len == 8 {
                        len = bits.read(16);
                    }
                    if len == 0 {
                        return Err(bad("empty filter code"));
                    }
                    let code: Vec<u8> = (0..len).map(|_| bits.read(8) as u8).collect();
                    self.add_vm_code(first, &code)?;
                }
                258 => {
                    if self.v3.last_len != 0 {
                        self.win
                            .copy(self.v3.old_dist[0].into(), self.v3.last_len.into())?;
                    }
                }
                259..=262 => {
                    let k = (n as usize).saturating_sub(259).min(3);
                    let dist = self.v3.old_dist.get(k).copied().unwrap_or(0);
                    if let Some(front) = self.v3.old_dist.get_mut(..=k) {
                        front.rotate_right(1);
                    }
                    self.v3.old_dist[0] = dist;
                    let ls = t.rd.decode(bits) as usize;
                    let len = ldecode(ls)
                        .saturating_add(2)
                        .saturating_add(bits.read(lbits(ls)));
                    self.v3.last_len = len;
                    self.win.copy(dist.into(), len.into())?;
                }
                _ => {
                    // 263..=270: short distances, length 2.
                    let k = (n as usize).saturating_sub(263);
                    let dist = u32::from(SDDECODE.get(k).copied().unwrap_or(0))
                        .saturating_add(1)
                        .saturating_add(bits.read(u32::from(SDBITS.get(k).copied().unwrap_or(0))));
                    self.insert_dist3(dist);
                    self.v3.last_len = 2;
                    self.win.copy(dist.into(), 2)?;
                }
            }
        }
        Ok(Unit::More)
    }

    /// One PPMd symbol (with its escapes).
    fn ppm_symbol(&mut self, bits: &mut Bits<'_>) -> Result<Unit> {
        let esc = self.v3.esc;
        let ppm = self.v3.ppm.as_mut().ok_or_else(|| bad("no PPMd model"))?;
        let ch = ppm
            .decode_char(bits)
            .ok_or_else(|| bad("corrupt PPMd data"))?;
        if ch != esc {
            self.win.put(ch);
            return Ok(Unit::More);
        }
        let next = ppm
            .decode_char(bits)
            .ok_or_else(|| bad("corrupt PPMd data"))?;
        match next {
            0 => {
                if !self.tables3(bits)? {
                    return Ok(Unit::End);
                }
            }
            2 => return Ok(Unit::End),
            3 => {
                let first = ppm
                    .decode_char(bits)
                    .ok_or_else(|| bad("corrupt PPMd data"))?;
                let mut len = u32::from(first & 7).saturating_add(1);
                if len == 7 {
                    let b = ppm
                        .decode_char(bits)
                        .ok_or_else(|| bad("corrupt PPMd data"))?;
                    len = u32::from(b).saturating_add(7);
                } else if len == 8 {
                    let b1 = ppm
                        .decode_char(bits)
                        .ok_or_else(|| bad("corrupt PPMd data"))?;
                    let b2 = ppm
                        .decode_char(bits)
                        .ok_or_else(|| bad("corrupt PPMd data"))?;
                    len = u32::from(b1) << 8 | u32::from(b2);
                }
                if len == 0 {
                    return Err(bad("empty filter code"));
                }
                let mut code = Vec::with_capacity(len as usize);
                for _ in 0..len {
                    code.push(
                        ppm.decode_char(bits)
                            .ok_or_else(|| bad("corrupt PPMd data"))?,
                    );
                    if bits.overrun() {
                        return Err(bad("PPMd data runs past the end"));
                    }
                }
                self.add_vm_code(u32::from(first), &code)?;
            }
            4 => {
                let mut dist = 0u32;
                for _ in 0..3 {
                    let b = ppm
                        .decode_char(bits)
                        .ok_or_else(|| bad("corrupt PPMd data"))?;
                    dist = dist << 8 | u32::from(b);
                }
                let len = ppm
                    .decode_char(bits)
                    .ok_or_else(|| bad("corrupt PPMd data"))?;
                self.win.copy(
                    u64::from(dist).saturating_add(2),
                    u64::from(len).saturating_add(32),
                )?;
            }
            5 => {
                let len = ppm
                    .decode_char(bits)
                    .ok_or_else(|| bad("corrupt PPMd data"))?;
                self.win.copy(1, u64::from(len).saturating_add(4))?;
            }
            _ => self.win.put(ch),
        }
        Ok(Unit::More)
    }

    /// unrar's `AddVMCode`: declares a filter (new byte code, or one seen
    /// before) on a block ahead.
    fn add_vm_code(&mut self, first: u32, code: &[u8]) -> Result<()> {
        let mut b = Bits {
            data: code,
            base: 0,
            pos: 0,
        };
        let mut pos = if first & 0x80 != 0 {
            let p = vm_data(&mut b);
            if p == 0 {
                self.v3.defs.clear();
                self.v3.last_filter = 0;
                self.pending.clear();
                0
            } else {
                p.saturating_sub(1) as usize
            }
        } else {
            self.v3.last_filter
        };
        if pos > self.v3.defs.len() {
            return Err(bad("filter number out of range"));
        }
        self.v3.last_filter = pos;
        let new = pos == self.v3.defs.len();
        if new {
            if pos > MAX_FILTERS {
                return Err(bad("too many filters"));
            }
            self.v3.defs.push(FilterDef {
                make: None,
                last_len: 0,
            });
        }
        if self.pending.len() > MAX_FILTERS {
            return Err(bad("too many pending filters"));
        }
        let mut start = vm_data(&mut b);
        if first & 0x40 != 0 {
            start = start.wrapping_add(258);
        }
        let len = if first & 0x20 != 0 {
            let l = vm_data(&mut b);
            if let Some(d) = self.v3.defs.get_mut(pos) {
                d.last_len = l;
            }
            l
        } else {
            self.v3.defs.get(pos).map_or(0, |d| d.last_len)
        };
        let mut r = [0u32; 7];
        r[4] = len;
        if first & 0x10 != 0 {
            let mask = b.read(7);
            for (i, reg) in r.iter_mut().enumerate() {
                if mask & (1 << i) != 0 {
                    *reg = vm_data(&mut b);
                }
            }
        }
        if new {
            let size = vm_data(&mut b);
            let at = b.byte_pos();
            if size >= 0x10000
                || size == 0
                || at.saturating_add(u64::from(size)) > code.len() as u64
            {
                return Err(bad("invalid filter byte code size"));
            }
            let vm: Vec<u8> = (0..size).map(|_| b.read(8) as u8).collect();
            if let Some(d) = self.v3.defs.get_mut(pos) {
                d.make = standard(&vm);
            }
        }
        pos = pos.min(self.v3.defs.len().saturating_sub(1));
        let kind = match self.v3.defs.get(pos).and_then(|d| d.make) {
            Some(make) => make(r),
            None => Kind::Unknown,
        };
        self.pending.push(Pending {
            start: self.win.pos().saturating_add(u64::from(start)),
            len: u64::from(len),
            kind,
        });
        Ok(())
    }
}
