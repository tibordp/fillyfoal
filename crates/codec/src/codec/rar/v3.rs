//! RAR 2.9/3.x streams (unpack version 29): blocks of LZ77 symbols under
//! four prefix codes, or of PPMd variant H, with RarVM filter declarations.
//!
//! Follows libarchive's `archive_read_support_format_rar.c` (`parse_codes`,
//! `expand`, the PPMd branch of `read_data_compressed`, `read_filter` and
//! `parse_filter`); the constant tables are the ones `expand` lists. Where
//! this reader goes beyond libarchive (solid groups) it says so. See
//! [`super`] for provenance.

use super::bits::Bits;
use super::filters::{self, Kind};
use super::huffman::{Code, read_lengths};
use super::ppmd::Ppm;
use super::{BATCH, Member, Pending, Stream, Unit, bad};
use crate::codec::crc32;
use crate::error::Result;

/// Alphabet sizes: main (literals, commands, lengths), distance slots,
/// low distance bits (16 = repeat), lengths of repeated distances.
const MAIN: usize = 299;
const DIST: usize = 60;
const LOW: usize = 17;
const LEN: usize = 28;
const TABLES: usize = MAIN + DIST + LOW + LEN;

/// Match length slots: base and extra bits (`lengthbases`, `lengthbits`).
const LEN_BITS: [u8; LEN] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5,
];
/// Distance slots: extra bits (`offsetbits`).
const DIST_BITS: [u8; DIST] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18,
];
/// Two-byte matches at short distances (`shortbases`, `shortbits`).
const SHORT_BASE: [u32; 8] = [0, 4, 8, 16, 32, 64, 128, 192];
const SHORT_BITS: [u8; 8] = [2, 2, 3, 4, 5, 6, 6, 6];

const LEN_BASE: [u32; LEN] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128,
    160, 192, 224,
];
/// Distance slot bases (`offsetbases`).
const DIST_BASE: [u32; DIST] = [
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536,
    2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072, 196608,
    262144, 327680, 393216, 458752, 524288, 589824, 655360, 720896, 786432, 851968, 917504, 983040,
    1048576, 1310720, 1572864, 1835008, 2097152, 2359296, 2621440, 2883584, 3145728, 3407872,
    3670016, 3932160,
];

/// A RarVM program seen in the stream.
#[derive(Clone)]
struct Program {
    /// The block length of its last use (the default for the next).
    last_len: u32,
    crc: u32,
    len: usize,
}

#[derive(Clone)]
struct Codes {
    main: Code,
    dist: Code,
    low: Code,
    len: Code,
}

/// What carries over between blocks (and between the files of a solid
/// group).
#[derive(Clone)]
pub struct State {
    /// Code lengths, kept for the next table's delta coding.
    lengths: [u8; TABLES],
    codes: Option<Codes>,
    /// Read tables before the next symbol.
    new_table: bool,
    ppmd: Option<Box<Ppm>>,
    in_ppmd: bool,
    escape: u8,
    old: [u64; 4],
    last_dist: u64,
    last_len: u64,
    low: u64,
    low_repeats: u32,
    programs: Vec<Program>,
    last_program: usize,
}

impl Default for State {
    fn default() -> Self {
        State {
            lengths: [0; TABLES],
            codes: None,
            new_table: true,
            ppmd: None,
            in_ppmd: false,
            escape: 2,
            old: [0; 4],
            last_dist: 0,
            last_len: 0,
            low: 0,
            low_repeats: 0,
            programs: Vec::new(),
            last_program: 0,
        }
    }
}

impl State {
    /// Heap bytes a clone copies: the prefix codes, the PPMd model (its
    /// pages in use, up to the model's memory size) and the programs.
    pub fn heap_size(&self) -> usize {
        let codes = self.codes.as_ref().map_or(0, |c| {
            [&c.main, &c.dist, &c.low, &c.len]
                .iter()
                .map(|code| code.heap_size())
                .fold(0, usize::saturating_add)
        });
        let ppmd = self.ppmd.as_ref().map_or(0, |p| {
            std::mem::size_of::<Ppm>().saturating_add(p.heap_size())
        });
        codes.saturating_add(ppmd).saturating_add(
            self.programs
                .capacity()
                .saturating_mul(std::mem::size_of::<Program>()),
        )
    }
}

/// A RarVM variable-length number (libarchive's `membr_next_rarvm_number`).
fn vm_number(b: &mut Bits<'_>) -> u32 {
    match b.read(2) {
        0 => b.read(4),
        1 => {
            let v = b.read(8);
            if v >= 16 {
                v
            } else {
                0xffff_ff00 | v << 4 | b.read(4)
            }
        }
        2 => b.read(16),
        _ => b.read(32),
    }
}

impl State {
    /// Reads a block start: a PPMd block's parameters, or LZ tables
    /// (libarchive's `parse_codes`).
    fn read_tables(&mut self, bits: &mut Bits<'_>) -> Result<()> {
        bits.align();
        if bits.peek(1) != 0 {
            self.in_ppmd = true;
            // libarchive: the escape is 2 unless the block names another.
            self.escape = 2;
            let ppm = self.ppmd.get_or_insert_with(|| Box::new(Ppm::new()));
            return ppm.init(bits, &mut self.escape);
        }
        bits.skip(1);
        self.in_ppmd = false;
        // Low-distance repeats belong to the table they were read with.
        self.low = 0;
        self.low_repeats = 0;
        if !bits.flag() {
            self.lengths = [0; TABLES];
        }
        read_lengths(bits, &mut self.lengths, true)?;
        let (main, rest) = self.lengths.split_at(MAIN);
        let (dist, rest) = rest.split_at(DIST);
        let (low, len) = rest.split_at(LOW);
        self.codes = Some(Codes {
            main: Code::new(main)?,
            dist: Code::new(dist)?,
            low: Code::new(low)?,
            len: Code::new(len)?,
        });
        Ok(())
    }

    fn push_old(&mut self, dist: u64) {
        self.old = [dist, self.old[0], self.old[1], self.old[2]];
    }
}

/// How the member's data continues after the symbol just decoded.
enum Step {
    More,
    End,
}

impl Stream {
    /// Decodes RAR 3 symbols of member `m` until the input position reaches
    /// byte `stop` (of the member) or a batch is done.
    pub(super) fn run3(&mut self, mut bits: Bits<'_>, m: Member, stop: u64) -> Result<Unit> {
        if !self.started {
            self.started = true;
            if self.v3.new_table || self.v3.codes.is_none() && !self.v3.in_ppmd {
                self.v3.new_table = false;
                self.v3.read_tables(&mut bits)?;
            }
        }
        let end = bits.end();
        let mut unit = Unit::More;
        // At least one unit per call (the driver keeps a margin of input
        // beyond `stop`), so that every call makes progress.
        for n in 0..BATCH {
            if n > 0 && bits.pos >> 3 >= stop {
                break;
            }
            let complete = self.win.pos().saturating_sub(self.member_start) >= m.unpacked;
            let step = if self.v3.in_ppmd {
                // The range decoder reads up to 4 bytes ahead of its symbols.
                if complete || bits.pos > end.saturating_add(32) {
                    // As libarchive, stop at the recorded size (an end
                    // marker after it is not read).
                    self.v3.new_table = true;
                    Step::End
                } else {
                    self.ppmd_symbol(&mut bits)?
                }
            } else if bits.pos >= end {
                Step::End
            } else if complete {
                self.after_last_byte(&mut bits)?
            } else {
                self.lz_symbol(&mut bits)?
            };
            if let Step::End = step {
                unit = Unit::End;
                break;
            }
        }
        self.bitpos = bits.pos;
        Ok(unit)
    }

    /// The member's output is complete. Like libarchive, a file ends at its
    /// recorded size; but a solid group needs to know whether the next file
    /// starts with tables, which the encoder says with an end-of-block
    /// symbol (256, 0, then 1 for new tables) after the last byte. Read it if
    /// it is there; otherwise leave the rest unread and have the next file
    /// read tables (libarchive does not decode RAR 3 solid groups; this is
    /// our choice).
    fn after_last_byte(&mut self, bits: &mut Bits<'_>) -> Result<Step> {
        let mut ahead = *bits;
        let sym = self
            .v3
            .codes
            .as_ref()
            .ok_or_else(|| bad("no tables"))?
            .main
            .decode(&mut ahead);
        if let Ok(256) = sym {
            *bits = ahead;
            return self.end_of_block(bits, true);
        }
        self.v3.new_table = true;
        Ok(Step::End)
    }

    /// Symbol 256 (libarchive's `expand`): 1 = new tables follow now; 0 =
    /// end of a block, then 1 if new tables start the next one. The file
    /// itself ends only at its recorded size (`complete`).
    fn end_of_block(&mut self, bits: &mut Bits<'_>, complete: bool) -> Result<Step> {
        if bits.flag() {
            self.v3.read_tables(bits)?;
            return Ok(Step::More);
        }
        let new_table = bits.flag();
        if complete {
            self.v3.new_table = new_table;
            return Ok(Step::End);
        }
        if new_table {
            self.v3.read_tables(bits)?;
        }
        Ok(Step::More)
    }

    /// One LZ symbol (libarchive's `expand`).
    fn lz_symbol(&mut self, bits: &mut Bits<'_>) -> Result<Step> {
        let st = &mut self.v3;
        let codes = st.codes.as_ref().ok_or_else(|| bad("no tables"))?;
        let sym = usize::from(codes.main.decode(bits)?);
        let (dist, len) = match sym {
            0..=255 => {
                self.win.put(sym as u8);
                return Ok(Step::More);
            }
            256 => return self.end_of_block(bits, false),
            257 => {
                self.read_filter3(bits)?;
                return Ok(Step::More);
            }
            258 => {
                if st.last_len == 0 {
                    return Ok(Step::More);
                }
                (st.last_dist, st.last_len)
            }
            259..=262 => {
                let idx = sym.saturating_sub(259);
                let dist = st.old.get(idx).copied().unwrap_or(0);
                let slot = usize::from(codes.len.decode(bits)?);
                let len = length(bits, slot)?.saturating_add(2);
                // Move the distance to the front.
                for k in (1..=idx).rev() {
                    if let Some(v) = st.old.get(k.saturating_sub(1)).copied()
                        && let Some(o) = st.old.get_mut(k)
                    {
                        *o = v;
                    }
                }
                st.old[0] = dist;
                (dist, len)
            }
            263..=270 => {
                let k = sym.saturating_sub(263);
                let base = SHORT_BASE.get(k).copied().unwrap_or(0);
                let nbits = SHORT_BITS.get(k).copied().unwrap_or(0);
                let dist = u64::from(base)
                    .saturating_add(1)
                    .saturating_add(u64::from(bits.read(nbits.into())));
                st.push_old(dist);
                (dist, 2)
            }
            _ => {
                let mut len = length(bits, sym.saturating_sub(271))?.saturating_add(3);
                let slot = usize::from(codes.dist.decode(bits)?);
                let base = *DIST_BASE
                    .get(slot)
                    .ok_or_else(|| bad("invalid distance slot"))?;
                let nbits = u32::from(DIST_BITS.get(slot).copied().unwrap_or(0));
                let mut dist = u64::from(base).saturating_add(1);
                if slot > 9 {
                    if nbits > 4 {
                        dist =
                            dist.saturating_add(u64::from(bits.read(nbits.saturating_sub(4))) << 4);
                    }
                    if st.low_repeats > 0 {
                        st.low_repeats = st.low_repeats.saturating_sub(1);
                        dist = dist.saturating_add(st.low);
                    } else {
                        let low = codes.low.decode(bits)?;
                        if low == 16 {
                            st.low_repeats = 15;
                            dist = dist.saturating_add(st.low);
                        } else {
                            st.low = u64::from(low);
                            dist = dist.saturating_add(st.low);
                        }
                    }
                } else {
                    dist = dist.saturating_add(u64::from(bits.read(nbits)));
                }
                if dist >= 0x2000 {
                    len = len.saturating_add(1);
                }
                if dist >= 0x4_0000 {
                    len = len.saturating_add(1);
                }
                st.push_old(dist);
                (dist, len)
            }
        };
        st.last_dist = dist;
        st.last_len = len;
        self.win.copy(dist, len)?;
        Ok(Step::More)
    }

    /// One PPMd symbol, or an escape sequence (libarchive's PPMd branch of
    /// `read_data_compressed`): escape then 0 = new tables, 2 = end of
    /// data, 3 = filter (unsupported, as in libarchive), 4 = match (3-byte
    /// distance - 2, length - 32), 5 = run of the last byte (length - 4);
    /// anything else stands for the escape byte itself.
    fn ppmd_symbol(&mut self, bits: &mut Bits<'_>) -> Result<Step> {
        let corrupt = || bad("corrupt PPMd data");
        let escape = self.v3.escape;
        let ppm = self.v3.ppmd.as_mut().ok_or_else(corrupt)?;
        let c = ppm.decode_char(bits).ok_or_else(corrupt)?;
        if c != escape {
            self.win.put(c);
            return Ok(Step::More);
        }
        let code = ppm.decode_char(bits).ok_or_else(corrupt)?;
        match code {
            0 => {
                self.v3.read_tables(bits)?;
            }
            2 => {
                self.v3.new_table = true;
                return Ok(Step::End);
            }
            3 => return Err(bad("filters in PPMd blocks are not supported")),
            4 => {
                let mut dist = 0u64;
                for _ in 0..3 {
                    dist = dist << 8 | u64::from(ppm.decode_char(bits).ok_or_else(corrupt)?);
                }
                let len = ppm.decode_char(bits).ok_or_else(corrupt)?;
                self.win
                    .copy(dist.saturating_add(2), u64::from(len).saturating_add(32))?;
            }
            5 => {
                let len = ppm.decode_char(bits).ok_or_else(corrupt)?;
                self.win.copy(1, u64::from(len).saturating_add(4))?;
            }
            _ => self.win.put(escape),
        }
        Ok(Step::More)
    }

    /// Symbol 257: a filter declaration (libarchive's `read_filter`): a
    /// flags byte whose low 3 bits give the record length (1–6, or 7: a
    /// byte + 7, 8: 16 bits), then the record (`parse_filter`).
    fn read_filter3(&mut self, bits: &mut Bits<'_>) -> Result<()> {
        let flags = bits.get_byte();
        let len = match flags & 7 {
            6 => usize::from(bits.get_byte()).saturating_add(7),
            7 => bits.read(16) as usize,
            n => usize::from(n).saturating_add(1),
        };
        let record: Vec<u8> = (0..len).map(|_| bits.get_byte()).collect();
        self.parse_filter3(&record, flags)
    }

    /// A filter record: program number (with flag 0x80; 0 forgets all
    /// programs), block start relative to the current position (+258 with
    /// flag 0x40), block length (with 0x20, else the program's last),
    /// registers (with 0x10), byte code for a new program, global data
    /// (with 0x08).
    fn parse_filter3(&mut self, record: &[u8], flags: u8) -> Result<()> {
        let invalid = || bad("invalid filter declaration");
        let end = (record.len() as u64).saturating_mul(8);
        let mut b = Bits {
            data: record,
            base: 0,
            pos: 0,
        };
        let st = &mut self.v3;
        let num = if flags & 0x80 != 0 {
            let n = vm_number(&mut b);
            let n = if n == 0 {
                st.programs.clear();
                self.pending.retain(|p| !p.kind.rar3);
                0
            } else {
                n.saturating_sub(1) as usize
            };
            if n > st.programs.len() {
                return Err(invalid());
            }
            st.last_program = n;
            n
        } else {
            st.last_program
        };
        let start = u64::from(vm_number(&mut b))
            .saturating_add(self.win.pos())
            .saturating_add(if flags & 0x40 != 0 { 258 } else { 0 });
        let known = st.programs.get(num);
        let len = if flags & 0x20 != 0 {
            vm_number(&mut b)
        } else {
            known.map_or(0, |p| p.last_len)
        };
        if u64::from(len) > filters::VM_MEMORY {
            return Err(invalid());
        }
        let mut regs = [0u32; 7];
        if flags & 0x10 != 0 {
            let mask = b.read(7);
            for (i, r) in regs.iter_mut().enumerate() {
                if mask >> i & 1 != 0 {
                    *r = vm_number(&mut b);
                }
            }
        }
        if num == st.programs.len() {
            let code_len = vm_number(&mut b) as usize;
            if code_len == 0 || code_len > 0x1_0000 {
                return Err(invalid());
            }
            let code: Vec<u8> = (0..code_len).map(|_| b.get_byte()).collect();
            // The first byte is the XOR of the others (libarchive's
            // `compile_program` checks it).
            let xor = code.iter().skip(1).fold(0u8, |x, &v| x ^ v);
            if code.first() != Some(&xor) {
                return Err(invalid());
            }
            st.programs.push(Program {
                last_len: 0,
                crc: crc32(&code),
                len: code_len,
            });
        }
        let prog = st.programs.get_mut(num).ok_or_else(invalid)?;
        prog.last_len = len;
        if flags & 0x08 != 0 {
            let global = vm_number(&mut b);
            if global > 0x2000 - 0x40 {
                return Err(invalid());
            }
            b.skip(global.saturating_mul(8));
        }
        if b.pos > end {
            return Err(invalid());
        }
        let filter = filters::standard(prog.crc, prog.len, &regs).ok_or_else(|| {
            bad(&format!(
                "unsupported RarVM filter program (length {}, CRC32 {:#010x})",
                prog.len, prog.crc
            ))
        })?;
        self.pending.push(Pending {
            start,
            len: u64::from(len),
            kind: Kind { filter, rar3: true },
        });
        Ok(())
    }
}

/// A match length from its slot and extra bits.
fn length(bits: &mut Bits<'_>, slot: usize) -> Result<u64> {
    let base = *LEN_BASE
        .get(slot)
        .ok_or_else(|| bad("invalid length slot"))?;
    let nbits = LEN_BITS.get(slot).copied().unwrap_or(0);
    Ok(u64::from(base).saturating_add(u64::from(bits.read(nbits.into()))))
}
