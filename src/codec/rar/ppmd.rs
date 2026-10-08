//! PPMd variant H (Dmitry Shkarin's PPMd, as in RAR 2.9 and 7-Zip's
//! `Ppmd7`) with RAR's carry-less range decoder.
//!
//! Organised like 7-Zip's `Ppmd7` (public domain; Dmitry Shkarin's PPMd
//! var. H). `Ppm::init`, the block header reader, was rewritten on
//! 2026-10-08 from the PPMd branch of libarchive's `parse_codes` (BSD-2)
//! after a provenance review found it followed unRAR's code. The model is
//! checked byte for byte against 7-Zip's PPMd encoder (through `pyppmd`,
//! with the 7z range coder: see the tests); RAR PPMd blocks re-encoded
//! from such streams with RAR's coder decode the same in libarchive.
//!
//! The model lives in a heap of 12-byte units addressed by 32-bit offsets.
//! The heap (up to 256 MiB) is allocated in pages as the model touches it,
//! so memory follows what was decoded rather than the size the stream asks
//! for.

use super::bits::Bits;
use crate::error::{Diagnostic, Result};

const UNIT: u32 = 12;
const MAX_FREQ: u32 = 124;
const INT_BITS: u32 = 7;
const PERIOD_BITS: u32 = 7;
const BIN_SCALE: u32 = 1 << (INT_BITS + PERIOD_BITS);
const N_INDEXES: usize = 38;
const MAX_ORDER: usize = 64;
const EXP_ESCAPE: [u8; 16] = [25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2];
const INIT_BIN_ESC: [u16; 8] = [
    0x3cdd, 0x1f3f, 0x59bf, 0x48f3, 0x64a1, 0x5abc, 0x6632, 0x6051,
];
const PAGE_BITS: u32 = 16;
const PAGE: usize = 1 << PAGE_BITS;

/// Range coder operations: (start, size, total).
#[cfg(test)]
pub type Trace = Vec<(u32, u32, u32)>;

/// The heap, allocated in pages on first write.
#[derive(Default)]
struct Mem {
    pages: Vec<Option<Box<[u8]>>>,
}

impl Mem {
    fn reset(&mut self, size: u32) {
        let n = (size >> PAGE_BITS).saturating_add(1) as usize;
        self.pages.clear();
        self.pages.resize_with(n, || None);
    }

    fn r8(&self, a: u32) -> u8 {
        self.pages
            .get((a >> PAGE_BITS) as usize)
            .and_then(Option::as_ref)
            .and_then(|p| p.get((a as usize) & (PAGE - 1)))
            .copied()
            .unwrap_or(0)
    }

    fn w8(&mut self, a: u32, v: u8) {
        if let Some(slot) = self.pages.get_mut((a >> PAGE_BITS) as usize) {
            let page = slot.get_or_insert_with(|| vec![0u8; PAGE].into_boxed_slice());
            if let Some(b) = page.get_mut((a as usize) & (PAGE - 1)) {
                *b = v;
            }
        }
    }

    fn r16(&self, a: u32) -> u32 {
        u32::from(self.r8(a)) | u32::from(self.r8(a.wrapping_add(1))) << 8
    }

    fn w16(&mut self, a: u32, v: u32) {
        self.w8(a, v as u8);
        self.w8(a.wrapping_add(1), (v >> 8) as u8);
    }

    fn r32(&self, a: u32) -> u32 {
        self.r16(a) | self.r16(a.wrapping_add(2)) << 16
    }

    fn w32(&mut self, a: u32, v: u32) {
        self.w16(a, v & 0xffff);
        self.w16(a.wrapping_add(2), v >> 16);
    }

    fn copy(&mut self, dst: u32, src: u32, len: u32) {
        for i in 0..len {
            let b = self.r8(src.wrapping_add(i));
            self.w8(dst.wrapping_add(i), b);
        }
    }
}

/// A state (symbol, frequency, successor) held by value.
#[derive(Clone, Copy, Default)]
struct State {
    symbol: u8,
    freq: u8,
    successor: u32,
}

#[derive(Clone, Copy, Default)]
struct See {
    summ: u16,
    shift: u8,
    count: u8,
}

impl See {
    fn update(&mut self) {
        if u32::from(self.shift) < PERIOD_BITS {
            self.count = self.count.wrapping_sub(1);
            if self.count == 0 {
                self.summ = self.summ.wrapping_mul(2);
                self.count = (3u32 << self.shift.min(7)) as u8;
                self.shift = self.shift.saturating_add(1);
            }
        }
    }
}

/// Which SEE context an escape used.
#[derive(Clone, Copy)]
enum SeeRef {
    Dummy,
    At(usize, usize),
}

/// A PPMd model and its range decoder.
pub struct Ppm {
    mem: Mem,
    size: u32,
    allocated: bool,
    text: u32,
    units_start: u32,
    lo_unit: u32,
    hi_unit: u32,
    glue_count: u32,
    free_list: [u32; N_INDEXES],
    indx2units: [u8; N_INDEXES],
    units2indx: [u8; 128],
    ns2indx: [u8; 256],
    ns2bsindx: [u8; 256],
    hb2flag: [u8; 256],
    min_context: u32,
    max_context: u32,
    found_state: u32,
    order_fall: u32,
    init_esc: u32,
    prev_success: u32,
    max_order: u32,
    hi_bits_flag: u32,
    run_length: i32,
    init_rl: i32,
    see: [[See; 16]; 25],
    dummy_see: See,
    bin_summ: [[u16; 64]; 128],
    low: u32,
    code: u32,
    range: u32,
    /// The total of the last threshold (for traces).
    total: u32,
    /// 7-Zip's range coder instead of RAR's.
    seven: bool,
    trace: Option<Vec<(u32, u32, u32)>>,
}

/// Heap offset of the text area (so that offset 0 is never a valid
/// reference).
const ALIGN: u32 = 4;

fn corrupt() -> Diagnostic {
    Diagnostic::malformed("RAR: corrupt PPMd data")
}

impl Default for Ppm {
    fn default() -> Self {
        Self::new()
    }
}

impl Ppm {
    pub fn new() -> Self {
        let mut indx2units = [0u8; N_INDEXES];
        let mut units2indx = [0u8; 128];
        let mut k = 0usize;
        for (i, slot) in indx2units.iter_mut().enumerate() {
            let step = if i >= 12 {
                4
            } else {
                (i >> 2).saturating_add(1)
            };
            for _ in 0..step {
                if let Some(u) = units2indx.get_mut(k) {
                    *u = i as u8;
                }
                k = k.saturating_add(1);
            }
            *slot = k as u8;
        }
        let mut ns2bsindx = [0u8; 256];
        for (i, v) in ns2bsindx.iter_mut().enumerate() {
            *v = match i {
                0 => 0,
                1 => 2,
                2..=10 => 4,
                _ => 6,
            };
        }
        let mut ns2indx = [0u8; 256];
        let (mut m, mut k, mut step) = (3u32, 1u32, 1u32);
        for (i, v) in ns2indx.iter_mut().enumerate() {
            if i < 3 {
                *v = i as u8;
                continue;
            }
            *v = m as u8;
            k = k.saturating_sub(1);
            if k == 0 {
                step = step.saturating_add(1);
                k = step;
                m = m.saturating_add(1);
            }
        }
        let mut hb2flag = [0u8; 256];
        for (i, v) in hb2flag.iter_mut().enumerate() {
            *v = if i >= 0x40 { 8 } else { 0 };
        }
        Ppm {
            mem: Mem::default(),
            size: 0,
            allocated: false,
            text: 0,
            units_start: 0,
            lo_unit: 0,
            hi_unit: 0,
            glue_count: 0,
            free_list: [0; N_INDEXES],
            indx2units,
            units2indx,
            ns2indx,
            ns2bsindx,
            hb2flag,
            min_context: 0,
            max_context: 0,
            found_state: 0,
            order_fall: 0,
            init_esc: 0,
            prev_success: 0,
            max_order: 0,
            hi_bits_flag: 0,
            run_length: 0,
            init_rl: 0,
            see: [[See::default(); 16]; 25],
            dummy_see: See::default(),
            bin_summ: [[0; 64]; 128],
            low: 0,
            code: 0,
            range: 0,
            total: 0,
            seven: false,
            trace: None,
        }
    }

    // --- Model start-up --------------------------------------------------

    /// Starts a model of `order` in a heap of `size` bytes (7-Zip's
    /// `Ppmd7_Alloc` + `Ppmd7_Init`).
    pub fn start(&mut self, order: u32, size: u32) {
        self.size = size;
        self.mem
            .reset(ALIGN.saturating_add(size).saturating_add(UNIT));
        self.allocated = true;
        self.max_order = order;
        self.restart();
        self.dummy_see = See {
            summ: 0,
            shift: PERIOD_BITS as u8,
            count: 64,
        };
    }

    fn i2u(&self, i: usize) -> u32 {
        u32::from(self.indx2units.get(i).copied().unwrap_or(0))
    }

    fn u2i(&self, nu: u32) -> usize {
        usize::from(
            self.units2indx
                .get((nu as usize).saturating_sub(1))
                .copied()
                .unwrap_or(0),
        )
    }

    fn restart(&mut self) {
        self.mem
            .reset(ALIGN.saturating_add(self.size).saturating_add(UNIT));
        self.free_list = [0; N_INDEXES];
        self.text = ALIGN;
        self.hi_unit = self.text.saturating_add(self.size);
        let units = (self.size / 8 / UNIT).wrapping_mul(7 * UNIT);
        self.lo_unit = self.hi_unit.saturating_sub(units);
        self.units_start = self.lo_unit;
        self.glue_count = 0;
        self.order_fall = self.max_order;
        self.init_rl = (self.max_order.min(12) as i32)
            .wrapping_neg()
            .wrapping_sub(1);
        self.run_length = self.init_rl;
        self.prev_success = 0;
        self.hi_unit = self.hi_unit.saturating_sub(UNIT);
        let mc = self.hi_unit;
        self.min_context = mc;
        self.max_context = mc;
        self.mem.w32(mc.wrapping_add(8), 0);
        self.mem.w16(mc, 256);
        self.mem.w16(mc.wrapping_add(2), 257);
        let stats = self.lo_unit;
        self.found_state = stats;
        self.lo_unit = self.lo_unit.saturating_add(256 / 2 * UNIT);
        self.mem.w32(mc.wrapping_add(4), stats);
        for i in 0..256u32 {
            let s = stats.wrapping_add(i.wrapping_mul(6));
            self.set_state(
                s,
                State {
                    symbol: i as u8,
                    freq: 1,
                    successor: 0,
                },
            );
        }
        for (i, row) in self.bin_summ.iter_mut().enumerate() {
            for (k, &esc) in INIT_BIN_ESC.iter().enumerate() {
                let val = BIN_SCALE.wrapping_sub(
                    u32::from(esc)
                        .checked_div((i as u32).saturating_add(2))
                        .unwrap_or(0),
                ) as u16;
                for m in (0..64).step_by(8) {
                    if let Some(v) = row.get_mut(k.saturating_add(m)) {
                        *v = val;
                    }
                }
            }
        }
        for (i, row) in self.see.iter_mut().enumerate() {
            for s in row.iter_mut() {
                *s = See {
                    summ: ((i as u32).wrapping_mul(5).wrapping_add(10) << (PERIOD_BITS - 4)) as u16,
                    shift: (PERIOD_BITS - 4) as u8,
                    count: 4,
                };
            }
        }
    }

    // --- Heap structures ------------------------------------------------

    fn ns(&self, c: u32) -> u32 {
        self.mem.r16(c)
    }
    fn set_ns(&mut self, c: u32, v: u32) {
        self.mem.w16(c, v);
    }
    fn summ(&self, c: u32) -> u32 {
        self.mem.r16(c.wrapping_add(2))
    }
    fn set_summ(&mut self, c: u32, v: u32) {
        self.mem.w16(c.wrapping_add(2), v);
    }
    fn stats(&self, c: u32) -> u32 {
        self.mem.r32(c.wrapping_add(4))
    }
    fn set_stats(&mut self, c: u32, v: u32) {
        self.mem.w32(c.wrapping_add(4), v);
    }
    fn suffix(&self, c: u32) -> u32 {
        self.mem.r32(c.wrapping_add(8))
    }
    fn one_state(c: u32) -> u32 {
        c.wrapping_add(2)
    }
    fn sym(&self, s: u32) -> u32 {
        u32::from(self.mem.r8(s))
    }
    fn freq(&self, s: u32) -> u32 {
        u32::from(self.mem.r8(s.wrapping_add(1)))
    }
    fn set_freq(&mut self, s: u32, v: u32) {
        self.mem.w8(s.wrapping_add(1), v as u8);
    }
    fn successor(&self, s: u32) -> u32 {
        self.mem.r32(s.wrapping_add(2))
    }
    fn set_successor(&mut self, s: u32, v: u32) {
        self.mem.w32(s.wrapping_add(2), v);
    }
    fn state(&self, s: u32) -> State {
        State {
            symbol: self.mem.r8(s),
            freq: self.mem.r8(s.wrapping_add(1)),
            successor: self.successor(s),
        }
    }
    fn set_state(&mut self, s: u32, v: State) {
        self.mem.w8(s, v.symbol);
        self.mem.w8(s.wrapping_add(1), v.freq);
        self.set_successor(s, v.successor);
    }
    fn swap_states(&mut self, a: u32, b: u32) {
        let (x, y) = (self.state(a), self.state(b));
        self.set_state(a, y);
        self.set_state(b, x);
    }

    // --- Allocator ------------------------------------------------------

    fn insert_node(&mut self, node: u32, indx: usize) {
        let head = self.free_list.get(indx).copied().unwrap_or(0);
        self.mem.w32(node, head);
        if let Some(f) = self.free_list.get_mut(indx) {
            *f = node;
        }
    }

    fn remove_node(&mut self, indx: usize) -> u32 {
        let node = self.free_list.get(indx).copied().unwrap_or(0);
        let next = self.mem.r32(node);
        if let Some(f) = self.free_list.get_mut(indx) {
            *f = next;
        }
        node
    }

    fn split_block(&mut self, ptr: u32, old: usize, new: usize) {
        let nu = self.i2u(old).saturating_sub(self.i2u(new));
        let ptr = ptr.wrapping_add(self.i2u(new).wrapping_mul(UNIT));
        let mut i = self.u2i(nu);
        if self.i2u(i) != nu {
            i = i.saturating_sub(1);
            let k = self.i2u(i);
            self.insert_node(
                ptr.wrapping_add(k.wrapping_mul(UNIT)),
                nu.saturating_sub(k).saturating_sub(1) as usize,
            );
        }
        self.insert_node(ptr, i);
    }

    fn glue_free_blocks(&mut self) {
        // Nodes: stamp (u16, 0 = free), units (u16), next, prev (u32).
        let head = ALIGN.saturating_add(self.size);
        let mut n = head;
        self.glue_count = 255;
        for i in 0..N_INDEXES {
            let nu = self.i2u(i);
            let mut next = self.free_list.get(i).copied().unwrap_or(0);
            if let Some(f) = self.free_list.get_mut(i) {
                *f = 0;
            }
            let mut guard = 0u32;
            while next != 0 && guard < (1 << 25) {
                guard = guard.saturating_add(1);
                let node = next;
                let after = self.mem.r32(node);
                self.mem.w32(node.wrapping_add(4), n);
                self.mem.w32(n.wrapping_add(8), next);
                n = next;
                next = after;
                self.mem.w16(node, 0);
                self.mem.w16(node.wrapping_add(2), nu);
            }
        }
        self.mem.w16(head, 1);
        self.mem.w32(head.wrapping_add(4), n);
        self.mem.w32(n.wrapping_add(8), head);
        if self.lo_unit != self.hi_unit {
            self.mem.w16(self.lo_unit, 1);
        }
        // Glue adjacent free blocks.
        let mut guard = 0u32;
        while n != head && guard < (1 << 25) {
            guard = guard.saturating_add(1);
            let node = n;
            let mut nu = self.mem.r16(node.wrapping_add(2));
            loop {
                let node2 = node.wrapping_add(nu.wrapping_mul(UNIT));
                nu = nu.wrapping_add(self.mem.r16(node2.wrapping_add(2)));
                if self.mem.r16(node2) != 0 || nu >= 0x10000 {
                    break;
                }
                let prev2 = self.mem.r32(node2.wrapping_add(8));
                let next2 = self.mem.r32(node2.wrapping_add(4));
                self.mem.w32(prev2.wrapping_add(4), next2);
                self.mem.w32(next2.wrapping_add(8), prev2);
                self.mem.w16(node.wrapping_add(2), nu);
            }
            n = self.mem.r32(node.wrapping_add(4));
        }
        // Refill the free lists.
        n = self.mem.r32(head.wrapping_add(4));
        guard = 0;
        while n != head && guard < (1 << 25) {
            guard = guard.saturating_add(1);
            let mut node = n;
            let next = self.mem.r32(node.wrapping_add(4));
            let mut nu = self.mem.r16(node.wrapping_add(2));
            while nu > 128 {
                self.insert_node(node, N_INDEXES - 1);
                nu = nu.saturating_sub(128);
                node = node.wrapping_add(128 * UNIT);
            }
            let mut i = self.u2i(nu);
            if self.i2u(i) != nu {
                i = i.saturating_sub(1);
                let k = self.i2u(i);
                self.insert_node(
                    node.wrapping_add(k.wrapping_mul(UNIT)),
                    nu.saturating_sub(k).saturating_sub(1) as usize,
                );
            }
            self.insert_node(node, i);
            n = next;
        }
    }

    fn alloc_units_rare(&mut self, indx: usize) -> Option<u32> {
        if self.glue_count == 0 {
            self.glue_free_blocks();
            if self.free_list.get(indx).copied().unwrap_or(0) != 0 {
                return Some(self.remove_node(indx));
            }
        }
        let mut i = indx;
        loop {
            i = i.saturating_add(1);
            if i >= N_INDEXES {
                let bytes = self.i2u(indx).wrapping_mul(UNIT);
                self.glue_count = self.glue_count.saturating_sub(1);
                return if self.units_start.saturating_sub(self.text) > bytes {
                    self.units_start = self.units_start.saturating_sub(bytes);
                    Some(self.units_start)
                } else {
                    None
                };
            }
            if self.free_list.get(i).copied().unwrap_or(0) != 0 {
                break;
            }
        }
        let r = self.remove_node(i);
        self.split_block(r, i, indx);
        Some(r)
    }

    fn alloc_units(&mut self, indx: usize) -> Option<u32> {
        if self.free_list.get(indx).copied().unwrap_or(0) != 0 {
            return Some(self.remove_node(indx));
        }
        let bytes = self.i2u(indx).wrapping_mul(UNIT);
        if bytes <= self.hi_unit.saturating_sub(self.lo_unit) {
            let r = self.lo_unit;
            self.lo_unit = self.lo_unit.saturating_add(bytes);
            return Some(r);
        }
        self.alloc_units_rare(indx)
    }

    fn alloc_context(&mut self) -> Option<u32> {
        if self.hi_unit != self.lo_unit {
            self.hi_unit = self.hi_unit.saturating_sub(UNIT);
            Some(self.hi_unit)
        } else if self.free_list[0] != 0 {
            Some(self.remove_node(0))
        } else {
            self.alloc_units_rare(0)
        }
    }

    fn shrink_units(&mut self, old: u32, old_nu: u32, new_nu: u32) -> u32 {
        let i0 = self.u2i(old_nu);
        let i1 = self.u2i(new_nu);
        if i0 == i1 {
            return old;
        }
        if self.free_list.get(i1).copied().unwrap_or(0) != 0 {
            let ptr = self.remove_node(i1);
            self.mem.copy(ptr, old, new_nu.wrapping_mul(UNIT));
            self.insert_node(old, i0);
            return ptr;
        }
        self.split_block(old, i0, i1);
        old
    }

    // --- Model update ---------------------------------------------------

    /// Finds the state of `symbol` in context `c`.
    fn find(&self, c: u32, symbol: u32) -> Option<u32> {
        if self.ns(c) == 1 {
            return Some(Self::one_state(c));
        }
        let stats = self.stats(c);
        (0..self.ns(c).min(256))
            .map(|i| stats.wrapping_add(i.wrapping_mul(6)))
            .find(|&s| self.sym(s) == symbol)
    }

    fn create_successors(&mut self, skip: bool) -> Option<u32> {
        let mut c = self.min_context;
        let fs = self.found_state;
        let up_branch = self.successor(fs);
        let fsym = self.sym(fs);
        let mut ps = [0u32; MAX_ORDER];
        let mut num = 0usize;
        if !skip {
            ps[0] = fs;
            num = 1;
        }
        while self.suffix(c) != 0 {
            c = self.suffix(c);
            let s = self.find(c, fsym)?;
            let succ = self.successor(s);
            if succ != up_branch {
                c = succ;
                if num == 0 {
                    return Some(c);
                }
                break;
            }
            *ps.get_mut(num)? = s;
            num = num.saturating_add(1);
        }
        let up_sym = self.mem.r8(up_branch);
        let up_freq = if self.ns(c) == 1 {
            self.freq(Self::one_state(c))
        } else {
            let s = self.find(c, u32::from(up_sym))?;
            let cf = self.freq(s).wrapping_sub(1);
            let s0 = self.summ(c).wrapping_sub(self.ns(c)).wrapping_sub(cf);
            let v = if cf.wrapping_mul(2) <= s0 {
                u32::from(cf.wrapping_mul(5) > s0)
            } else {
                cf.wrapping_mul(2)
                    .wrapping_add(s0.wrapping_mul(3))
                    .wrapping_sub(1)
                    .checked_div(s0.wrapping_mul(2))
                    .unwrap_or(0)
            };
            v.wrapping_add(1)
        };
        let up = State {
            symbol: up_sym,
            freq: up_freq as u8,
            successor: up_branch.wrapping_add(1),
        };
        while num > 0 {
            let c1 = self.alloc_context()?;
            self.set_ns(c1, 1);
            self.set_state(Self::one_state(c1), up);
            self.mem.w32(c1.wrapping_add(8), c);
            num = num.saturating_sub(1);
            let s = *ps.get(num)?;
            self.set_successor(s, c1);
            c = c1;
        }
        Some(c)
    }

    fn update_model(&mut self) {
        if self.update_model_inner().is_none() {
            self.restart();
        }
    }

    fn update_model_inner(&mut self) -> Option<()> {
        let fs = self.state(self.found_state);
        let fsym = u32::from(fs.symbol);
        let ffreq = u32::from(fs.freq);
        let mut f_successor = fs.successor;
        let mc = self.min_context;
        if ffreq < MAX_FREQ / 4 && self.suffix(mc) != 0 {
            let c = self.suffix(mc);
            if self.ns(c) == 1 {
                let s = Self::one_state(c);
                if self.freq(s) < 32 {
                    self.set_freq(s, self.freq(s).wrapping_add(1));
                }
            } else {
                let stats = self.stats(c);
                let mut s = self.find(c, fsym)?;
                if s != stats {
                    let prev = s.wrapping_sub(6);
                    if self.freq(s) >= self.freq(prev) {
                        self.swap_states(s, prev);
                        s = prev;
                    }
                }
                if self.freq(s) < MAX_FREQ - 9 {
                    self.set_freq(s, self.freq(s).wrapping_add(2));
                    self.set_summ(c, self.summ(c).wrapping_add(2));
                }
            }
        }
        if self.order_fall == 0 {
            let c = self.create_successors(true)?;
            self.min_context = c;
            self.max_context = c;
            self.set_successor(self.found_state, c);
            return Some(());
        }
        self.mem.w8(self.text, fs.symbol);
        self.text = self.text.wrapping_add(1);
        let mut successor = self.text;
        if self.text >= self.units_start {
            return None;
        }
        if f_successor != 0 {
            if f_successor <= successor {
                f_successor = self.create_successors(false)?;
            }
            self.order_fall = self.order_fall.wrapping_sub(1);
            if self.order_fall == 0 {
                successor = f_successor;
                if self.max_context != self.min_context {
                    self.text = self.text.wrapping_sub(1);
                }
            }
        } else {
            self.set_successor(self.found_state, successor);
            f_successor = self.min_context;
        }
        let ns = self.ns(mc);
        let s0 = self
            .summ(mc)
            .wrapping_sub(ns)
            .wrapping_sub(ffreq.wrapping_sub(1));
        let mut c = self.max_context;
        let mut guard = 0usize;
        while c != mc {
            guard = guard.saturating_add(1);
            if guard > 4 * MAX_ORDER {
                return None;
            }
            let ns1 = self.ns(c);
            if ns1 != 1 {
                if ns1 & 1 == 0 {
                    let old_nu = ns1 >> 1;
                    let i = self.u2i(old_nu);
                    if i != self.u2i(old_nu.wrapping_add(1)) {
                        let ptr = self.alloc_units(i.saturating_add(1))?;
                        let old = self.stats(c);
                        self.mem.copy(ptr, old, old_nu.wrapping_mul(UNIT));
                        self.insert_node(old, i);
                        self.set_stats(c, ptr);
                    }
                }
                let summ = self.summ(c);
                let add = u32::from(ns1.wrapping_mul(2) < ns)
                    | u32::from(ns1.wrapping_mul(4) <= ns && summ <= ns1.wrapping_mul(8)) << 1;
                self.set_summ(c, summ.wrapping_add(add));
            } else {
                let s = self.alloc_units(0)?;
                let mut st = self.state(Self::one_state(c));
                self.set_stats(c, s);
                let f = u32::from(st.freq);
                st.freq = if f < MAX_FREQ / 4 - 1 {
                    (f * 2) as u8
                } else {
                    (MAX_FREQ - 4) as u8
                };
                self.set_state(s, st);
                self.set_summ(
                    c,
                    u32::from(st.freq)
                        .wrapping_add(self.init_esc)
                        .wrapping_add(u32::from(ns > 3)),
                );
            }
            let summ = self.summ(c);
            let mut cf = ffreq.wrapping_mul(2).wrapping_mul(summ.wrapping_add(6));
            let sf = s0.wrapping_add(summ);
            if cf < sf.wrapping_mul(6) {
                cf = 1u32
                    .wrapping_add(u32::from(cf > sf))
                    .wrapping_add(u32::from(cf >= sf.wrapping_mul(4)));
                self.set_summ(c, summ.wrapping_add(3));
            } else {
                cf = 4u32
                    .wrapping_add(u32::from(cf >= sf.wrapping_mul(9)))
                    .wrapping_add(u32::from(cf >= sf.wrapping_mul(12)))
                    .wrapping_add(u32::from(cf >= sf.wrapping_mul(15)));
                self.set_summ(c, summ.wrapping_add(cf));
            }
            let s = self.stats(c).wrapping_add(ns1.wrapping_mul(6));
            self.set_state(
                s,
                State {
                    symbol: fs.symbol,
                    freq: cf as u8,
                    successor,
                },
            );
            self.set_ns(c, ns1.wrapping_add(1));
            c = self.suffix(c);
        }
        self.max_context = f_successor;
        self.min_context = f_successor;
        Some(())
    }

    fn rescale(&mut self) {
        let mc = self.min_context;
        let stats = self.stats(mc);
        let mut s = self.found_state;
        // Move the found state to the front.
        let tmp = self.state(s);
        let mut guard = 0u32;
        while s != stats && guard < 256 {
            guard = guard.saturating_add(1);
            let prev = self.state(s.wrapping_sub(6));
            self.set_state(s, prev);
            s = s.wrapping_sub(6);
        }
        self.set_state(s, tmp);
        let num_stats = self.ns(mc);
        let mut esc_freq = self.summ(mc).wrapping_sub(self.freq(s));
        let adder = u32::from(self.order_fall != 0);
        let f = self.freq(s).wrapping_add(4).wrapping_add(adder) >> 1;
        self.set_freq(s, f);
        let mut sum_freq = f;
        let mut i = num_stats.wrapping_sub(1).min(255);
        while i > 0 {
            s = s.wrapping_add(6);
            esc_freq = esc_freq.wrapping_sub(self.freq(s));
            let f = self.freq(s).wrapping_add(adder) >> 1;
            self.set_freq(s, f);
            sum_freq = sum_freq.wrapping_add(f);
            if f > self.freq(s.wrapping_sub(6)) {
                let tmp = self.state(s);
                let mut s1 = s;
                loop {
                    let prev = self.state(s1.wrapping_sub(6));
                    self.set_state(s1, prev);
                    s1 = s1.wrapping_sub(6);
                    if s1 == stats || u32::from(tmp.freq) <= self.freq(s1.wrapping_sub(6)) {
                        break;
                    }
                }
                self.set_state(s1, tmp);
            }
            i = i.saturating_sub(1);
        }
        if self.freq(s) == 0 {
            let mut i = 0u32;
            loop {
                i = i.wrapping_add(1);
                s = s.wrapping_sub(6);
                if self.freq(s) != 0 || s == stats {
                    break;
                }
            }
            esc_freq = esc_freq.wrapping_add(i);
            let new_ns = num_stats.wrapping_sub(i);
            self.set_ns(mc, new_ns);
            if new_ns == 1 {
                let mut tmp = self.state(stats);
                loop {
                    tmp.freq = tmp.freq.wrapping_sub(tmp.freq >> 1);
                    esc_freq >>= 1;
                    if esc_freq <= 1 {
                        break;
                    }
                }
                let idx = self.u2i((num_stats.wrapping_add(1)) >> 1);
                self.insert_node(stats, idx);
                self.found_state = Self::one_state(mc);
                self.set_state(self.found_state, tmp);
                return;
            }
            let n0 = (num_stats.wrapping_add(1)) >> 1;
            let n1 = (new_ns.wrapping_add(1)) >> 1;
            if n0 != n1 {
                let ns = self.shrink_units(stats, n0, n1);
                self.set_stats(mc, ns);
            }
        }
        self.set_summ(
            mc,
            sum_freq.wrapping_add(esc_freq).wrapping_sub(esc_freq >> 1),
        );
        self.found_state = self.stats(mc);
    }

    fn next_context(&mut self) {
        let c = self.successor(self.found_state);
        if self.order_fall == 0 && c > self.text {
            self.min_context = c;
            self.max_context = c;
        } else {
            self.update_model();
        }
    }

    fn make_esc_freq(&mut self, num_masked: u32) -> (SeeRef, u32) {
        let mc = self.min_context;
        let ns = self.ns(mc);
        if ns == 256 {
            return (SeeRef::Dummy, 1);
        }
        let diff = ns.wrapping_sub(num_masked);
        let i = usize::from(
            self.ns2indx
                .get((diff as usize).wrapping_sub(1) & 0xff)
                .copied()
                .unwrap_or(0),
        );
        let suffix_ns = i64::from(self.ns(self.suffix(mc)));
        let k = usize::from(i64::from(diff) < suffix_ns.wrapping_sub(i64::from(ns)))
            | usize::from(self.summ(mc) < ns.wrapping_mul(11)) << 1
            | usize::from(num_masked > diff) << 2
            | self.hi_bits_flag as usize;
        let Some(see) = self.see.get_mut(i).and_then(|r| r.get_mut(k)) else {
            return (SeeRef::Dummy, 1);
        };
        let r = u32::from(see.summ) >> see.shift.min(15);
        see.summ = see.summ.wrapping_sub(r as u16);
        (SeeRef::At(i, k), r.wrapping_add(u32::from(r == 0)))
    }

    fn see_mut(&mut self, r: SeeRef) -> &mut See {
        match r {
            SeeRef::Dummy => &mut self.dummy_see,
            SeeRef::At(i, k) => self
                .see
                .get_mut(i)
                .and_then(|row| row.get_mut(k))
                .unwrap_or(&mut self.dummy_see),
        }
    }

    // --- Decoding -------------------------------------------------------

    /// Reads the parameters of a PPMd block and starts its range decoder,
    /// following the PPMd branch of libarchive's `parse_codes`.
    ///
    /// The flags byte (its top bit is the PPMd marker the caller peeked)
    /// says whether a memory size follows (0x20, which also restarts the
    /// model with a fresh allocator) and whether a new escape symbol
    /// follows (0x40); its low five bits give the model order. A block
    /// without 0x20 continues the current model, and is rejected when no
    /// model has been started ("Invalid PPMd sequence" in libarchive).
    /// Like libarchive, an order of 1 is rejected, leaving any earlier
    /// model as it was, and the range decoder's first four bytes must not
    /// all be 0xff (the code has to lie below the initial range).
    pub fn init(&mut self, bits: &mut Bits<'_>, esc: &mut u8) -> Result<()> {
        let flags = bits.get_byte();
        let restart = flags & 0x20 != 0;
        // Memory is given in MiB, less one; it is never zero.
        let size = if restart {
            u32::from(bits.get_byte()).wrapping_add(1) << 20
        } else {
            0
        };
        if flags & 0x40 != 0 {
            *esc = bits.get_byte();
        }
        if restart {
            let mut order = u32::from(flags & 0x1f).wrapping_add(1);
            if order > 16 {
                order = order.wrapping_sub(16).wrapping_mul(3).wrapping_add(16);
            }
            if order == 1 {
                return Err(corrupt());
            }
            // 7-Zip's `Ppmd7_Alloc` + `Ppmd7_Init`.
            self.start(order, size);
        } else if !self.allocated {
            return Err(corrupt());
        }
        // The range decoder (libarchive's `PpmdRAR_RangeDec_Init`).
        self.low = 0;
        self.range = u32::MAX;
        self.code = 0;
        for _ in 0..4 {
            self.code = self.code << 8 | u32::from(bits.get_byte());
        }
        if self.code == u32::MAX {
            return Err(corrupt());
        }
        Ok(())
    }

    fn normalize(&mut self, bits: &mut Bits<'_>) {
        const TOP: u32 = 1 << 24;
        const BOT: u32 = 1 << 15;
        if self.seven {
            while self.range < TOP {
                self.code = self.code << 8 | u32::from(bits.get_byte());
                self.range <<= 8;
            }
            return;
        }
        loop {
            if (self.low ^ self.low.wrapping_add(self.range)) >= TOP {
                if self.range >= BOT {
                    break;
                }
                self.range = self.low.wrapping_neg() & (BOT - 1);
            }
            self.code = self.code << 8 | u32::from(bits.get_byte());
            self.range <<= 8;
            self.low <<= 8;
        }
    }

    /// `(code - low) / (range /= total)`.
    fn threshold(&mut self, total: u32) -> Option<u32> {
        self.total = total;
        self.range = self.range.checked_div(total)?;
        self.code.wrapping_sub(self.low).checked_div(self.range)
    }

    fn decode(&mut self, bits: &mut Bits<'_>, start: u32, size: u32) {
        if let Some(t) = self.trace.as_mut() {
            t.push((start, size, self.total));
        }
        if self.seven {
            self.code = self.code.wrapping_sub(self.range.wrapping_mul(start));
        } else {
            self.low = self.low.wrapping_add(self.range.wrapping_mul(start));
        }
        self.range = self.range.wrapping_mul(size);
        self.normalize(bits);
    }

    /// A binary context's bit with probability `bs` / `BIN_SCALE` for 0;
    /// `Some(true)` for symbol 0.
    fn bin(&mut self, bits: &mut Bits<'_>, bs: u32) -> Option<bool> {
        if self.seven {
            let bound = (self.range >> (INT_BITS + PERIOD_BITS)).wrapping_mul(bs);
            let zero = self.code < bound;
            if let Some(t) = self.trace.as_mut() {
                t.push(if zero {
                    (0, bs, BIN_SCALE)
                } else {
                    (bs, BIN_SCALE.wrapping_sub(bs), BIN_SCALE)
                });
            }
            if zero {
                self.range = bound;
            } else {
                self.code = self.code.wrapping_sub(bound);
                self.range = self.range.wrapping_sub(bound);
            }
            self.normalize(bits);
            return Some(zero);
        }
        self.range >>= INT_BITS + PERIOD_BITS;
        self.total = BIN_SCALE;
        let count = self.code.wrapping_sub(self.low).checked_div(self.range)?;
        let zero = count < bs;
        if zero {
            self.decode(bits, 0, bs);
        } else {
            self.decode(bits, bs, BIN_SCALE.wrapping_sub(bs));
        }
        Some(zero)
    }

    /// Decodes `n` bytes of a 7z-style PPMd stream (7-Zip's range coder),
    /// for checking the model against 7-Zip's encoder. With `trace`, also
    /// returns the coder operations (start, size, total), which re-encoded
    /// with RAR's coder give a RAR stream of the same symbols.
    #[cfg(test)]
    pub fn decode_7z(
        data: &[u8],
        order: u32,
        mem: u32,
        n: usize,
        trace: bool,
    ) -> Option<(Vec<u8>, Trace)> {
        let mut p = Ppm::new();
        p.seven = true;
        p.trace = trace.then(Vec::new);
        let mut bits = Bits {
            data,
            base: 0,
            pos: 0,
        };
        if bits.get_byte() != 0 {
            return None;
        }
        p.range = u32::MAX;
        for _ in 0..4 {
            p.code = p.code << 8 | u32::from(bits.get_byte());
        }
        p.start(order, mem);
        let mut out = Vec::with_capacity(n.min(1 << 24));
        for _ in 0..n {
            out.push(p.decode_char(&mut bits)?);
        }
        Some((out, p.trace.unwrap_or_default()))
    }

    fn valid_context(&self, c: u32) -> bool {
        c > self.text && c < ALIGN.saturating_add(self.size)
    }

    /// Decodes one byte; `None` on corrupt data.
    pub fn decode_char(&mut self, bits: &mut Bits<'_>) -> Option<u8> {
        if !self.allocated || !self.valid_context(self.min_context) {
            return None;
        }
        let mut mask = [true; 256];
        let mut num_masked;
        let mc = self.min_context;
        let ns = self.ns(mc);
        if ns != 1 {
            let stats = self.stats(mc);
            if !self.valid_context(stats) || ns > 256 {
                return None;
            }
            let summ = self.summ(mc);
            let count = self.threshold(summ)?;
            if count >= summ {
                return None;
            }
            let mut s = stats;
            let mut hi = self.freq(s);
            if count < hi {
                self.decode(bits, 0, hi);
                self.found_state = s;
                let symbol = self.mem.r8(s);
                // Update1_0.
                self.prev_success = u32::from(hi.wrapping_mul(2) > summ);
                self.run_length = self.run_length.wrapping_add(self.prev_success as i32);
                self.set_summ(mc, summ.wrapping_add(4));
                self.set_freq(s, hi.wrapping_add(4));
                if hi.wrapping_add(4) > MAX_FREQ {
                    self.rescale();
                }
                self.next_context();
                return Some(symbol);
            }
            self.prev_success = 0;
            for _ in 1..ns {
                s = s.wrapping_add(6);
                let f = self.freq(s);
                hi = hi.wrapping_add(f);
                if hi > count {
                    self.decode(bits, hi.wrapping_sub(f), f);
                    self.found_state = s;
                    let symbol = self.mem.r8(s);
                    // Update1.
                    self.set_freq(s, f.wrapping_add(4));
                    self.set_summ(mc, summ.wrapping_add(4));
                    let prev = s.wrapping_sub(6);
                    if self.freq(s) > self.freq(prev) {
                        self.swap_states(s, prev);
                        self.found_state = prev;
                        if self.freq(prev) > MAX_FREQ {
                            self.rescale();
                        }
                    }
                    self.next_context();
                    return Some(symbol);
                }
            }
            self.hi_bits_flag = u32::from(
                self.hb2flag
                    .get(self.sym(self.found_state) as usize)
                    .copied()
                    .unwrap_or(0),
            );
            self.decode(bits, hi, summ.wrapping_sub(hi));
            for k in 0..ns {
                let sym = self.sym(stats.wrapping_add(k.wrapping_mul(6)));
                if let Some(m) = mask.get_mut(sym as usize) {
                    *m = false;
                }
            }
            num_masked = ns;
        } else {
            let rs = Self::one_state(mc);
            let rs_freq = self.freq(rs);
            let rs_sym = self.sym(rs);
            self.hi_bits_flag = u32::from(
                self.hb2flag
                    .get(self.sym(self.found_state) as usize)
                    .copied()
                    .unwrap_or(0),
            );
            let suffix_ns = self.ns(self.suffix(mc));
            let i = (rs_freq as usize).wrapping_sub(1) & 0x7f;
            let bs_index = usize::from(
                self.ns2bsindx
                    .get((suffix_ns as usize).wrapping_sub(1) & 0xff)
                    .copied()
                    .unwrap_or(0),
            );
            let k = (self.prev_success as usize)
                .wrapping_add(bs_index)
                .wrapping_add(self.hi_bits_flag as usize)
                .wrapping_add(
                    usize::from(self.hb2flag.get(rs_sym as usize).copied().unwrap_or(0)) << 1,
                )
                .wrapping_add(((self.run_length >> 26) & 0x20) as usize);
            let bs = u32::from(
                self.bin_summ
                    .get(i)
                    .and_then(|r| r.get(k & 63))
                    .copied()
                    .unwrap_or(0),
            );
            let mean = (bs + (1 << (PERIOD_BITS - 2))) >> PERIOD_BITS;
            if self.bin(bits, bs)? {
                let nbs = bs.wrapping_add(1 << INT_BITS).wrapping_sub(mean);
                if let Some(v) = self.bin_summ.get_mut(i).and_then(|r| r.get_mut(k & 63)) {
                    *v = nbs as u16;
                }
                self.found_state = rs;
                self.set_freq(rs, rs_freq.wrapping_add(u32::from(rs_freq < 128)));
                self.prev_success = 1;
                self.run_length = self.run_length.wrapping_add(1);
                self.next_context();
                return Some(rs_sym as u8);
            }
            let nbs = bs.wrapping_sub(mean);
            if let Some(v) = self.bin_summ.get_mut(i).and_then(|r| r.get_mut(k & 63)) {
                *v = nbs as u16;
            }
            self.init_esc = u32::from(
                EXP_ESCAPE
                    .get((nbs >> 10) as usize & 15)
                    .copied()
                    .unwrap_or(0),
            );
            if let Some(m) = mask.get_mut(rs_sym as usize) {
                *m = false;
            }
            num_masked = 1;
            self.prev_success = 0;
        }
        let mut ps = [0u32; 256];
        loop {
            let mut c = self.min_context;
            let mut depth = 0usize;
            loop {
                self.order_fall = self.order_fall.wrapping_add(1);
                c = self.suffix(c);
                depth = depth.saturating_add(1);
                if !self.valid_context(c) || depth > 4 * MAX_ORDER {
                    return None;
                }
                if self.ns(c) != num_masked {
                    break;
                }
            }
            self.min_context = c;
            let ns = self.ns(c);
            if ns > 256 || ns < num_masked {
                return None;
            }
            let stats = self.stats(c);
            let (see, esc_freq) = self.make_esc_freq(num_masked);
            let want = ns.wrapping_sub(num_masked) as usize;
            let mut hi = 0u32;
            let mut n = 0usize;
            for k in 0..ns {
                if n >= want {
                    break;
                }
                let s = stats.wrapping_add(k.wrapping_mul(6));
                if mask.get(self.sym(s) as usize).copied().unwrap_or(false) {
                    hi = hi.wrapping_add(self.freq(s));
                    if let Some(p) = ps.get_mut(n) {
                        *p = s;
                    }
                    n = n.saturating_add(1);
                }
            }
            let total = esc_freq.wrapping_add(hi);
            let count = self.threshold(total)?;
            if count >= total {
                return None;
            }
            if count < hi {
                let mut acc = 0u32;
                let mut found = 0u32;
                for &s in ps.iter().take(n) {
                    acc = acc.wrapping_add(self.freq(s));
                    if acc > count {
                        found = s;
                        break;
                    }
                }
                let f = self.freq(found);
                self.decode(bits, acc.wrapping_sub(f), f);
                self.see_mut(see).update();
                self.found_state = found;
                let symbol = self.mem.r8(found);
                // Update2.
                self.set_freq(found, f.wrapping_add(4));
                self.set_summ(c, self.summ(c).wrapping_add(4));
                if f.wrapping_add(4) > MAX_FREQ {
                    self.rescale();
                }
                self.run_length = self.init_rl;
                self.next_context();
                return Some(symbol);
            }
            self.decode(bits, hi, total.wrapping_sub(hi));
            let s = self.see_mut(see);
            s.summ = s.summ.wrapping_add(total as u16);
            for &s in ps.iter().take(n) {
                let sym = self.sym(s);
                if let Some(m) = mask.get_mut(sym as usize) {
                    *m = false;
                }
            }
            num_masked = ns;
        }
    }
}
