//! PPMd variant I, revision 1 (Dmitry Shkarin's PPMd var. I), as ZIP's
//! compression method 98 stores it.
//!
//! Organised like `Ppmd8.c`/`Ppmd8Dec.c` of Igor Pavlov's LZMA SDK (public
//! domain), which implements Shkarin's var. I rev. 1 for 7-Zip's ZIP
//! support; see `THIRD-PARTY.md`. It differs from variant H (`rar::ppmd`)
//! in the context layout (a symbol-count byte and a flags byte that index
//! the SEE and binary tables), in the update rules, and in what happens
//! when the model's memory runs out: restart from scratch (restoration
//! method 0) or cut the model down to its recently used part (method 1;
//! method 2, freezing, is not supported, as in 7-Zip). The range coder is
//! the carry-less one of Shkarin's PPMd (a 4-byte code, no leading byte).
//!
//! A ZIP entry's data starts with a 16-bit little-endian word: model order
//! less one (bits 0-3), memory size in MiB less one (bits 4-11) and the
//! restoration method (bits 12-15). The decoder stops after the entry's
//! recorded size, and reads the end marker 7-Zip writes after it if one
//! is there.
//!
//! Checked byte for byte against 7-Zip's own Ppmd8 encoder (through
//! pyppmd), including runs that exhaust a small memory and restart or cut
//! the model off, and against `7zz a -tzip -mm=PPMd` (the `zip/ppmd.zip`
//! fixture).
//!
//! The model lives in a heap of 12-byte units addressed by 32-bit offsets
//! (allocated in pages as the model touches it, see `rar::PpmdMem`).
//! Rebuilding the model when memory runs out walks it once, so that step
//! is bounded by the memory size (at most 256 MiB) rather than a constant.

use super::pipeline::{Decoder, Status};
use super::rar::PpmdMem as Mem;
use crate::error::{Diagnostic, Result};

const UNIT: u32 = 12;
const MAX_FREQ: u32 = 124;
const INT_BITS: u32 = 7;
const PERIOD_BITS: u32 = 7;
const BIN_SCALE: u32 = 1 << (INT_BITS + PERIOD_BITS);
const N_INDEXES: usize = 38;
const MIN_ORDER: u32 = 2;
const MAX_ORDER: u32 = 16;
const EMPTY_NODE: u32 = 0xffff_ffff;
const EXP_ESCAPE: [u8; 16] = [25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2];
const INIT_BIN_ESC: [u16; 8] = [
    0x3cdd, 0x1f3f, 0x59bf, 0x48f3, 0x64a1, 0x5abc, 0x6632, 0x6051,
];
/// Restoration methods.
const RESTART: u32 = 0;
const CUT_OFF: u32 = 1;
/// Input the decoder keeps unread before decoding a symbol, unless the
/// input has ended: more than one symbol can use (each of at most 17
/// coder operations reads at most 6 bytes).
const MARGIN: usize = 256;
/// Symbols decoded per call at most.
const BATCH: usize = 4096;

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

/// The input of the range decoder: bytes past the end read as zeros, and
/// `pos` then runs past `data.len()`.
struct In<'a> {
    data: &'a [u8],
    pos: usize,
}

impl In<'_> {
    fn byte(&mut self) -> u8 {
        let b = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos = self.pos.saturating_add(1);
        b
    }
}

/// The result of decoding one symbol.
enum Sym {
    Byte(u8),
    /// An escape from the order -1 context: the end marker.
    End,
}

/// A PPMd var. I model and its range decoder (7-Zip's `CPpmd8`).
#[derive(Clone)]
struct Model {
    mem: Mem,
    size: u32,
    align: u32,
    text: u32,
    units_start: u32,
    lo_unit: u32,
    hi_unit: u32,
    glue_count: u32,
    free_list: [u32; N_INDEXES],
    stamps: [u32; N_INDEXES],
    indx2units: [u8; N_INDEXES],
    units2indx: [u8; 128],
    ns2indx: [u8; 260],
    ns2bsindx: [u8; 256],
    min_context: u32,
    max_context: u32,
    found_state: u32,
    order_fall: u32,
    init_esc: u32,
    prev_success: u32,
    max_order: u32,
    restore_method: u32,
    run_length: i32,
    init_rl: i32,
    see: [[See; 32]; 24],
    dummy_see: See,
    bin_summ: [[u16; 64]; 25],
    low: u32,
    code: u32,
    range: u32,
}

fn corrupt() -> Diagnostic {
    Diagnostic::malformed("PPMd: corrupt data")
}

impl Model {
    /// `Ppmd8_Construct`, `Ppmd8_Alloc` and `Ppmd8_Init`.
    fn new(order: u32, size: u32, restore_method: u32) -> Self {
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
        let mut ns2indx = [0u8; 260];
        let (mut m, mut k) = (5u32, 1u32);
        for (i, v) in ns2indx.iter_mut().enumerate() {
            if i < 5 {
                *v = i as u8;
                continue;
            }
            *v = m as u8;
            k = k.saturating_sub(1);
            if k == 0 {
                m = m.saturating_add(1);
                k = m.saturating_sub(4);
            }
        }
        let align = 4u32.wrapping_sub(size & 3);
        let mut p = Model {
            mem: Mem::default(),
            size,
            align,
            text: 0,
            units_start: 0,
            lo_unit: 0,
            hi_unit: 0,
            glue_count: 0,
            free_list: [0; N_INDEXES],
            stamps: [0; N_INDEXES],
            indx2units,
            units2indx,
            ns2indx,
            ns2bsindx,
            min_context: 0,
            max_context: 0,
            found_state: 0,
            order_fall: 0,
            init_esc: 0,
            prev_success: 0,
            max_order: order,
            restore_method,
            run_length: 0,
            init_rl: 0,
            see: [[See::default(); 32]; 24],
            dummy_see: See {
                summ: 0,
                shift: PERIOD_BITS as u8,
                count: 64,
            },
            bin_summ: [[0; 64]; 25],
            low: 0,
            code: 0,
            range: 0,
        };
        p.restart();
        p
    }

    fn heap_size(&self) -> usize {
        self.mem.heap_size()
    }

    fn i2u(&self, i: usize) -> u32 {
        u32::from(self.indx2units.get(i).copied().unwrap_or(0))
    }

    fn u2i(&self, nu: u32) -> usize {
        usize::from(
            self.units2indx
                .get((nu as usize).wrapping_sub(1))
                .copied()
                .unwrap_or(0),
        )
    }

    fn ns2indx(&self, i: u32) -> u32 {
        u32::from(self.ns2indx.get(i as usize).copied().unwrap_or(0))
    }

    /// `RestartModel`.
    fn restart(&mut self) {
        self.mem.reset(self.align.saturating_add(self.size));
        self.free_list = [0; N_INDEXES];
        self.stamps = [0; N_INDEXES];
        self.text = self.align;
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
        self.set_suffix(mc, 0);
        self.set_num_stats(mc, 255);
        self.set_flags(mc, 0);
        self.set_summ(mc, 256 + 1);
        let stats = self.lo_unit;
        self.found_state = stats;
        self.lo_unit = self.lo_unit.saturating_add(256 / 2 * UNIT);
        self.set_stats(mc, stats);
        for i in 0..256u32 {
            self.set_state(
                stats.wrapping_add(i.wrapping_mul(6)),
                State {
                    symbol: i as u8,
                    freq: 1,
                    successor: 0,
                },
            );
        }
        let mut i = 0u32;
        for m in 0..25u32 {
            while self.ns2indx(i) == m {
                i = i.wrapping_add(1);
            }
            for (k, &esc) in INIT_BIN_ESC.iter().enumerate() {
                let val = BIN_SCALE
                    .wrapping_sub(u32::from(esc).checked_div(i.saturating_add(1)).unwrap_or(0))
                    as u16;
                if let Some(row) = self.bin_summ.get_mut(m as usize) {
                    for r in (0..64).step_by(8) {
                        if let Some(v) = row.get_mut(k.saturating_add(r)) {
                            *v = val;
                        }
                    }
                }
            }
        }
        let mut i = 0u32;
        for m in 0..24u32 {
            while self.ns2indx(i.wrapping_add(3)) == m.wrapping_add(3) {
                i = i.wrapping_add(1);
            }
            if let Some(row) = self.see.get_mut(m as usize) {
                for s in row.iter_mut() {
                    *s = See {
                        summ: (i.wrapping_mul(2).wrapping_add(5) << (PERIOD_BITS - 4)) as u16,
                        shift: (PERIOD_BITS - 4) as u8,
                        count: 7,
                    };
                }
            }
        }
    }

    // --- Heap structures ------------------------------------------------
    //
    // Context: NumStats (u8, states less one), Flags (u8), SummFreq (u16),
    // Stats (u32), Suffix (u32); a context of one state holds it at offset
    // 2. State: Symbol, Freq, Successor (u32). Free node: Stamp, Next, NU.

    fn num_stats(&self, c: u32) -> u32 {
        u32::from(self.mem.r8(c))
    }
    fn set_num_stats(&mut self, c: u32, v: u32) {
        self.mem.w8(c, v as u8);
    }
    fn flags(&self, c: u32) -> u32 {
        u32::from(self.mem.r8(c.wrapping_add(1)))
    }
    fn set_flags(&mut self, c: u32, v: u32) {
        self.mem.w8(c.wrapping_add(1), v as u8);
    }
    fn summ(&self, c: u32) -> u32 {
        self.mem.r16(c.wrapping_add(2))
    }
    fn set_summ(&mut self, c: u32, v: u32) {
        self.mem.w16(c.wrapping_add(2), v & 0xffff);
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
    fn set_suffix(&mut self, c: u32, v: u32) {
        self.mem.w32(c.wrapping_add(8), v);
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
    /// The state of `symbol` among the `n` states at `stats`.
    fn find(&self, stats: u32, n: u32, symbol: u32) -> Option<u32> {
        (0..n.min(256))
            .map(|i| stats.wrapping_add(i.wrapping_mul(6)))
            .find(|&s| self.sym(s) == symbol)
    }
    /// The state of `symbol` in context `c` (with several states).
    fn find_in(&self, c: u32, symbol: u32) -> Option<u32> {
        self.find(self.stats(c), self.num_stats(c).wrapping_add(1), symbol)
    }
    /// The flag a state's symbol contributes to its context's flags.
    fn hi_flag(symbol: u32) -> u32 {
        if symbol >= 0x40 { 0x08 } else { 0 }
    }

    // --- Allocator ------------------------------------------------------

    fn node_nu(&self, n: u32) -> u32 {
        self.mem.r32(n.wrapping_add(8))
    }

    fn insert_node(&mut self, node: u32, indx: usize) {
        let head = self.free_list.get(indx).copied().unwrap_or(0);
        self.mem.w32(node, EMPTY_NODE);
        self.mem.w32(node.wrapping_add(4), head);
        self.mem.w32(node.wrapping_add(8), self.i2u(indx));
        if let Some(f) = self.free_list.get_mut(indx) {
            *f = node;
        }
        if let Some(s) = self.stamps.get_mut(indx) {
            *s = s.wrapping_add(1);
        }
    }

    fn remove_node(&mut self, indx: usize) -> u32 {
        let node = self.free_list.get(indx).copied().unwrap_or(0);
        let next = self.mem.r32(node.wrapping_add(4));
        if let Some(f) = self.free_list.get_mut(indx) {
            *f = next;
        }
        if let Some(s) = self.stamps.get_mut(indx) {
            *s = s.wrapping_sub(1);
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

    /// Bounds the walks over the heap's free blocks.
    fn max_nodes(&self) -> u32 {
        (self.size / UNIT).saturating_add(16)
    }

    fn glue_free_blocks(&mut self) {
        // The list of free blocks to keep, linked through Next; `prev`
        // is where the next link goes (0: the head).
        let mut head = 0u32;
        let mut prev: Option<u32> = None;
        self.glue_count = 1 << 13;
        self.stamps = [0; N_INDEXES];
        if self.lo_unit != self.hi_unit {
            self.mem.w32(self.lo_unit, 0);
        }
        let cap = self.max_nodes();
        let mut guard = 0u32;
        for i in 0..N_INDEXES {
            let mut next = self.free_list.get(i).copied().unwrap_or(0);
            if let Some(f) = self.free_list.get_mut(i) {
                *f = 0;
            }
            while next != 0 && guard < cap {
                guard = guard.saturating_add(1);
                let node = next;
                if self.node_nu(node) != 0 {
                    match prev {
                        None => head = node,
                        Some(p) => self.mem.w32(p.wrapping_add(4), node),
                    }
                    prev = Some(node);
                    let mut inner = 0u32;
                    loop {
                        let nu = self.node_nu(node);
                        let node2 = node.wrapping_add(nu.wrapping_mul(UNIT));
                        if self.mem.r32(node2) != EMPTY_NODE || inner >= cap {
                            break;
                        }
                        inner = inner.saturating_add(1);
                        let nu2 = self.node_nu(node2);
                        self.mem.w32(node.wrapping_add(8), nu.wrapping_add(nu2));
                        self.mem.w32(node2.wrapping_add(8), 0);
                    }
                }
                next = self.mem.r32(node.wrapping_add(4));
            }
        }
        match prev {
            None => head = 0,
            Some(p) => self.mem.w32(p.wrapping_add(4), 0),
        }
        let mut guard = 0u32;
        while head != 0 && guard < cap {
            guard = guard.saturating_add(1);
            let mut node = head;
            head = self.mem.r32(node.wrapping_add(4));
            let mut nu = self.node_nu(node);
            if nu == 0 {
                continue;
            }
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
                self.glue_count = self.glue_count.wrapping_sub(1);
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

    fn copy_units(&mut self, dst: u32, src: u32, nu: u32) {
        self.mem.copy(dst, src, nu.wrapping_mul(UNIT));
    }

    fn shrink_units(&mut self, old: u32, old_nu: u32, new_nu: u32) -> u32 {
        let i0 = self.u2i(old_nu);
        let i1 = self.u2i(new_nu);
        if i0 == i1 {
            return old;
        }
        if self.free_list.get(i1).copied().unwrap_or(0) != 0 {
            let ptr = self.remove_node(i1);
            self.copy_units(ptr, old, new_nu);
            self.insert_node(old, i0);
            return ptr;
        }
        self.split_block(old, i0, i1);
        old
    }

    fn free_units(&mut self, ptr: u32, nu: u32) {
        let i = self.u2i(nu);
        self.insert_node(ptr, i);
    }

    fn special_free_unit(&mut self, ptr: u32) {
        if ptr != self.units_start {
            self.insert_node(ptr, 0);
        } else {
            self.units_start = self.units_start.saturating_add(UNIT);
        }
    }

    fn move_units_up(&mut self, old: u32, nu: u32) -> u32 {
        let indx = self.u2i(nu);
        if old > self.units_start.saturating_add(16 * 1024)
            || old > self.free_list.get(indx).copied().unwrap_or(0)
        {
            return old;
        }
        let ptr = self.remove_node(indx);
        self.copy_units(ptr, old, nu);
        if old != self.units_start {
            self.insert_node(old, indx);
        } else {
            self.units_start = self
                .units_start
                .saturating_add(self.i2u(indx).wrapping_mul(UNIT));
        }
        ptr
    }

    fn expand_text_area(&mut self) {
        let mut count = [0u32; N_INDEXES];
        if self.lo_unit != self.hi_unit {
            self.mem.w32(self.lo_unit, 0);
        }
        let cap = self.max_nodes();
        let mut node = self.units_start;
        let mut guard = 0u32;
        while self.mem.r32(node) == EMPTY_NODE && guard < cap {
            guard = guard.saturating_add(1);
            self.mem.w32(node, 0);
            let nu = self.node_nu(node);
            if let Some(c) = count.get_mut(self.u2i(nu)) {
                *c = c.wrapping_add(1);
            }
            if nu == 0 {
                break;
            }
            node = node.wrapping_add(nu.wrapping_mul(UNIT));
        }
        self.units_start = node;
        for (i, left) in count.iter_mut().enumerate() {
            // Where the link to the node being looked at lives: the list
            // head (None) or a node's Next field.
            let mut link: Option<u32> = None;
            let mut guard = 0u32;
            while *left != 0 && guard < cap {
                guard = guard.saturating_add(1);
                let mut node = match link {
                    None => self.free_list.get(i).copied().unwrap_or(0),
                    Some(l) => self.mem.r32(l),
                };
                if node == 0 {
                    break;
                }
                while self.mem.r32(node) == 0 {
                    let next = self.mem.r32(node.wrapping_add(4));
                    match link {
                        None => {
                            if let Some(f) = self.free_list.get_mut(i) {
                                *f = next;
                            }
                        }
                        Some(l) => self.mem.w32(l, next),
                    }
                    node = next;
                    if let Some(s) = self.stamps.get_mut(i) {
                        *s = s.wrapping_sub(1);
                    }
                    *left = left.saturating_sub(1);
                    if *left == 0 || node == 0 {
                        break;
                    }
                }
                link = Some(node.wrapping_add(4));
            }
        }
    }

    // --- Restoring the model when memory runs out -------------------------

    fn refresh(&mut self, c: u32, old_nu: u32, scale: u32) {
        let mut i = self.num_stats(c);
        let stats = self.stats(c);
        let mut s = self.shrink_units(stats, old_nu, i.wrapping_add(2) >> 1);
        self.set_stats(c, s);
        let keep = if scale != 0 { 0x14 } else { 0x10 };
        let mut flags = (self.flags(c) & keep) | Self::hi_flag(self.sym(s));
        let mut esc_freq = self.summ(c).wrapping_sub(self.freq(s));
        let f = self.freq(s).wrapping_add(scale) >> scale;
        self.set_freq(s, f);
        let mut sum_freq = f;
        while i > 0 {
            s = s.wrapping_add(6);
            esc_freq = esc_freq.wrapping_sub(self.freq(s));
            let f = self.freq(s).wrapping_add(scale) >> scale;
            self.set_freq(s, f);
            sum_freq = sum_freq.wrapping_add(f);
            flags |= Self::hi_flag(self.sym(s));
            i = i.saturating_sub(1);
        }
        self.set_summ(
            c,
            sum_freq.wrapping_add(esc_freq.wrapping_add(scale) >> scale),
        );
        self.set_flags(c, flags);
    }

    /// `CutOff`: drops the states whose successors lie in the text area
    /// (or beyond the maximum order) below context `c` at `order`.
    /// Recursion is bounded by the maximum order.
    fn cut_off(&mut self, c: u32, order: u32) -> u32 {
        if self.num_stats(c) == 0 {
            let s = Self::one_state(c);
            if self.successor(s) >= self.units_start {
                let v = if order < self.max_order {
                    let succ = self.successor(s);
                    self.cut_off(succ, order.saturating_add(1))
                } else {
                    0
                };
                self.set_successor(s, v);
                if v != 0 || order <= 9 {
                    return c;
                }
            }
            self.special_free_unit(c);
            return 0;
        }
        let tmp = self.num_stats(c).wrapping_add(2) >> 1;
        let stats = self.stats(c);
        let stats = self.move_units_up(stats, tmp);
        self.set_stats(c, stats);
        let mut i = i64::from(self.num_stats(c));
        let mut k = i;
        while k >= 0 {
            let s = stats.wrapping_add((k as u32).wrapping_mul(6));
            if self.successor(s) < self.units_start {
                let s2 = stats.wrapping_add((i as u32).wrapping_mul(6));
                i = i.wrapping_sub(1);
                self.set_successor(s, 0);
                self.swap_states(s, s2);
            } else if order < self.max_order {
                let succ = self.successor(s);
                let v = self.cut_off(succ, order.saturating_add(1));
                self.set_successor(s, v);
            } else {
                self.set_successor(s, 0);
            }
            k = k.wrapping_sub(1);
        }
        if i != i64::from(self.num_stats(c)) && order != 0 {
            self.set_num_stats(c, (i & 0xff) as u32);
            let s = stats;
            if i < 0 {
                self.free_units(s, tmp);
                self.special_free_unit(c);
                return 0;
            }
            if i == 0 {
                let st = self.state(s);
                self.set_flags(
                    c,
                    (self.flags(c) & 0x10) | Self::hi_flag(u32::from(st.symbol)),
                );
                self.set_state(Self::one_state(c), st);
                self.free_units(s, tmp);
                let one = Self::one_state(c);
                self.set_freq(one, self.freq(one).wrapping_add(11) >> 3);
            } else {
                let scale = u32::from(self.summ(c) > 16u32.wrapping_mul(i as u32));
                self.refresh(c, tmp, scale);
            }
        }
        c
    }

    fn used_memory(&self) -> u32 {
        let mut v = 0u32;
        for (i, &n) in self.stamps.iter().enumerate() {
            v = v.wrapping_add(n.wrapping_mul(self.i2u(i)));
        }
        self.size
            .wrapping_sub(self.hi_unit.wrapping_sub(self.lo_unit))
            .wrapping_sub(self.units_start.wrapping_sub(self.text))
            .wrapping_sub(v.wrapping_mul(UNIT))
    }

    /// `RestoreModel`.
    fn restore(&mut self, c1: u32) {
        self.text = self.align;
        let cap = MAX_ORDER.saturating_mul(4).saturating_add(8);
        let mut c = self.max_context;
        let mut guard = 0u32;
        while c != c1 && c != 0 && guard < cap {
            guard = guard.saturating_add(1);
            let ns = self.num_stats(c).wrapping_sub(1);
            self.set_num_stats(c, ns);
            if ns & 0xff == 0 {
                let s = self.stats(c);
                let st = self.state(s);
                self.set_flags(
                    c,
                    (self.flags(c) & 0x10) | Self::hi_flag(u32::from(st.symbol)),
                );
                self.set_state(Self::one_state(c), st);
                self.special_free_unit(s);
                let one = Self::one_state(c);
                self.set_freq(one, self.freq(one).wrapping_add(11) >> 3);
            } else {
                let nu = self.num_stats(c).wrapping_add(3) >> 1;
                self.refresh(c, nu, 0);
            }
            c = self.suffix(c);
        }
        while c != self.min_context && c != 0 && guard < cap {
            guard = guard.saturating_add(1);
            if self.num_stats(c) == 0 {
                let one = Self::one_state(c);
                let f = self.freq(one);
                self.set_freq(one, f.wrapping_sub(f >> 1));
            } else {
                let summ = self.summ(c).wrapping_add(4);
                self.set_summ(c, summ);
                if summ & 0xffff > 128u32.wrapping_add(4u32.wrapping_mul(self.num_stats(c))) {
                    let nu = self.num_stats(c).wrapping_add(2) >> 1;
                    self.refresh(c, nu, 1);
                }
            }
            c = self.suffix(c);
        }
        if self.restore_method == RESTART || self.used_memory() < (self.size >> 1) {
            self.restart();
        } else {
            let mut guard = 0u32;
            while self.suffix(self.max_context) != 0 && guard < cap {
                guard = guard.saturating_add(1);
                self.max_context = self.suffix(self.max_context);
            }
            let mut rounds = 0u32;
            loop {
                self.cut_off(self.max_context, 0);
                self.expand_text_area();
                rounds = rounds.saturating_add(1);
                if self.used_memory() <= 3u32.wrapping_mul(self.size >> 2) || rounds >= 64 {
                    break;
                }
            }
            self.glue_count = 0;
            self.order_fall = self.max_order;
        }
    }

    // --- Model update ---------------------------------------------------

    fn alloc_context(&mut self) -> Option<u32> {
        if self.hi_unit != self.lo_unit {
            self.hi_unit = self.hi_unit.saturating_sub(UNIT);
            Some(self.hi_unit)
        } else if self.free_list.first().copied().unwrap_or(0) != 0 {
            Some(self.remove_node(0))
        } else {
            self.alloc_units_rare(0)
        }
    }

    /// `CreateSuccessors`; `None` when memory runs out (or the model is
    /// inconsistent).
    fn create_successors(&mut self, skip: bool, s1: Option<u32>, mut c: u32) -> Option<u32> {
        let fs = self.found_state;
        let up_branch = self.successor(fs);
        let fsym = self.sym(fs);
        let mut ps = [0u32; MAX_ORDER as usize + 1];
        let mut num = 0usize;
        if !skip {
            *ps.get_mut(num)? = fs;
            num = num.saturating_add(1);
        }
        let mut s1 = s1;
        let mut guard = 0u32;
        while self.suffix(c) != 0 {
            guard = guard.saturating_add(1);
            if guard > 4 * MAX_ORDER {
                return None;
            }
            c = self.suffix(c);
            let s = if let Some(s) = s1.take() {
                s
            } else if self.num_stats(c) != 0 {
                let s = self.find_in(c, fsym)?;
                if self.freq(s) < MAX_FREQ - 9 {
                    self.set_freq(s, self.freq(s).wrapping_add(1));
                    self.set_summ(c, self.summ(c).wrapping_add(1));
                }
                s
            } else {
                let s = Self::one_state(c);
                let suffix_ns = self.num_stats(self.suffix(c));
                let f = self.freq(s);
                let add = u32::from(suffix_ns == 0) & u32::from(f < 24);
                self.set_freq(s, f.wrapping_add(add));
                s
            };
            let successor = self.successor(s);
            if successor != up_branch {
                c = successor;
                if num == 0 {
                    return Some(c);
                }
                break;
            }
            *ps.get_mut(num)? = s;
            num = num.saturating_add(1);
        }
        let up_sym = u32::from(self.mem.r8(up_branch));
        let flags = (if self.sym(fs) >= 0x40 { 0x10 } else { 0 }) | Self::hi_flag(up_sym);
        let up_freq = if self.num_stats(c) == 0 {
            self.freq(Self::one_state(c))
        } else {
            let s = self.find_in(c, up_sym)?;
            let cf = self.freq(s).wrapping_sub(1);
            let s0 = self
                .summ(c)
                .wrapping_sub(self.num_stats(c))
                .wrapping_sub(cf);
            let v = if cf.wrapping_mul(2) <= s0 {
                u32::from(cf.wrapping_mul(5) > s0)
            } else {
                cf.wrapping_add(s0.wrapping_mul(2))
                    .wrapping_sub(3)
                    .checked_div(s0)
                    .unwrap_or(0)
            };
            v.wrapping_add(1)
        };
        let up = State {
            symbol: up_sym as u8,
            freq: up_freq as u8,
            successor: up_branch.wrapping_add(1),
        };
        while num > 0 {
            let c1 = self.alloc_context()?;
            self.set_num_stats(c1, 0);
            self.set_flags(c1, flags);
            self.set_state(Self::one_state(c1), up);
            self.set_suffix(c1, c);
            num = num.saturating_sub(1);
            let s = *ps.get(num)?;
            self.set_successor(s, c1);
            c = c1;
        }
        Some(c)
    }

    /// `ReduceOrder`; `None` for a null context.
    fn reduce_order(&mut self, s1: Option<u32>, mut c: u32) -> Option<u32> {
        let c1 = c;
        let up_branch = self.text;
        let fs = self.found_state;
        let fsym = self.sym(fs);
        self.set_successor(fs, up_branch);
        self.order_fall = self.order_fall.wrapping_add(1);
        let mut s1 = s1;
        let mut guard = 0u32;
        let s = loop {
            guard = guard.saturating_add(1);
            if guard > 4 * MAX_ORDER {
                return None;
            }
            let s = if let Some(s) = s1.take() {
                c = self.suffix(c);
                s
            } else {
                if self.suffix(c) == 0 {
                    return Some(c);
                }
                c = self.suffix(c);
                if self.num_stats(c) != 0 {
                    let s = self.find_in(c, fsym)?;
                    if self.freq(s) < MAX_FREQ - 9 {
                        self.set_freq(s, self.freq(s).wrapping_add(2));
                        self.set_summ(c, self.summ(c).wrapping_add(2));
                    }
                    s
                } else {
                    let s = Self::one_state(c);
                    let f = self.freq(s);
                    self.set_freq(s, f.wrapping_add(u32::from(f < 32)));
                    s
                }
            };
            if self.successor(s) != 0 {
                break s;
            }
            self.set_successor(s, up_branch);
            self.order_fall = self.order_fall.wrapping_add(1);
        };
        if self.successor(s) <= up_branch {
            let s2 = self.found_state;
            self.found_state = s;
            let successor = self.create_successors(false, None, c);
            self.set_successor(s, successor.unwrap_or(0));
            self.found_state = s2;
        }
        if self.order_fall == 1 && c1 == self.max_context {
            let v = self.successor(s);
            self.set_successor(self.found_state, v);
            self.text = self.text.wrapping_sub(1);
        }
        match self.successor(s) {
            0 => None,
            v => Some(v),
        }
    }

    /// `UpdateModel`; `None` when the model is inconsistent (corrupt
    /// data).
    fn update_model(&mut self) -> Option<()> {
        let fs = self.found_state;
        let fst = self.state(fs);
        let fsym = u32::from(fst.symbol);
        let ffreq = u32::from(fst.freq);
        let mut f_successor = fst.successor;
        let mut s: Option<u32> = None;
        let mc = self.min_context;
        if ffreq < MAX_FREQ / 4 && self.suffix(mc) != 0 {
            let c = self.suffix(mc);
            if self.num_stats(c) == 0 {
                let st = Self::one_state(c);
                if self.freq(st) < 32 {
                    self.set_freq(st, self.freq(st).wrapping_add(1));
                }
                s = Some(st);
            } else {
                let stats = self.stats(c);
                let mut st = self.find_in(c, fsym)?;
                if st != stats {
                    let prev = st.wrapping_sub(6);
                    if self.freq(st) >= self.freq(prev) {
                        self.swap_states(st, prev);
                        st = prev;
                    }
                }
                if self.freq(st) < MAX_FREQ - 9 {
                    self.set_freq(st, self.freq(st).wrapping_add(2));
                    self.set_summ(c, self.summ(c).wrapping_add(2));
                }
                s = Some(st);
            }
        }
        let mut c = self.max_context;
        if self.order_fall == 0 && f_successor != 0 {
            match self.create_successors(true, s, mc) {
                None => {
                    self.set_successor(fs, 0);
                    self.restore(c);
                }
                Some(cs) => {
                    self.set_successor(fs, cs);
                    self.max_context = cs;
                }
            }
            return Some(());
        }
        self.mem.w8(self.text, fst.symbol);
        self.text = self.text.wrapping_add(1);
        let mut successor = self.text;
        if self.text >= self.units_start {
            self.restore(c);
            return Some(());
        }
        if f_successor == 0 {
            match self.reduce_order(s, mc) {
                None => {
                    self.restore(c);
                    return Some(());
                }
                Some(cs) => f_successor = cs,
            }
        } else if f_successor < self.units_start {
            match self.create_successors(false, s, mc) {
                None => {
                    self.restore(c);
                    return Some(());
                }
                Some(cs) => f_successor = cs,
            }
        }
        self.order_fall = self.order_fall.wrapping_sub(1);
        if self.order_fall == 0 {
            successor = f_successor;
            if self.max_context != self.min_context {
                self.text = self.text.wrapping_sub(1);
            }
        }
        let mc = self.min_context;
        let ns = self.num_stats(mc);
        let s0 = self.summ(mc).wrapping_sub(ns).wrapping_sub(ffreq);
        let flag = Self::hi_flag(fsym);
        let mut guard = 0u32;
        while c != mc {
            guard = guard.saturating_add(1);
            if guard > 4 * MAX_ORDER || c == 0 {
                return None;
            }
            let ns1 = self.num_stats(c);
            if ns1 != 0 {
                if ns1 & 1 != 0 {
                    let old_nu = ns1.wrapping_add(1) >> 1;
                    let i = self.u2i(old_nu);
                    if i != self.u2i(old_nu.wrapping_add(1)) {
                        let Some(ptr) = self.alloc_units(i.saturating_add(1)) else {
                            self.restore(c);
                            return Some(());
                        };
                        let old = self.stats(c);
                        self.copy_units(ptr, old, old_nu);
                        self.insert_node(old, i);
                        self.set_stats(c, ptr);
                    }
                }
                let add = u32::from(ns1.wrapping_mul(3).wrapping_add(1) < ns);
                self.set_summ(c, self.summ(c).wrapping_add(add));
            } else {
                let Some(s2) = self.alloc_units(0) else {
                    self.restore(c);
                    return Some(());
                };
                let mut st = self.state(Self::one_state(c));
                self.set_stats(c, s2);
                let f = u32::from(st.freq);
                st.freq = if f < MAX_FREQ / 4 - 1 {
                    (f * 2) as u8
                } else {
                    (MAX_FREQ - 4) as u8
                };
                self.set_state(s2, st);
                self.set_summ(
                    c,
                    u32::from(st.freq)
                        .wrapping_add(self.init_esc)
                        .wrapping_add(u32::from(ns > 2)),
                );
            }
            let summ = self.summ(c);
            let mut cf = ffreq.wrapping_mul(2).wrapping_mul(summ.wrapping_add(6));
            let sf = s0.wrapping_add(summ);
            if cf < sf.wrapping_mul(6) {
                cf = 1u32
                    .wrapping_add(u32::from(cf > sf))
                    .wrapping_add(u32::from(cf >= sf.wrapping_mul(4)));
                self.set_summ(c, summ.wrapping_add(4));
            } else {
                cf = 4u32
                    .wrapping_add(u32::from(cf > sf.wrapping_mul(9)))
                    .wrapping_add(u32::from(cf > sf.wrapping_mul(12)))
                    .wrapping_add(u32::from(cf > sf.wrapping_mul(15)));
                self.set_summ(c, summ.wrapping_add(cf));
            }
            let s2 = self
                .stats(c)
                .wrapping_add(ns1.wrapping_add(1).wrapping_mul(6));
            self.set_state(
                s2,
                State {
                    symbol: fst.symbol,
                    freq: cf as u8,
                    successor,
                },
            );
            self.set_flags(c, self.flags(c) | flag);
            self.set_num_stats(c, ns1.wrapping_add(1));
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
        let mut esc_freq = self.summ(mc).wrapping_sub(self.freq(s));
        let adder = u32::from(self.order_fall != 0);
        let f = self.freq(s).wrapping_add(4).wrapping_add(adder) >> 1;
        self.set_freq(s, f);
        let mut sum_freq = f;
        let mut i = self.num_stats(mc);
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
            let num_stats = self.num_stats(mc);
            let mut i = 0u32;
            loop {
                i = i.wrapping_add(1);
                s = s.wrapping_sub(6);
                if self.freq(s) != 0 || s == stats || i > 256 {
                    break;
                }
            }
            esc_freq = esc_freq.wrapping_add(i);
            let new_ns = num_stats.wrapping_sub(i) & 0xff;
            self.set_num_stats(mc, new_ns);
            if new_ns == 0 {
                let mut tmp = self.state(stats);
                let f = u32::from(tmp.freq)
                    .wrapping_mul(2)
                    .wrapping_add(esc_freq)
                    .wrapping_sub(1)
                    .checked_div(esc_freq)
                    .unwrap_or(0)
                    .min(MAX_FREQ / 3);
                tmp.freq = f as u8;
                let idx = self.u2i(num_stats.wrapping_add(2) >> 1);
                self.insert_node(stats, idx);
                self.set_flags(
                    mc,
                    (self.flags(mc) & 0x10) | Self::hi_flag(u32::from(tmp.symbol)),
                );
                self.found_state = Self::one_state(mc);
                self.set_state(self.found_state, tmp);
                return;
            }
            let n0 = num_stats.wrapping_add(2) >> 1;
            let n1 = new_ns.wrapping_add(2) >> 1;
            if n0 != n1 {
                let ns = self.shrink_units(stats, n0, n1);
                self.set_stats(mc, ns);
            }
            let mut flags = self.flags(mc) & !0x08;
            let mut s = self.stats(mc);
            flags |= Self::hi_flag(self.sym(s));
            for _ in 0..new_ns {
                s = s.wrapping_add(6);
                flags |= Self::hi_flag(self.sym(s));
            }
            self.set_flags(mc, flags);
        }
        self.set_summ(
            mc,
            sum_freq.wrapping_add(esc_freq).wrapping_sub(esc_freq >> 1),
        );
        self.set_flags(mc, self.flags(mc) | 0x04);
        self.found_state = self.stats(mc);
    }

    fn next_context(&mut self) -> Option<()> {
        let c = self.successor(self.found_state);
        if self.order_fall == 0 && c > self.text {
            self.min_context = c;
            self.max_context = c;
        } else {
            self.update_model()?;
            self.min_context = self.max_context;
        }
        Some(())
    }

    fn make_esc_freq(&mut self, num_masked: u32) -> (SeeRef, u32) {
        let mc = self.min_context;
        let ns = self.num_stats(mc);
        if ns == 0xff {
            return (SeeRef::Dummy, 1);
        }
        let i = self.ns2indx(ns.wrapping_add(2)).wrapping_sub(3) as usize;
        let suffix_ns = self.num_stats(self.suffix(mc));
        // The three terms use separate bits (1, 2, and 4 to 16).
        let k = u32::from(self.summ(mc) > 11u32.wrapping_mul(ns.wrapping_add(1)))
            | u32::from(ns.wrapping_mul(2) < suffix_ns.wrapping_add(num_masked)) << 1
            | self.flags(mc);
        let Some(see) = self.see.get_mut(i).and_then(|r| r.get_mut(k as usize)) else {
            return (SeeRef::Dummy, 1);
        };
        let r = u32::from(see.summ) >> see.shift.min(15);
        see.summ = see.summ.wrapping_sub(r as u16);
        (SeeRef::At(i, k as usize), r.wrapping_add(u32::from(r == 0)))
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

    // --- Range decoder --------------------------------------------------

    fn start_coder(&mut self, input: &mut In<'_>) -> bool {
        self.low = 0;
        self.range = u32::MAX;
        self.code = 0;
        for _ in 0..4 {
            self.code = self.code << 8 | u32::from(input.byte());
        }
        self.code < u32::MAX
    }

    fn threshold(&mut self, total: u32) -> Option<u32> {
        self.range = self.range.checked_div(total)?;
        self.code.checked_div(self.range)
    }

    /// `RangeDec_Decode`; `None` if the coder breaks down (a range of
    /// zero, which no encoder produces).
    fn decode(&mut self, input: &mut In<'_>, start: u32, size: u32) -> Option<()> {
        const TOP: u32 = 1 << 24;
        const BOT: u32 = 1 << 15;
        let start = start.wrapping_mul(self.range);
        self.low = self.low.wrapping_add(start);
        self.code = self.code.wrapping_sub(start);
        self.range = self.range.wrapping_mul(size);
        for _ in 0..8 {
            if (self.low ^ self.low.wrapping_add(self.range)) >= TOP {
                if self.range >= BOT {
                    return Some(());
                }
                self.range = self.low.wrapping_neg() & (BOT - 1);
            }
            self.code = self.code << 8 | u32::from(input.byte());
            self.range <<= 8;
            self.low <<= 8;
        }
        None
    }

    fn valid_context(&self, c: u32) -> bool {
        c >= self.align && c < self.align.saturating_add(self.size)
    }

    /// `Ppmd8_DecodeSymbol`; `None` on corrupt data.
    fn decode_symbol(&mut self, input: &mut In<'_>) -> Option<Sym> {
        if !self.valid_context(self.min_context) {
            return None;
        }
        let mut mask = [true; 256];
        let mc = self.min_context;
        let ns = self.num_stats(mc);
        if ns != 0 {
            let stats = self.stats(mc);
            if !self.valid_context(stats) {
                return None;
            }
            let summ = self.summ(mc);
            let count = self.threshold(summ)?;
            let mut s = stats;
            let mut hi = self.freq(s);
            if count < hi {
                self.decode(input, 0, hi)?;
                self.found_state = s;
                let symbol = self.mem.r8(s);
                // Update1_0.
                self.prev_success = u32::from(hi.wrapping_mul(2) >= summ);
                self.run_length = self.run_length.wrapping_add(self.prev_success as i32);
                self.set_summ(mc, summ.wrapping_add(4));
                self.set_freq(s, hi.wrapping_add(4));
                if hi.wrapping_add(4) > MAX_FREQ {
                    self.rescale();
                }
                self.next_context()?;
                return Some(Sym::Byte(symbol));
            }
            self.prev_success = 0;
            for _ in 0..ns {
                s = s.wrapping_add(6);
                let f = self.freq(s);
                hi = hi.wrapping_add(f);
                if hi > count {
                    self.decode(input, hi.wrapping_sub(f), f)?;
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
                    self.next_context()?;
                    return Some(Sym::Byte(symbol));
                }
            }
            if count >= summ {
                return None;
            }
            self.decode(input, hi, summ.wrapping_sub(hi))?;
            for k in 0..=ns {
                let sym = self.sym(stats.wrapping_add(k.wrapping_mul(6)));
                if let Some(m) = mask.get_mut(sym as usize) {
                    *m = false;
                }
            }
        } else {
            let rs = Self::one_state(mc);
            let rs_freq = self.freq(rs);
            let rs_sym = self.sym(rs);
            let row = self.ns2indx(rs_freq.wrapping_sub(1)) as usize;
            let suffix_ns = self.num_stats(self.suffix(mc));
            let col = u32::from(self.ns2bsindx.get(suffix_ns as usize).copied().unwrap_or(0))
                .wrapping_add(self.prev_success)
                .wrapping_add(self.flags(mc))
                .wrapping_add(((self.run_length >> 26) & 0x20) as u32)
                as usize;
            let prob = u32::from(
                self.bin_summ
                    .get(row)
                    .and_then(|r| r.get(col))
                    .copied()
                    .unwrap_or(0),
            );
            self.range >>= 14;
            let count = self.code.checked_div(self.range)?;
            let mean = (prob + (1 << (PERIOD_BITS - 2))) >> PERIOD_BITS;
            if count < prob {
                self.decode(input, 0, prob)?;
                let np = prob.wrapping_add(1 << INT_BITS).wrapping_sub(mean);
                if let Some(v) = self.bin_summ.get_mut(row).and_then(|r| r.get_mut(col)) {
                    *v = np as u16;
                }
                self.found_state = rs;
                // UpdateBin.
                self.set_freq(rs, rs_freq.wrapping_add(u32::from(rs_freq < 196)));
                self.prev_success = 1;
                self.run_length = self.run_length.wrapping_add(1);
                self.next_context()?;
                return Some(Sym::Byte(rs_sym as u8));
            }
            self.decode(input, prob, BIN_SCALE.wrapping_sub(prob))?;
            let np = prob.wrapping_sub(mean);
            if let Some(v) = self.bin_summ.get_mut(row).and_then(|r| r.get_mut(col)) {
                *v = np as u16;
            }
            self.init_esc = u32::from(
                EXP_ESCAPE
                    .get(((np & 0xffff) >> 10) as usize)
                    .copied()
                    .unwrap_or(0),
            );
            if let Some(m) = mask.get_mut(rs_sym as usize) {
                *m = false;
            }
            self.prev_success = 0;
        }
        let mut ps = [0u32; 256];
        loop {
            let num_masked = self.num_stats(self.min_context);
            let mut c = self.min_context;
            let mut depth = 0u32;
            loop {
                self.order_fall = self.order_fall.wrapping_add(1);
                if self.suffix(c) == 0 {
                    return Some(Sym::End);
                }
                c = self.suffix(c);
                depth = depth.saturating_add(1);
                if !self.valid_context(c) || depth > 4 * MAX_ORDER {
                    return None;
                }
                if self.num_stats(c) != num_masked {
                    break;
                }
            }
            self.min_context = c;
            let ns = self.num_stats(c);
            if ns < num_masked {
                return None;
            }
            let stats = self.stats(c);
            let want = ns.wrapping_sub(num_masked) as usize;
            let mut hi = 0u32;
            let mut n = 0usize;
            for k in 0..=ns {
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
            if n < want {
                return None;
            }
            let (see, esc_freq) = self.make_esc_freq(num_masked);
            let total = esc_freq.wrapping_add(hi);
            let count = self.threshold(total)?;
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
                self.decode(input, acc.wrapping_sub(f), f)?;
                self.see_mut(see).update();
                self.found_state = found;
                let symbol = self.mem.r8(found);
                // Update2.
                self.set_summ(c, self.summ(c).wrapping_add(4));
                self.set_freq(found, f.wrapping_add(4));
                if f.wrapping_add(4) > MAX_FREQ {
                    self.rescale();
                }
                self.run_length = self.init_rl;
                self.update_model()?;
                self.min_context = self.max_context;
                return Some(Sym::Byte(symbol));
            }
            if count >= total {
                return None;
            }
            self.decode(input, hi, total.wrapping_sub(hi))?;
            let s = self.see_mut(see);
            s.summ = s.summ.wrapping_add(total as u16);
            for &s in ps.iter().take(n) {
                let sym = self.sym(s);
                if let Some(m) = mask.get_mut(sym as usize) {
                    *m = false;
                }
            }
        }
    }
}

/// ZIP's PPMd (method 98): the 2-byte parameter word, then a PPMd var. I
/// stream decoded to `size` bytes.
#[derive(Clone)]
pub struct Ppmd8 {
    model: Option<Box<Model>>,
    size: u64,
    produced: u64,
    /// Input position (bytes consumed by the range decoder).
    pos: usize,
    /// The end marker after the data has been looked for.
    ended: bool,
}

impl Ppmd8 {
    pub fn new(size: u64) -> Self {
        Ppmd8 {
            model: None,
            size,
            produced: 0,
            pos: 0,
            ended: false,
        }
    }

    /// After the last byte: reads the end marker 7-Zip writes there, if
    /// it is one, so the stream's length counts it.
    fn end_marker(&mut self, input: &[u8], eof: bool) {
        if self.ended || !(eof || self.pos.saturating_add(MARGIN) <= input.len()) {
            return;
        }
        self.ended = true;
        let Some(model) = self.model.as_mut() else {
            return;
        };
        let mut inp = In {
            data: input,
            pos: self.pos,
        };
        if let Some(Sym::End) = model.decode_symbol(&mut inp)
            && inp.pos <= input.len()
        {
            self.pos = inp.pos;
        }
    }

    /// Reads the parameter word and starts the model and its coder.
    fn begin(&mut self, input: &[u8]) -> Result<()> {
        let (Some(&lo), Some(&hi)) = (input.first(), input.get(1)) else {
            return Err(Diagnostic::malformed("PPMd: input ends unexpectedly"));
        };
        let word = u32::from(lo) | u32::from(hi) << 8;
        let order = (word & 0xf).saturating_add(1);
        let mem = ((word >> 4) & 0xff).saturating_add(1) << 20;
        let restore = word >> 12;
        if order < MIN_ORDER || restore > 2 {
            return Err(Diagnostic::malformed(format!(
                "PPMd: invalid parameters (order {order}, restoration method {restore})"
            )));
        }
        if restore != RESTART && restore != CUT_OFF {
            return Err(Diagnostic::unsupported(
                "PPMd model freezing (restoration method 2)",
            ));
        }
        let mut model = Box::new(Model::new(order, mem, restore));
        let mut inp = In {
            data: input.get(2..).unwrap_or_default(),
            pos: 0,
        };
        if !model.start_coder(&mut inp) {
            return Err(Diagnostic::malformed("PPMd: invalid range coder start"));
        }
        if inp.pos > inp.data.len() {
            return Err(Diagnostic::malformed("PPMd: input ends unexpectedly"));
        }
        self.pos = inp.pos.saturating_add(2);
        self.model = Some(model);
        Ok(())
    }
}

impl Decoder for Ppmd8 {
    fn decode(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Status> {
        if self.produced >= self.size {
            return Ok(Status::Done);
        }
        if self.model.is_none() {
            if input.len() < 6 && !eof {
                return Ok(Status::NeedInput);
            }
            self.begin(input)?;
        }
        let Some(model) = self.model.as_mut() else {
            return Err(Diagnostic::internal("PPMd: no model"));
        };
        let target = out.len().saturating_add(step.clamp(1, BATCH));
        let mut inp = In {
            data: input,
            pos: self.pos,
        };
        let start = out.len();
        while self.produced < self.size && out.len() < target {
            if !eof && inp.pos.saturating_add(MARGIN) > input.len() {
                break;
            }
            if out.len() >= limit {
                return Err(Diagnostic::output_limit(limit));
            }
            match model.decode_symbol(&mut inp) {
                Some(Sym::Byte(b)) => {
                    out.push(b);
                    self.produced = self.produced.saturating_add(1);
                }
                Some(Sym::End) => {
                    return Err(Diagnostic::malformed(format!(
                        "PPMd: end marker after {:#x} of {:#x} bytes",
                        self.produced, self.size
                    )));
                }
                None if inp.pos > input.len() => {
                    return Err(Diagnostic::malformed("PPMd: input ends unexpectedly"));
                }
                None => return Err(corrupt()),
            }
            if inp.pos > input.len() {
                return Err(Diagnostic::malformed("PPMd: input ends unexpectedly"));
            }
        }
        self.pos = inp.pos;
        if self.produced >= self.size {
            self.end_marker(input, eof);
            return Ok(Status::Done);
        }
        Ok(if out.len() > start {
            Status::More
        } else {
            Status::NeedInput
        })
    }

    fn consumed(&self) -> usize {
        self.pos
    }

    fn warning(&self, _out: &[u8]) -> Option<Diagnostic> {
        None
    }

    fn releasable_input(&self) -> usize {
        self.pos
    }

    fn release_input(&mut self, n: usize) {
        self.pos = self.pos.saturating_sub(n);
    }

    /// All of it: the model keeps its own history.
    fn releasable_output(&self, out_len: usize) -> usize {
        out_len
    }

    fn checkpoint(&self) -> Option<Box<dyn Decoder>> {
        Some(Box::new(self.clone()))
    }

    fn state_size(&self) -> usize {
        std::mem::size_of::<Self>().saturating_add(self.model.as_ref().map_or(0, |m| {
            std::mem::size_of::<Model>().saturating_add(m.heap_size())
        }))
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]
mod tests {
    use super::*;
    use crate::codec::pipeline::{decode_all, verify_checkpoints};

    /// Decodes `n` bytes of a bare PPMd var. I stream.
    fn decode_raw(data: &[u8], order: u32, mem: u32, restore: u32, n: usize) -> Vec<u8> {
        let mut m = Model::new(order, mem, restore);
        let mut input = In { data, pos: 0 };
        assert!(m.start_coder(&mut input));
        let mut out = Vec::new();
        while out.len() < n {
            match m.decode_symbol(&mut input) {
                Some(Sym::Byte(b)) => out.push(b),
                Some(Sym::End) => panic!("end marker at {}", out.len()),
                None => panic!("corrupt at {}", out.len()),
            }
        }
        out
    }

    /// The model against 7-Zip's encoder (`tests/data/zip/ppmd8.py`),
    /// including runs that exhaust its memory and restart or cut it off.
    #[test]
    fn ppmd8_matches_7zip() {
        let want = include_bytes!("testdata/words.txt");
        let cases: [(&[u8], u32, u32, u32); 5] = [
            (
                include_bytes!("testdata/ppmd8-6-1048576-0.bin"),
                6,
                1 << 20,
                0,
            ),
            (
                include_bytes!("testdata/ppmd8-16-65536-0.bin"),
                16,
                1 << 16,
                0,
            ),
            (
                include_bytes!("testdata/ppmd8-16-65536-1.bin"),
                16,
                1 << 16,
                1,
            ),
            (
                include_bytes!("testdata/ppmd8-8-98304-1.bin"),
                8,
                3 << 15,
                1,
            ),
            (
                include_bytes!("testdata/ppmd8-2-65536-0.bin"),
                2,
                1 << 16,
                0,
            ),
        ];
        for (data, order, mem, restore) in cases {
            let got = decode_raw(data, order, mem, restore, want.len());
            let first = got.iter().zip(want.iter()).position(|(a, b)| a != b);
            assert_eq!(first, None, "order {order} mem {mem} restore {restore}");
        }
    }

    /// The ZIP framing: the parameter word, then the stream; decoded in
    /// small steps with input fed piecemeal, and from checkpoints.
    #[test]
    fn zip_stream() {
        let want = include_bytes!("testdata/words.txt");
        // Order 6, 1 MiB, restart.
        let mut zip = vec![5u8, 0];
        zip.extend_from_slice(include_bytes!("testdata/ppmd8-6-1048576-0.bin"));
        let make = || -> Box<dyn Decoder> { Box::new(Ppmd8::new(want.len() as u64)) };
        assert_eq!(decode_all(make().as_mut(), &zip, 1 << 20).unwrap(), want);

        let mut d = make();
        let mut out = Vec::new();
        let mut have = 0;
        loop {
            let eof = have >= zip.len();
            match d
                .decode(&zip[..have], eof, &mut out, 1000, 1 << 20)
                .unwrap()
            {
                Status::Done => break,
                Status::More => {}
                Status::NeedInput => have = (have + 333).min(zip.len()),
            }
        }
        assert_eq!(out, want);

        let (checked, _) = verify_checkpoints(make, &zip, 20_000, 1).unwrap();
        assert!(checked >= 4, "{checked}");

        // Truncated: an error at the end of the input, never wrong bytes.
        assert!(decode_all(make().as_mut(), &zip[..zip.len() / 2], 1 << 20).is_err());
        // Restoration method 2 (freezing) is not supported; order 1 is
        // invalid.
        let mut frozen = zip.clone();
        frozen[1] = 0x20;
        assert!(decode_all(make().as_mut(), &frozen, 1 << 20).is_err());
        let mut order1 = zip.clone();
        order1[0] = 0;
        assert!(decode_all(make().as_mut(), &order1, 1 << 20).is_err());
    }

    /// Damaged streams end in an error or wrong bytes, within bounded work.
    #[test]
    fn corrupt_streams_settle() {
        let mut zip = vec![0x0f, 0x00];
        zip.extend_from_slice(include_bytes!("testdata/ppmd8-16-65536-1.bin"));
        for i in (2..zip.len()).step_by(97) {
            let mut bad = zip.clone();
            bad[i] ^= 0x5a;
            let _ = decode_all(Ppmd8::new(200_000).decoder().as_mut(), &bad, 1 << 20);
        }
    }

    impl Ppmd8 {
        fn decoder(self) -> Box<dyn Decoder> {
            Box::new(self)
        }
    }
}
