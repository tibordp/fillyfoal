//! Unix `compress` (`.Z`): LZW with LSB-first codes of 9 up to 16 bits and,
//! in block mode, a CLEAR code. Codes come in groups of `bits` bytes; when
//! the code width changes or the table is cleared, the rest of the group is
//! skipped (the original implementation's buffering, now part of the
//! format).

use crate::codec::filters::Filter;
use crate::error::{Diagnostic, Result};

fn bad(what: &str) -> Diagnostic {
    Diagnostic::malformed(format!(".Z: {what}"))
}

#[derive(Clone, Copy)]
pub struct UnixCompress;

impl Filter for UnixCompress {
    fn apply(&self, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        if input.get(..2) != Some(&[0x1f, 0x9d]) {
            return Err(bad("missing magic"));
        }
        let flags = *input.get(2).ok_or_else(|| bad("truncated header"))?;
        let max_bits = u32::from(flags & 0x1f);
        if !(9..=16).contains(&max_bits) {
            return Err(bad("maximum code width out of range"));
        }
        let block_mode = flags & 0x80 != 0;
        let max_max_code = 1usize << max_bits;
        let data = input.get(3..).unwrap_or_default();
        let total_bits = data.len().saturating_mul(8);
        // Positions count bits from the start of the code data.
        let mut pos = 0usize;
        let mut bits = 9u32;
        let mut max_code = (1usize << bits).saturating_sub(1);
        let first = if block_mode { 257 } else { 256 };
        let mut free = first;
        let mut prefix = vec![0u16; max_max_code];
        let mut suffix: Vec<u8> = (0..max_max_code).map(|i| u8::try_from(i & 0xff).unwrap_or(0)).collect();
        let mut old: Option<usize> = None;
        let mut fin = 0u8;
        let mut out = Vec::new();
        let mut stack = Vec::new();
        // Skips to the end of the current group of `bits` codes, counted
        // from where the codes of this width began (`mark`).
        let mut mark = 0usize;
        let align = |pos: usize, mark: usize, bits: u32| -> usize {
            let group = usize::try_from(bits).unwrap_or(9).saturating_mul(8);
            mark.saturating_add(pos.saturating_sub(mark).div_ceil(group).saturating_mul(group))
        };
        loop {
            if free > max_code && bits < max_bits {
                pos = align(pos, mark, bits);
                mark = pos;
                bits = bits.saturating_add(1);
                max_code = if bits == max_bits { max_max_code } else { (1usize << bits).saturating_sub(1) };
            }
            if pos.saturating_add(usize::try_from(bits).unwrap_or(16)) > total_bits {
                break;
            }
            let mut code = 0usize;
            for i in 0..bits {
                let p = pos.saturating_add(usize::try_from(i).unwrap_or(0));
                let b = data.get(p / 8).copied().unwrap_or(0) >> (p % 8) & 1;
                code |= usize::from(b) << i;
            }
            pos = pos.saturating_add(usize::try_from(bits).unwrap_or(16));
            let Some(prev) = old else {
                if code > 255 {
                    return Err(bad("first code is not a literal"));
                }
                fin = u8::try_from(code).unwrap_or(0);
                out.push(fin);
                old = Some(code);
                continue;
            };
            if code == 256 && block_mode {
                free = first.saturating_sub(1);
                pos = align(pos, mark, bits);
                mark = pos;
                bits = 9;
                max_code = (1usize << bits).saturating_sub(1);
                continue;
            }
            let incode = code;
            stack.clear();
            if code >= free {
                if code > free {
                    return Err(bad("code beyond the table"));
                }
                stack.push(fin);
                code = prev;
            }
            while code >= 256 {
                stack.push(suffix.get(code).copied().ok_or_else(|| bad("code beyond the table"))?);
                code = usize::from(prefix.get(code).copied().ok_or_else(|| bad("code beyond the table"))?);
                if stack.len() > max_max_code {
                    return Err(bad("string loop"));
                }
            }
            fin = u8::try_from(code).unwrap_or(0);
            stack.push(fin);
            out.extend(stack.iter().rev());
            if out.len() > limit {
                return Err(Diagnostic::limit(format!("decompressed data exceeds {limit:#x} bytes")));
            }
            if free < max_max_code {
                if let Some(p) = prefix.get_mut(free) {
                    *p = u16::try_from(prev).unwrap_or(0);
                }
                if let Some(s) = suffix.get_mut(free) {
                    *s = fin;
                }
                free = free.saturating_add(1);
            }
            old = Some(incode);
        }
        Ok(out)
    }
}
