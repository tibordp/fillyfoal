//! Compressed WIM resources: a chunk table (one 4-byte, or for resources
//! over 4 GiB 8-byte, offset per chunk after the first, relative to the end
//! of the table), then the chunks. Each chunk is compressed independently,
//! or stored when compression did not shrink it.

use crate::codec::pipeline::{Decode, Step};
use crate::codec::{Codec, lzx, pipeline};
use crate::error::{Diagnostic, Result};

fn bad(what: &str) -> Diagnostic {
    Diagnostic::malformed(format!("WIM resource: {what}"))
}

/// The chunk codec.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// XPRESS (LZ77+Huffman).
    Xpress,
    Lzx,
}

/// A non-solid compressed resource of `original` bytes in `chunk`-byte
/// chunks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Resource {
    pub kind: Kind,
    pub chunk: u32,
    pub original: u64,
}

/// A [`Resource`] decoded a chunk per step. Chunk offsets are read from the
/// table in the input as they are needed; the last chunk runs to the end of
/// the input, so it waits for all of it.
#[derive(Clone)]
pub struct Decoder {
    resource: Resource,
    /// The next chunk.
    index: u64,
    consumed: usize,
    done: bool,
}

impl Decoder {
    pub fn new(resource: Resource) -> Self {
        Decoder { resource, index: 0, consumed: 0, done: false }
    }
}

impl Decode for Decoder {
    fn step(&mut self, input: &[u8], eof: bool, out: &mut Vec<u8>, step: usize, limit: usize) -> Result<Step> {
        let r = self.resource;
        let chunk = u64::from(r.chunk);
        if !chunk.is_power_of_two() || !(1 << 15..=1 << 21).contains(&chunk) {
            return Err(Diagnostic::unsupported(format!("WIM chunk size {chunk:#x}")));
        }
        let original = usize::try_from(r.original).map_err(|_| bad("too large"))?;
        if original > limit {
            return Err(Diagnostic::limit(format!("decompressed data exceeds {limit:#x} bytes")));
        }
        let chunks = r.original.div_ceil(chunk);
        // The table has one entry per chunk after the first (and the empty
        // resource is one empty chunk).
        let entries = chunks.saturating_sub(1);
        let entry: usize = if r.original > u64::from(u32::MAX) { 8 } else { 4 };
        let table_len = usize::try_from(entries)
            .ok()
            .and_then(|n| n.checked_mul(entry))
            .filter(|&n| n <= input.len())
            .ok_or_else(|| bad("chunk table larger than the resource"))?;
        let (table, body) = input.split_at_checked(table_len).ok_or_else(|| bad("truncated chunk table"))?;
        let start_of = |i: u64| -> Result<usize> {
            let Some(i) = i.checked_sub(1) else { return Ok(0) };
            let at = usize::try_from(i).ok().and_then(|i| i.checked_mul(entry)).unwrap_or(usize::MAX);
            let e = table.get(at..at.saturating_add(entry)).ok_or_else(|| bad("truncated chunk table"))?;
            let v = e.iter().rev().fold(0u64, |acc, &b| acc << 8 | u64::from(b));
            usize::try_from(v).map_err(|_| bad("bad chunk offset"))
        };
        let window_bits = u8::try_from(chunk.trailing_zeros()).unwrap_or(15);
        let mark = out.len();
        while !self.done {
            let i = self.index;
            let last = i >= entries;
            if last && !eof {
                return Err(bad("waiting for the last chunk"));
            }
            let from = start_of(i)?;
            let to = if last { body.len() } else { start_of(i.saturating_add(1))? };
            let data = body.get(from..to).ok_or_else(|| bad("chunk outside the resource"))?;
            let len = chunk.min(r.original.saturating_sub(i.saturating_mul(chunk)));
            let ulen = usize::try_from(len).unwrap_or(usize::MAX);
            if data.len() >= ulen {
                out.extend_from_slice(data.get(..ulen).unwrap_or_default());
            } else {
                let codec = match r.kind {
                    Kind::Xpress => Codec::XpressHuffman { size: len },
                    Kind::Lzx => Codec::Lzx(lzx::Params {
                        window_bits,
                        ..lzx::Params::wim_chunk(len)
                    }),
                };
                let mut decoder = codec.decoder().ok_or_else(|| Diagnostic::internal("no decoder"))?;
                let decoded = pipeline::decode_all(decoder.as_mut(), data, ulen)?;
                if decoded.len() != ulen {
                    return Err(bad("chunk decoded to the wrong size"));
                }
                out.extend_from_slice(&decoded);
            }
            self.index = i.saturating_add(1);
            self.consumed = table_len.saturating_add(to);
            if last {
                if out.len() != original {
                    return Err(bad("chunks do not add up to the resource size"));
                }
                self.done = true;
            } else if out.len().saturating_sub(mark) >= step {
                return Ok(Step::More);
            }
        }
        Ok(Step::Done)
    }

    fn consumed(&self) -> usize {
        self.consumed
    }
}
