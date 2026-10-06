//! Compressed WIM resources: a chunk table (one 4-byte, or for resources
//! over 4 GiB 8-byte, offset per chunk after the first, relative to the end
//! of the table), then the chunks. Each chunk is compressed independently,
//! or stored when compression did not shrink it.

use crate::codec::filters::Filter;
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

impl Filter for Resource {
    fn apply(&self, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        let chunk = u64::from(self.chunk);
        if !chunk.is_power_of_two() || !(1 << 15..=1 << 21).contains(&chunk) {
            return Err(Diagnostic::unsupported(format!("WIM chunk size {chunk:#x}")));
        }
        let original = usize::try_from(self.original).map_err(|_| bad("too large"))?;
        if original > limit {
            return Err(Diagnostic::limit(format!("decompressed data exceeds {limit:#x} bytes")));
        }
        let chunks = self.original.div_ceil(chunk);
        let entry: usize = if self.original > u64::from(u32::MAX) { 8 } else { 4 };
        let table_len = usize::try_from(chunks.saturating_sub(1))
            .ok()
            .and_then(|n| n.checked_mul(entry))
            .filter(|&n| n <= input.len())
            .ok_or_else(|| bad("chunk table larger than the resource"))?;
        let (table, body) = input.split_at_checked(table_len).ok_or_else(|| bad("truncated chunk table"))?;
        let mut starts = vec![0usize];
        for e in table.chunks_exact(entry) {
            let v = e.iter().rev().fold(0u64, |acc, &b| acc << 8 | u64::from(b));
            starts.push(usize::try_from(v).map_err(|_| bad("bad chunk offset"))?);
        }
        starts.push(body.len());
        let window_bits = u8::try_from(chunk.trailing_zeros()).unwrap_or(15);
        let mut out = Vec::with_capacity(original);
        for (i, pair) in starts.windows(2).enumerate() {
            let [from, to] = *pair else { break };
            let data = body.get(from..to).ok_or_else(|| bad("chunk outside the resource"))?;
            let done = u64::try_from(i).unwrap_or(u64::MAX).saturating_mul(chunk);
            let len = chunk.min(self.original.saturating_sub(done));
            let ulen = usize::try_from(len).unwrap_or(usize::MAX);
            if data.len() >= ulen {
                out.extend_from_slice(data.get(..ulen).unwrap_or_default());
                continue;
            }
            let codec = match self.kind {
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
        if out.len() != original {
            return Err(bad("chunks do not add up to the resource size"));
        }
        Ok(out)
    }
}
