//! Compressed WIM resources. Two framings (wimlib's `resource.c` describes
//! both):
//!
//! - A non-solid resource is a chunk table (one 4-byte, or for resources
//!   over 4 GiB 8-byte, offset per chunk after the first, relative to the
//!   end of the table), then the chunks.
//! - A solid resource (several streams compressed together, as in ESD
//!   files) starts with a 16-byte header (decoded size, chunk size and
//!   compression format, which override the image's), then a table of
//!   every chunk's compressed size (4 bytes each), then the chunks.
//!
//! Each chunk is compressed independently (XPRESS, LZX or LZMS), or stored
//! when compression did not shrink it; the last chunk runs to the end of
//! the resource. XPRESS and LZX chunks (at most 2 MiB) are decoded a whole
//! chunk per step; LZMS chunks, which solid resources make up to 1 GiB
//! (64 MiB by default), a bounded amount per step.

use std::sync::Arc;

use crate::codec::pipeline::{Decoder, Status};
use crate::codec::{Codec, lzms, lzx, pipeline};
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
    Lzms,
}

impl Kind {
    /// The compression format of a solid resource header (1 XPRESS, 2 LZX,
    /// 3 LZMS).
    pub fn from_solid_format(format: u32) -> Option<Kind> {
        match format {
            1 => Some(Kind::Xpress),
            2 => Some(Kind::Lzx),
            3 => Some(Kind::Lzms),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Kind::Xpress => "XPRESS",
            Kind::Lzx => "LZX",
            Kind::Lzms => "LZMS",
        }
    }
}

/// The size of a solid resource's header.
pub const SOLID_HEADER: usize = 16;

/// A compressed resource of `original` bytes in `chunk`-byte chunks; with
/// `solid`, in the solid framing (header included in the input).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Resource {
    pub kind: Kind,
    pub chunk: u32,
    pub original: u64,
    pub solid: bool,
}

/// Where the chunks are: each one's start, relative to the end of the
/// table.
#[derive(Clone, Debug)]
struct Table {
    starts: Arc<[u64]>,
    /// Header and table bytes before the first chunk.
    len: usize,
    /// Whether the starts never decrease (otherwise a chunk may lie in
    /// consumed input, which is then kept).
    ascending: bool,
}

/// An LZMS chunk in progress: its decoder, its decoded bytes so far (the
/// window its matches reach back into, before the x86 filter), and the
/// filter that writes them out.
#[derive(Clone, Debug)]
struct LzmsChunk {
    block: lzms::Block,
    window: Vec<u8>,
    filter: lzms::X86,
}

/// A [`Resource`] decoder. The table is copied out of the input by the
/// first step (shared, so checkpoints stay cheap), so that consumed input
/// can be released. A chunk is started only once all of its input is in,
/// so no step ever runs out of input halfway.
#[derive(Clone, Debug)]
pub struct WimDecoder {
    resource: Resource,
    table: Option<Table>,
    /// The next chunk (or the one in progress).
    index: u64,
    lzms: Option<LzmsChunk>,
    consumed: usize,
    /// Input and output bytes dropped from the front.
    released_in: usize,
    released_out: usize,
    done: bool,
}

impl WimDecoder {
    pub fn new(resource: Resource) -> Self {
        WimDecoder {
            resource,
            table: None,
            index: 0,
            lzms: None,
            consumed: 0,
            released_in: 0,
            released_out: 0,
            done: false,
        }
    }

    /// Decoders that start at every `every`-th chunk boundary (from chunk
    /// `every` on) of the resource whose input starts with `head` (its
    /// header and chunk table, or more): each chunk is compressed on its
    /// own, so a decoder needs no history. With each, its output position
    /// and its offset in the resource's input. Empty when `head` does not
    /// hold the whole table, or chunks start out of order.
    pub fn seeds(resource: Resource, head: &[u8], every: u64) -> Vec<(u64, u64, WimDecoder)> {
        let base = WimDecoder::new(resource);
        let Ok(Some(table)) = base.read_table(head, false) else {
            return Vec::new();
        };
        if !table.ascending {
            return Vec::new();
        }
        let chunk = u64::from(resource.chunk);
        let mut seeds = Vec::new();
        let mut k = every.max(1);
        while k < base.chunks() {
            let Some(&start) = usize::try_from(k).ok().and_then(|i| table.starts.get(i)) else {
                break;
            };
            let in_pos = start.saturating_add(u64::try_from(table.len).unwrap_or(u64::MAX));
            let (Ok(released_in), Some(out_pos)) = (usize::try_from(in_pos), k.checked_mul(chunk))
            else {
                break;
            };
            let Ok(released_out) = usize::try_from(out_pos) else {
                break;
            };
            seeds.push((
                out_pos,
                in_pos,
                WimDecoder {
                    table: Some(table.clone()),
                    index: k,
                    released_in,
                    released_out,
                    ..WimDecoder::new(resource)
                },
            ));
            k = k.saturating_add(every.max(1));
        }
        seeds
    }

    fn chunks(&self) -> u64 {
        // The empty resource is one empty chunk.
        self.resource
            .original
            .div_ceil(u64::from(self.resource.chunk))
            .max(1)
    }

    /// Reads the table, or returns `None` if the input does not hold it yet.
    fn read_table(&self, input: &[u8], eof: bool) -> Result<Option<Table>> {
        let r = self.resource;
        let chunks = self.chunks();
        let (entries, entry, skip) = if r.solid {
            (chunks, 4usize, SOLID_HEADER)
        } else if r.original > u64::from(u32::MAX) {
            (chunks.saturating_sub(1), 8, 0)
        } else {
            (chunks.saturating_sub(1), 4, 0)
        };
        let len = usize::try_from(entries)
            .ok()
            .and_then(|n| n.checked_mul(entry))
            .and_then(|n| n.checked_add(skip))
            .ok_or_else(|| bad("chunk table larger than the resource"))?;
        let Some(raw) = input.get(skip..len) else {
            return if eof {
                Err(bad("chunk table larger than the resource"))
            } else {
                Ok(None)
            };
        };
        let values = raw
            .chunks(entry)
            .map(|e| e.iter().rev().fold(0u64, |acc, &b| acc << 8 | u64::from(b)));
        let starts: Arc<[u64]> = if r.solid {
            // Sizes: the starts are their running sums.
            std::iter::once(0)
                .chain(values.scan(0u64, |sum, size| {
                    *sum = sum.saturating_add(size);
                    Some(*sum)
                }))
                .take(usize::try_from(chunks).unwrap_or(usize::MAX))
                .collect()
        } else {
            std::iter::once(0).chain(values).collect()
        };
        let ascending = starts.windows(2).all(|w| matches!(w, [a, b] if a <= b));
        Ok(Some(Table {
            starts,
            len,
            ascending,
        }))
    }
}

impl Decoder for WimDecoder {
    fn decode(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Status> {
        let r = self.resource;
        let chunk = u64::from(r.chunk);
        let max_chunk = match r.kind {
            Kind::Xpress | Kind::Lzx => 1 << 21,
            Kind::Lzms => lzms::MAX_BLOCK as u64,
        };
        if !chunk.is_power_of_two() || !(1 << 15..=max_chunk).contains(&chunk) {
            return Err(Diagnostic::unsupported(format!(
                "WIM chunk size {chunk:#x}"
            )));
        }
        let original = usize::try_from(r.original).map_err(|_| bad("too large"))?;
        if original > limit.saturating_add(self.released_out) {
            return Err(Diagnostic::output_limit(limit));
        }
        if self.done {
            return Ok(Status::Done);
        }
        let table = match &self.table {
            Some(table) => table.clone(),
            None => match self.read_table(input, eof)? {
                Some(table) => {
                    self.table = Some(table.clone());
                    table
                }
                None => return Ok(Status::NeedInput),
            },
        };
        let chunks = self.chunks();
        // Where chunk `i` starts in the input as it is now.
        let released_in = self.released_in;
        let start_of = |i: u64| -> Result<usize> {
            let offset = usize::try_from(i)
                .ok()
                .and_then(|i| table.starts.get(i))
                .ok_or_else(|| bad("truncated chunk table"))?;
            usize::try_from(*offset)
                .ok()
                .and_then(|o| o.checked_add(table.len))
                .and_then(|at| at.checked_sub(released_in))
                .ok_or_else(|| bad("chunk outside the resource"))
        };
        let window_bits = u8::try_from(chunk.trailing_zeros()).unwrap_or(15);
        let mark = out.len();
        let waiting = |out: &Vec<u8>| -> Result<Status> {
            Ok(if out.len() > mark {
                Status::More
            } else {
                Status::NeedInput
            })
        };
        loop {
            let i = self.index;
            let last = i.saturating_add(1) >= chunks;
            if last && !eof {
                return waiting(out);
            }
            let from = start_of(i)?;
            let to = if last {
                input.len()
            } else {
                start_of(i.saturating_add(1))?
            };
            if to > input.len() {
                if eof {
                    return Err(bad("chunk outside the resource"));
                }
                return waiting(out);
            }
            let data = input
                .get(from..to)
                .ok_or_else(|| bad("chunk outside the resource"))?;
            let len = chunk.min(r.original.saturating_sub(i.saturating_mul(chunk)));
            let ulen = usize::try_from(len).unwrap_or(usize::MAX);
            if let Some(cur) = &mut self.lzms {
                let budget = step.saturating_sub(out.len().saturating_sub(mark)).max(1);
                let until = cur.window.len().saturating_add(budget);
                cur.block.decode(data, &mut cur.window, until)?;
                cur.filter.run(&cur.window, out);
                if !cur.filter.done() {
                    if out.len().saturating_sub(mark) >= step {
                        return Ok(Status::More);
                    }
                    continue;
                }
                self.lzms = None;
            } else if data.len() >= ulen {
                out.extend_from_slice(data.get(..ulen).unwrap_or_default());
            } else if r.kind == Kind::Lzms {
                self.lzms = Some(LzmsChunk {
                    block: lzms::Block::new(data, ulen)?,
                    window: Vec::new(),
                    filter: lzms::X86::new(ulen),
                });
                continue;
            } else {
                let codec = match r.kind {
                    Kind::Xpress => Codec::XpressHuffman { size: len },
                    _ => Codec::Lzx(lzx::Params {
                        window_bits,
                        ..lzx::Params::wim_chunk(len)
                    }),
                };
                let mut decoder = codec
                    .decoder()
                    .ok_or_else(|| Diagnostic::internal("no decoder"))?;
                let decoded = pipeline::decode_all(decoder.as_mut(), data, ulen)?;
                if decoded.len() != ulen {
                    return Err(bad("chunk decoded to the wrong size"));
                }
                out.extend_from_slice(&decoded);
            }
            self.index = i.saturating_add(1);
            self.consumed = to;
            if last {
                if self.released_out.saturating_add(out.len()) != original {
                    return Err(bad("chunks do not add up to the resource size"));
                }
                self.done = true;
                return Ok(Status::Done);
            }
            if out.len().saturating_sub(mark) >= step {
                return Ok(Status::More);
            }
        }
    }

    fn consumed(&self) -> usize {
        self.consumed
    }

    fn warning(&self, _out: &[u8]) -> Option<Diagnostic> {
        None
    }

    fn releasable_input(&self) -> usize {
        // The table has been copied out before anything is consumed.
        if self.table.as_ref().is_some_and(|t| t.ascending) {
            self.consumed
        } else {
            0
        }
    }

    fn release_input(&mut self, n: usize) {
        self.consumed = self.consumed.saturating_sub(n);
        self.released_in = self.released_in.saturating_add(n);
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        // Chunks are independent, and an LZMS chunk keeps its own window.
        out_len
    }

    fn release_output(&mut self, n: usize) {
        self.released_out = self.released_out.saturating_add(n);
    }

    fn checkpoint(&self) -> Option<Box<dyn Decoder>> {
        Some(Box::new(self.clone()))
    }

    fn state_size(&self) -> usize {
        // Between chunks only the decoder itself (the table is shared);
        // inside an LZMS chunk, its window, filter and codes too.
        let chunk = self.lzms.as_ref().map_or(0, |c| {
            c.window
                .capacity()
                .saturating_add(c.filter.heap_size())
                .saturating_add(c.block.heap_size())
        });
        std::mem::size_of::<Self>().saturating_add(chunk)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use crate::codec::pipeline::verify_checkpoints;

    /// A resource of the LZX chunk from `tests/data/cab` (the test
    /// encoder's, checked with 7-Zip) and stored chunks, as
    /// `tests/on_demand.rs` builds it.
    #[test]
    fn checkpoints_between_chunks_are_free() {
        let lzx = std::fs::read(format!(
            "{}/../../tests/data/cab/wim-chunk.lzx",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let stored: Vec<u8> = (0..32768u32 * 2 + 1000)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        let chunks: Vec<&[u8]> = vec![
            &lzx,
            &stored[..32768],
            &lzx,
            &lzx,
            &stored[32768..65536],
            &lzx,
            &lzx,
            &stored[65536..],
        ];
        let (mut table, mut body) = (Vec::new(), Vec::new());
        for (i, data) in chunks.iter().enumerate() {
            if i > 0 {
                table.extend_from_slice(&(body.len() as u32).to_le_bytes());
            }
            body.extend_from_slice(data);
        }
        let input = [table, body].concat();
        let resource = Resource {
            kind: Kind::Lzx,
            chunk: 32768,
            original: 32768 * 7 + 1000,
            solid: false,
        };
        let (checked, largest) =
            verify_checkpoints(|| Box::new(WimDecoder::new(resource)), &input, 1, 1).unwrap();
        assert_eq!(checked, 7);
        assert_eq!(largest, std::mem::size_of::<WimDecoder>());

        // Decoders seeded at chunk boundaries give the tail of the output.
        let whole = pipeline::decode_all(&mut WimDecoder::new(resource), &input, 1 << 20).unwrap();
        let seeds = WimDecoder::seeds(resource, &input, 2);
        assert_eq!(
            seeds.iter().map(|s| s.0).collect::<Vec<_>>(),
            [65536, 131072, 196608]
        );
        for (out_pos, in_pos, mut decoder) in seeds {
            let tail =
                pipeline::decode_all(&mut decoder, &input[in_pos as usize..], 1 << 20).unwrap();
            assert_eq!(tail, whole[out_pos as usize..], "seed at {out_pos:#x}");
        }
        // Not without the whole table.
        assert!(WimDecoder::seeds(resource, &input[..10], 2).is_empty());
    }

    fn le64(b: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
    }

    /// Decodes every stream of a wimlib-written image (see
    /// `tests/data/wim/make.sh`) and checks it against the SHA-1 its lookup
    /// table entry records; resources are decoded in small steps with a
    /// checkpoint taken and resumed after every few.
    fn check_image(name: &str) -> usize {
        use crate::codec::crypto::hash::{Hash, Sha1};
        let file = std::fs::read(format!(
            "{}/../../tests/fixtures/external/wim/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let flags = u32::from_le_bytes(file[16..20].try_into().unwrap());
        let chunk = u32::from_le_bytes(file[20..24].try_into().unwrap());
        let kind = match flags {
            f if f & 0x2_0000 != 0 => Kind::Xpress,
            f if f & 0x4_0000 != 0 => Kind::Lzx,
            _ => Kind::Lzms,
        };
        let (size, _, offset, _) = res_of(&file[48..72]);
        let table = &file[offset as usize..(offset + size) as usize];
        let decode = |r: Resource, data: &[u8]| -> Vec<u8> {
            verify_checkpoints(|| Box::new(WimDecoder::new(r)), data, 4096, 3).unwrap();
            pipeline::decode_all(&mut WimDecoder::new(r), data, 1 << 30).unwrap()
        };
        let mut solid: Vec<u8> = Vec::new();
        let mut checked = 0;
        let entries: Vec<_> = table.chunks(50).collect();
        // Solid resources first: blobs refer to their concatenation.
        for e in &entries {
            let (size, flags, offset, original) = res_of(e);
            if flags & 0x10 != 0 && original == 1 << 32 {
                let data = &file[offset as usize..(offset + size) as usize];
                let usize_ = le64(data, 0);
                let r = Resource {
                    kind: Kind::from_solid_format(u32::from_le_bytes(
                        data[12..16].try_into().unwrap(),
                    ))
                    .unwrap(),
                    chunk: u32::from_le_bytes(data[8..12].try_into().unwrap()),
                    original: usize_,
                    solid: true,
                };
                solid.extend(decode(r, data));
            }
        }
        for e in &entries {
            let (size, flags, offset, original) = res_of(e);
            let sha = &e[30..50];
            let stream = if flags & 0x10 != 0 {
                if original == 1 << 32 {
                    continue;
                }
                solid[offset as usize..(offset + size) as usize].to_vec()
            } else if flags & 0x04 != 0 {
                let data = &file[offset as usize..(offset + size) as usize];
                decode(
                    Resource {
                        kind,
                        chunk,
                        original,
                        solid: false,
                    },
                    data,
                )
            } else {
                file[offset as usize..(offset + size) as usize].to_vec()
            };
            assert_eq!(Sha1::digest(&stream), sha, "{name}: stream at {offset:#x}");
            checked += 1;
        }
        checked
    }

    fn res_of(e: &[u8]) -> (u64, u8, u64, u64) {
        (
            le64(e, 0) & 0xff_ffff_ffff_ffff,
            e[7],
            le64(e, 8),
            le64(e, 16),
        )
    }

    #[test]
    fn decodes_wimlib_lzms_images() {
        assert_eq!(check_image("lzms.wim"), 5);
        assert_eq!(check_image("solid.esd"), 5);
        assert_eq!(check_image("solid-lzx.wim"), 2);
    }

    /// A solid LZMS chunk of 16 MiB (zeros, from wimlib; long matches) is
    /// decoded a bounded amount per step, and a checkpoint inside it
    /// counts its window.
    #[test]
    fn large_lzms_chunks_decode_in_bounded_steps() {
        let file = std::fs::read(format!(
            "{}/../../tests/data/wim/zeros.esd",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let (len, _, at, _) = res_of(&file[48..72]);
        let entries: Vec<&[u8]> = file[at as usize..(at + len) as usize].chunks(50).collect();
        let e = entries
            .iter()
            .find(|e| e[7] & 0x10 != 0 && le64(e, 16) == 1 << 32)
            .unwrap();
        let (size, _, offset, _) = res_of(e);
        let data = &file[offset as usize..(offset + size) as usize];
        let r = Resource {
            kind: Kind::Lzms,
            chunk: u32::from_le_bytes(data[8..12].try_into().unwrap()),
            original: le64(data, 0),
            solid: true,
        };
        assert_eq!((r.chunk, r.original), (1 << 24, 1 << 24));
        let mut d = WimDecoder::new(r);
        let mut out = Vec::new();
        let mut calls = 0;
        loop {
            let before = out.len();
            let status = d.decode(data, true, &mut out, 65536, 1 << 30).unwrap();
            assert!(
                out.len() - before <= 65536 + 16,
                "{} bytes in one step",
                out.len() - before
            );
            calls += 1;
            if calls == 10 {
                assert!(d.state_size() > out.len());
            }
            if status == Status::Done {
                break;
            }
        }
        assert!(calls >= 256);
        assert_eq!(out.len(), 1 << 24);
        assert!(out.iter().all(|&b| b == 0));
    }
}
