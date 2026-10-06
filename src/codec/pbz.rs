//! Apple's chunked compression wrapper (`pbzx`, `pbze`, `pbz4`, `pbzz`),
//! as written by `aa` and used for OTA payloads: a 12-byte header (magic,
//! big-endian chunk size), then chunks of (uncompressed size, compressed
//! size, data). Each chunk is an independent stream in the algorithm the
//! magic names, or stored when both sizes are equal.

use crate::codec::lz::lz4_block;
use crate::codec::pipeline::{self, Decode, Step};
use crate::codec::Codec;
use crate::error::{Diagnostic, Result};

fn bad(what: &str) -> Diagnostic {
    Diagnostic::malformed(format!("pbz: {what}"))
}

fn u64_be(data: &[u8], at: usize) -> Option<u64> {
    data.get(at..at.checked_add(8)?).and_then(|s| s.try_into().ok()).map(u64::from_be_bytes)
}

fn u32_le(data: &[u8], at: usize) -> Option<u32> {
    data.get(at..at.checked_add(4)?).and_then(|s| s.try_into().ok()).map(u32::from_le_bytes)
}

/// Apple's LZ4 framing: `bv41` (raw size, compressed size, LZ4 block),
/// `bv4-` (raw size, stored bytes), ended by `bv4$`. Blocks may refer back
/// into earlier blocks' output.
pub fn lz4_bv4(input: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<()> {
    let mut pos = 0usize;
    loop {
        let magic = input.get(pos..pos.saturating_add(4)).ok_or_else(|| bad("truncated LZ4 block header"))?;
        let field = |i: usize| -> Result<usize> {
            let v = u32_le(input, pos.saturating_add(i)).ok_or_else(|| bad("truncated LZ4 block header"))?;
            usize::try_from(v).map_err(|_| bad("LZ4 block too large"))
        };
        match magic {
            b"bv4$" => return Ok(()),
            b"bv41" => {
                let raw = field(4)?;
                let packed = field(8)?;
                let start = pos.saturating_add(12);
                let data = input.get(start..start.saturating_add(packed)).ok_or_else(|| bad("truncated LZ4 block"))?;
                let before = out.len();
                lz4_block(data, out, limit)?;
                if out.len().saturating_sub(before) != raw {
                    return Err(bad("LZ4 block size mismatch"));
                }
                pos = start.saturating_add(packed);
            }
            b"bv4-" => {
                let raw = field(4)?;
                let start = pos.saturating_add(8);
                let data = input.get(start..start.saturating_add(raw)).ok_or_else(|| bad("truncated stored block"))?;
                if out.len().saturating_add(raw) > limit {
                    return Err(Diagnostic::limit(format!("decompressed data exceeds {limit:#x} bytes")));
                }
                out.extend_from_slice(data);
                pos = start.saturating_add(raw);
            }
            _ => return Err(bad("unknown LZ4 block magic")),
        }
    }
}

/// Whether a chunk's data is compressed with `algorithm` (the magic's last
/// byte). Stored chunks normally have equal sizes, but some writers record
/// the nominal chunk size, so they are recognised by content.
pub fn looks_compressed(algorithm: u8, data: &[u8]) -> bool {
    match algorithm {
        b'x' => data.starts_with(b"\xfd7zXZ\0"),
        b'e' => data.starts_with(b"bvx"),
        b'4' => data.starts_with(b"bv4"),
        _ => data.first().is_some_and(|b| b & 0x0f == 8),
    }
}

/// A pbz stream, decoded a chunk per step (each chunk through its own
/// decoder, to the end of the chunk).
#[derive(Clone, Default)]
pub struct Pbz {
    pos: usize,
    done: bool,
}

/// Decodes one compressed chunk (`algorithm` is the magic's last byte).
fn chunk(algorithm: u8, data: &[u8], room: usize) -> Result<Vec<u8>> {
    let codec = match algorithm {
        b'x' => Codec::Xz,
        b'e' => Codec::Lzfse,
        b'z' => Codec::Zlib,
        _ => {
            let mut v = Vec::new();
            lz4_bv4(data, &mut v, room)?;
            return Ok(v);
        }
    };
    let mut decoder = codec.decoder().ok_or_else(|| Diagnostic::internal("no chunk decoder"))?;
    pipeline::decode_all(decoder.as_mut(), data, room)
}

impl Decode for Pbz {
    fn step(&mut self, input: &[u8], eof: bool, out: &mut Vec<u8>, step: usize, limit: usize) -> Result<Step> {
        let algorithm = match input.get(..4) {
            Some([b'p', b'b', b'z', a @ (b'x' | b'e' | b'4' | b'z')]) => *a,
            _ => return Err(bad("not a pbz stream")),
        };
        self.pos = self.pos.max(12);
        let mark = out.len();
        while !self.done {
            let pos = self.pos;
            if pos >= input.len() {
                if !eof {
                    return Err(bad("truncated chunk header"));
                }
                self.pos = input.len();
                self.done = true;
                break;
            }
            let raw = u64_be(input, pos).ok_or_else(|| bad("truncated chunk header"))?;
            let packed = u64_be(input, pos.saturating_add(8)).ok_or_else(|| bad("truncated chunk header"))?;
            let raw = usize::try_from(raw).map_err(|_| bad("chunk too large"))?;
            let packed = usize::try_from(packed).map_err(|_| bad("chunk too large"))?;
            let start = pos.saturating_add(16);
            let data = input.get(start..start.saturating_add(packed)).ok_or_else(|| bad("truncated chunk"))?;
            let room = limit.saturating_sub(out.len());
            let compressed = looks_compressed(algorithm, data);
            if raw == packed || !compressed {
                if data.len() > room {
                    return Err(Diagnostic::limit(format!("decompressed data exceeds {limit:#x} bytes")));
                }
                out.extend_from_slice(data);
            } else {
                let decoded = chunk(algorithm, data, room)?;
                if decoded.len() != raw {
                    return Err(bad("chunk size mismatch"));
                }
                if decoded.len() > room {
                    return Err(Diagnostic::limit(format!("decompressed data exceeds {limit:#x} bytes")));
                }
                out.extend_from_slice(&decoded);
            }
            self.pos = start.saturating_add(packed);
            if out.len().saturating_sub(mark) >= step {
                return Ok(Step::More);
            }
        }
        Ok(Step::Done)
    }

    fn consumed(&self) -> usize {
        self.pos
    }
}
