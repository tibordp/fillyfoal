//! Apple's chunked compression wrapper (`pbzx`, `pbze`, `pbz4`, `pbzz`),
//! as written by `aa` and used for OTA payloads: a 12-byte header (magic,
//! big-endian chunk size), then chunks of (uncompressed size, compressed
//! size, data). Each chunk is an independent stream in the algorithm the
//! magic names, or stored when both sizes are equal.
//!
//! [`Pbz`] waits for a whole chunk (its input) and then decodes it a step
//! at a time: a stored chunk is copied `step` bytes per call, a compressed
//! one runs through its own decoder ([`Nested`]) a step per call, and
//! Apple's LZ4 framing a `bv4` block per call (an LZ4 block is decoded
//! whole: the framing does not bound its size, but `aa` writes blocks of
//! 64 KiB or less).

use crate::codec::Codec;
use crate::codec::lz::lz4_block;
use crate::codec::pipeline::{Decoder, Status};
use crate::error::{Diagnostic, Result};

fn bad(what: &str) -> Diagnostic {
    Diagnostic::malformed(format!("pbz: {what}"))
}

fn too_large(limit: usize) -> Diagnostic {
    Diagnostic::limit(format!("decompressed data exceeds {limit:#x} bytes"))
}

fn u64_be(data: &[u8], at: usize) -> Option<u64> {
    data.get(at..at.checked_add(8)?)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_be_bytes)
}

fn u32_le(data: &[u8], at: usize) -> Option<u32> {
    data.get(at..at.checked_add(4)?)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
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

/// One independent stream inside a container (a pbz chunk, a PSARC block)
/// whose input is all there: decoded through its own decoder a step per
/// call, into a buffer of its own (its dictionary), whose new bytes are
/// appended to the container's output.
pub(crate) struct Nested {
    decoder: Box<dyn Decoder>,
    buf: Vec<u8>,
    done: bool,
}

impl Nested {
    pub(crate) fn new(codec: &Codec) -> Result<Self> {
        Ok(Nested {
            decoder: codec
                .decoder()
                .ok_or_else(|| Diagnostic::internal("no decoder"))?,
            buf: Vec::new(),
            done: false,
        })
    }

    /// Runs one step over `data` (the whole stream), producing at most
    /// `room` bytes in all, and appends the new output to `out`. Returns
    /// whether the stream has ended.
    pub(crate) fn pump(
        &mut self,
        data: &[u8],
        out: &mut Vec<u8>,
        step: usize,
        room: usize,
    ) -> Result<bool> {
        if self.done {
            return Ok(true);
        }
        let mark = self.buf.len();
        let status = self.decoder.decode(data, true, &mut self.buf, step, room)?;
        out.extend_from_slice(self.buf.get(mark..).unwrap_or_default());
        match status {
            Status::Done => self.done = true,
            Status::More => {}
            Status::NeedInput => return Err(Diagnostic::malformed("stream ended early")),
        }
        Ok(self.done)
    }

    /// Bytes produced so far.
    pub(crate) fn produced(&self) -> usize {
        self.buf.len()
    }

    /// The decoder's warning (a checksum mismatch), once ended.
    pub(crate) fn warning(&self) -> Option<Diagnostic> {
        self.decoder.warning(&self.buf)
    }
}

/// The chunk being decoded.
enum Chunk {
    /// Copied as is; `copied` bytes so far.
    Stored { copied: usize },
    /// Through the chunk algorithm's decoder.
    Nested(Nested),
    /// Apple's LZ4 framing (`bv41` LZ4 blocks, `bv4-` stored blocks, ended
    /// by `bv4$`); blocks may refer back into earlier blocks' output, which
    /// `buf` keeps. `at` is the next block's offset in the chunk.
    Bv4 { at: usize, buf: Vec<u8> },
}

/// The current chunk, with its data's input position and length, and its
/// decoded size.
struct Current {
    chunk: Chunk,
    start: usize,
    packed: usize,
    raw: usize,
}

/// A pbz stream, decoded a step at a time (see the module docs).
#[derive(Default)]
pub struct Pbz {
    /// The next chunk header's input position (the current chunk's, while
    /// one is being decoded).
    pos: usize,
    /// The magic's last byte, once the header has been read.
    algorithm: Option<u8>,
    current: Option<Current>,
    done: bool,
}

/// Decodes the `bv4` block at `at` of `data` into `buf`; returns the next
/// block's offset, or `None` at the end marker.
fn bv4_block(data: &[u8], at: usize, buf: &mut Vec<u8>, limit: usize) -> Result<Option<usize>> {
    let magic = data
        .get(at..at.saturating_add(4))
        .ok_or_else(|| bad("truncated LZ4 block header"))?;
    let field = |i: usize| -> Result<usize> {
        let v =
            u32_le(data, at.saturating_add(i)).ok_or_else(|| bad("truncated LZ4 block header"))?;
        usize::try_from(v).map_err(|_| bad("LZ4 block too large"))
    };
    match magic {
        b"bv4$" => Ok(None),
        b"bv41" => {
            let raw = field(4)?;
            let packed = field(8)?;
            let start = at.saturating_add(12);
            let block = data
                .get(start..start.saturating_add(packed))
                .ok_or_else(|| bad("truncated LZ4 block"))?;
            let before = buf.len();
            lz4_block(block, buf, limit)?;
            if buf.len().saturating_sub(before) != raw {
                return Err(bad("LZ4 block size mismatch"));
            }
            Ok(Some(start.saturating_add(packed)))
        }
        b"bv4-" => {
            let raw = field(4)?;
            let start = at.saturating_add(8);
            let block = data
                .get(start..start.saturating_add(raw))
                .ok_or_else(|| bad("truncated stored block"))?;
            if buf.len().saturating_add(raw) > limit {
                return Err(too_large(limit));
            }
            buf.extend_from_slice(block);
            Ok(Some(start.saturating_add(raw)))
        }
        _ => Err(bad("unknown LZ4 block magic")),
    }
}

impl Pbz {
    /// Starts the chunk at `pos` once all of it has arrived, or says why
    /// not (the end of the stream, or more input needed).
    fn start(
        &mut self,
        algorithm: u8,
        input: &[u8],
        eof: bool,
        room: usize,
        limit: usize,
    ) -> Result<Option<Status>> {
        let pos = self.pos;
        if pos >= input.len() {
            if !eof {
                return Ok(Some(Status::NeedInput));
            }
            self.pos = input.len();
            self.done = true;
            return Ok(Some(Status::Done));
        }
        let (Some(raw), Some(packed)) = (u64_be(input, pos), u64_be(input, pos.saturating_add(8)))
        else {
            return if eof {
                Err(bad("truncated chunk header"))
            } else {
                Ok(Some(Status::NeedInput))
            };
        };
        let raw = usize::try_from(raw).map_err(|_| bad("chunk too large"))?;
        let packed = usize::try_from(packed).map_err(|_| bad("chunk too large"))?;
        let start = pos.saturating_add(16);
        let Some(data) = input.get(start..start.saturating_add(packed)) else {
            return if eof {
                Err(bad("truncated chunk"))
            } else {
                Ok(Some(Status::NeedInput))
            };
        };
        let chunk = if raw == packed || !looks_compressed(algorithm, data) {
            if data.len() > room {
                return Err(too_large(limit));
            }
            Chunk::Stored { copied: 0 }
        } else {
            match algorithm {
                b'x' => Chunk::Nested(Nested::new(&Codec::Xz)?),
                b'e' => Chunk::Nested(Nested::new(&Codec::Lzfse)?),
                b'z' => Chunk::Nested(Nested::new(&Codec::Zlib)?),
                _ => Chunk::Bv4 {
                    at: 0,
                    buf: Vec::new(),
                },
            }
        };
        self.current = Some(Current {
            chunk,
            start,
            packed,
            raw,
        });
        Ok(None)
    }
}

impl Decoder for Pbz {
    fn decode(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Status> {
        if self.done {
            return Ok(Status::Done);
        }
        let algorithm = match self.algorithm {
            Some(a) => a,
            None => {
                let a = match input.get(..4) {
                    Some([b'p', b'b', b'z', a @ (b'x' | b'e' | b'4' | b'z')]) => *a,
                    None if !eof => return Ok(Status::NeedInput),
                    _ => return Err(bad("not a pbz stream")),
                };
                self.algorithm = Some(a);
                self.pos = 12;
                a
            }
        };
        if self.current.is_none() {
            let room = limit.saturating_sub(out.len());
            if let Some(status) = self.start(algorithm, input, eof, room, limit)? {
                return Ok(status);
            }
        }
        let Some(cur) = self.current.as_mut() else {
            return Ok(Status::More);
        };
        let data = input
            .get(cur.start..cur.start.saturating_add(cur.packed))
            .unwrap_or_default();
        let step = step.max(1);
        let finished = match &mut cur.chunk {
            Chunk::Stored { copied } => {
                let n = step.min(cur.packed.saturating_sub(*copied));
                out.extend_from_slice(
                    data.get(*copied..copied.saturating_add(n))
                        .unwrap_or_default(),
                );
                *copied = copied.saturating_add(n);
                *copied >= cur.packed
            }
            Chunk::Nested(nested) => {
                // The chunk may produce what the limit left at its start.
                let room = limit
                    .saturating_sub(out.len())
                    .saturating_add(nested.produced());
                let ended = nested.pump(data, out, step, room)?;
                if nested.produced() > cur.raw || ended && nested.produced() != cur.raw {
                    return Err(bad("chunk size mismatch"));
                }
                ended
            }
            Chunk::Bv4 { at, buf } => {
                let room = limit.saturating_sub(out.len()).saturating_add(buf.len());
                let mark = buf.len();
                let next = bv4_block(data, *at, buf, room)?;
                out.extend_from_slice(buf.get(mark..).unwrap_or_default());
                match next {
                    _ if buf.len() > cur.raw => return Err(bad("chunk size mismatch")),
                    Some(n) => {
                        *at = n;
                        false
                    }
                    None if buf.len() != cur.raw => return Err(bad("chunk size mismatch")),
                    None => true,
                }
            }
        };
        if finished {
            self.pos = cur.start.saturating_add(cur.packed);
            self.current = None;
        }
        Ok(Status::More)
    }

    fn consumed(&self) -> usize {
        self.pos
    }

    fn warning(&self, _out: &[u8]) -> Option<Diagnostic> {
        None
    }

    fn releasable_input(&self) -> usize {
        // Chunks are read whole from `pos`; the header is parsed once.
        self.pos
    }

    fn release_input(&mut self, n: usize) {
        self.pos = self.pos.saturating_sub(n);
        if let Some(cur) = self.current.as_mut() {
            cur.start = cur.start.saturating_sub(n);
        }
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        // Chunks are independent streams, and keep their own history.
        out_len
    }
}
