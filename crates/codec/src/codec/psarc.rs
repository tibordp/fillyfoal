//! A PlayStation archive (PSARC) entry's blocks.
//!
//! An entry is split into blocks of the archive's block size, stored back
//! to back from the entry's offset; the archive's block-size table gives
//! each one's stored length. A length of zero stands for a whole block
//! stored as is; a block whose stored length equals its decoded length is
//! stored too; any other block is one zlib stream or one `.lzma` ("LZMA
//! alone") stream, whichever its first bytes look like (the header names
//! the archive's codec, but packers store incompressible blocks raw).
//! Written from memory of the format as documented by the community
//! tools; see `formats::games::archives`.
//!
//! [`Decoder`] waits for a whole block (its input) and then decodes it a
//! step at a time: a stored block is copied `step` bytes per call, a
//! compressed one runs through its own decoder a step per call. The block
//! size comes from the file (usually 64 KiB, but up to 4 GiB), so nothing
//! is decoded in one piece.

use std::sync::Arc;

use crate::codec::Codec;
use crate::codec::pbz::Nested;
use crate::codec::pipeline::Status;
use crate::error::{Diagnostic, Result};

fn bad(what: impl std::fmt::Display) -> Diagnostic {
    Diagnostic::malformed(format!("PSARC entry: {what}"))
}

/// What an entry's blocks need to be decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The archive's block size.
    pub block_size: u32,
    /// The entry's decoded size.
    pub size: u64,
    /// The stored lengths of the entry's blocks (from the block-size
    /// table; 0 is a whole stored block).
    pub blocks: Arc<[u32]>,
}

/// How the current block decodes.
enum Kind {
    /// Copied as is; `copied` bytes so far.
    Stored {
        copied: usize,
    },
    Nested(Nested),
}

/// The block being decoded: its kind, where its input ends, and its
/// decoded size.
struct Block {
    kind: Kind,
    end: usize,
    want: usize,
}

/// Decodes an [`Entry`] a step at a time (see the module docs).
pub struct Decoder {
    entry: Entry,
    /// The next block's index and input position (the current block's,
    /// while one is being decoded).
    block: usize,
    at: usize,
    produced: u64,
    current: Option<Block>,
}

impl Decoder {
    pub fn new(entry: Entry) -> Self {
        Decoder {
            entry,
            block: 0,
            at: 0,
            produced: 0,
            current: None,
        }
    }

    /// Starts the next block once all of it has arrived, or says why not
    /// (the end of the entry, or more input needed).
    fn start(&mut self, input: &[u8], eof: bool, limit: usize) -> Result<Option<Status>> {
        let left = self.entry.size.saturating_sub(self.produced);
        if left == 0 {
            return Ok(Some(Status::Done));
        }
        let Some(&stored) = self.entry.blocks.get(self.block) else {
            return Err(bad(format!(
                "{:#x} bytes missing after the last block",
                left
            )));
        };
        let block_size = u64::from(self.entry.block_size.max(1));
        let want = left.min(block_size);
        let len = if stored == 0 {
            block_size
        } else {
            u64::from(stored)
        };
        let len = usize::try_from(len).unwrap_or(usize::MAX);
        let end = self.at.saturating_add(len);
        let Some(data) = input.get(self.at..end) else {
            return if eof {
                Err(bad(format!("block {} truncated", self.block)))
            } else {
                Ok(Some(Status::NeedInput))
            };
        };
        if self.produced.saturating_add(want) > crate::bytes::to_u64(limit) {
            return Err(Diagnostic::limit(format!(
                "decompressed data exceeds {limit:#x} bytes"
            )));
        }
        let want = usize::try_from(want).unwrap_or(usize::MAX);
        let kind = if stored == 0 || u64::from(stored) == crate::bytes::to_u64(want) {
            Kind::Stored { copied: 0 }
        } else {
            let codec = match data {
                [0x78, ..] => Codec::Zlib,
                [0x5d, 0, 0, ..] => Codec::LzmaAlone,
                _ => {
                    return Err(bad(format!(
                        "block {} is neither zlib nor LZMA",
                        self.block
                    )));
                }
            };
            Kind::Nested(Nested::new(&codec)?)
        };
        self.current = Some(Block { kind, end, want });
        Ok(None)
    }
}

impl crate::codec::pipeline::Decoder for Decoder {
    fn decode(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Status> {
        if self.current.is_none()
            && let Some(status) = self.start(input, eof, limit)?
        {
            return Ok(status);
        }
        let Some(cur) = self.current.as_mut() else {
            return Ok(Status::More);
        };
        let data = input.get(self.at..cur.end).unwrap_or_default();
        let mark = out.len();
        let finished = match &mut cur.kind {
            Kind::Stored { copied } => {
                let take = cur.want.min(data.len());
                let n = step.max(1).min(take.saturating_sub(*copied));
                out.extend_from_slice(
                    data.get(*copied..copied.saturating_add(n))
                        .unwrap_or_default(),
                );
                *copied = copied.saturating_add(n);
                *copied >= take
            }
            Kind::Nested(nested) => {
                let ended = nested.pump(data, out, step, cur.want)?;
                if ended {
                    if let Some(w) = nested.warning() {
                        return Err(w);
                    }
                    if nested.produced() != cur.want {
                        return Err(bad(format!(
                            "block {} decoded to {:#x} bytes, expected {:#x}",
                            self.block,
                            nested.produced(),
                            cur.want
                        )));
                    }
                }
                ended
            }
        };
        self.produced = self
            .produced
            .saturating_add(crate::bytes::to_u64(out.len().saturating_sub(mark)));
        if finished {
            self.at = cur.end;
            self.block = self.block.saturating_add(1);
            self.current = None;
        }
        Ok(Status::More)
    }

    fn consumed(&self) -> usize {
        self.at
    }

    fn warning(&self, _out: &[u8]) -> Option<Diagnostic> {
        None
    }

    fn releasable_input(&self) -> usize {
        self.at
    }

    fn release_input(&mut self, n: usize) {
        self.at = self.at.saturating_sub(n);
        if let Some(cur) = self.current.as_mut() {
            cur.end = cur.end.saturating_sub(n);
        }
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        // Blocks are independent streams, and keep their own history.
        out_len
    }
}
