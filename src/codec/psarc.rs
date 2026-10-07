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

use std::sync::Arc;

use crate::codec::Codec;
use crate::codec::pipeline::{Decode, Step, decode_all};
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

/// Decodes an [`Entry`] a block per step.
#[derive(Clone, Debug)]
pub struct Decoder {
    entry: Entry,
    /// The next block's index and input position.
    block: usize,
    at: usize,
    produced: u64,
}

impl Decoder {
    pub fn new(entry: Entry) -> Self {
        Decoder {
            entry,
            block: 0,
            at: 0,
            produced: 0,
        }
    }
}

impl Decode for Decoder {
    fn step(
        &mut self,
        input: &[u8],
        _eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        let goal = out.len().saturating_add(step);
        let block_size = u64::from(self.entry.block_size.max(1));
        loop {
            let left = self.entry.size.saturating_sub(self.produced);
            if left == 0 {
                return Ok(Step::Done);
            }
            if out.len() >= goal {
                return Ok(Step::More);
            }
            let Some(&stored) = self.entry.blocks.get(self.block) else {
                return Err(bad(format!(
                    "{:#x} bytes missing after the last block",
                    left
                )));
            };
            let want = left.min(block_size);
            let len = if stored == 0 {
                block_size
            } else {
                u64::from(stored)
            };
            let len = usize::try_from(len).unwrap_or(usize::MAX);
            let end = self.at.saturating_add(len);
            let data = input
                .get(self.at..end)
                .ok_or_else(|| bad(format!("block {} truncated", self.block)))?;
            let want_us = usize::try_from(want).unwrap_or(usize::MAX);
            let decoded = if stored == 0 || u64::from(stored) == want {
                data.get(..want_us).unwrap_or(data).to_vec()
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
                let mut d = codec.decoder().ok_or_else(|| bad("no decoder"))?;
                let block = decode_all(d.as_mut(), data, want_us)?;
                if let Some(w) = d.warning(&block) {
                    return Err(w);
                }
                if block.len() != want_us {
                    return Err(bad(format!(
                        "block {} decoded to {:#x} bytes, expected {want:#x}",
                        self.block,
                        block.len()
                    )));
                }
                block
            };
            if self
                .produced
                .saturating_add(crate::bytes::to_u64(decoded.len()))
                > crate::bytes::to_u64(limit)
            {
                return Err(Diagnostic::limit(format!(
                    "decompressed data exceeds {limit:#x} bytes"
                )));
            }
            self.produced = self
                .produced
                .saturating_add(crate::bytes::to_u64(decoded.len()));
            out.extend_from_slice(&decoded);
            self.at = end;
            self.block = self.block.saturating_add(1);
        }
    }

    fn consumed(&self) -> usize {
        self.at
    }

    fn releasable_input(&self) -> usize {
        self.at
    }

    fn release_input(&mut self, n: usize) {
        self.at = self.at.saturating_sub(n);
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        out_len
    }
}
