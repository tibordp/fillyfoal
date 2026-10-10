//! A cabinet folder's data blocks (`CFDATA`) through the folder's codec.
//!
//! Each block is a checksum, packed and unpacked sizes, `data_reserve`
//! reserved bytes and the packed data; the folder's uncompressed stream is
//! the concatenation of the blocks' output. How blocks relate depends on
//! the method (bits 0..3 of the folder's compression type; bits 8..12 are
//! the window size for Quantum and LZX):
//! - 0, none: the data is stored.
//! - 1, MSZIP: `CK` and a DEFLATE stream ending in a final block; its
//!   distances may reach back into the previous block's output (a 32 KiB
//!   preset dictionary).
//! - 2, Quantum: one frame per block, the arithmetic coder restarting at
//!   each (models and window carry over).
//! - 3, LZX: the blocks' data concatenated form one LZX stream, each
//!   block's unpacked size being one frame.
//!
//! The decoder works block by block, so a folder is decoded lazily, as far
//! as reads reach. Folders continued from or to another cabinet are not
//! supported.

use crate::codec::inflate;
use crate::codec::lzx::{self, Lzx};
use crate::codec::pipeline::{Decoder, Status};
use crate::codec::quantum::Quantum;
use crate::error::{DiagKind, Diagnostic, Result};

/// MSZIP history carried from block to block.
const MSZIP_DICT: usize = 32 * 1024;

fn bad(what: impl std::fmt::Display) -> Diagnostic {
    Diagnostic::malformed(format!("cabinet folder: {what}"))
}

/// What a folder's data blocks need to be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Folder {
    /// The folder's compression type (`typeCompress`).
    pub kind: u16,
    /// Reserved bytes in every data block header (`cbCFData`).
    pub data_reserve: u8,
}

impl Folder {
    pub fn method(&self) -> u16 {
        self.kind & 0x0f
    }

    pub fn window_bits(&self) -> u8 {
        u8::try_from(self.kind >> 8 & 0x1f).unwrap_or(0)
    }
}

enum Method {
    Stored,
    Mszip,
    Quantum(Quantum),
    Lzx {
        core: Lzx,
        /// The concatenated data of the blocks parsed so far.
        stream: Vec<u8>,
        /// Unpacked sizes of blocks parsed but not decoded yet.
        frames: std::collections::VecDeque<usize>,
    },
}

/// Decodes a folder's data blocks; see the module documentation.
pub struct FolderDecoder {
    folder: Folder,
    method: Result<Method>,
    /// The next block header in the input.
    at: usize,
    /// The last 32 KiB of output (MSZIP).
    dict: Vec<u8>,
}

impl FolderDecoder {
    pub fn new(folder: Folder) -> Self {
        let method = match folder.method() {
            0 => Ok(Method::Stored),
            1 => Ok(Method::Mszip),
            2 => Quantum::new(folder.window_bits()).map(Method::Quantum),
            3 => Lzx::new(lzx::Params::cab(folder.window_bits())).map(|core| Method::Lzx {
                core,
                stream: Vec::new(),
                frames: std::collections::VecDeque::new(),
            }),
            m => Err(Diagnostic::unsupported(format!(
                "cabinet compression method {m}"
            ))),
        };
        FolderDecoder {
            folder,
            method,
            at: 0,
            dict: Vec::new(),
        }
    }

    /// The next block, if all of it is in `input`: `(data, unpacked size,
    /// end)`.
    fn block(
        at: usize,
        reserve: u8,
        input: &[u8],
        eof: bool,
    ) -> Result<Option<(&[u8], usize, usize)>> {
        let head = 8usize.saturating_add(usize::from(reserve));
        let (Some(packed), Some(unpacked)) = (
            crate::bytes::u16_le(input, at.saturating_add(4)),
            crate::bytes::u16_le(input, at.saturating_add(6)),
        ) else {
            return if eof {
                Err(bad("truncated data block header"))
            } else {
                Ok(None)
            };
        };
        let start = at.saturating_add(head);
        let end = start.saturating_add(usize::from(packed));
        match input.get(start..end) {
            Some(data) => Ok(Some((data, usize::from(unpacked), end))),
            None if eof => Err(bad("truncated data block")),
            None => Ok(None),
        }
    }
}

fn check_limit(len: usize, limit: usize) -> Result<()> {
    if len > limit {
        Err(Diagnostic::output_limit(limit))
    } else {
        Ok(())
    }
}

impl Decoder for FolderDecoder {
    fn decode(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Status> {
        let target = out.len().saturating_add(step);
        let start_len = out.len();
        let method = self.method.as_mut().map_err(|e| e.clone())?;
        loop {
            // LZX: decode the frames whose data is all in (a frame may read
            // a pad byte from the next block).
            if let Method::Lzx {
                core,
                stream,
                frames,
            } = method
            {
                let ended = eof && self.at >= input.len();
                while let Some(&len) = frames.front() {
                    if frames.len() < 2 && !ended || out.len() >= target {
                        break;
                    }
                    frames.pop_front();
                    core.frame(stream, ended && frames.is_empty(), false, len, out, limit)?;
                    // Drop the data the core has read (it buffers bits
                    // read ahead), so `stream` holds about a block.
                    let used = core.consumed().min(stream.len());
                    core.release_input(used);
                    stream.drain(..used);
                }
            }
            if out.len() >= target {
                return Ok(Status::More);
            }
            if self.at >= input.len() {
                if !eof {
                    return Ok(if out.len() > start_len {
                        Status::More
                    } else {
                        Status::NeedInput
                    });
                }
                if let Method::Lzx { frames, .. } = method
                    && !frames.is_empty()
                {
                    continue;
                }
                return Ok(Status::Done);
            }
            let Some((data, unpacked, end)) =
                Self::block(self.at, self.folder.data_reserve, input, eof)?
            else {
                return Ok(if out.len() > start_len {
                    Status::More
                } else {
                    Status::NeedInput
                });
            };
            self.at = end;
            match method {
                Method::Stored => {
                    if data.len() != unpacked {
                        return Err(bad("stored block sizes differ"));
                    }
                    check_limit(out.len().saturating_add(data.len()), limit)?;
                    out.extend_from_slice(data);
                }
                Method::Mszip => {
                    let Some(body) = data.strip_prefix(b"CK") else {
                        return Err(bad("MSZIP block without 'CK' signature"));
                    };
                    check_limit(out.len().saturating_add(unpacked), limit)?;
                    let (block, _) = inflate::inflate_with_dictionary(body, &self.dict, unpacked)
                        .map_err(|e| {
                        if e.kind == DiagKind::Limit {
                            bad(format!(
                                "MSZIP block decodes to more than {unpacked:#x} bytes"
                            ))
                        } else {
                            e
                        }
                    })?;
                    if block.len() != unpacked {
                        return Err(bad(format!(
                            "MSZIP block decoded to {:#x} bytes, expected {unpacked:#x}",
                            block.len()
                        )));
                    }
                    self.dict.extend_from_slice(&block);
                    let excess = self.dict.len().saturating_sub(MSZIP_DICT);
                    self.dict.drain(..excess);
                    out.extend_from_slice(&block);
                }
                Method::Quantum(q) => q.frame(data, unpacked, out, limit)?,
                Method::Lzx { stream, frames, .. } => {
                    stream.extend_from_slice(data);
                    frames.push_back(unpacked);
                }
            }
        }
    }

    fn consumed(&self) -> usize {
        self.at
    }

    fn warning(&self, _out: &[u8]) -> Option<Diagnostic> {
        None
    }

    fn releasable_input(&self) -> usize {
        // Blocks before the next header are parsed (LZX copies their data).
        self.at
    }

    fn release_input(&mut self, n: usize) {
        self.at = self.at.saturating_sub(n);
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        // No method reads `out`: MSZIP keeps its own 32 KiB dictionary,
        // Quantum and LZX their own history.
        out_len
    }
}
