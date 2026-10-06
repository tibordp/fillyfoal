//! The decoder interface shared by every codec, filter and cipher, and
//! chains of them.
//!
//! A codec author implements [`Decode`]: decode from *all input seen so far*
//! into *all output so far*, a bounded step at a time, treating a shortage
//! of input as an error. [`Streaming`] turns that into a resumable
//! [`Decoder`]: it snapshots the decoder before each step and, when input
//! ran out before the end of the stream, rolls back and asks for more. So
//! decoders are written as if the whole input were in memory, and still run
//! lazily, as far as reads reach.

use crate::error::{Diagnostic, Result};

/// Progress of a decoding step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// More output may follow; call again.
    More,
    /// The stream has ended.
    Done,
}

/// What a codec author implements.
pub trait Decode: Clone + Send + 'static {
    /// Decodes from `input` (everything fed so far; `eof` once no more will
    /// come) into `out` (everything produced so far) until at least `step`
    /// more bytes have been produced or the stream ends. Producing more
    /// than `limit` bytes in total is an error. Running out of input is an
    /// error too: the caller rolls back and retries with more.
    fn step(&mut self, input: &[u8], eof: bool, out: &mut Vec<u8>, step: usize, limit: usize) -> Result<Step>;

    /// Input bytes consumed so far.
    fn consumed(&self) -> usize;

    /// A problem that does not stop decoding (a checksum mismatch), once
    /// the stream has ended.
    fn warning(&self, _out: &[u8]) -> Option<Diagnostic> {
        None
    }
}

/// Status of a [`Decoder`] step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Output was produced; call again for more.
    More,
    /// More input is needed before any further output.
    NeedInput,
    /// The stream has ended.
    Done,
}

/// A resumable decoder over growing buffers (object safe, chainable).
pub trait Decoder: Send {
    fn decode(&mut self, input: &[u8], eof: bool, out: &mut Vec<u8>, step: usize, limit: usize) -> Result<Status>;
    fn consumed(&self) -> usize;
    fn warning(&self, out: &[u8]) -> Option<Diagnostic>;
}

/// Adapts a [`Decode`] into a [`Decoder`] by rolling back steps that ran out
/// of input.
#[derive(Clone)]
pub struct Streaming<D>(pub D);

impl<D: Decode> Decoder for Streaming<D> {
    fn decode(&mut self, input: &[u8], eof: bool, out: &mut Vec<u8>, step: usize, limit: usize) -> Result<Status> {
        let saved = self.0.clone();
        let mark = out.len();
        match self.0.step(input, eof, out, step, limit) {
            Ok(Step::More) => Ok(Status::More),
            Ok(Step::Done) => Ok(Status::Done),
            Err(_) if !eof => {
                // Most likely a shortage of input; retry once more arrives.
                // A genuine error recurs at the end of the input.
                self.0 = saved;
                out.truncate(mark);
                Ok(Status::NeedInput)
            }
            Err(e) => Err(e),
        }
    }

    fn consumed(&self) -> usize {
        self.0.consumed()
    }

    fn warning(&self, out: &[u8]) -> Option<Diagnostic> {
        self.0.warning(out)
    }
}

/// Decoders applied in sequence: each stage's output is the next one's input.
pub struct Chain {
    stages: Vec<Stage>,
}

struct Stage {
    decoder: Box<dyn Decoder>,
    /// This stage's output so far (the next stage's input); unused for the
    /// last stage, which writes to the caller's buffer.
    out: Vec<u8>,
    done: bool,
}

impl Chain {
    pub fn new(decoders: Vec<Box<dyn Decoder>>) -> Self {
        Chain {
            stages: decoders
                .into_iter()
                .map(|decoder| Stage {
                    decoder,
                    out: Vec::new(),
                    done: false,
                })
                .collect(),
        }
    }

    /// Runs stage `i` (not the last) for one step, feeding it from the
    /// previous stage or the external input.
    fn pump(&mut self, i: usize, input: &[u8], eof: bool, step: usize, limit: usize) -> Result<Status> {
        let (before, rest) = self.stages.split_at_mut(i);
        let Some(stage) = rest.first_mut() else {
            return Ok(Status::Done);
        };
        if stage.done {
            return Ok(Status::Done);
        }
        let (src, src_eof) = match before.last() {
            Some(prev) => (prev.out.as_slice(), prev.done),
            None => (input, eof),
        };
        let status = stage.decoder.decode(src, src_eof, &mut stage.out, step, limit)?;
        if status == Status::Done {
            stage.done = true;
        }
        if status == Status::NeedInput && i > 0 {
            // Pull more from the stage before.
            let prev = i.saturating_sub(1);
            return match self.pump(prev, input, eof, step, limit)? {
                Status::NeedInput => Ok(Status::NeedInput),
                _ => Ok(Status::More),
            };
        }
        Ok(status)
    }
}

impl Decoder for Chain {
    fn decode(&mut self, input: &[u8], eof: bool, out: &mut Vec<u8>, step: usize, limit: usize) -> Result<Status> {
        let Some(last) = self.stages.len().checked_sub(1) else {
            // An empty chain copies its input.
            let from = out.len().min(input.len());
            out.extend_from_slice(input.get(from..).unwrap_or_default());
            return Ok(if eof { Status::Done } else { Status::NeedInput });
        };
        loop {
            let (before, rest) = self.stages.split_at_mut(last);
            let Some(stage) = rest.first_mut() else {
                return Ok(Status::Done);
            };
            let (src, src_eof) = match before.last() {
                Some(prev) => (prev.out.as_slice(), prev.done),
                None => (input, eof),
            };
            match stage.decoder.decode(src, src_eof, out, step, limit)? {
                Status::NeedInput if last > 0 => {
                    if self.pump(last.saturating_sub(1), input, eof, step, limit)? == Status::NeedInput {
                        return Ok(Status::NeedInput);
                    }
                }
                status => return Ok(status),
            }
        }
    }

    fn consumed(&self) -> usize {
        self.stages.first().map_or(0, |s| s.decoder.consumed())
    }

    fn warning(&self, out: &[u8]) -> Option<Diagnostic> {
        let last = self.stages.len().saturating_sub(1);
        self.stages.iter().enumerate().find_map(|(i, stage)| {
            let produced = if i == last { out } else { stage.out.as_slice() };
            stage.decoder.warning(produced)
        })
    }
}

/// Decodes a whole in-memory buffer (for tests and small inputs).
pub fn decode_all(decoder: &mut dyn Decoder, input: &[u8], limit: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        match decoder.decode(input, true, &mut out, usize::MAX, limit)? {
            Status::Done => return Ok(out),
            Status::More => {}
            Status::NeedInput => return Err(Diagnostic::malformed("stream ended early")),
        }
    }
}

/// A decoder that fails immediately (an invalid codec configuration).
#[derive(Clone)]
pub struct Failing(pub &'static str);

impl Decode for Failing {
    fn step(&mut self, _: &[u8], _: bool, _: &mut Vec<u8>, _: usize, _: usize) -> Result<Step> {
        Err(Diagnostic::malformed(self.0))
    }

    fn consumed(&self) -> usize {
        0
    }
}
