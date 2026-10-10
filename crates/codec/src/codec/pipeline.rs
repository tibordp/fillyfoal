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
//!
//! # Releasing
//!
//! A long lazily decoded stream would keep all its input and output. A
//! decoder that can tell what it no longer needs lets the caller drop it:
//! [`Decode::releasable_input`] is input it will never read again (what it
//! has consumed, give or take a partial byte), and
//! [`Decode::releasable_output`] is output before its window (the history
//! its back-references can reach). The caller drops at most that many bytes
//! from the front and calls `release_input`/`release_output` with the
//! amount, and the decoder shifts the positions it keeps by it. From then
//! on `input` and `out` start later than the stream does; `consumed` and
//! every position are relative to the buffers as they are now. A decoder
//! that releases output must not checksum `out` in [`Decode::warning`]:
//! it keeps running checksums instead. The defaults release nothing.
//!
//! # Checkpoints
//!
//! A lazily decoded stream is decoded forwards; reading behind what it
//! still holds would mean decoding again from the start. A decoder that can
//! be cloned cheaply lets the caller keep checkpoints instead: a clone of
//! the decoder, released down to its window (the output its history still
//! reaches) and to its unread input, plus the window bytes. Resuming from
//! one decodes onwards from there. A checkpoint costs its window plus the
//! decoder's own state, so it is nearly free where the history resets (a
//! new gzip member or zstd frame: everything before is releasable) and as
//! large as the dictionary elsewhere; the caller spaces checkpoints by that
//! cost.
//!
//! A codec opts in with [`Decode::heap_size`]: the heap bytes a clone of it
//! copies, which must be honest (a decoder that keeps its window inside
//! itself, rather than in the caller's `out`, must count it).

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
    fn step(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step>;

    /// Input bytes consumed so far.
    fn consumed(&self) -> usize;

    /// A problem that does not stop decoding (a checksum mismatch), once
    /// the stream has ended. `out` is the output still held, which is not
    /// all of it once output has been released: checksums over the whole
    /// output must be computed as it is produced.
    fn warning(&self, _out: &[u8]) -> Option<Diagnostic> {
        None
    }

    /// Input bytes at the front that the decoder will never read again
    /// (at most [`consumed`](Self::consumed)). See "Releasing" in the
    /// module docs. The default, 0, keeps all input.
    fn releasable_input(&self) -> usize {
        0
    }

    /// Rebases the decoder's input positions after the caller drops the
    /// first `n` (at most [`releasable_input`](Self::releasable_input))
    /// bytes of its input.
    fn release_input(&mut self, _n: usize) {}

    /// Output bytes at the front that the decoder will never read again
    /// (what lies before its window), given `out_len` bytes of output. The
    /// default, 0, keeps all output.
    fn releasable_output(&self, _out_len: usize) -> usize {
        0
    }

    /// Rebases the decoder's output positions after the caller drops the
    /// first `n` (at most [`releasable_output`](Self::releasable_output))
    /// bytes of its output.
    fn release_output(&mut self, _n: usize) {}

    /// Heap bytes a clone of this decoder copies (tables, buffers it owns),
    /// or `None` if it must not be checkpointed (the default). See
    /// "Checkpoints" in the module docs.
    fn heap_size(&self) -> Option<usize> {
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
    fn decode(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Status>;
    fn consumed(&self) -> usize;
    fn warning(&self, out: &[u8]) -> Option<Diagnostic>;

    /// Input bytes at the front that the decoder will never read again
    /// (at most [`consumed`](Self::consumed)). See "Releasing" in the
    /// module docs. The default, 0, keeps all input.
    fn releasable_input(&self) -> usize {
        0
    }

    /// Rebases the decoder's input positions after the caller drops the
    /// first `n` (at most [`releasable_input`](Self::releasable_input))
    /// bytes of its input.
    fn release_input(&mut self, _n: usize) {}

    /// Output bytes at the front that the decoder will never read again
    /// (what lies before its window), given `out_len` bytes of output. The
    /// default, 0, keeps all output.
    fn releasable_output(&self, _out_len: usize) -> usize {
        0
    }

    /// Rebases the decoder's output positions after the caller drops the
    /// first `n` (at most [`releasable_output`](Self::releasable_output))
    /// bytes of its output.
    fn release_output(&mut self, _n: usize) {}

    /// A copy of this decoder to resume from later, or `None` if it cannot
    /// be checkpointed. See "Checkpoints" in the module docs.
    fn checkpoint(&self) -> Option<Box<dyn Decoder>> {
        None
    }

    /// Bytes a [`checkpoint`](Self::checkpoint) holds besides the window
    /// the caller keeps with it.
    fn state_size(&self) -> usize {
        0
    }
}

/// Adapts a [`Decode`] into a [`Decoder`] by rolling back steps that ran out
/// of input.
#[derive(Clone)]
pub struct Streaming<D>(pub D);

impl<D: Decode> Decoder for Streaming<D> {
    fn decode(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Status> {
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

    fn releasable_input(&self) -> usize {
        self.0.releasable_input()
    }

    fn release_input(&mut self, n: usize) {
        self.0.release_input(n);
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        self.0.releasable_output(out_len)
    }

    fn release_output(&mut self, n: usize) {
        self.0.release_output(n);
    }

    fn checkpoint(&self) -> Option<Box<dyn Decoder>> {
        self.0.heap_size()?;
        Some(Box::new(self.clone()))
    }

    fn state_size(&self) -> usize {
        std::mem::size_of::<D>().saturating_add(self.0.heap_size().unwrap_or(0))
    }
}

/// Bytes in flight between two stages of a [`Chain`] (produced by one, not
/// yet read by the next) that a checkpoint may copy. A chain holding more
/// (a stage that waits for all of its input) is not checkpointed: resuming
/// it would mean waiting for all of that input again anyway.
const MAX_IN_FLIGHT: usize = 64 * 1024;

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
    fn pump(
        &mut self,
        i: usize,
        input: &[u8],
        eof: bool,
        step: usize,
        limit: usize,
    ) -> Result<Status> {
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
        let status = stage
            .decoder
            .decode(src, src_eof, &mut stage.out, step, limit)?;
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
    fn decode(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Status> {
        let Some(last) = self.stages.len().checked_sub(1) else {
            // An empty chain copies its input.
            let from = out.len().min(input.len());
            out.extend_from_slice(input.get(from..).unwrap_or_default());
            return Ok(if eof { Status::Done } else { Status::NeedInput });
        };
        self.trim();
        let (before, rest) = self.stages.split_at_mut(last);
        let Some(stage) = rest.first_mut() else {
            return Ok(Status::Done);
        };
        let (src, src_eof) = match before.last() {
            Some(prev) => (prev.out.as_slice(), prev.done),
            None => (input, eof),
        };
        match stage.decoder.decode(src, src_eof, out, step, limit)? {
            // One step upstream per call, so a call stays bounded even when
            // the last stage waits for all of its input (a whole-buffer
            // filter): the caller calls again, and can yield in between.
            Status::NeedInput if last > 0 => {
                match self.pump(last.saturating_sub(1), input, eof, step, limit)? {
                    Status::NeedInput => Ok(Status::NeedInput),
                    _ => Ok(Status::More),
                }
            }
            status => Ok(status),
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

    fn releasable_input(&self) -> usize {
        self.stages
            .first()
            .map_or(0, |s| s.decoder.releasable_input())
    }

    fn release_input(&mut self, n: usize) {
        if let Some(s) = self.stages.first_mut() {
            s.decoder.release_input(n);
        }
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        self.stages
            .last()
            .map_or(0, |s| s.decoder.releasable_output(out_len))
    }

    fn release_output(&mut self, n: usize) {
        if let Some(s) = self.stages.last_mut() {
            s.decoder.release_output(n);
        }
    }

    /// Every stage checkpointed, with the intermediate buffers: each holds
    /// its stage's window, and at most [`MAX_IN_FLIGHT`] bytes the next
    /// stage has yet to read.
    fn checkpoint(&self) -> Option<Box<dyn Decoder>> {
        for pair in self.stages.windows(2) {
            let [prev, next] = pair else { continue };
            if prev.out.len().saturating_sub(next.decoder.consumed()) > MAX_IN_FLIGHT {
                return None;
            }
        }
        let mut stages = Vec::with_capacity(self.stages.len());
        for stage in &self.stages {
            stages.push(Stage {
                decoder: stage.decoder.checkpoint()?,
                out: stage.out.clone(),
                done: stage.done,
            });
        }
        Some(Box::new(Chain { stages }))
    }

    fn state_size(&self) -> usize {
        self.stages
            .iter()
            .map(|s| s.decoder.state_size().saturating_add(s.out.len()))
            .fold(0, usize::saturating_add)
    }
}

impl Chain {
    /// Drops what both sides of each intermediate buffer are done with.
    fn trim(&mut self) {
        for i in 1..self.stages.len() {
            let (before, rest) = self.stages.split_at_mut(i);
            let (Some(prev), Some(next)) = (before.last_mut(), rest.first_mut()) else {
                continue;
            };
            let n = next
                .decoder
                .releasable_input()
                .min(prev.decoder.releasable_output(prev.out.len()))
                .min(prev.out.len());
            if n > 0 {
                next.decoder.release_input(n);
                prev.decoder.release_output(n);
                prev.out.drain(..n);
            }
        }
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
