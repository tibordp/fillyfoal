//! Elementary streams reassembled from PES payloads, shared by program
//! streams and transport streams.
//!
//! A stream's payload bytes are described as a pieces source over the
//! packets that carry them (no copy) and embedded as the stream's own
//! format, so an MPEG-2 video stream in a VOB opens as `mpeg2video` and an
//! AC-3 stream in a transport stream as `ac3`. A long stream is cut into
//! parts of bounded size (at most [`PART_PIECES`] packets or
//! [`PART_BYTES`] bytes), each its own source, so the piece tables stay
//! small and the first part opens before the walk has reached the end of
//! the file. Parts start at a packet boundary; the elementary stream
//! dissectors resynchronise at the next start code or frame header.

use crate::cx::Cx;
use crate::formats::{Format, Input, embedded, embedded_as};
use crate::node::Node;
use crate::span::{Origin, Span};

use crate::formats::util::fmt::plural;

/// Most packets in one part.
pub const PART_PIECES: usize = 4096;
/// Most payload bytes in one part.
pub const PART_BYTES: u64 = 4 << 20;

/// How a stream's payload is presented.
#[derive(Clone, Copy, Debug)]
pub enum Target {
    /// A known elementary stream format.
    Format(&'static Format),
    /// Identified by the probes (a PES stream whose codec the container
    /// does not say).
    Detect,
    /// Payload with no dissector (LPCM, subtitles, private data).
    Data,
}

/// Collects a stream's payload pieces and pushes them as parts.
pub struct Parts {
    input: Input,
    target: Target,
    transform: &'static str,
    pieces: Vec<Span>,
    bytes: u64,
    /// A full part held back until it is known not to be the only one.
    pending: Option<(Vec<Span>, u64, u64)>,
    /// Parts pushed so far.
    pushed: u64,
    /// Stream bytes before the current part.
    offset: u64,
}

impl Parts {
    pub fn new(input: Input, target: Target, transform: &'static str) -> Self {
        Parts {
            input,
            target,
            transform,
            pieces: Vec::new(),
            bytes: 0,
            pending: None,
            pushed: 0,
            offset: 0,
        }
    }

    /// Adds the next payload piece; pushes a part when one is complete.
    pub async fn add(&mut self, cx: &Cx, piece: Span) {
        if piece.len == 0 {
            return;
        }
        if self.pieces.len() >= PART_PIECES || self.bytes.saturating_add(piece.len) > PART_BYTES {
            self.close(cx).await;
        }
        // Adjacent pieces (payload split by nothing) merge.
        if let Some(last) = self.pieces.last_mut()
            && last.source == piece.source
            && last.end() == piece.offset
        {
            last.len = last.len.saturating_add(piece.len);
        } else {
            self.pieces.push(piece);
        }
        self.bytes = self.bytes.saturating_add(piece.len);
    }

    /// Ends the current part: it becomes pending, and a part pending
    /// before it is pushed.
    async fn close(&mut self, cx: &Cx) {
        if self.pieces.is_empty() {
            return;
        }
        let pieces = std::mem::take(&mut self.pieces);
        let bytes = std::mem::replace(&mut self.bytes, 0);
        let at = self.offset;
        self.offset = self.offset.saturating_add(bytes);
        if let Some(prev) = self.pending.replace((pieces, bytes, at)) {
            self.push_part(cx, prev, false).await;
        }
    }

    /// Pushes what is left. Returns the number of parts pushed in all.
    pub async fn finish(mut self, cx: &Cx) -> u64 {
        self.close(cx).await;
        if let Some(last) = self.pending.take() {
            let only = self.pushed == 0;
            self.push_part(cx, last, only).await;
        } else {
            cx.emit(Node::new("No payload").summary("no PES packets of this stream in the file"));
        }
        self.pushed
    }

    async fn push_part(&mut self, cx: &Cx, (pieces, bytes, at): (Vec<Span>, u64, u64), only: bool) {
        let count = pieces.len();
        self.pushed = self.pushed.saturating_add(1);
        let name = if only {
            match self.target {
                Target::Format(f) => f.title.to_owned(),
                _ => "Payload".to_owned(),
            }
        } else {
            format!("Part {}", self.pushed)
        };
        let mut summary = format!(
            "{} bytes from {}",
            bytes,
            plural(crate::bytes::to_u64(count), "piece")
        );
        if !only {
            summary = format!("stream bytes {at}–{}, {summary}", at.saturating_add(bytes));
        }
        let span = match pieces.as_slice() {
            [one] => Ok(*one),
            _ => {
                let first = pieces.first().map_or(0, |s| s.offset);
                let last = pieces.last().map_or(first, Span::end);
                let source = pieces.first().map_or(self.input.span.source, |s| s.source);
                cx.add_pieces_stepped(
                    Origin {
                        parent: Span::new(source, first, last.saturating_sub(first)),
                        transform: self.transform,
                    },
                    &pieces,
                )
                .await
            }
        };
        let node = match span {
            Ok(span) => {
                let input = self.input.nested(span);
                match self.target {
                    Target::Format(f) => embedded_as(name, input, f),
                    Target::Detect => embedded(name, input),
                    Target::Data => Node::new(name).span(span),
                }
            }
            Err(e) => Node::new(name).diag(e),
        };
        cx.push(node.summary(summary)).await;
    }
}
