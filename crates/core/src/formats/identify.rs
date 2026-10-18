//! Identification without a session, in the same request/response style
//! as [`crate::Session`]: the caller supplies the bytes it asks for. This
//! is the detection step a session runs for a node (both phases, the
//! deep tail only when a candidate wants it, the name as a tie-breaker),
//! and the session runs it through this type, so a host that identifies a
//! file on its own gets the same answer the session's tree shows.
//!
//! ```ignore
//! let mut id = Identify::new(&REGISTRY, len, Some(name));
//! let format = loop {
//!     match id.poll() {
//!         Identified::NeedBytes(ranges) => {
//!             for r in ranges {
//!                 id.provide(r.offset, &read(r.offset, r.len)?);
//!             }
//!         }
//!         Identified::Done(format) => break format,
//!     }
//! };
//! ```

use super::{DEEP_TAIL_LEN, Deep, Format, HEAD_LEN, Head, Registry, TAIL_LEN};
use crate::bytes::to_u64;

/// Bytes [`Identify`] needs: `len` bytes at `offset` (fewer at the end of
/// the input are fine).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteRange {
    pub offset: u64,
    pub len: u64,
}

/// What [`Identify::poll`] needs next.
#[derive(Clone, Debug)]
pub enum Identified {
    /// Supply these ranges with [`Identify::provide`], then poll again.
    NeedBytes(Vec<ByteRange>),
    /// The format, or `None` if nothing matched.
    Done(Option<&'static Format>),
}

/// Identifies one input (see the module docs).
pub struct Identify {
    registry: &'static Registry,
    len: u64,
    len_known: bool,
    cheap_tail: bool,
    max_read: u64,
    name: Option<String>,
    head: Option<Vec<u8>>,
    tail: Option<Vec<u8>>,
    deep_tail: Option<Vec<u8>>,
    /// The first phase's answer, once it has run.
    first: Option<Option<&'static Format>>,
    units: u64,
    result: Option<Option<&'static Format>>,
}

impl Identify {
    /// An input of `len` bytes, opened under `name` (a file name, an
    /// archive member's path), if it has one.
    pub fn new(registry: &'static Registry, len: u64, name: Option<&str>) -> Identify {
        Identify {
            registry,
            len,
            len_known: true,
            cheap_tail: true,
            max_read: u64::MAX,
            name: name.map(str::to_owned),
            head: None,
            tail: None,
            deep_tail: None,
            first: None,
            units: 0,
            result: None,
        }
    }

    /// `len` is only an upper bound (content decoded on demand whose size
    /// nothing records): nothing near the end is asked for, and probes are
    /// told the length is unknown.
    pub fn len_unknown(mut self) -> Identify {
        self.len_known = false;
        self
    }

    /// Reading near the end is expensive (it would decode a whole stream):
    /// don't ask for the tails.
    pub fn without_tails(mut self) -> Identify {
        self.cheap_tail = false;
        self
    }

    /// Ask for at most `n` bytes at a time.
    pub fn max_read(mut self, n: u64) -> Identify {
        self.max_read = n;
        self
    }

    /// Work units the probes took (see [`Registry::identify_costed`]).
    pub fn units(&self) -> u64 {
        self.units
    }

    /// The first bytes of the input, once supplied.
    pub fn head(&self) -> Option<&[u8]> {
        self.head.as_deref()
    }

    /// The input's length, as given.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the input is known to be empty.
    pub fn is_empty(&self) -> bool {
        self.head.as_ref().is_some_and(Vec::is_empty)
    }

    fn tails(&self) -> bool {
        self.len_known && self.cheap_tail
    }

    fn head_range(&self) -> ByteRange {
        let n = HEAD_LEN.min(self.max_read);
        ByteRange {
            offset: 0,
            len: if self.len_known { n.min(self.len) } else { n },
        }
    }

    fn end_range(&self, n: u64) -> ByteRange {
        let n = n.min(self.max_read).min(self.len);
        ByteRange {
            offset: self.len.saturating_sub(n),
            len: n,
        }
    }

    /// The input's tail as probes see it, if it is known yet.
    fn tail_ready(&self) -> bool {
        self.tail.is_some() || !(self.len > HEAD_LEN && self.tails())
    }

    /// Supplies bytes asked for by [`poll`](Identify::poll).
    pub fn provide(&mut self, offset: u64, data: &[u8]) {
        if self.head.is_none() && offset == 0 {
            self.head = Some(data.to_vec());
        } else if self.first.is_none() && self.tail.is_none() {
            self.tail = Some(data.to_vec());
        } else if self.first.is_some() && self.deep_tail.is_none() {
            self.deep_tail = Some(data.to_vec());
        }
    }

    /// The next step: bytes to supply, or the answer.
    pub fn poll(&mut self) -> Identified {
        if let Some(result) = self.result {
            return Identified::Done(result);
        }
        if self.first.is_none() {
            let mut need = Vec::new();
            if self.head.is_none() {
                if self.len_known && self.len == 0 {
                    self.head = Some(Vec::new());
                } else {
                    need.push(self.head_range());
                }
            }
            if !self.tail_ready() {
                need.push(self.end_range(TAIL_LEN));
            }
            if !need.is_empty() {
                return Identified::NeedBytes(need);
            }
            self.first_phase();
        }
        if self.result.is_none() && self.deep_tail.is_none() {
            let head_len = self.head.as_ref().map_or(0, |h| to_u64(h.len()));
            if self.len_known && self.len <= head_len {
                self.deep_tail = self.head.clone();
            } else if self.tails() {
                return Identified::NeedBytes(vec![self.end_range(DEEP_TAIL_LEN)]);
            } else {
                self.deep_tail = Some(Vec::new());
            }
        }
        if self.result.is_none() {
            self.second_phase();
        }
        Identified::Done(self.result.flatten())
    }

    /// Runs the first phase; settles the answer if no second-phase probe
    /// wants a say, and marks the deep tail as not needed if none asks
    /// for it.
    fn first_phase(&mut self) {
        let data = self.head.as_deref().unwrap_or_default();
        // A short input is its own tail.
        let tail = match &self.tail {
            Some(t) => t.as_slice(),
            None if self.len <= HEAD_LEN => data,
            None => &[],
        };
        let head = Head {
            data,
            tail,
            len: self.len,
            len_known: self.len_known,
        };
        let (first, units) = self.registry.identify_costed(&head);
        self.units = units;
        self.first = Some(first);
        let mut candidates = self.registry.deep_candidates(first).peekable();
        if candidates.peek().is_none() {
            self.result = Some(first);
        } else if !candidates.any(|d| d.tail) {
            self.deep_tail = Some(Vec::new());
        }
    }

    fn second_phase(&mut self) {
        let data = self.head.as_deref().unwrap_or_default();
        let tail = match &self.tail {
            Some(t) => t.as_slice(),
            None if self.len <= HEAD_LEN => data,
            None => &[],
        };
        let head = Head {
            data,
            tail,
            len: self.len,
            len_known: self.len_known,
        };
        let first = self.first.flatten();
        self.result = Some(self.registry.identify_deep(&Deep {
            head: &head,
            tail: self.deep_tail.as_deref().unwrap_or_default(),
            name: self.name.as_deref(),
            first,
        }));
    }
}
