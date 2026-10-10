//! A bounded cache of fixed-size chunks of source bytes.
//!
//! All dissector reads go through this cache. Misses are reported as chunk
//! indices, which the session turns into byte requests for the host, so the
//! host always reads whole aligned chunks (built-in read-ahead).

use std::collections::{BTreeSet, HashMap};

use crate::bytes::{to_u64, to_usize};
use crate::span::SourceId;

pub(crate) struct ByteCache {
    chunk_size: u64,
    capacity: usize,
    used: usize,
    clock: u64,
    chunks: HashMap<(SourceId, u64), Chunk>,
    /// The chunks by last use, oldest first, for eviction in logarithmic
    /// time (a host may choose small chunks, and so many of them).
    order: BTreeSet<(u64, SourceId, u64)>,
}

struct Chunk {
    data: Vec<u8>,
    last_used: u64,
}

impl ByteCache {
    pub fn new(chunk_size: u64, capacity: usize) -> Self {
        ByteCache {
            chunk_size: chunk_size.max(1),
            capacity,
            used: 0,
            clock: 0,
            chunks: HashMap::new(),
            order: BTreeSet::new(),
        }
    }

    pub fn chunk_size(&self) -> u64 {
        self.chunk_size
    }

    pub fn chunk_index(&self, offset: u64) -> u64 {
        offset.checked_div(self.chunk_size).unwrap_or(0)
    }

    pub fn chunk_start(&self, index: u64) -> u64 {
        index.saturating_mul(self.chunk_size)
    }

    pub fn contains(&self, source: SourceId, index: u64) -> bool {
        self.chunks.contains_key(&(source, index))
    }

    /// Marks a chunk as used now.
    fn touch(&mut self, source: SourceId, index: u64) {
        let clock = self.clock;
        if let Some(chunk) = self.chunks.get_mut(&(source, index)) {
            self.order.remove(&(chunk.last_used, source, index));
            chunk.last_used = clock;
            self.order.insert((clock, source, index));
        }
    }

    /// Copies bytes `start..end` of `source`, or returns the indices of the
    /// chunks that must be supplied first. The caller guarantees that `end`
    /// does not exceed the source length.
    pub fn read(&mut self, source: SourceId, start: u64, end: u64) -> Result<Vec<u8>, Vec<u64>> {
        if end <= start {
            return Ok(Vec::new());
        }
        let first = self.chunk_index(start);
        let last = self.chunk_index(end.saturating_sub(1));
        let missing: Vec<u64> = (first..=last)
            .filter(|&i| !self.contains(source, i))
            .collect();
        self.clock = self.clock.wrapping_add(1);
        // The chunks this read has stay fresh, also when some are missing,
        // so that supplying those evicts other chunks rather than these.
        for index in first..=last {
            self.touch(source, index);
        }
        if !missing.is_empty() {
            return Err(missing);
        }
        let mut out = Vec::with_capacity(to_usize(end.saturating_sub(start)));
        for index in first..=last {
            let chunk_start = self.chunk_start(index);
            let Some(chunk) = self.chunks.get(&(source, index)) else {
                break;
            };
            let from = to_usize(start.saturating_sub(chunk_start));
            let to = to_usize(end.saturating_sub(chunk_start)).min(chunk.data.len());
            if let Some(bytes) = chunk.data.get(from..to) {
                out.extend_from_slice(bytes);
            }
        }
        Ok(out)
    }

    pub fn insert(&mut self, source: SourceId, index: u64, data: Vec<u8>) {
        self.clock = self.clock.wrapping_add(1);
        let len = data.len();
        let chunk = Chunk {
            data,
            last_used: self.clock,
        };
        if let Some(old) = self.chunks.insert((source, index), chunk) {
            self.used = self.used.saturating_sub(old.data.len());
            self.order.remove(&(old.last_used, source, index));
        }
        self.order.insert((self.clock, source, index));
        self.used = self.used.saturating_add(len);
        self.evict();
    }

    /// Drops chunks of `source` at or beyond `len` (the source shrank).
    pub fn truncate(&mut self, source: SourceId, len: u64) {
        let chunk_size = self.chunk_size;
        let mut freed = 0usize;
        let order = &mut self.order;
        self.chunks.retain(|&(s, index), chunk| {
            let keep = s != source
                || index
                    .saturating_mul(chunk_size)
                    .saturating_add(to_u64(chunk.data.len()))
                    <= len;
            if !keep {
                freed = freed.saturating_add(chunk.data.len());
                order.remove(&(chunk.last_used, s, index));
            }
            keep
        });
        self.used = self.used.saturating_sub(freed);
    }

    fn evict(&mut self) {
        while self.used > self.capacity && self.chunks.len() > 1 {
            let Some((_, source, index)) = self.order.pop_first() else {
                break;
            };
            if let Some(chunk) = self.chunks.remove(&(source, index)) {
                self.used = self.used.saturating_sub(chunk.data.len());
            }
        }
    }
}
