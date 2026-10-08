//! Charging synchronous work over in-memory buffers (see "Accounting for
//! work" in `docs/DISSECTORS.md`): [`Pace`] counts cheap steps of an
//! input-dependent loop and charges a unit every so many, and [`Resumable`]
//! splits a byte-at-a-time scan into bounded steps with a checkpoint
//! between them.

use crate::cx::Cx;

/// Cheap steps (bytes scanned, small items parsed) per unit of work: on the
/// order of a microsecond.
pub const STEPS_PER_UNIT: u64 = 4096;

/// Counts work done by a synchronous loop and charges one unit (a
/// [`Cx::checkpoint`], which may suspend) every `per_unit` of it.
pub struct Pace<'a> {
    cx: &'a Cx,
    per_unit: u64,
    work: u64,
}

impl<'a> Pace<'a> {
    pub fn new(cx: &'a Cx, per_unit: u64) -> Self {
        Pace {
            cx,
            per_unit: per_unit.max(1),
            work: 0,
        }
    }

    pub fn cx(&self) -> &'a Cx {
        self.cx
    }

    /// Counts `n` steps, charging a unit for every `per_unit` of them.
    pub async fn add(&mut self, n: u64) {
        self.work = self.work.saturating_add(n);
        while self.work >= self.per_unit {
            self.work = self.work.saturating_sub(self.per_unit);
            self.cx.checkpoint().await;
        }
    }

    /// Counts one step.
    pub async fn step(&mut self) {
        self.add(1).await;
    }
}

/// A computation over an in-memory buffer that runs in bounded steps.
pub trait Resumable {
    type Output;

    /// Does about `budget` cheap steps (bytes scanned) of work; returns
    /// whether the computation is complete.
    fn step(&mut self, budget: u64) -> bool;

    fn finish(self) -> Self::Output;
}

/// Runs `r` to completion, [`STEPS_PER_UNIT`] steps per unit of work.
pub async fn run_paced<R: Resumable + Send>(cx: &Cx, mut r: R) -> R::Output {
    loop {
        let done = r.step(STEPS_PER_UNIT);
        cx.checkpoint().await;
        if done {
            return r.finish();
        }
    }
}

/// Runs `r` to completion in one go: for buffers bounded by a small
/// constant, and for tests.
pub fn run_all<R: Resumable>(mut r: R) -> R::Output {
    while !r.step(u64::MAX) {}
    r.finish()
}

/// The first index in `data` at or after `from` whose byte satisfies
/// `pred`, searched in paced pieces.
pub async fn position_paced(
    cx: &Cx,
    data: &[u8],
    from: usize,
    pred: impl Fn(u8) -> bool + Send,
) -> Option<usize> {
    let piece = usize::try_from(STEPS_PER_UNIT).unwrap_or(4096);
    let mut at = from;
    while let Some(chunk) = data.get(at..at.saturating_add(piece).min(data.len())) {
        if chunk.is_empty() {
            return None;
        }
        if let Some(p) = chunk.iter().position(|&b| pred(b)) {
            return Some(at.saturating_add(p));
        }
        at = at.saturating_add(chunk.len());
        cx.checkpoint().await;
    }
    None
}
