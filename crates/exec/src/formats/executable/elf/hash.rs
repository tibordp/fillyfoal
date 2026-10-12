//! Symbol hash tables (SysV `SHT_HASH`, `SHT_GNU_HASH`) and packed
//! relative relocations (`SHT_RELR`).

use super::{Class, Elf, word};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::struct_node;
use crate::formats::util::binutil::get_at;
use crate::formats::util::fmt::plural;
use crate::formats::util::val::hex;
use crate::node::{Count, Node};
use crate::span::Span;

/// `SHT_HASH`: nbucket and nchain, then the bucket and chain arrays of
/// symbol indices (32-bit entries, or 64-bit where `sh_entsize` says so).
pub(super) async fn sysv(cx: Cx, (class, span, entsize): (Class, Span, u64)) -> Result<()> {
    let size: u64 = if entsize == 8 { 8 } else { 4 };
    let head = cx.read(span.sub_exact(0, size.saturating_mul(2))?).await?;
    let get = |at: u64| {
        if size == 8 {
            get_at::<u64>(&head, at, class.endian)
        } else {
            get_at::<u32>(&head, at, class.endian).map(u64::from)
        }
    };
    let nbucket = get(0).unwrap_or(0);
    let nchain = get(size).unwrap_or(0);
    cx.emit(struct_node(
        "Header",
        span.sub(0, size.saturating_mul(2)),
        class.endian,
        size,
        |f, &size| {
            if size == 8 {
                f.u64("nbucket").emit()?;
                f.u64("nchain").emit()?;
            } else {
                f.u32("nbucket").emit()?;
                f.u32("nchain").emit()?;
            }
            Ok(())
        },
    ));
    let buckets = span.sub(size.saturating_mul(2), nbucket.saturating_mul(size));
    let chains = span.sub(
        size.saturating_mul(2).saturating_add(buckets.len),
        nchain.saturating_mul(size),
    );
    cx.emit(
        Node::new("Buckets")
            .span(buckets)
            .summary(plural(nbucket, "bucket")),
    );
    let mut node = Node::new("Chains").span(chains).summary(format!(
        "{nchain_entry}, one per symbol",
        nchain_entry = plural(nchain, "entry")
    ));
    if chains.len < nchain.saturating_mul(size) {
        node = node.diag(Diagnostic::truncated(chains, chains.len));
    }
    cx.emit(node);
    cx.annotate(format!(
        "{nbucket_bucket}, {nchain_symbol}",
        nbucket_bucket = plural(nbucket, "bucket"),
        nchain_symbol = plural(nchain, "symbol")
    ));
    Ok(())
}

/// `SHT_GNU_HASH`: nbuckets, symoffset, bloom_size and bloom_shift, then
/// the Bloom filter words, the buckets and the hash values of the hashed
/// symbols (from `symoffset` on).
pub(super) async fn gnu(cx: Cx, (class, span): (Class, Span)) -> Result<()> {
    let head = cx.read(span.sub_exact(0, 16)?).await?;
    let get = |at: u64| get_at::<u32>(&head, at, class.endian).unwrap_or(0);
    let (nbuckets, symoffset, bloom_size, shift) = (get(0), get(4), get(8), get(12));
    cx.emit(struct_node(
        "Header",
        span.sub(0, 16),
        class.endian,
        (),
        |f, _| {
            f.u32("nbuckets").emit()?;
            f.u32("symoffset")
                .desc("Index of the first symbol in the hash table")
                .emit()?;
            f.u32("bloom_size").desc("Bloom filter words").emit()?;
            f.u32("bloom_shift").emit()?;
            Ok(())
        },
    ));
    let bloom = span.sub(16, u64::from(bloom_size).saturating_mul(class.word()));
    cx.emit(Node::new("Bloom filter").span(bloom).summary(format!(
        "{bloom_size_word}, shift {shift}",
        bloom_size_word = plural(bloom_size, "word")
    )));
    let buckets_at = 16u64.saturating_add(bloom.len);
    let buckets = span.sub(buckets_at, u64::from(nbuckets).saturating_mul(4));
    cx.emit(
        Node::new("Buckets")
            .span(buckets)
            .summary(plural(nbuckets, "bucket")),
    );
    let chains = span.tail(buckets_at.saturating_add(buckets.len));
    let hashed = chains.len / 4;
    cx.emit(
        Node::new("Hash values")
            .span(chains)
            .summary(plural(hashed, "symbol")),
    );
    cx.annotate(format!(
        "{nbuckets_bucket}, {hashed} hashed symbols from index {symoffset}",
        nbuckets_bucket = plural(nbuckets, "bucket")
    ));
    Ok(())
}

/// Most RELR words read at once.
const RELR_BATCH: u64 = 4096;

/// `SHT_RELR`: each even word is an address to relocate (and starts a run);
/// each odd word is a bitmap of the following 31 or 63 words.
pub(super) async fn relr(cx: Cx, (elf, span): (Elf, Span)) -> Result<()> {
    let class = elf.class;
    let w = class.word();
    let n = span.len.checked_div(w).unwrap_or(0);
    let bits = w.saturating_mul(8).saturating_sub(1);
    cx.set_count(Count::Exact(n));
    // The address after the last one relocated: where a bitmap starts.
    let mut next = 0u64;
    let mut i = 0u64;
    while i < n {
        let batch = n.saturating_sub(i).min(RELR_BATCH);
        let at = i.saturating_mul(w);
        let data = cx
            .read(span.sub_exact(at, batch.saturating_mul(w))?)
            .await?;
        for k in 0..batch {
            let off = k.saturating_mul(w);
            let v = word(&data, off, class).unwrap_or(0);
            let entry = span.sub(at.saturating_add(off), w);
            let node = if v & 1 == 0 {
                next = v.saturating_add(w);
                let mut node = Node::new(format!("[{}]", i.saturating_add(k)))
                    .span(entry)
                    .value(hex(v, class.bits()))
                    .summary(format!("address {}", elf.describe(v)));
                if let Some(t) = elf.vaddr_span(v, w) {
                    node = node.target(t);
                }
                node
            } else {
                let count = (v >> 1).count_ones();
                let first = (1..=bits).find(|b| (v >> b) & 1 != 0).unwrap_or(1);
                let start = next.saturating_add(first.saturating_sub(1).saturating_mul(w));
                let node = Node::new(format!("[{}]", i.saturating_add(k)))
                    .span(entry)
                    .value(hex(v, class.bits()))
                    .summary(format!(
                        "bitmap: {count} addresses in {:#x}..{:#x}, first {start:#x}",
                        next,
                        next.saturating_add(bits.saturating_mul(w))
                    ));
                next = next.saturating_add(bits.saturating_mul(w));
                node
            };
            cx.push(node).await;
        }
        i = i.saturating_add(batch);
    }
    Ok(())
}
