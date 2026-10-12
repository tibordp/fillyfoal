//! The ext3/ext4 journal (JBD2): a superblock, then a circular log of
//! descriptor, data, commit and revoke blocks. All of it is big-endian.

use crate::bytes::{to_u64, u16_be, u32_be};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::disk::{fragments_node, size, uuid_value};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag};

use super::FsRef;
use super::inode::{Inode, content};

const BE: Endian = Endian::Big;
const MAGIC: u32 = 0xc03b_3998;
/// Log blocks described at most.
const MAX_LOG_BLOCKS: u64 = 1 << 20;

const BLOCK_TYPES: EnumTable = &[
    (1, "descriptor"),
    (2, "commit"),
    (3, "superblock v1"),
    (4, "superblock v2"),
    (5, "revoke"),
    (6, "fast commit"),
];

const COMPAT: FlagTable = &[flag(0x1, "CHECKSUM")];

const INCOMPAT: FlagTable = &[
    flag(0x01, "REVOKE"),
    flag(0x02, "64BIT"),
    flag(0x04, "ASYNC_COMMIT"),
    flag(0x08, "CSUM_V2"),
    flag(0x10, "CSUM_V3"),
    flag(0x20, "FAST_COMMIT"),
];

const CSUM_TYPES: EnumTable = &[(1, "CRC-32"), (2, "MD5"), (3, "SHA-1"), (4, "CRC-32C")];

fn header(f: &mut Fields<'_>) -> Result<u32> {
    f.u32("Magic").hex().emit()?;
    let ty = f.u32("Block type").enumeration(BLOCK_TYPES).emit()?;
    f.u32("Sequence").emit()?;
    Ok(ty)
}

fn superblock_layout(f: &mut Fields<'_>, computed: &Option<u32>) -> Result<()> {
    let ty = header(f)?;
    f.u32("Block size").emit()?;
    f.u32("Blocks")
        .desc("Length of the journal in blocks")
        .emit()?;
    f.u32("First log block").emit()?;
    f.u32("First expected sequence").emit()?;
    f.u32("Log start")
        .with(|&v, n| {
            if v == 0 {
                n.summary("clean: nothing to replay")
            } else {
                n
            }
        })
        .emit()?;
    f.i32("Error").emit()?;
    if ty != 4 {
        let rest = f.remaining();
        if rest > 0 {
            f.bytes("Unused", rest).emit()?;
        }
        return Ok(());
    }
    f.u32("Compatible features").hex().flags(COMPAT).emit()?;
    f.u32("Incompatible features")
        .hex()
        .flags(INCOMPAT)
        .emit()?;
    f.u32("Read-only compatible features").hex().emit()?;
    f.bytes("UUID", 16).with(uuid_value).emit()?;
    let users = f
        .u32("Users")
        .desc("Filesystems sharing this journal")
        .emit()?;
    f.u32("Dynamic superblock copy").emit()?;
    f.u32("Maximum transaction blocks").emit()?;
    f.u32("Maximum transaction data blocks").emit()?;
    f.u8("Checksum type").enumeration(CSUM_TYPES).emit()?;
    f.bytes("Padding", 3).emit()?;
    f.u32("Fast commit blocks").emit()?;
    f.u32("Log head").emit()?;
    f.bytes("Padding", 160).emit()?;
    f.u32("Checksum")
        .hex()
        .with(|&v, n| match computed {
            Some(c) if *c == v => n.summary("valid"),
            Some(c) => n.diag(Diagnostic::warning(format!("mismatch: computed {c:#010x}"))),
            None => n,
        })
        .emit()?;
    let shown = u64::from(users).min(48);
    for _ in 0..shown {
        f.bytes("User", 16).with(uuid_value).emit()?;
    }
    let rest = f.remaining();
    if rest > 0 {
        f.node(
            Node::new("Unused user slots")
                .span(f.peek_span(rest))
                .summary(size(rest)),
        );
    }
    Ok(())
}

/// The journal: its inode, its blocks, the superblock and the log.
pub(super) async fn journal(cx: Cx, (fs, ino): (FsRef, u32)) -> Result<()> {
    let inode = Inode::read(&cx, &fs, ino).await?;
    cx.emit(super::inode::record(&fs, &inode, format!("Inode {ino}")));
    let (data, pieces) = content(&cx, &fs, &inode, inode.size()).await?;
    cx.emit(fragments_node(&cx, "Blocks", pieces).await);
    let sb_span = data.sub(0, 1024);
    let raw = cx.read_avail(sb_span).await?;
    if u32_be(&raw, 0) != Some(MAGIC) {
        return Err(Diagnostic::malformed("bad journal superblock magic").at(sb_span.sub(0, 4)));
    }
    let v2 = u32_be(&raw, 4) == Some(4);
    let csum = v2 && u32_be(&raw, 0x28).is_some_and(|f| f & 0x18 != 0);
    let computed = csum.then(|| {
        crate::formats::disk::crc32c_update(
            crate::formats::disk::crc32c_update(
                crate::formats::disk::crc32c_update(!0, raw.get(..0xfc).unwrap_or_default()),
                &[0; 4],
            ),
            raw.get(0x100..).unwrap_or_default(),
        )
    });
    let block = u64::from(u32_be(&raw, 12).unwrap_or(0));
    let maxlen = u64::from(u32_be(&raw, 16).unwrap_or(0));
    let first = u64::from(u32_be(&raw, 20).unwrap_or(0));
    let start = u64::from(u32_be(&raw, 28).unwrap_or(0));
    cx.emit(
        struct_node(
            "Journal superblock",
            sb_span,
            BE,
            computed,
            superblock_layout,
        )
        .summary(format!(
            "{} blocks of {}, {}",
            maxlen,
            size(block),
            if start == 0 {
                "clean"
            } else {
                "needs recovery"
            }
        )),
    );
    if block == 0 || block > 65536 {
        return Err(Diagnostic::malformed(format!("journal block size {block}")));
    }
    if block > 1024 {
        cx.emit(
            Node::new("Unused")
                .span(data.sub(1024, block.saturating_sub(1024)))
                .summary("rest of the superblock's block"),
        );
    }
    let log = data.sub(
        first.saturating_mul(block),
        maxlen.saturating_sub(first).saturating_mul(block),
    );
    if start == 0 {
        cx.emit(
            Node::new("Log")
                .span(log)
                .summary(format!("{}, empty (the journal is clean)", size(log.len))),
        );
    } else {
        cx.emit(
            Node::new("Log")
                .span(log)
                .summary(format!(
                    "{}, transactions from block {start}",
                    size(log.len)
                ))
                .lazy(
                    log_blocks,
                    Log {
                        data,
                        block,
                        start,
                        maxlen,
                        first,
                        incompat: u32_be(&raw, 0x28).unwrap_or(0),
                        sequence: u32_be(&raw, 24).unwrap_or(0),
                    },
                ),
        );
    }
    Ok(())
}

/// The bytes of a descriptor block tag (`journal_tag_bytes`).
fn tag_bytes(incompat: u32) -> usize {
    if incompat & 0x10 != 0 {
        return 16;
    }
    let mut n = 12usize;
    if incompat & 0x08 != 0 {
        n = n.saturating_add(2);
    }
    if incompat & 0x02 == 0 {
        n = n.saturating_sub(4);
    }
    n
}

/// Tag flags (`JBD2_FLAG_*`).
const TAG_FLAGS: FlagTable = &[
    flag(0x1, "ESCAPE"),
    flag(0x2, "SAME_UUID"),
    flag(0x4, "DELETED"),
    flag(0x8, "LAST_TAG"),
];
const ESCAPE: u32 = 0x1;
const SAME_UUID: u32 = 0x2;
const LAST_TAG: u32 = 0x8;

/// A descriptor block tag: target block, flags, checksum, and where the
/// tag (with its UUID, if any) ends.
#[derive(Clone, Copy, Debug)]
struct Tag {
    block: u64,
    flags: u32,
    csum: Option<u32>,
    end: usize,
}

/// The tag at `at` in a descriptor block (`journal_block_tag3_t` with
/// CSUM_V3, else `journal_block_tag_t`).
fn tag_at(desc: &[u8], at: usize, incompat: u32) -> Tag {
    let v3 = incompat & 0x10 != 0;
    let lo = u64::from(u32_be(desc, at).unwrap_or(0));
    let (flags, hi_at, csum) = if v3 {
        (
            u32_be(desc, at.saturating_add(4)).unwrap_or(0),
            at.saturating_add(8),
            u32_be(desc, at.saturating_add(12)),
        )
    } else {
        (
            u32::from(u16_be(desc, at.saturating_add(6)).unwrap_or(0)),
            at.saturating_add(8),
            (incompat & 0x08 != 0)
                .then(|| u16_be(desc, at.saturating_add(4)).map(u32::from))
                .flatten(),
        )
    };
    let hi = if incompat & 0x02 != 0 {
        u64::from(u32_be(desc, hi_at).unwrap_or(0))
    } else {
        0
    };
    let mut end = at.saturating_add(tag_bytes(incompat));
    if flags & SAME_UUID == 0 {
        end = end.saturating_add(16);
    }
    Tag {
        block: hi << 32 | lo,
        flags,
        csum,
        end,
    }
}

/// End of the tag area: a checksummed descriptor ends in a 4-byte tail.
fn tags_end(len: usize, incompat: u32) -> usize {
    if incompat & 0x18 != 0 {
        len.saturating_sub(4)
    } else {
        len
    }
}

/// The tags of a descriptor block, up to the last one.
fn tags(desc: &[u8], incompat: u32) -> Vec<Tag> {
    let size = tag_bytes(incompat);
    let end = tags_end(desc.len(), incompat);
    let mut out = Vec::new();
    let mut at = 12usize;
    while at.saturating_add(size) <= end {
        let tag = tag_at(desc, at, incompat);
        out.push(tag);
        at = tag.end;
        if tag.flags & LAST_TAG != 0 {
            break;
        }
    }
    out
}

#[derive(Clone, Copy, Debug)]
struct Log {
    data: Span,
    block: u64,
    start: u64,
    maxlen: u64,
    first: u64,
    incompat: u32,
    /// The superblock's first expected transaction (`s_sequence`).
    sequence: u32,
}

/// Walks the log from its start the way `do_one_pass` scans it:
/// descriptor blocks (and the data blocks they announce), commit and
/// revoke blocks, while each carries the transaction expected next (one
/// more after every commit). The first block that does not is where the
/// log ends: a block left over from an older pass, shown as stale.
async fn log_blocks(cx: Cx, log: Log) -> Result<()> {
    let mut b = log.start;
    let mut expected = log.sequence;
    let mut pending: std::collections::VecDeque<Tag> = std::collections::VecDeque::new();
    let mut steps = 0u64;
    while steps < MAX_LOG_BLOCKS.min(log.maxlen) {
        steps = steps.saturating_add(1);
        let span = log.data.sub(b.saturating_mul(log.block), log.block);
        if let Some(tag) = pending.pop_front() {
            cx.push(Node::new(format!("Block {b}")).span(span).summary(format!(
                "logged copy of filesystem block {}{}",
                tag.block,
                if tag.flags & ESCAPE != 0 {
                    " (escaped: its first 4 bytes were the journal magic)"
                } else {
                    ""
                }
            )))
            .await;
        } else {
            let head = cx.read_avail(span).await?;
            if u32_be(&head, 0) != Some(MAGIC) {
                if steps == 1 {
                    cx.diag(Diagnostic::malformed(
                        "the log start holds no journal block",
                    ));
                }
                break;
            }
            let ty = u32_be(&head, 4).unwrap_or(0);
            let seq = u32_be(&head, 8).unwrap_or(0);
            let kind = crate::value::lookup(BLOCK_TYPES, ty.into()).unwrap_or("unknown");
            if seq != expected || !matches!(ty, 1 | 2 | 5) {
                cx.push(
                    struct_node(format!("Block {b}"), span.sub(0, 12), BE, (), header_layout)
                        .summary(format!(
                            "{kind}, transaction {seq}: stale, the log ends here \
                             (transaction {expected} expected next)"
                        )),
                )
                .await;
                break;
            }
            let node = match ty {
                1 => {
                    pending = tags(&head, log.incompat).into();
                    struct_node(
                        format!("Block {b}"),
                        span,
                        BE,
                        log.incompat,
                        descriptor_layout,
                    )
                    .summary(format!(
                        "descriptor, transaction {seq}, {} blocks follow",
                        pending.len()
                    ))
                }
                2 => {
                    expected = expected.wrapping_add(1);
                    struct_node(format!("Block {b}"), span, BE, (), commit_layout)
                        .summary(format!("commit, transaction {seq}"))
                }
                _ => {
                    let used = u32_be(&head, 12).unwrap_or(0);
                    let record = if log.incompat & 0x02 != 0 { 8 } else { 4 };
                    struct_node(format!("Block {b}"), span, BE, log.incompat, revoke_layout)
                        .summary(format!(
                            "revoke, transaction {seq}, {} blocks revoked",
                            used.saturating_sub(16).checked_div(record).unwrap_or(0)
                        ))
                }
            };
            cx.push(node).await;
        }
        b = b.saturating_add(1);
        if b >= log.maxlen {
            b = log.first;
        }
        if b == log.start {
            break;
        }
    }
    Ok(())
}

fn header_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    header(f)?;
    Ok(())
}

/// A descriptor block: the header, a tag per logged block, the tail.
fn descriptor_layout(f: &mut Fields<'_>, incompat: &u32) -> Result<()> {
    header(f)?;
    let data = &f.block().data;
    let end = tags_end(data.len(), *incompat);
    let size = tag_bytes(*incompat);
    let mut i = 0u32;
    let mut at = 12usize;
    while at.saturating_add(size) <= end {
        let tag = tag_at(data, at, *incompat);
        let (flag_names, _) = crate::value::decode_flags(TAG_FLAGS, tag.flags.into());
        let mut summary = format!("filesystem block {}", tag.block);
        if !flag_names.is_empty() {
            summary = format!("{summary}, {}", flag_names.join(" | "));
        }
        if let Some(c) = tag.csum {
            summary = format!("{summary}, checksum {c:#x}");
        }
        f.seek(to_u64(at));
        f.node(
            Node::new(format!("Tag {i}"))
                .span(f.peek_span(to_u64(size)))
                .summary(summary),
        );
        f.skip(to_u64(size));
        if tag.flags & SAME_UUID == 0 {
            f.bytes("UUID", 16).with(uuid_value).emit()?;
        }
        i = i.saturating_add(1);
        at = tag.end;
        if tag.flags & LAST_TAG != 0 {
            break;
        }
    }
    if *incompat & 0x18 != 0 && end >= 12 {
        f.seek(to_u64(end));
        f.u32("Block checksum").hex().emit()?;
    }
    Ok(())
}

/// Revoked blocks shown in a revoke block at most.
const MAX_REVOKED: u64 = 1024;

/// A revoke block: the header, the bytes used, the revoked blocks.
fn revoke_layout(f: &mut Fields<'_>, incompat: &u32) -> Result<()> {
    header(f)?;
    let used = f
        .u32("Bytes used")
        .desc("Header, this count and the block numbers")
        .emit()?;
    let wide = incompat & 0x02 != 0;
    let record = if wide { 8 } else { 4 };
    let total = u64::from(used)
        .saturating_sub(16)
        .checked_div(record)
        .unwrap_or(0);
    let shown = total
        .min(MAX_REVOKED)
        .min(f.remaining().checked_div(record).unwrap_or(0));
    for _ in 0..shown {
        if wide {
            f.u64("Revoked block").emit()?;
        } else {
            f.u32("Revoked block").emit()?;
        }
    }
    if total > shown {
        f.node(
            Node::new("More revoked blocks")
                .summary(format!("{} not shown", total.saturating_sub(shown))),
        );
    }
    if incompat & 0x18 != 0 && f.remaining() >= 4 {
        f.seek(f.pos().saturating_add(f.remaining()).saturating_sub(4));
        f.u32("Block checksum").hex().emit()?;
    }
    Ok(())
}

/// A commit block (`commit_header`).
fn commit_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    header(f)?;
    f.u8("Checksum type").enumeration(CSUM_TYPES).emit()?;
    f.u8("Checksum size").emit()?;
    f.bytes("Padding", 2).emit()?;
    f.u32("Checksum").hex().emit()?;
    f.bytes("Checksum (rest)", 28).emit()?;
    f.u64("Commit time").timestamp().emit()?;
    f.u32("Commit time (nanoseconds)").emit()?;
    Ok(())
}
