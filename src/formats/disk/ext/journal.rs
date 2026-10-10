//! The ext3/ext4 journal (JBD2): a superblock, then a circular log of
//! descriptor, data, commit and revoke blocks. All of it is big-endian.

use crate::bytes::u32_be;
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

/// The file system blocks a descriptor block's tags describe.
fn tags(desc: &[u8], incompat: u32) -> Vec<u64> {
    let size = tag_bytes(incompat);
    let v3 = incompat & 0x10 != 0;
    let end = if incompat & 0x18 != 0 {
        desc.len().saturating_sub(4)
    } else {
        desc.len()
    };
    let mut out = Vec::new();
    let mut at = 12usize;
    while at.saturating_add(size) <= end {
        let lo = u64::from(u32_be(desc, at).unwrap_or(0));
        let flags = if v3 {
            u32_be(desc, at.saturating_add(4)).unwrap_or(0)
        } else {
            u32::from(crate::bytes::u16_be(desc, at.saturating_add(6)).unwrap_or(0))
        };
        let hi = if incompat & 0x02 != 0 {
            u64::from(u32_be(desc, at.saturating_add(8)).unwrap_or(0))
        } else {
            0
        };
        out.push(hi << 32 | lo);
        at = at.saturating_add(size);
        if flags & 2 == 0 {
            at = at.saturating_add(16);
        }
        if flags & 8 != 0 {
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
}

/// Walks the log from its start: descriptor blocks (and the data blocks
/// they announce), commit and revoke blocks, until a block is not part of
/// the log.
async fn log_blocks(cx: Cx, log: Log) -> Result<()> {
    let mut b = log.start;
    let mut pending: std::collections::VecDeque<u64> = std::collections::VecDeque::new();
    let mut steps = 0u64;
    while steps < MAX_LOG_BLOCKS.min(log.maxlen) {
        steps = steps.saturating_add(1);
        let span = log.data.sub(b.saturating_mul(log.block), log.block);
        if let Some(target) = pending.pop_front() {
            cx.push(
                Node::new(format!("Block {b}"))
                    .span(span)
                    .summary(format!("logged copy of filesystem block {target}")),
            )
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
            if ty == 1 {
                pending = tags(&head, log.incompat).into();
            }
            cx.push(
                struct_node(format!("Block {b}"), span.sub(0, 12), BE, (), header_layout).summary(
                    format!(
                        "{}, transaction {seq}{}",
                        crate::value::lookup(BLOCK_TYPES, ty.into()).unwrap_or("unknown"),
                        if ty == 1 {
                            format!(", {} blocks follow", pending.len())
                        } else {
                            String::new()
                        }
                    ),
                ),
            )
            .await;
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
