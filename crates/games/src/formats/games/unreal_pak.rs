//! The index of an Unreal Engine `.pak` file (the footer and the probe are
//! in `archives`).
//!
//! From repak (`pak.rs` `Index::read`, `entry.rs`) and FPakFile in UE's
//! IPlatformFilePak: before v10 the index is the mount point, a count and
//! (path, FPakEntry) pairs; from v10 it holds the mount point, a count, the
//! path hash seed, where the path-hash and full-directory indexes are, the
//! bit-packed "encoded" entries and the entries too irregular to encode.

use std::sync::Arc;

use super::unreal::{check_count, fstring};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse};
use crate::formats::Input;
use crate::formats::util::fmt;
use crate::node::{Count, Node};
use crate::span::Span;

const LE: Endian = Endian::Little;

/// What the pak footer says about the index.
#[derive(Clone, Debug)]
pub struct PakFooter {
    pub version: u32,
    /// v8 with four method names: FPakEntry's method is a byte.
    pub narrow_method: bool,
    pub encrypted: bool,
    pub frozen: bool,
    pub index_offset: u64,
    pub index_size: u64,
    /// Compression method names (v8+); before v8 the method is a flag.
    pub methods: Arc<[String]>,
}

impl PakFooter {
    /// The compression method an entry's method field names.
    fn method(&self, raw: u32) -> String {
        if raw == 0 {
            return "none".into();
        }
        if self.version < 8 {
            return match raw {
                1 => "Zlib",
                2 => "Gzip",
                4 => "Custom",
                _ => "unknown",
            }
            .into();
        }
        usize::try_from(raw.saturating_sub(1))
            .ok()
            .and_then(|i| self.methods.get(i))
            .filter(|s| !s.is_empty())
            .cloned()
            .unwrap_or_else(|| format!("method {raw}"))
    }

    /// The size of the FPakEntry serialized in front of a file's data.
    fn entry_size(&self, compressed: bool, blocks: u64) -> u64 {
        let mut size: u64 = if self.narrow_method { 45 } else { 48 };
        if self.version == 1 {
            size = size.saturating_add(8);
        }
        if compressed && self.version >= 3 {
            size = size
                .saturating_add(4)
                .saturating_add(blocks.saturating_mul(16));
        }
        if self.version >= 3 {
            size = size.saturating_add(5);
        }
        size
    }
}

/// One file's data, as an index entry describes it.
#[derive(Clone, Debug, Default)]
struct PakEntry {
    size: u64,
    method: u32,
    /// Compression blocks (or the stored data) as absolute (start, end)
    /// offsets in the pak.
    blocks: Vec<(u64, u64)>,
    encrypted: bool,
    block_size: u32,
}

/// FPakEntry (in the index before v10, or an irregular one from v10).
fn pak_entry(f: &mut Fields<'_>, footer: &PakFooter) -> Result<PakEntry> {
    let offset = f.u64("Offset").hex().get()?;
    let compressed = f.u64("Stored size").get()?;
    let size = f.u64("Size").get()?;
    let method = if footer.narrow_method {
        f.u8("Compression method").get()?.into()
    } else {
        f.u32("Compression method").get()?
    };
    if footer.version == 1 {
        f.u64("Timestamp").get()?;
    }
    f.bytes("SHA-1", 20).get()?;
    let mut e = PakEntry {
        size,
        method,
        ..PakEntry::default()
    };
    if footer.version >= 3 {
        if method != 0 {
            let count = f.u32("Compression blocks").get()?;
            check_count(
                f,
                i32::try_from(count).unwrap_or(-1),
                16,
                "compression block",
            )?;
            // From v5 block offsets count from the entry's offset.
            let base = if footer.version >= 5 { offset } else { 0 };
            for _ in 0..count {
                let start = f.u64("Block start").get()?;
                let end = f.u64("Block end").get()?;
                e.blocks
                    .push((base.saturating_add(start), base.saturating_add(end)));
            }
        }
        e.encrypted = f.u8("Flags").get()? & 1 != 0;
        e.block_size = f.u32("Compression block size").get()?;
    }
    if e.blocks.is_empty() {
        let at = offset.saturating_add(footer.entry_size(false, 0));
        e.blocks.push((at, at.saturating_add(compressed)));
    }
    Ok(e)
}

/// An encoded entry (v10+, `FPakFile::EncodePakEntry`): flags, then the
/// offset and sizes in 32 or 64 bits, then the block sizes.
fn encoded_entry(f: &mut Fields<'_>, footer: &PakFooter) -> Result<PakEntry> {
    let bits = f.u32("Flags").get()?;
    let method = (bits >> 23) & 0x3f;
    let encrypted = bits & (1 << 22) != 0;
    let count = u64::from((bits >> 6) & 0xffff);
    let block_size = match bits & 0x3f {
        0x3f => f.u32("Block size").get()?,
        n => n << 11,
    };
    let mut var = |bit: u32, name: &'static str| -> Result<u64> {
        if bits & (1 << bit) != 0 {
            Ok(f.u32(name).get()?.into())
        } else {
            f.u64(name).get()
        }
    };
    let offset = var(31, "Offset")?;
    let size = var(30, "Size")?;
    let compressed = if method == 0 {
        size
    } else {
        var(29, "Stored size")?
    };
    let start = offset.saturating_add(footer.entry_size(method != 0, count));
    let mut blocks = Vec::new();
    if count > 1 || (count == 1 && encrypted) {
        if count.saturating_mul(4) > f.remaining() {
            return Err(Diagnostic::malformed(format!("{count} compression blocks")));
        }
        let mut at = start;
        for _ in 0..count {
            let len = u64::from(f.u32("Block size").get()?);
            blocks.push((at, at.saturating_add(len)));
            // Encrypted blocks are padded to the AES block size.
            at = at.saturating_add(if encrypted {
                len.next_multiple_of(16)
            } else {
                len
            });
        }
    } else {
        blocks.push((start, start.saturating_add(compressed)));
    }
    Ok(PakEntry {
        size,
        method,
        blocks,
        encrypted,
        block_size,
    })
}

/// The node for a file in the pak: its data, decoded where we can.
fn file_node(input: Input, footer: &PakFooter, name: String, e: &PakEntry) -> Node {
    use crate::codec::Codec;
    use crate::codec::psarc::{self, BlockCodec};
    let method = footer.method(e.method);
    let first = e.blocks.first().map_or(0, |b| b.0);
    let last = e.blocks.last().map_or(0, |b| b.1);
    let span = input.span.sub(first, last.saturating_sub(first));
    let contiguous = e
        .blocks
        .windows(2)
        .all(|w| matches!(w, [a, b] if a.1 == b.0));
    let summary = if e.method == 0 {
        fmt::size(e.size)
    } else {
        format!(
            "{}, {method}, {}",
            fmt::size(e.size),
            fmt::plural(crate::bytes::to_u64(e.blocks.len()), "block")
        )
    };
    let lower = method.to_ascii_lowercase();
    let codec = match lower.as_str() {
        _ if e.encrypted => Err("encrypted entry (AES-256, no key)".to_owned()),
        "none" => Ok(None),
        _ if !contiguous => Err(format!("{method} blocks out of order")),
        "zlib" if e.blocks.len() == 1 => Ok(Some(Codec::Zlib)),
        "lz4" if e.blocks.len() == 1 => Ok(Some(Codec::Lz4Block)),
        // Zstandard frames back to back decode as one stream.
        "zstd" => Ok(Some(Codec::Zstd)),
        // One stream per block, back to back: PSARC's block codec (also for
        // a single gzip block, whose member header it skips).
        "zlib" | "gzip" | "lz4" => Ok(Some(Codec::Psarc(psarc::Entry {
            block_size: e.block_size,
            size: e.size,
            blocks: e
                .blocks
                .iter()
                .map(|&(a, b)| u32::try_from(b.saturating_sub(a)).unwrap_or(u32::MAX))
                .collect(),
            codec: match lower.as_str() {
                "zlib" => BlockCodec::Zlib,
                "gzip" => BlockCodec::Gzip,
                _ => BlockCodec::Lz4Block,
            },
        }))),
        _ => Err(format!("{method} compression")),
    };
    let node = match codec {
        Ok(None) => crate::formats::embedded(name, input.nested(span)),
        Ok(Some(codec)) => crate::formats::content(name, input, span, codec, Some(e.size)),
        Err(why) => Node::new(name)
            .span(span)
            .diag(Diagnostic::unsupported(why).at(span)),
    };
    node.summary(summary)
}

#[derive(Clone)]
struct PakIndex {
    input: Input,
    index: Span,
    footer: PakFooter,
}

/// The lazy node for the index.
pub fn pak_index_node(input: Input, index: Span, footer: PakFooter) -> Node {
    let node = Node::new("Index").span(index);
    if footer.encrypted {
        return node.diag(Diagnostic::unsupported("encrypted index (AES-256, no key)"));
    }
    if footer.frozen {
        return node.diag(Diagnostic::unsupported("frozen index (v9)"));
    }
    node.lazy(
        pak_index,
        PakIndex {
            input,
            index,
            footer,
        },
    )
}

/// Where the index keeps its parts.
#[derive(Clone)]
struct PakLayout {
    mount: String,
    count: u32,
    /// v1-v9: where the (path, entry) pairs start.
    entries: u64,
    /// v10+: the full directory index, if the pak has one.
    directory: Option<Span>,
    /// v10+: the encoded entries, and where the irregular entries start.
    encoded: Span,
    irregular: u64,
    /// v10+: how many irregular entries the index says it holds.
    irregulars: u32,
}

/// An optional region of the v10+ index: a flag, then offset, size and
/// SHA-1.
fn index_region(f: &mut Fields<'_>, name: &'static str, file: Span) -> Result<Option<Span>> {
    if f.u32(name).emit()? == 0 {
        return Ok(None);
    }
    let offset = f.u64("Offset").hex().emit()?;
    let size = f.u64("Size").emit()?;
    f.bytes("SHA-1", 20).emit()?;
    let span = file.sub(offset, size);
    f.node(Node::new(name).span(span).summary(fmt::size(size)));
    Ok(Some(span))
}

fn index_layout(f: &mut Fields<'_>, (footer, file): &(PakFooter, Span)) -> Result<PakLayout> {
    let mount = fstring(f, "Mount point")?;
    let count = f.u32("Entry count").emit()?;
    let mut l = PakLayout {
        mount,
        count,
        entries: f.pos(),
        directory: None,
        encoded: f.peek_span(0),
        irregular: 0,
        irregulars: 0,
    };
    if footer.version < 10 {
        return Ok(l);
    }
    f.u64("Path hash seed").hex().emit()?;
    index_region(f, "Path hash index", *file)?;
    l.directory = index_region(f, "Full directory index", *file)?;
    let size = f.u32("Encoded entries size").emit()?;
    l.encoded = f.peek_span(size.into());
    f.node(Node::new("Encoded entries").span(l.encoded));
    f.skip(size.into());
    l.irregulars = f.u32("Irregular entries").emit()?;
    l.irregular = f.pos();
    Ok(l)
}

async fn pak_index(cx: Cx, st: PakIndex) -> Result<()> {
    let ctx = (st.footer.clone(), st.input.span);
    let layout = parse(&cx, st.index, LE, &ctx, index_layout).await?;
    let summary = format!(
        "{} under \"{}\"",
        fmt::plural(layout.count, "file"),
        layout.mount
    );
    let block = cx.block(st.index).await?;
    index_layout(&mut Fields::emitting(&cx, &block, LE), &ctx)?;
    cx.emit(
        Node::new("Files")
            .summary(summary)
            .lazy(pak_files, (st, layout)),
    );
    Ok(())
}

/// Where each irregular entry starts in the index, found once per index
/// (entries vary in size, so finding the n-th means walking those before
/// it): up to the count the index gives or the first entry that does not
/// parse.
async fn irregular_starts(
    cx: &Cx,
    st: &PakIndex,
    index: &crate::cx::Block,
    layout: &PakLayout,
) -> Arc<Vec<u64>> {
    if let Some(starts) = cx.cached::<Vec<u64>>(st.index, "pak-irregular") {
        return starts;
    }
    let mut f = Fields::new(index, LE);
    f.seek(layout.irregular);
    let mut starts = Vec::new();
    for _ in 0..layout.irregulars {
        let at = f.pos();
        if pak_entry(&mut f, &st.footer).is_err() {
            break;
        }
        starts.push(at);
        cx.checkpoint().await;
    }
    let starts = Arc::new(starts);
    cx.cache(st.index, "pak-irregular", starts.clone());
    starts
}

/// The irregular entry an encoded offset of `offset` (negative) names.
fn irregular_entry(
    index: &crate::cx::Block,
    starts: &[u64],
    footer: &PakFooter,
    offset: i32,
) -> Result<PakEntry> {
    let wanted = offset.unsigned_abs().saturating_sub(1);
    let Some(&at) = usize::try_from(wanted).ok().and_then(|i| starts.get(i)) else {
        return Err(Diagnostic::malformed(format!(
            "irregular entry {wanted} of {}",
            starts.len()
        )));
    };
    let mut e = Fields::new(index, LE);
    e.seek(at);
    pak_entry(&mut e, footer)
}

/// The files: (path, entry) pairs before v10; from v10 the full directory
/// index's directories and files, each naming an encoded entry by its
/// offset (or, negative, an irregular one).
async fn pak_files(cx: Cx, (st, layout): (PakIndex, PakLayout)) -> Result<()> {
    let footer = &st.footer;
    cx.set_count(Count::Exact(layout.count.into()));
    let index = cx.block(st.index).await?;
    if footer.version < 10 {
        let (pos, done) = cx.resume::<(u64, u32)>().unwrap_or((layout.entries, 0));
        let mut f = Fields::new(&index, LE);
        f.seek(pos);
        for i in done..layout.count {
            let at = (f.pos(), i);
            cx.mark(move || at);
            let path = fstring(&mut f, "Path")?;
            let entry = pak_entry(&mut f, footer)?;
            cx.push(file_node(st.input, footer, path, &entry)).await;
        }
        return Ok(());
    }
    let Some(directory) = layout.directory else {
        return Err(Diagnostic::unsupported(
            "pak without a full directory index",
        ));
    };
    let dir = cx.block(directory).await?;
    let encoded = cx.block(layout.encoded).await?;
    let mut starts: Option<Arc<Vec<u64>>> = None;
    let mut f = Fields::new(&dir, LE);
    let (pos, mut dir_name, mut files_left, mut dirs_left) =
        match cx.resume::<(u64, String, u32, u32)>() {
            Some(state) => state,
            None => {
                let dirs = f.u32("Directories").get()?;
                (f.pos(), String::new(), 0, dirs)
            }
        };
    f.seek(pos);
    loop {
        if files_left == 0 {
            if dirs_left == 0 {
                break;
            }
            dirs_left = dirs_left.saturating_sub(1);
            dir_name = fstring(&mut f, "Directory")?;
            files_left = f.u32("Files").get()?;
            cx.checkpoint().await;
            continue;
        }
        let at = (f.pos(), dir_name.clone(), files_left, dirs_left);
        cx.mark(move || at);
        files_left = files_left.saturating_sub(1);
        let name = fstring(&mut f, "File")?;
        let offset = f.i32("Entry").get()?;
        // i32::MIN marks a deleted entry.
        if offset == i32::MIN {
            cx.checkpoint().await;
            continue;
        }
        let path = format!("{}{name}", dir_name.strip_prefix('/').unwrap_or(&dir_name));
        let entry = if offset >= 0 {
            let mut e = Fields::new(&encoded, LE);
            e.seek(u64::try_from(offset).unwrap_or(0));
            encoded_entry(&mut e, footer)
        } else {
            let table = match &starts {
                Some(t) => t.clone(),
                None => {
                    let t = irregular_starts(&cx, &st, &index, &layout).await;
                    starts = Some(t.clone());
                    t
                }
            };
            irregular_entry(&index, &table, footer, offset)
        };
        let node = match entry {
            Ok(entry) => file_node(st.input, footer, path, &entry),
            Err(e) => Node::new(path).diag(e),
        };
        cx.push(node).await;
    }
    Ok(())
}
