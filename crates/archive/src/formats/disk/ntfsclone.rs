//! ntfsclone special images (`ntfsclone --save-image`, from ntfs-3g).
//!
//! A little-endian header (the magic `\0ntfsclone-image`, the image format
//! version, the cluster size, the device size, the volume's cluster count
//! and the clusters in use, then since version 10.0 the offset of the image
//! data, which ntfsclone aligns to 8 bytes) is followed by a stream of
//! per-cluster commands: a gap of empty clusters, or the next cluster's
//! bytes (see [`crate::codec::ntfsclone`]). The stream runs one cluster past
//! the volume, to the backup boot sector (version 10.1; version 10.0 images
//! end with the volume), and nothing follows it.
//!
//! The volume is the command stream decoded on demand
//! (`Codec::NtfsClone`), so opening it decodes only as far as reads reach,
//! and it is dissected as nested content (an NTFS volume). The command
//! listing walks the stream itself, coalescing runs of clusters, and
//! reports what only a walk can find (a stream that ends early, bytes after
//! the last cluster, an in-use count that disagrees with the data).
//!
//! Images piped through gzip (`ntfsclone -s -o - | gzip`) are gzip files
//! whose content is identified as this. gzip records no usable size, so
//! that content's length is unknown until it has been decoded to its end;
//! this is a streaming format (`formats::STREAMING`), which needs nothing
//! from the length, so the volume decodes on demand through both stages and
//! opening it decodes only the start of the gzip stream.
//!
//! Checked against images written by ntfs-3g 2022.10.3 (fixtures in
//! `tests/fixtures/external/`) and against how its `ntfsclone` reads them
//! (`open_image` and `restore_image`, read for facts only). Images older
//! than version 10.0 (host byte order, no data offset) are read as
//! little-endian, the only byte order known to have written them; none was
//! available to check.

use std::sync::Arc;

use crate::codec::ntfsclone::{CMD_GAP, CMD_NEXT, Image, MAX_CLUSTER};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{DiagKind, Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::disk::size;
use crate::formats::util::fmt::plural;
use crate::formats::{Codec, Format, Input, Probe, dissect_or_data};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{Radix, Value};

const LE: Endian = Endian::Little;
const MAGIC: &[u8; 16] = b"\0ntfsclone-image";
/// The first version with a defined (little-endian) byte order and a data
/// offset.
const SAFE_MAJOR: u8 = 10;
/// The newest version ntfsclone knows (minor versions only extend the
/// header compatibly).
const MAJOR: u8 = 10;
/// Clusters a run node of the command listing covers at most.
const MAX_RUN: u64 = 1 << 16;
/// Bytes between the header fields and the data offset shown in the header
/// node, at most (ntfsclone pads to 8 bytes; a crafted offset can be
/// gigabytes away).
const MAX_PADDING: u64 = 4096;

pub static FORMAT: Format = Format {
    name: "ntfsclone",
    title: "ntfsclone special image",
    extensions: &["ntfsclone"],
    mime: "application/x-ntfsclone-image",
    probe: Probe::Magic(&[(0, MAGIC)]),
    dissect: crate::expander!(dissect: Input),
};

record! {
    /// The header fields every version has.
    pub struct Header {
        magic: bytes[16] "Magic",
        major: u8 "Major version",
        minor: u8 "Minor version",
        cluster_size: u32 "Cluster size" .with(|&v, n| n.summary(size(v.into()))),
        device_size: u64 "Device size" .with(|&v, n| n.summary(size(v))),
        clusters: i64 "Clusters" .desc("Clusters in the volume; the image goes one further, to the backup boot sector"),
        in_use: u64 "Clusters in use" .desc("Not counting the backup boot sector's cluster"),
    }
}

/// The header, and where the command stream starts.
struct Parsed {
    h: Header,
    /// Where ntfsclone starts reading commands: past the fields it knows,
    /// or at the data offset if that is further.
    start: u64,
}

fn header_layout(f: &mut Fields<'_>, _: &()) -> Result<Parsed> {
    let h = Header::read(f)?;
    let mut start = Header::SIZE;
    if h.major >= SAFE_MAJOR {
        let o = f
            .u32("Data offset")
            .hex()
            .check(|&o| {
                (u64::from(o) < Header::SIZE.saturating_add(4)).then(|| {
                    Diagnostic::warning(
                        "data offset inside the header (ntfsclone reads on from its end)",
                    )
                })
            })
            .emit()?;
        start = Header::SIZE.saturating_add(4).max(o.into());
    }
    let rest = start.saturating_sub(f.pos()).min(f.remaining());
    if rest > 0 {
        f.bytes("Padding", rest).emit()?;
    }
    Ok(Parsed { h, start })
}

/// What the expanders share.
struct State {
    input: Input,
    /// The command stream: from the data offset to the end of the input.
    stream: Span,
    image: Image,
    in_use: u64,
    /// Whether the stream goes on to the backup boot sector (10.1).
    backup: bool,
    volume_len: u64,
}

impl State {
    /// The volume decoded on demand (memoized, so every caller gets the
    /// same source).
    fn volume(&self, cx: &Cx) -> Result<Span> {
        cx.decode_lazy(self.stream, &Codec::NtfsClone(self.image), self.volume_len)
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    // At most the fields ntfsclone knows, to find the data offset.
    let fixed = file.sub(0, Header::SIZE.saturating_add(4));
    let p = parse(&cx, fixed, LE, &(), header_layout).await?;
    let h = &p.h;
    let fields = if h.major >= SAFE_MAJOR {
        Header::SIZE.saturating_add(4)
    } else {
        Header::SIZE
    };
    let header_span = file.sub(0, p.start.min(fields.saturating_add(MAX_PADDING)));
    let version = format!("{}.{}", h.major, h.minor);
    let mut header = struct_node("Header", header_span, LE, (), header_layout)
        .summary(format!("version {version}"));
    if h.major < SAFE_MAJOR {
        header = header.diag(Diagnostic::note(
            "an image older than version 10.0, in the byte order of the machine that wrote it; read as little-endian",
        ));
    }
    let cs = h.cluster_size;
    let image = Image {
        cluster_size: cs,
        device_size: h.device_size,
        clusters: u64::try_from(h.clusters).unwrap_or(0),
    };
    let backup = h.major > SAFE_MAJOR || (h.major == SAFE_MAJOR && h.minor >= 1);
    let volume_len = image.volume_len(backup);
    cx.annotate(format!(
        "ntfsclone image {version}, {} volume, {} clusters, {} in use",
        size(image.offset(image.clusters)),
        size(cs.into()),
        h.in_use
    ));
    let mut problem = None;
    if h.major > MAJOR {
        problem = Some(Diagnostic::unsupported(format!(
            "image format version {version} (ntfsclone knows up to {MAJOR}.x)"
        )));
    } else if cs == 0 || cs > MAX_CLUSTER {
        problem = Some(Diagnostic::malformed(format!("cluster size {cs:#x}")));
    } else if h.clusters < 0 {
        problem = Some(Diagnostic::malformed(format!(
            "negative cluster count {}",
            h.clusters
        )));
    }
    if problem.is_none() {
        if !cs.is_power_of_two() || cs < 256 {
            header = header.diag(Diagnostic::warning(format!(
                "cluster size {cs:#x} is not a power of two from 256"
            )));
        }
        if image.offset(image.clusters) > h.device_size {
            header = header.diag(Diagnostic::warning(format!(
                "the volume ({}) is larger than the device ({})",
                size(image.offset(image.clusters)),
                size(h.device_size)
            )));
        }
        if h.in_use > image.clusters {
            header = header.diag(Diagnostic::warning(format!(
                "{} clusters in use, of {}",
                h.in_use, image.clusters
            )));
        }
    }
    cx.emit(header);
    if p.start > header_span.len {
        let skipped = file.sub(header_span.len, p.start.saturating_sub(header_span.len));
        cx.emit(
            Node::new("Before the data")
                .span(skipped)
                .summary(size(skipped.len)),
        );
    }
    if let Some(problem) = problem {
        return Err(problem.at(header_span));
    }
    let state = Arc::new(State {
        stream: file.tail(p.start.min(file.len)),
        input,
        image,
        in_use: h.in_use,
        backup,
        volume_len,
    });
    // No spans on these two: the stream's end is not known yet when the
    // image is the content of a gzip stream decoded on demand (this is a
    // streaming format), and the tree must not depend on it.
    cx.emit(
        Node::new("Volume")
            .summary(size(volume_len))
            .desc("The volume restored from the command stream, decoded as far as reads reach")
            .lazy(volume, state.clone()),
    );
    cx.emit(
        Node::new("Commands")
            .summary("runs of saved and empty clusters")
            .lazy(commands, state),
    );
    Ok(())
}

async fn volume(cx: Cx, state: Arc<State>) -> Result<()> {
    let span = state.volume(&cx)?;
    dissect_or_data(cx, state.input.nested(span)).await
}

/// A shortage of input found by the walk.
fn ends_early(message: String, at: Span) -> Diagnostic {
    Diagnostic::new(DiagKind::Truncated, message).at(at)
}

/// Lists the command stream as runs of data and empty clusters, from
/// resume marks when the host seeks.
async fn commands(cx: Cx, state: Arc<State>) -> Result<()> {
    let stream = state.stream;
    let image = state.image;
    let clusters = image.clusters;
    let volume = state.volume(&cx).ok();
    // Stream offset, next cluster, data clusters seen before it.
    let (mut pos, mut lcn, mut data) = cx.resume::<(u64, u64, u64)>().unwrap_or((0, 0, 0));
    let mut clean = true;
    // Version 10.1 images go one cluster further, to the backup boot
    // sector; 10.0 images end with the volume.
    let end = clusters.saturating_add(u64::from(state.backup));
    while lcn < end {
        let run = (pos, lcn, data);
        cx.progress_in(stream, pos);
        let Some(&cmd) = cx.read_avail(stream.sub(pos, 1)).await?.first() else {
            if lcn < clusters {
                cx.diag(ends_early(
                    format!("the image ends at cluster {lcn} of {}", clusters),
                    stream.sub(pos, 0),
                ));
                clean = false;
            } else if state.backup {
                // ntfsclone restores such an image with a warning.
                cx.diag(Diagnostic::warning(
                    "the image ends without the backup boot sector's cluster",
                ));
            }
            break;
        };
        let node = match cmd {
            CMD_GAP => {
                let span = stream.sub(pos, 9);
                let raw = cx.read_avail(span).await?;
                let Some(count) = raw
                    .get(1..9)
                    .and_then(|b| <[u8; 8]>::try_from(b).ok())
                    .map(i64::from_le_bytes)
                else {
                    let span = Span::new(span.source, span.offset, crate::bytes::to_u64(raw.len()));
                    cx.mark(move || run);
                    cx.push(Node::new("Gap").span(span).diag(ends_early(
                        "the image ends inside a gap command".into(),
                        span,
                    )))
                    .await;
                    clean = false;
                    break;
                };
                let node = Node::new("Gap").span(span);
                let n = match u64::try_from(count) {
                    Ok(n) if n > 0 && lcn.saturating_add(n) <= clusters => n,
                    _ => {
                        let problem = if count < 0 {
                            Diagnostic::unsupported(format!(
                                "backward gap of {count} clusters (a metadata image saved with --ignore-fs-check)"
                            ))
                        } else if count == 0 {
                            Diagnostic::malformed("empty gap")
                        } else {
                            Diagnostic::malformed(format!(
                                "gap of {count} clusters runs past the last cluster ({clusters})"
                            ))
                        };
                        cx.mark(move || run);
                        cx.push(
                            node.summary(format!("{count} clusters"))
                                .diag(problem.at(span)),
                        )
                        .await;
                        clean = false;
                        break;
                    }
                };
                let last = lcn.saturating_add(n).saturating_sub(1);
                let bytes = image.offset(n);
                pos = pos.saturating_add(9);
                let name = if n == 1 {
                    format!("Cluster {lcn}")
                } else {
                    format!("Clusters {lcn}–{last}")
                };
                let mut node = node
                    .renamed(name)
                    .summary(format!("empty, {}", size(bytes)));
                if let Some(v) = volume {
                    node = node.target(v.sub(image.offset(lcn), bytes));
                }
                lcn = last.saturating_add(1);
                node
            }
            CMD_NEXT => {
                let first = lcn;
                let mut bytes = 0u64;
                let mut problem = None;
                // Consecutive data commands, up to a bounded run.
                loop {
                    let Some(len) = image.cluster_len(lcn) else {
                        problem = Some(Diagnostic::malformed(format!(
                            "cluster {lcn} lies past the end of the device"
                        )));
                        break;
                    };
                    let body = pos.saturating_add(1);
                    pos = body.saturating_add(len);
                    bytes = bytes.saturating_add(len);
                    lcn = lcn.saturating_add(1);
                    data = data.saturating_add(1);
                    if lcn.saturating_sub(first).is_multiple_of(4096) {
                        cx.progress_in(stream, pos);
                    }
                    // The next command, or the end of the stream: only then
                    // is its length needed (it may not be known before).
                    let next = cx.read_avail(stream.sub(pos, 1)).await?.first().copied();
                    if next.is_none() {
                        let end = cx.known(stream).await.len;
                        if end < pos {
                            let have = len.saturating_sub(pos.saturating_sub(end));
                            bytes = bytes.saturating_sub(pos.saturating_sub(end));
                            pos = end;
                            problem = Some(ends_early(
                                format!(
                                    "the image ends inside cluster {} ({have:#x} of {len:#x} bytes)",
                                    lcn.saturating_sub(1)
                                ),
                                stream.sub(body, have),
                            ));
                        }
                        break;
                    }
                    if next != Some(CMD_NEXT) || lcn >= end || lcn.saturating_sub(first) >= MAX_RUN
                    {
                        break;
                    }
                }
                let last = lcn.saturating_sub(1).max(first);
                let span = stream.sub(run.0, pos.saturating_sub(run.0));
                let name = if last == first {
                    format!("Cluster {first}")
                } else {
                    format!("Clusters {first}–{last}")
                };
                // The cluster past the volume's last holds the backup boot
                // sector.
                let backup = if lcn > clusters {
                    ", backup boot sector"
                } else {
                    ""
                };
                let mut node = Node::new(name)
                    .span(span)
                    .summary(format!("data, {}{backup}", size(bytes)));
                if let Some(v) = volume {
                    node = node.target(v.sub(image.offset(first), bytes));
                }
                if let Some(problem) = problem {
                    clean = false;
                    cx.mark(move || run);
                    cx.push(node.diag(problem)).await;
                    break;
                }
                node
            }
            other => {
                let span = stream.sub(pos, 1);
                cx.mark(move || run);
                cx.push(
                    Node::new("Unknown command")
                        .span(span)
                        .value(Value::UInt {
                            value: u64::from(other),
                            bits: 8,
                            radix: Radix::Hex,
                        })
                        .diag(
                            Diagnostic::malformed(format!("unknown command {other:#04x}")).at(span),
                        ),
                )
                .await;
                clean = false;
                break;
            }
        };
        cx.mark(move || run);
        cx.push(node).await;
    }
    cx.progress_in(stream, pos);
    if !clean {
        return Ok(());
    }
    let stream = cx.known(stream).await;
    if pos < stream.len {
        let span = stream.tail(pos);
        cx.mark(move || (pos, lcn, data));
        cx.push(
            Node::new("Trailing data")
                .span(span)
                .summary(size(span.len))
                .diag(
                    Diagnostic::warning(format!(
                        "{} after the last cluster ({clusters})",
                        plural(span.len, "byte")
                    ))
                    .at(span),
                ),
        )
        .await;
    }
    // The header's count leaves out the backup boot sector's cluster.
    let counted = if lcn > clusters {
        data.saturating_sub(1)
    } else {
        data
    };
    if counted != state.in_use {
        cx.diag(Diagnostic::warning(format!(
            "{} saved before the backup boot sector; the header says {} in use",
            plural(counted, "cluster"),
            state.in_use
        )));
    }
    Ok(())
}
