//! CRIU checkpoint images (`criu dump -D dir`: `inventory.img`,
//! `core-<pid>.img`, `mm-<pid>.img`, `pagemap-<pid>.img`, `files.img`,
//! ...).
//!
//! Each image starts with two 32-bit magics in the host's byte order: the
//! image class (`IMG_COMMON`, or `IMG_SERVICE` for CRIU's own records such
//! as `stats-dump`) and the image type; the inventory has only its own
//! magic. Entries follow, each a 32-bit size and a protocol buffers
//! message of the image type's schema. Some types carry raw data after an
//! entry: pipe and FIFO contents, socket queues, TCP stream queues, BPF map
//! data, System V IPC contents, and the file data of ghost files, each
//! shown after the entry's fields as content that is identified on
//! expansion (a message queue's messages one by one); the
//! pagemap image starts with a `pagemap_head` and continues with
//! `pagemap_entry` records. `pages-<n>.img` holds only raw page data (no
//! magic, no entries; the pagemap says which pages it holds), so it is not
//! identified as this format.
//!
//! Message schemas (field numbers, names, types, enum values, flag names)
//! follow CRIU's `images/*.proto` and the flag tables of `crit`
//! (`pycriu`), read for these facts; the magic numbers are those of
//! `criu/include/magic.h`. Types whose schema is not listed here are shown
//! by wire type. Repeated fields whose position means something are
//! labelled by it: resource limits (`RLIMIT_*`), signal actions, AArch64
//! registers, auxiliary vector pairs (`AT_*`), using the generic Linux
//! numbering (MIPS numbers some limits and signals differently).
//! Checked against images written by `criu dump` 4.1.1 and 4.2.1 (external
//! fixtures, including pipe, socket, TCP, IPC and ghost file data).

use crate::bytes::{u32_be, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::fmt::{plural, preview};
use crate::formats::util::wire::protobuf::{self as proto, Elem, Index, Msg, Ty, f, varint_in};
use crate::formats::{Head, Input, Probe, embedded};
use crate::node::Node;
use crate::span::Span;
use crate::value::Radix;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};
use std::borrow::Cow;

const IMG_COMMON: u32 = 0x5456_4319;
const IMG_SERVICE: u32 = 0x5510_5940;
const INVENTORY: u32 = 0x5831_3116;

/// Image types: magic, name, what it holds, entry schema, raw data after
/// entries.
struct ImageType {
    magic: u32,
    name: &'static str,
    title: &'static str,
    msg: &'static Msg,
    extra: Extra,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Extra {
    None,
    /// Raw bytes after each entry, as many as varint field `n` says.
    Field(u64),
    /// Two such fields: the data of the first, then of the second, with
    /// their names.
    Fields(u64, &'static str, u64, &'static str),
    /// System V shared memory: `size` rounded up to 4, unless the data is
    /// in the pagemap.
    Shm,
    /// Semaphores: `nsems` 16-bit values, rounded up to 8 bytes.
    Sem,
    /// Message queues: `qnum` messages, each a sized `ipc_msg` and its
    /// text rounded up to 8 bytes.
    Msg,
    /// The pagemap: a `pagemap_head`, then `pagemap_entry` records.
    Pagemap,
    /// A ghost file: its entry, then chunks (or the whole file's data).
    Ghost,
}

const fn t(magic: u32, name: &'static str, title: &'static str, msg: &'static Msg) -> ImageType {
    ImageType {
        magic,
        name,
        title,
        msg,
        extra: Extra::None,
    }
}

const fn tx(
    magic: u32,
    name: &'static str,
    title: &'static str,
    msg: &'static Msg,
    extra: Extra,
) -> ImageType {
    ImageType {
        magic,
        name,
        title,
        msg,
        extra,
    }
}

const U: &Msg = &proto::UNKNOWN;

static TYPES: &[ImageType] = &[
    t(
        INVENTORY,
        "INVENTORY",
        "checkpoint inventory",
        &INVENTORY_ENTRY,
    ),
    t(0x5027_3030, "PSTREE", "process tree", &PSTREE_ENTRY),
    t(
        0x5621_3732,
        "FDINFO",
        "file descriptors of a task",
        &FDINFO_ENTRY,
    ),
    tx(
        0x5608_4025,
        "PAGEMAP",
        "memory pages of a task",
        &PAGEMAP_ENTRY,
        Extra::Pagemap,
    ),
    t(0x5505_3847, "CORE", "task and thread state", &CORE_ENTRY),
    t(
        0x5443_2030,
        "IDS",
        "kernel object IDs of a task",
        &IDS_ENTRY,
    ),
    t(0x5412_3737, "VMAS", "memory areas", &VMA_ENTRY),
    t(0x5651_3555, "PIPES", "pipes", &PIPE_ENTRY),
    tx(
        0x5645_3709,
        "PIPES_DATA",
        "pipe contents",
        &PIPE_DATA_ENTRY,
        Extra::Field(2),
    ),
    t(0x5836_4939, "FIFO", "FIFOs", &FIFO_ENTRY),
    tx(
        0x5933_3054,
        "FIFO_DATA",
        "FIFO contents",
        &PIPE_DATA_ENTRY,
        Extra::Field(2),
    ),
    t(0x5534_4201, "SIGACT", "signal actions", &SA_ENTRY),
    t(0x5437_3943, "UNIXSK", "Unix sockets", &UNIX_SK_ENTRY),
    t(0x5644_3851, "INETSK", "Internet sockets", &INET_SK_ENTRY),
    t(0x6045_4618, "PACKETSK", "packet sockets", U),
    t(0x5746_4056, "ITIMERS", "interval timers", &ITIMER_ENTRY),
    t(
        0x5260_3957,
        "POSIX_TIMERS",
        "POSIX timers",
        &POSIX_TIMER_ENTRY,
    ),
    tx(
        0x5626_4026,
        "SK_QUEUES",
        "socket queues",
        &SK_PACKET_ENTRY,
        Extra::Field(2),
    ),
    t(0x5447_3203, "UTSNS", "UTS namespace", &UTSNS_ENTRY),
    t(0x5402_3547, "CREDS", "credentials", &CREDS_ENTRY),
    t(
        0x5311_5007,
        "IPC_VAR",
        "IPC namespace variables",
        &IPC_VAR_ENTRY,
    ),
    tx(
        0x4628_3044,
        "IPCNS_SHM",
        "System V shared memory",
        &IPC_SHM_ENTRY,
        Extra::Shm,
    ),
    tx(
        0x5545_3737,
        "IPCNS_MSG",
        "System V message queues",
        &IPC_MSG_ENTRY,
        Extra::Msg,
    ),
    tx(
        0x5957_3019,
        "IPCNS_SEM",
        "System V semaphores",
        &IPC_SEM_ENTRY,
        Extra::Sem,
    ),
    t(0x5036_3636, "REG_FILES", "regular files", &REG_FILE_ENTRY),
    t(0x5925_5641, "EXT_FILES", "external files", U),
    t(0x5140_3912, "FS", "file system context", &FS_ENTRY),
    t(0x5749_2820, "MM", "memory layout", &MM_ENTRY),
    t(0x5913_3954, "REMAP_FPATH", "remapped file paths", U),
    tx(
        0x5258_3605,
        "GHOST_FILE",
        "ghost (deleted) file",
        &GHOST_FILE_ENTRY,
        Extra::Ghost,
    ),
    tx(
        0x5146_5506,
        "TCP_STREAM",
        "TCP stream state",
        &TCP_STREAM_ENTRY,
        Extra::Fields(1, "Receive queue", 3, "Send queue"),
    ),
    t(0x4452_3722, "EVENTFD_FILE", "eventfds", &EVENTFD_ENTRY),
    t(
        0x4502_3858,
        "EVENTPOLL_FILE",
        "epoll instances",
        &EVENTPOLL_FILE,
    ),
    t(
        0x4443_3746,
        "EVENTPOLL_TFD",
        "epoll targets",
        &EVENTPOLL_TFD,
    ),
    t(0x5732_3820, "SIGNALFD", "signalfds", &SIGNALFD_ENTRY),
    t(
        0x4842_4431,
        "INOTIFY_FILE",
        "inotify instances",
        &INOTIFY_FILE,
    ),
    t(0x5456_2009, "INOTIFY_WD", "inotify watches", &INOTIFY_WD),
    t(0x5556_3928, "MNTS", "mount points", &MNT_ENTRY),
    t(0x5737_3951, "NETDEV", "network devices", U),
    t(0x5593_3752, "NETNS", "network namespace", U),
    t(0x5943_3025, "TTY_FILES", "terminals", &TTY_FILE_ENTRY),
    t(0x5945_3036, "TTY_INFO", "terminal settings", &TTY_INFO),
    t(0x5941_3026, "TTY_DATA", "terminal buffers", &TTY_DATA),
    t(0x5432_3616, "FILE_LOCKS", "file locks", &FILE_LOCK),
    t(0x5711_3925, "RLIMIT", "resource limits", &RLIMIT_ENTRY),
    t(
        0x5509_6122,
        "FANOTIFY_FILE",
        "fanotify instances",
        &FANOTIFY_FILE,
    ),
    t(
        0x5650_6035,
        "FANOTIFY_MARK",
        "fanotify marks",
        &FANOTIFY_MARK,
    ),
    t(0x5925_5647, "SIGNAL", "pending signals", U),
    t(0x5800_5614, "NETLINK_SK", "netlink sockets", U),
    t(0x6139_4011, "NS_FILES", "namespace files", &NS_FILE_ENTRY),
    t(0x5714_3751, "TUNFILE", "TUN/TAP files", U),
    t(0x5938_3330, "CGROUP", "control groups", &CGROUP_ENTRY),
    t(0x5049_3712, "TIMERFD", "timerfds", &TIMERFD_ENTRY),
    t(0x6140_4013, "CPUINFO", "CPU features", U),
    t(0x5547_4906, "USERNS", "user namespace", &USERNS_ENTRY),
    t(0x6441_3049, "SECCOMP", "seccomp filters", &SECCOMP_ENTRY),
    t(0x6734_3323, "BINFMT_MISC", "binfmt_misc entries", U),
    t(0x4935_3943, "AUTOFS", "autofs mounts", U),
    t(0x5630_3138, "FILES", "open files", &FILE_ENTRY),
    t(0x4845_3499, "MEMFD_INODE", "memfd inodes", U),
    t(0x4311_4433, "TIMENS", "time namespace", &TIMENS_ENTRY),
    t(0x6115_7326, "PIDNS", "PID namespace", &PIDNS_ENTRY),
    t(0x5750_6142, "BPFMAP_FILE", "BPF maps", U),
    tx(
        0x6432_4033,
        "BPFMAP_DATA",
        "BPF map data",
        &BPFMAP_DATA_ENTRY,
        Extra::Fields(2, "Keys", 3, "Values"),
    ),
    t(0x5942_3047, "APPARMOR", "AppArmor policies", U),
    t(0x5443_5556, "PIDFD", "pidfds", U),
    t(
        0x5709_3306,
        "STATS",
        "dump or restore statistics",
        &STATS_ENTRY,
    ),
    t(0x5700_4059, "IRMAP_CACHE", "inotify path cache", U),
    t(0x5702_3458, "KDAT", "kernel feature cache", U),
];

fn image_type(magic: u32) -> Option<&'static ImageType> {
    TYPES.iter().find(|t| t.magic == magic)
}

/// The byte order and where the entries start, from the magics.
fn layout(data: &[u8]) -> Option<(Endian, &'static ImageType, u64)> {
    for (endian, read) in [
        (Endian::Little, u32_le as fn(&[u8], usize) -> Option<u32>),
        (Endian::Big, u32_be as fn(&[u8], usize) -> Option<u32>),
    ] {
        let first = read(data, 0)?;
        if first == INVENTORY {
            return Some((endian, image_type(INVENTORY)?, 4));
        }
        if matches!(first, IMG_COMMON | IMG_SERVICE) {
            let ty = image_type(read(data, 4)?)?;
            return Some((endian, ty, 8));
        }
    }
    None
}

fn criu_probe(h: &Head<'_>) -> bool {
    let Some((endian, ty, at)) = layout(h.data) else {
        return false;
    };
    if ty.magic != INVENTORY {
        return true;
    }
    // The inventory has only a 4-byte magic: its first entry must be a
    // sane size and start with `img_version`.
    let size = match endian {
        Endian::Little => u32_le(h.data, 4),
        Endian::Big => u32_be(h.data, 4),
    };
    size.is_some_and(|s| (2..=0x10000).contains(&s))
        && h.data.get(crate::bytes::to_usize(at.saturating_add(4))) == Some(&0x08)
}

declare_format!(pub CRIU_IMAGE = "criu-image", "CRIU checkpoint image", ["img"], "application/x-criu-image",
    Probe::Custom(criu_probe), criu);

const MAGICS: EnumTable = &[
    (IMG_COMMON as u64, "IMG_COMMON"),
    (IMG_SERVICE as u64, "IMG_SERVICE"),
];

async fn criu(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 8)).await?;
    let Some((endian, ty, at)) = layout(&head) else {
        return Err(Diagnostic::malformed("not a CRIU image (unknown magic)").at(file.sub(0, 8)));
    };
    // For a pagemap: the pages image's ID and the next page in it.
    let (pos, mut index, mut phase, mut pages) = match cx.resume::<(u64, u64, Phase, (u64, u64))>()
    {
        Some(state) => state,
        None => {
            let read = |off: usize| match endian {
                Endian::Little => u32_le(&head, off),
                Endian::Big => u32_be(&head, off),
            };
            if at == 8 {
                let class = read(0).unwrap_or(0);
                cx.emit(
                    Node::new("Image class")
                        .span(file.sub(0, 4))
                        .value(enum32(class, MAGICS)),
                );
            }
            cx.emit(
                Node::new("Image type")
                    .span(file.sub(at.saturating_sub(4), 4))
                    .value(Value::Enum {
                        raw: u64::from(ty.magic),
                        bits: 32,
                        name: Some(ty.name.into()),
                    })
                    .summary(ty.title),
            );
            cx.annotate(format!("CRIU {} image ({})", ty.name, ty.title));
            (at, 0u64, Phase::First, (0u64, 0u64))
        }
    };
    let mut cur = Cursor::new(&cx, file, endian);
    cur.seek(pos);
    while !cur.at_end() {
        let start = cur.pos();
        let state = (start, index, phase, pages);
        cx.mark(move || state);
        cx.progress_in(file, file.offset.saturating_add(start));
        // Raw data that is the rest of a ghost file.
        if phase == Phase::GhostData {
            let rest = cur.span(cur.remaining());
            cx.push(data_node(&cx, &input, "File data", rest).await?)
                .await;
            break;
        }
        let size = u64::from(cur.u32().await?);
        let body = cur.span(size);
        if body.len < size {
            cx.diag(Diagnostic::truncated(
                Span::new(body.source, body.offset, size),
                body.len,
            ));
            break;
        }
        cur.skip(size);
        let (msg, label): (&'static Msg, &str) = match (ty.extra, phase) {
            (Extra::Pagemap, Phase::First) => (&PAGEMAP_HEAD, "pagemap_head"),
            (Extra::Ghost, Phase::GhostChunks) => (&GHOST_CHUNK_ENTRY, "ghost_chunk_entry"),
            _ => (ty.msg, ty.msg.name),
        };
        // The title and extra-data sizes are in the first fields: a
        // prefix of a large entry is enough.
        let data = cx.read(body.sub(0, TITLE_MAX)).await?;
        let mut title = entry_title(&data, msg).unwrap_or_else(|| plural(size, "byte"));
        if ty.extra == Extra::Pagemap {
            if phase == Phase::First {
                pages.0 = varint_in(&data, 1).unwrap_or(0);
            } else {
                let (run, present) = pagemap_pages(&data);
                title.push_str(&format!(" · {}", plural(run, "page")));
                if present && run > 0 {
                    // Present pages are in the pages image, in order.
                    let (id, at) = pages;
                    let last = at.saturating_add(run).saturating_sub(1);
                    if run == 1 {
                        title.push_str(&format!(", pages-{id}.img page {at}"));
                    } else {
                        title.push_str(&format!(", pages-{id}.img pages {at}–{last}"));
                    }
                    pages.1 = at.saturating_add(run);
                }
            }
        }
        let entry_span = cur.since(start);
        let mut node = Node::new(format!("{label} [{index}]"))
            .span(entry_span)
            .summary(title);
        // Raw data after the entry.
        let first = match ty.extra {
            Extra::Fields(a, ..) => varint_in(&data, a).unwrap_or(0),
            _ => 0,
        };
        let extra = match (ty.extra, phase) {
            (Extra::Field(n), _) => varint_in(&data, n).unwrap_or(0),
            (Extra::Fields(_, _, b, _), _) => {
                first.saturating_add(varint_in(&data, b).unwrap_or(0))
            }
            (Extra::Shm, _) => {
                if varint_in(&data, 3).unwrap_or(0) != 0 {
                    0
                } else {
                    round_up(varint_in(&data, 2).unwrap_or(0), 4)
                }
            }
            (Extra::Sem, _) => round_up(varint_in(&data, 2).unwrap_or(0).saturating_mul(2), 8),
            (Extra::Ghost, Phase::GhostChunks) => varint_in(&data, 1).unwrap_or(0),
            _ => 0,
        };
        let mut after = After::None;
        if extra > 0 {
            let raw = cur.span(extra);
            if raw.len < extra {
                node = node.diag(Diagnostic::truncated(
                    Span::new(raw.source, raw.offset, extra),
                    raw.len,
                ));
            }
            cur.skip(extra);
            node = node.span(cur.since(start));
            after = match ty.extra {
                Extra::Fields(_, a, _, b) => After::Two(a, raw.sub(0, first), b, raw.tail(first)),
                Extra::Sem => {
                    let nsems = varint_in(&data, 2).unwrap_or(0);
                    After::Sem(raw.sub(0, nsems.saturating_mul(2)))
                }
                _ => After::Data(raw),
            };
        }
        if ty.extra == Extra::Msg {
            // The queue's messages follow its entry.
            let qnum = varint_in(&data, 3).unwrap_or(0);
            let mstart = cur.pos();
            for _ in 0..qnum {
                if cur.at_end() {
                    break;
                }
                let n = u64::from(cur.u32().await?);
                let mbody = cur.span(n);
                cur.skip(n);
                let m = cx.read(mbody.sub(0, TITLE_MAX)).await?;
                cur.skip(round_up(varint_in(&m, 2).unwrap_or(0), 8));
            }
            if cur.pos() > mstart {
                node = node.span(cur.since(start));
                after = After::Msgs(cur.since(mstart), qnum);
            }
        }
        let node = node.lazy(entry, (input, body, msg, endian, after));
        phase = match (ty.extra, phase) {
            (Extra::Pagemap, _) => Phase::Rest,
            (Extra::Ghost, Phase::First) => {
                if varint_in(&data, 9).unwrap_or(0) != 0 {
                    Phase::GhostChunks
                } else {
                    Phase::GhostData
                }
            }
            (_, p) => p,
        };
        cx.push(node).await;
        // The pagemap's entries are numbered after its head.
        index = if label == "pagemap_head" {
            0
        } else {
            index.saturating_add(1)
        };
    }
    Ok(())
}

/// A pagemap entry's page count (`nr_pages`, or `compat_nr_pages` in
/// images from before it) and whether its pages are in the pages image
/// (`PE_PRESENT`, or for images from before the flags, not `in_parent`;
/// CRIU's `pagemap.c`).
fn pagemap_pages(data: &[u8]) -> (u64, bool) {
    let present = match varint_in(data, 4) {
        Some(flags) => flags & 4 != 0,
        None => varint_in(data, 3).unwrap_or(0) == 0,
    };
    let n = varint_in(data, 5)
        .or_else(|| varint_in(data, 2))
        .unwrap_or(0);
    (n, present)
}

/// Where the walk is in an image whose entries are not all alike.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    First,
    Rest,
    GhostChunks,
    GhostData,
}

const TITLE_MAX: u64 = 16 * 1024;

fn round_up(v: u64, to: u64) -> u64 {
    v.div_ceil(to).saturating_mul(to)
}

fn enum32(raw: u32, table: EnumTable) -> Value {
    Value::Enum {
        raw: raw.into(),
        bits: 32,
        name: lookup(table, raw.into()).map(Into::into),
    }
}

/// Raw data after an entry.
#[derive(Clone, Copy, Debug)]
enum After {
    None,
    /// Pipe or FIFO contents, a socket packet, a ghost file chunk, shared
    /// memory.
    Data(Span),
    /// Two runs of data (TCP receive and send queues; BPF map keys and
    /// values).
    Two(&'static str, Span, &'static str, Span),
    /// Semaphore values (16-bit, in the image's byte order).
    Sem(Span),
    /// A message queue's messages: where they are and how many.
    Msgs(Span, u64),
}

type EntryState = (Input, Span, &'static Msg, Endian, After);

/// An entry: its size, its message's fields, then the raw data after it.
async fn entry(cx: Cx, (input, body, msg, endian, after): EntryState) -> Result<()> {
    cx.push(size_node(&cx, body, endian).await?).await;
    // The data is located by the walk, not by these fields: show it even
    // if they do not parse.
    let fields = proto::message(cx.clone(), (body, msg, 0u32)).await;
    match after {
        After::None => {}
        After::Data(span) => cx.push(data_node(&cx, &input, "Data", span).await?).await,
        After::Two(a, first, b, second) => {
            for (name, span) in [(a, first), (b, second)] {
                if span.len > 0 {
                    cx.push(data_node(&cx, &input, name, span).await?).await;
                }
            }
        }
        After::Sem(span) => {
            cx.push(
                Node::new("Values")
                    .span(span)
                    .summary(plural(span.len / 2, "semaphore"))
                    .lazy(semaphores, (span, endian)),
            )
            .await;
        }
        After::Msgs(span, qnum) => messages(&cx, input, span, qnum, endian).await?,
    }
    fields
}

/// A summary of an entry from its schema's title fields: the protobuf
/// helper's, except that an entry summarised by a single number names it
/// (`pages_id=1`), since nothing else around it says what it counts.
fn entry_title(data: &[u8], msg: &'static Msg) -> Option<String> {
    if let [num] = msg.title
        && let Some(spec) = msg.fields.iter().find(|f| f.num == *num)
        && let Ty::UInt | Ty::Int | Ty::SInt = spec.ty
    {
        return proto::title_of(data, msg).map(|v| format!("{}={v}", spec.name));
    }
    proto::title_of(data, msg)
}

/// The 32-bit size before a message whose body is `body`.
async fn size_node(cx: &Cx, body: Span, endian: Endian) -> Result<Node> {
    let span = Span::new(body.source, body.offset.saturating_sub(4), 4);
    let raw = cx.read(span).await?;
    let size = match endian {
        Endian::Little => u32_le(&raw, 0),
        Endian::Big => u32_be(&raw, 0),
    }
    .unwrap_or(0);
    Ok(Node::new("Size").span(span).value(Value::UInt {
        value: size.into(),
        bits: 32,
        radix: crate::value::Radix::Dec,
    }))
}

/// The size of raw data, with a preview if it is text.
async fn data_summary(cx: &Cx, span: Span) -> Result<String> {
    let head = cx.read(span.sub(0, 256)).await?;
    let size = plural(span.len, "byte");
    if crate::text::looks_like_text(&head) {
        let text = preview(&String::from_utf8_lossy(&head), 60);
        if !text.is_empty() {
            return Ok(format!("{size}: “{text}”"));
        }
    }
    Ok(size)
}

/// Raw data, identified and dissected on expansion.
async fn data_node(cx: &Cx, input: &Input, name: &'static str, span: Span) -> Result<Node> {
    let summary = data_summary(cx, span).await?;
    Ok(embedded(name, input.nested(span)).summary(summary))
}

/// Semaphore values, one node each.
async fn semaphores(cx: Cx, (span, endian): (Span, Endian)) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, endian);
    let mut i = 0u64;
    while cur.remaining() >= 2 {
        let at = cur.pos();
        let v = cur.u16().await?;
        cx.push(
            Node::new(format!("[{i}]"))
                .span(cur.since(at))
                .value(Value::UInt {
                    value: v.into(),
                    bits: 16,
                    radix: crate::value::Radix::Dec,
                }),
        )
        .await;
        i = i.saturating_add(1);
    }
    Ok(())
}

static IPC_MSG: Msg = msg(
    "ipc_msg",
    &[f(1, "mtype", Ty::UInt), f(2, "msize", Ty::UInt)],
    &[1, 2],
);

/// The messages of a System V message queue: each a sized `ipc_msg`,
/// then its text padded to 8 bytes.
async fn messages(cx: &Cx, input: Input, span: Span, qnum: u64, endian: Endian) -> Result<()> {
    let mut cur = Cursor::new(cx, span, endian);
    let mut i = 0u64;
    while i < qnum && !cur.at_end() {
        let start = cur.pos();
        let n = u64::from(cur.u32().await?);
        let body = cur.span(n);
        cur.skip(n);
        let m = cx.read(body.sub(0, TITLE_MAX)).await?;
        let msize = varint_in(&m, 2).unwrap_or(0);
        let text = cur.span(msize);
        cur.skip(round_up(msize, 8));
        let size = data_summary(cx, text).await?;
        let summary = match varint_in(&m, 1) {
            Some(t) => format!("mtype {t}, {size}"),
            None => size,
        };
        cx.push(
            Node::new(format!("message [{i}]"))
                .span(cur.since(start))
                .summary(summary)
                .lazy(message, (input, body, text, endian)),
        )
        .await;
        i = i.saturating_add(1);
    }
    Ok(())
}

/// One queued message: its size, its `ipc_msg` fields and its text.
async fn message(cx: Cx, (input, body, text, endian): (Input, Span, Span, Endian)) -> Result<()> {
    cx.push(size_node(&cx, body, endian).await?).await;
    let fields = proto::message(cx.clone(), (body, &IPC_MSG, 0u32)).await;
    cx.push(data_node(&cx, &input, "Text", text).await?).await;
    fields
}

// ---------------------------------------------------------------------------
// Schemas (from CRIU's images/*.proto)

const MARCH: EnumTable = &[
    (0, "UNKNOWN"),
    (1, "X86_64"),
    (2, "ARM"),
    (3, "AARCH64"),
    (4, "PPC64"),
    (5, "S390"),
    (6, "MIPS"),
    (7, "LOONGARCH64"),
    (8, "RISCV64"),
];
const LSMTYPE: EnumTable = &[(0, "NO_LSM"), (1, "SELINUX"), (2, "APPARMOR")];
const FD_TYPES: EnumTable = &[
    (0, "UND"),
    (1, "REG"),
    (2, "PIPE"),
    (3, "FIFO"),
    (4, "INETSK"),
    (5, "UNIXSK"),
    (6, "EVENTFD"),
    (7, "EVENTPOLL"),
    (8, "INOTIFY"),
    (9, "SIGNALFD"),
    (10, "PACKETSK"),
    (11, "TTY"),
    (12, "FANOTIFY"),
    (13, "NETLINKSK"),
    (14, "NS"),
    (15, "TUNF"),
    (16, "EXT"),
    (17, "TIMERFD"),
    (18, "MEMFD"),
    (19, "BPFMAP"),
    (20, "PIDFD"),
    (65534, "CTL_TTY"),
    (65535, "AUTOFS_PIPE"),
];
const SECCOMP_MODE: EnumTable = &[(0, "disabled"), (1, "strict"), (2, "filter")];
/// `task_state`: CRIU's own values (`compel/include/uapi/task-state.h`,
/// "Don't ever change the above values"): ALIVE 1, DEAD 2, STOPPED 3,
/// ZOMBIE 6. Zombies are dumped as DEAD (`dump_one_zombie`). pycriu's
/// table (3 Zombie, 6 Stopped) is wrong: a dumped `kill -STOP`ped task
/// has 3, a dumped zombie child 2 (external fixtures).
const TASK_STATE: EnumTable = &[
    (1, "Alive"),
    (2, "Dead (zombie)"),
    (3, "Stopped"),
    (6, "Zombie"),
];
const SK_SHUTDOWN: EnumTable = &[(0, "NONE"), (1, "READ"), (2, "WRITE"), (3, "BOTH")];
const SK_FAMILY: EnumTable = &[
    (1, "UNIX"),
    (2, "INET"),
    (10, "INET6"),
    (16, "NETLINK"),
    (17, "PACKET"),
];
const SK_TYPE: EnumTable = &[
    (1, "STREAM"),
    (2, "DGRAM"),
    (3, "RAW"),
    (5, "SEQPACKET"),
    (10, "PACKET"),
];

const PROT: FlagTable = &[
    flag(1, "PROT_READ"),
    flag(2, "PROT_WRITE"),
    flag(4, "PROT_EXEC"),
];
const MAP_FLAGS: FlagTable = &[
    flag(0x1, "MAP_SHARED"),
    flag(0x2, "MAP_PRIVATE"),
    flag(0x20, "MAP_ANON"),
    flag(0x100, "MAP_GROWSDOWN"),
];
const VMA_STATUS: FlagTable = &[
    flag(1 << 0, "VMA_AREA_REGULAR"),
    flag(1 << 1, "VMA_AREA_STACK"),
    flag(1 << 2, "VMA_AREA_VSYSCALL"),
    flag(1 << 3, "VMA_AREA_VDSO"),
    flag(1 << 5, "VMA_AREA_HEAP"),
    flag(1 << 6, "VMA_FILE_PRIVATE"),
    flag(1 << 7, "VMA_FILE_SHARED"),
    flag(1 << 8, "VMA_ANON_SHARED"),
    flag(1 << 9, "VMA_ANON_PRIVATE"),
    flag(1 << 10, "VMA_AREA_SYSVIPC"),
    flag(1 << 11, "VMA_AREA_SOCKET"),
    flag(1 << 12, "VMA_AREA_VVAR"),
    flag(1 << 13, "VMA_AREA_AIORING"),
    flag(1 << 14, "VMA_AREA_MEMFD"),
    flag(1 << 15, "VMA_AREA_SHSTK"),
    flag(1 << 31, "VMA_UNSUPP"),
];
const OPEN_FLAGS: FlagTable = &[
    flag(0o1, "O_WRONLY"),
    flag(0o2, "O_RDWR"),
    flag(0o100, "O_CREAT"),
    flag(0o200, "O_EXCL"),
    flag(0o400, "O_NOCTTY"),
    flag(0o1000, "O_TRUNC"),
    flag(0o2000, "O_APPEND"),
    flag(0o4000, "O_NONBLOCK"),
    flag(0o10000, "O_DSYNC"),
    flag(0o20000, "FASYNC"),
    flag(0o40000, "O_DIRECT"),
    flag(0o100000, "O_LARGEFILE"),
    flag(0o200000, "O_DIRECTORY"),
    flag(0o400000, "O_NOFOLLOW"),
    flag(0o1000000, "O_NOATIME"),
    flag(0o2000000, "O_CLOEXEC"),
];
const PMAP_FLAGS: FlagTable = &[
    flag(1, "PE_PARENT"),
    flag(2, "PE_LAZY"),
    flag(4, "PE_PRESENT"),
];

const fn msg(name: &'static str, fields: &'static [proto::F], title: &'static [u64]) -> Msg {
    Msg {
        name,
        fields,
        title,
    }
}

static IDS_ENTRY: Msg = msg(
    "task_kobj_ids_entry",
    &[
        f(1, "vm_id", Ty::UInt),
        f(2, "files_id", Ty::UInt),
        f(3, "fs_id", Ty::UInt),
        f(4, "sighand_id", Ty::UInt),
        f(5, "pid_ns_id", Ty::UInt),
        f(6, "net_ns_id", Ty::UInt),
        f(7, "ipc_ns_id", Ty::UInt),
        f(8, "uts_ns_id", Ty::UInt),
        f(9, "mnt_ns_id", Ty::UInt),
        f(10, "user_ns_id", Ty::UInt),
        f(11, "cgroup_ns_id", Ty::UInt),
        f(12, "time_ns_id", Ty::UInt),
    ],
    &[],
);

static PLUGINS_ENTRY: Msg = msg("plugins_entry", &[f(12, "plugins", Ty::Str)], &[]);

static INVENTORY_ENTRY: Msg = msg(
    "inventory_entry",
    &[
        f(1, "img_version", Ty::UInt),
        f(2, "fdinfo_per_id", Ty::Bool),
        f(3, "root_ids", Ty::Msg(&IDS_ENTRY)),
        f(4, "ns_per_id", Ty::Bool),
        f(5, "root_cg_set", Ty::UInt),
        f(6, "lsmtype", Ty::Enum(LSMTYPE)),
        f(8, "dump_uptime", Ty::UInt),
        f(9, "pre_dump_mode", Ty::UInt),
        f(10, "tcp_close", Ty::Bool),
        f(11, "network_lock_method", Ty::Enum(NETWORK_LOCK)),
        f(12, "plugins_entry", Ty::Msg(&PLUGINS_ENTRY)),
        f(13, "dump_criu_run_id", Ty::Str),
        f(14, "allow_uprobes", Ty::Bool),
    ],
    &[1, 6],
);

static PSTREE_ENTRY: Msg = msg(
    "pstree_entry",
    &[
        f(1, "pid", Ty::UInt),
        f(2, "ppid", Ty::UInt),
        f(3, "pgid", Ty::UInt),
        f(4, "sid", Ty::UInt),
        f(5, "threads", Ty::Packed(Elem::Varint)),
    ],
    &[1, 2],
);

static FDINFO_ENTRY: Msg = msg(
    "fdinfo_entry",
    &[
        f(1, "id", Ty::UInt),
        f(2, "flags", Ty::Hex),
        f(3, "type", Ty::Enum(FD_TYPES)),
        f(4, "fd", Ty::UInt),
        f(5, "xattr_security_selinux", Ty::Str),
    ],
    &[4, 3, 1],
);

static PAGEMAP_HEAD: Msg = msg("pagemap_head", &[f(1, "pages_id", Ty::UInt)], &[1]);

static PAGEMAP_ENTRY: Msg = msg(
    "pagemap_entry",
    &[
        f(1, "vaddr", Ty::Hex),
        f(2, "compat_nr_pages", Ty::UInt),
        f(3, "in_parent", Ty::Bool),
        f(4, "flags", Ty::Flags(PMAP_FLAGS)),
        f(5, "nr_pages", Ty::UInt),
    ],
    &[1, 4],
);

// --- core ------------------------------------------------------------------

static ITIMER_ENTRY: Msg = msg(
    "itimer_entry",
    &[
        f(1, "isec", Ty::Duration(1)),
        f(2, "iusec", Ty::Duration(1_000_000)),
        f(3, "vsec", Ty::Duration(1)),
        f(4, "vusec", Ty::Duration(1_000_000)),
    ],
    &[],
);

static POSIX_TIMER_ENTRY: Msg = msg(
    "posix_timer_entry",
    &[
        f(1, "it_id", Ty::UInt),
        f(2, "clock_id", Ty::UInt),
        f(3, "si_signo", Ty::UInt),
        f(4, "it_sigev_notify", Ty::UInt),
        f(5, "sival_ptr", Ty::Hex),
        f(6, "overrun", Ty::UInt),
        f(7, "isec", Ty::Duration(1)),
        f(8, "insec", Ty::Duration(1_000_000_000)),
        f(9, "vsec", Ty::Duration(1)),
        f(10, "vnsec", Ty::Duration(1_000_000_000)),
        f(11, "notify_thread_id", Ty::Int),
    ],
    &[1, 2],
);

static TASK_TIMERS: Msg = msg(
    "task_timers_entry",
    &[
        f(1, "real", Ty::Msg(&ITIMER_ENTRY)),
        f(2, "virt", Ty::Msg(&ITIMER_ENTRY)),
        f(3, "prof", Ty::Msg(&ITIMER_ENTRY)),
        f(4, "posix", Ty::Msg(&POSIX_TIMER_ENTRY)),
    ],
    &[],
);

/// `RLIM_INFINITY` (CRIU stores limits as 64-bit numbers).
const RLIM: EnumTable = &[(u64::MAX, "unlimited")];

static RLIMIT_ENTRY: Msg = msg(
    "rlimit_entry",
    &[
        f(1, "cur", Ty::Named(RLIM, Radix::Dec)),
        f(2, "max", Ty::Named(RLIM, Radix::Dec)),
    ],
    &[1, 2],
);

/// Resources in `RLIMIT_*` order: CRIU writes one limit per resource,
/// from 0 (`dump_task_rlimits`). This is the generic Linux numbering
/// (x86, Arm, PowerPC, s390, RISC-V, LoongArch); MIPS numbers some of
/// them differently.
const RLIMITS: &[&str] = &[
    "RLIMIT_CPU",
    "RLIMIT_FSIZE",
    "RLIMIT_DATA",
    "RLIMIT_STACK",
    "RLIMIT_CORE",
    "RLIMIT_RSS",
    "RLIMIT_NPROC",
    "RLIMIT_NOFILE",
    "RLIMIT_MEMLOCK",
    "RLIMIT_AS",
    "RLIMIT_LOCKS",
    "RLIMIT_SIGPENDING",
    "RLIMIT_MSGQUEUE",
    "RLIMIT_NICE",
    "RLIMIT_RTPRIO",
    "RLIMIT_RTTIME",
];

fn rlimit_label(i: u64) -> Cow<'static, str> {
    match usize::try_from(i).ok().and_then(|i| RLIMITS.get(i)) {
        Some(name) => Cow::Borrowed(*name),
        None => format!("rlimits[{i}]").into(),
    }
}

static TASK_RLIMITS: Msg = msg(
    "task_rlimits_entry",
    &[f(1, "rlimits", Ty::Msg(&RLIMIT_ENTRY)).indexed(Index::Label(rlimit_label))],
    &[],
);

/// Signals 1 to 31 (the generic Linux numbering; MIPS and others differ).
const SIGNALS: &[&str] = &[
    "SIGHUP",
    "SIGINT",
    "SIGQUIT",
    "SIGILL",
    "SIGTRAP",
    "SIGABRT",
    "SIGBUS",
    "SIGFPE",
    "SIGKILL",
    "SIGUSR1",
    "SIGSEGV",
    "SIGUSR2",
    "SIGPIPE",
    "SIGALRM",
    "SIGTERM",
    "SIGSTKFLT",
    "SIGCHLD",
    "SIGCONT",
    "SIGSTOP",
    "SIGTSTP",
    "SIGTTIN",
    "SIGTTOU",
    "SIGURG",
    "SIGXCPU",
    "SIGXFSZ",
    "SIGVTALRM",
    "SIGPROF",
    "SIGWINCH",
    "SIGIO",
    "SIGPWR",
    "SIGSYS",
];

/// The signal of the `i`th sigaction: CRIU writes one per signal from 1
/// to 64, skipping SIGKILL and SIGSTOP (`parasite_dump_sigacts_seized`).
fn sigaction_label(i: u64) -> Cow<'static, str> {
    let mut sig = i.saturating_add(1);
    for skipped in [9, 19] {
        if sig >= skipped {
            sig = sig.saturating_add(1);
        }
    }
    let name = usize::try_from(sig.saturating_sub(1))
        .ok()
        .and_then(|at| SIGNALS.get(at));
    match name {
        Some(name) => format!("sigactions[{name}]").into(),
        None => format!("sigactions[{sig}]").into(),
    }
}

/// Handler values with names.
const SIG_HANDLERS: EnumTable = &[(0, "SIG_DFL"), (1, "SIG_IGN")];

static SIGINFO: Msg = msg("siginfo_entry", &[f(1, "siginfo", Ty::Bytes)], &[]);
static SIGNAL_QUEUE: Msg = msg(
    "signal_queue_entry",
    &[f(1, "signals", Ty::Msg(&SIGINFO))],
    &[],
);

static SA_ENTRY: Msg = msg(
    "sa_entry",
    &[
        f(1, "sigaction", Ty::Named(SIG_HANDLERS, Radix::Hex)),
        f(2, "flags", Ty::Hex),
        f(3, "restorer", Ty::Hex),
        f(4, "mask", Ty::Hex),
        f(5, "compat_sigaction", Ty::Bool),
        f(6, "mask_extended", Ty::Hex),
    ],
    &[1],
);

static TASK_CORE: Msg = msg(
    "task_core_entry",
    &[
        f(1, "task_state", Ty::Enum(TASK_STATE)),
        f(2, "exit_code", Ty::UInt),
        f(3, "personality", Ty::Hex),
        f(4, "flags", Ty::Hex),
        f(5, "blk_sigset", Ty::Hex),
        f(6, "comm", Ty::Str),
        f(7, "timers", Ty::Msg(&TASK_TIMERS)),
        f(8, "rlimits", Ty::Msg(&TASK_RLIMITS)),
        f(9, "cg_set", Ty::UInt),
        f(10, "signals_s", Ty::Msg(&SIGNAL_QUEUE)),
        f(11, "old_seccomp_mode", Ty::Enum(SECCOMP_MODE)),
        f(12, "old_seccomp_filter", Ty::UInt),
        f(13, "loginuid", Ty::UInt),
        f(14, "oom_score_adj", Ty::Int),
        f(15, "sigactions", Ty::Msg(&SA_ENTRY)).indexed(Index::Label(sigaction_label)),
        f(18, "child_subreaper", Ty::Bool),
        f(20, "blk_sigset_extended", Ty::Hex),
        f(21, "stop_signo", Ty::UInt),
        f(22, "membarrier_registration_mask", Ty::Hex),
    ],
    &[6, 1],
);

static CREDS_ENTRY: Msg = msg(
    "creds_entry",
    &[
        f(1, "uid", Ty::UInt),
        f(2, "gid", Ty::UInt),
        f(3, "euid", Ty::UInt),
        f(4, "egid", Ty::UInt),
        f(5, "suid", Ty::UInt),
        f(6, "sgid", Ty::UInt),
        f(7, "fsuid", Ty::UInt),
        f(8, "fsgid", Ty::UInt),
        f(9, "cap_inh", Ty::Hex),
        f(10, "cap_prm", Ty::Hex),
        f(11, "cap_eff", Ty::Hex),
        f(12, "cap_bnd", Ty::Hex),
        f(13, "secbits", Ty::Hex),
        f(14, "groups", Ty::Packed(Elem::Varint)),
        f(15, "lsm_profile", Ty::Str),
        f(16, "lsm_sockcreate", Ty::Str),
        f(17, "apparmor_data", Ty::Bytes),
        f(18, "no_new_privs", Ty::UInt),
        f(19, "cap_amb", Ty::Hex),
    ],
    &[1, 2],
);

static THREAD_SAS: Msg = msg(
    "thread_sas_entry",
    &[
        f(1, "ss_sp", Ty::Hex),
        f(2, "ss_size", Ty::UInt),
        f(3, "ss_flags", Ty::Hex),
    ],
    &[],
);

static RSEQ_ENTRY: Msg = msg(
    "rseq_entry",
    &[
        f(1, "rseq_abi_pointer", Ty::Hex),
        f(2, "rseq_abi_size", Ty::UInt),
        f(3, "signature", Ty::Hex),
        f(4, "rseq_cs_pointer", Ty::Hex),
    ],
    &[],
);

static THREAD_CORE: Msg = msg(
    "thread_core_entry",
    &[
        f(1, "futex_rla", Ty::Hex),
        f(2, "futex_rla_len", Ty::UInt),
        f(3, "sched_nice", Ty::SInt),
        f(4, "sched_policy", Ty::UInt),
        f(5, "sched_prio", Ty::UInt),
        f(6, "blk_sigset", Ty::Hex),
        f(7, "sas", Ty::Msg(&THREAD_SAS)),
        f(8, "pdeath_sig", Ty::UInt),
        f(9, "signals_p", Ty::Msg(&SIGNAL_QUEUE)),
        f(10, "creds", Ty::Msg(&CREDS_ENTRY)),
        f(11, "seccomp_mode", Ty::Enum(SECCOMP_MODE)),
        f(12, "seccomp_filter", Ty::UInt),
        f(13, "comm", Ty::Str),
        f(14, "blk_sigset_extended", Ty::Hex),
        f(15, "rseq_entry", Ty::Msg(&RSEQ_ENTRY)),
        f(16, "cg_set", Ty::UInt),
    ],
    &[13],
);

static X86_REGS: Msg = msg(
    "user_x86_regs_entry",
    &[
        f(1, "r15", Ty::Hex),
        f(2, "r14", Ty::Hex),
        f(3, "r13", Ty::Hex),
        f(4, "r12", Ty::Hex),
        f(5, "bp", Ty::Hex),
        f(6, "bx", Ty::Hex),
        f(7, "r11", Ty::Hex),
        f(8, "r10", Ty::Hex),
        f(9, "r9", Ty::Hex),
        f(10, "r8", Ty::Hex),
        f(11, "ax", Ty::Hex),
        f(12, "cx", Ty::Hex),
        f(13, "dx", Ty::Hex),
        f(14, "si", Ty::Hex),
        f(15, "di", Ty::Hex),
        f(16, "orig_ax", Ty::Hex),
        f(17, "ip", Ty::Hex),
        f(18, "cs", Ty::Hex),
        f(19, "flags", Ty::Hex),
        f(20, "sp", Ty::Hex),
        f(21, "ss", Ty::Hex),
        f(22, "fs_base", Ty::Hex),
        f(23, "gs_base", Ty::Hex),
        f(24, "ds", Ty::Hex),
        f(25, "es", Ty::Hex),
        f(26, "fs", Ty::Hex),
        f(27, "gs", Ty::Hex),
        f(28, "mode", Ty::Enum(&[(1, "NATIVE"), (2, "COMPAT")])),
    ],
    &[17],
);

static THREAD_INFO_X86: Msg = msg(
    "thread_info_x86",
    &[
        f(1, "clear_tid_addr", Ty::Hex),
        f(2, "gpregs", Ty::Msg(&X86_REGS)),
        f(3, "fpregs", Ty::Msg(&X86_FPREGS)),
        f(4, "tls", Ty::Msg(&USER_DESC)),
    ],
    &[],
);

/// General registers x0 to x30, in order (`save_task_regs`).
fn x_label(i: u64) -> Cow<'static, str> {
    format!("x{i}").into()
}

/// FP/SIMD registers v0 to v31, each as its low then its high 64 bits.
fn v_label(i: u64) -> Cow<'static, str> {
    let half = if i.is_multiple_of(2) { "lo" } else { "hi" };
    format!("v{}.{half}", i / 2).into()
}

static AARCH64_REGS: Msg = msg(
    "user_aarch64_regs_entry",
    &[
        f(1, "regs", Ty::Hex).indexed(Index::Label(x_label)),
        f(2, "sp", Ty::Hex),
        f(3, "pc", Ty::Hex),
        f(4, "pstate", Ty::Hex),
    ],
    &[3],
);

static AARCH64_FPSIMD: Msg = msg(
    "user_aarch64_fpsimd_context_entry",
    &[
        f(1, "vregs", Ty::Hex).indexed(Index::Label(v_label)),
        f(2, "fpsr", Ty::Hex),
        f(3, "fpcr", Ty::Hex),
    ],
    &[],
);

static THREAD_INFO_AARCH64: Msg = msg(
    "thread_info_aarch64",
    &[
        f(1, "clear_tid_addr", Ty::Hex),
        f(2, "tls", Ty::Hex),
        f(3, "gpregs", Ty::Msg(&AARCH64_REGS)),
        f(4, "fpsimd", Ty::Msg(&AARCH64_FPSIMD)),
        f(5, "pac_keys", Ty::Msg(U)),
    ],
    &[],
);

static CORE_ENTRY: Msg = msg(
    "core_entry",
    &[
        f(1, "mtype", Ty::Enum(MARCH)),
        f(2, "thread_info", Ty::Msg(&THREAD_INFO_X86)),
        f(3, "tc", Ty::Msg(&TASK_CORE)),
        f(4, "ids", Ty::Msg(&IDS_ENTRY)),
        f(5, "thread_core", Ty::Msg(&THREAD_CORE)),
        f(6, "ti_arm", Ty::Msg(U)),
        f(8, "ti_aarch64", Ty::Msg(&THREAD_INFO_AARCH64)),
        f(9, "ti_ppc64", Ty::Msg(U)),
        f(10, "ti_s390", Ty::Msg(U)),
        f(11, "ti_mips", Ty::Msg(U)),
        f(12, "ti_loongarch64", Ty::Msg(U)),
        f(13, "ti_riscv64", Ty::Msg(U)),
    ],
    &[1],
);

// --- memory ------------------------------------------------------------------

static VMA_ENTRY: Msg = msg(
    "vma_entry",
    &[
        f(1, "start", Ty::Hex),
        f(2, "end", Ty::Hex),
        f(3, "pgoff", Ty::UInt),
        f(4, "shmid", Ty::UInt),
        f(5, "prot", Ty::Flags(PROT)),
        f(6, "flags", Ty::Flags(MAP_FLAGS)),
        f(7, "status", Ty::Flags(VMA_STATUS)),
        f(8, "fd", Ty::SInt),
        f(9, "madv", Ty::Hex),
        f(10, "fdflags", Ty::Hex),
    ],
    &[1, 2, 5],
);

static AIO_RING: Msg = msg(
    "aio_ring_entry",
    &[
        f(1, "id", Ty::UInt),
        f(2, "nr_req", Ty::UInt),
        f(3, "ring_len", Ty::UInt),
    ],
    &[],
);

/// The auxiliary vector's keys (`AT_*`, `linux/auxvec.h` and the
/// architectures' `asm/auxvec.h`); CRIU saves `/proc/<pid>/auxv` as
/// type/value pairs up to `AT_NULL` (`get_task_auxv`).
const AUXV: EnumTable = &[
    (0, "AT_NULL"),
    (1, "AT_IGNORE"),
    (2, "AT_EXECFD"),
    (3, "AT_PHDR"),
    (4, "AT_PHENT"),
    (5, "AT_PHNUM"),
    (6, "AT_PAGESZ"),
    (7, "AT_BASE"),
    (8, "AT_FLAGS"),
    (9, "AT_ENTRY"),
    (10, "AT_NOTELF"),
    (11, "AT_UID"),
    (12, "AT_EUID"),
    (13, "AT_GID"),
    (14, "AT_EGID"),
    (15, "AT_PLATFORM"),
    (16, "AT_HWCAP"),
    (17, "AT_CLKTCK"),
    (23, "AT_SECURE"),
    (24, "AT_BASE_PLATFORM"),
    (25, "AT_RANDOM"),
    (26, "AT_HWCAP2"),
    (27, "AT_RSEQ_FEATURE_SIZE"),
    (28, "AT_RSEQ_ALIGN"),
    (29, "AT_HWCAP3"),
    (30, "AT_HWCAP4"),
    (31, "AT_EXECFN"),
    (32, "AT_SYSINFO"),
    (33, "AT_SYSINFO_EHDR"),
    (51, "AT_MINSIGSTKSZ"),
];
/// Keys whose values are counts, sizes or IDs rather than addresses or
/// masks.
const AUXV_DECIMAL: &[u64] = &[2, 4, 5, 6, 11, 12, 13, 14, 17, 23, 27, 28, 51];

static MM_ENTRY: Msg = msg(
    "mm_entry",
    &[
        f(1, "mm_start_code", Ty::Hex),
        f(2, "mm_end_code", Ty::Hex),
        f(3, "mm_start_data", Ty::Hex),
        f(4, "mm_end_data", Ty::Hex),
        f(5, "mm_start_stack", Ty::Hex),
        f(6, "mm_start_brk", Ty::Hex),
        f(7, "mm_brk", Ty::Hex),
        f(8, "mm_arg_start", Ty::Hex),
        f(9, "mm_arg_end", Ty::Hex),
        f(10, "mm_env_start", Ty::Hex),
        f(11, "mm_env_end", Ty::Hex),
        f(12, "exe_file_id", Ty::UInt),
        f(13, "mm_saved_auxv", Ty::Packed(Elem::Varint)).indexed(Index::Pairs {
            key: "a_type",
            keys: AUXV,
            decimal: AUXV_DECIMAL,
        }),
        f(14, "vmas", Ty::Msg(&VMA_ENTRY)),
        f(15, "dumpable", Ty::Int),
        f(16, "aios", Ty::Msg(&AIO_RING)),
        f(17, "thp_disabled", Ty::Bool),
    ],
    &[12],
);

// --- files -------------------------------------------------------------------

static FOWN_ENTRY: Msg = msg(
    "fown_entry",
    &[
        f(1, "uid", Ty::UInt),
        f(2, "euid", Ty::UInt),
        f(3, "signum", Ty::UInt),
        f(4, "pid_type", Ty::UInt),
        f(5, "pid", Ty::UInt),
    ],
    &[],
);

static REG_FILE_ENTRY: Msg = msg(
    "reg_file_entry",
    &[
        f(1, "id", Ty::UInt),
        f(2, "flags", Ty::Flags(OPEN_FLAGS)),
        f(3, "pos", Ty::UInt),
        f(5, "fown", Ty::Msg(&FOWN_ENTRY)),
        f(6, "name", Ty::Str),
        f(7, "mnt_id", Ty::SInt),
        f(8, "size", Ty::UInt),
        f(9, "ext", Ty::Bool),
        f(10, "mode", Ty::Hex),
        f(11, "build_id", Ty::Hex),
        f(12, "checksum", Ty::Hex),
        f(13, "checksum_config", Ty::UInt),
        f(14, "checksum_parameter", Ty::UInt),
    ],
    &[6],
);

static PIPE_ENTRY: Msg = msg(
    "pipe_entry",
    &[
        f(1, "id", Ty::UInt),
        f(2, "pipe_id", Ty::UInt),
        f(3, "flags", Ty::Flags(OPEN_FLAGS)),
        f(4, "fown", Ty::Msg(&FOWN_ENTRY)),
    ],
    &[2],
);

static PIPE_DATA_ENTRY: Msg = msg(
    "pipe_data_entry",
    &[
        f(1, "pipe_id", Ty::UInt),
        f(2, "bytes", Ty::UInt),
        f(3, "size", Ty::UInt),
    ],
    &[1, 2],
);

static FIFO_ENTRY: Msg = msg(
    "fifo_entry",
    &[
        f(1, "id", Ty::UInt),
        f(2, "pipe_id", Ty::UInt),
        f(3, "regf_id", Ty::UInt),
    ],
    &[2],
);

static NS_FILE_ENTRY: Msg = msg(
    "ns_file_entry",
    &[
        f(1, "id", Ty::UInt),
        f(2, "ns_id", Ty::UInt),
        f(3, "ns_cflag", Ty::Hex),
        f(4, "flags", Ty::Flags(OPEN_FLAGS)),
    ],
    &[2],
);

static EVENTFD_ENTRY: Msg = msg(
    "eventfd_file_entry",
    &[
        f(1, "id", Ty::UInt),
        f(2, "flags", Ty::Flags(OPEN_FLAGS)),
        f(3, "fown", Ty::Msg(&FOWN_ENTRY)),
        f(4, "counter", Ty::UInt),
    ],
    &[4],
);

static SIGNALFD_ENTRY: Msg = msg(
    "signalfd_entry",
    &[
        f(1, "id", Ty::UInt),
        f(2, "flags", Ty::Hex),
        f(3, "fown", Ty::Msg(&FOWN_ENTRY)),
        f(4, "sigmask", Ty::Hex),
    ],
    &[4],
);

static TIMERFD_ENTRY: Msg = msg(
    "timerfd_entry",
    &[
        f(1, "id", Ty::UInt),
        f(2, "flags", Ty::Hex),
        f(3, "fown", Ty::Msg(&FOWN_ENTRY)),
        f(4, "clockid", Ty::UInt),
        f(5, "ticks", Ty::UInt),
        f(6, "settime_flags", Ty::Hex),
        f(7, "vsec", Ty::Duration(1)),
        f(8, "vnsec", Ty::Duration(1_000_000_000)),
        f(9, "isec", Ty::Duration(1)),
        f(10, "insec", Ty::Duration(1_000_000_000)),
    ],
    &[4],
);

static SK_OPTS: Msg = msg(
    "sk_opts_entry",
    &[
        f(1, "so_sndbuf", Ty::UInt),
        f(2, "so_rcvbuf", Ty::UInt),
        f(3, "so_snd_tmo_sec", Ty::Duration(1)),
        f(4, "so_snd_tmo_usec", Ty::Duration(1_000_000)),
        f(5, "so_rcv_tmo_sec", Ty::Duration(1)),
        f(6, "so_rcv_tmo_usec", Ty::Duration(1_000_000)),
        f(7, "reuseaddr", Ty::Bool),
        f(8, "so_priority", Ty::UInt),
        f(9, "so_rcvlowat", Ty::UInt),
        f(10, "so_mark", Ty::UInt),
        f(11, "so_passcred", Ty::Bool),
        f(12, "so_passsec", Ty::Bool),
        f(13, "so_dontroute", Ty::Bool),
        f(14, "so_no_check", Ty::Bool),
        f(15, "so_bound_dev", Ty::Str),
        f(17, "so_reuseport", Ty::Bool),
        f(18, "so_broadcast", Ty::Bool),
        f(19, "so_keepalive", Ty::Bool),
        f(20, "tcp_keepcnt", Ty::UInt),
        f(21, "tcp_keepidle", Ty::UInt),
        f(22, "tcp_keepintvl", Ty::UInt),
        f(23, "so_oobinline", Ty::UInt),
        f(24, "so_linger", Ty::UInt),
        f(25, "so_buf_lock", Ty::UInt),
    ],
    &[],
);

static FILE_PERMS: Msg = msg(
    "file_perms_entry",
    &[
        f(1, "mode", Ty::Hex),
        f(2, "uid", Ty::UInt),
        f(3, "gid", Ty::UInt),
    ],
    &[],
);

static UNIX_SK_ENTRY: Msg = msg(
    "unix_sk_entry",
    &[
        f(1, "id", Ty::UInt),
        f(2, "ino", Ty::UInt),
        f(3, "type", Ty::Enum(SK_TYPE)),
        f(4, "state", Ty::UInt),
        f(5, "flags", Ty::Hex),
        f(6, "uflags", Ty::Hex),
        f(7, "backlog", Ty::UInt),
        f(8, "peer", Ty::UInt),
        f(9, "fown", Ty::Msg(&FOWN_ENTRY)),
        f(10, "opts", Ty::Msg(&SK_OPTS)),
        f(11, "name", Ty::Bytes),
        f(12, "shutdown", Ty::Enum(SK_SHUTDOWN)),
        f(13, "file_perms", Ty::Msg(&FILE_PERMS)),
        f(14, "name_dir", Ty::Str),
        f(15, "deleted", Ty::Bool),
        f(16, "ns_id", Ty::UInt),
        f(17, "mnt_id", Ty::SInt),
    ],
    &[3, 2],
);

static INET_SK_ENTRY: Msg = msg(
    "inet_sk_entry",
    &[
        f(1, "id", Ty::UInt),
        f(2, "ino", Ty::UInt),
        f(3, "family", Ty::Enum(SK_FAMILY)),
        f(4, "type", Ty::Enum(SK_TYPE)),
        f(5, "proto", Ty::UInt),
        f(6, "state", Ty::UInt),
        f(7, "src_port", Ty::UInt),
        f(8, "dst_port", Ty::UInt),
        f(9, "flags", Ty::Hex),
        f(10, "backlog", Ty::UInt),
        f(11, "src_addr", Ty::Hex),
        f(12, "dst_addr", Ty::Hex),
        f(13, "fown", Ty::Msg(&FOWN_ENTRY)),
        f(14, "opts", Ty::Msg(&SK_OPTS)),
        f(15, "v6only", Ty::Bool),
        f(16, "ip_opts", Ty::Msg(&IP_OPTS)),
        f(17, "ifname", Ty::Str),
        f(18, "ns_id", Ty::UInt),
        f(19, "shutdown", Ty::Enum(SK_SHUTDOWN)),
        f(20, "tcp_opts", Ty::Msg(&TCP_OPTS)),
    ],
    &[3, 4, 7, 8],
);

static IP_OPTS_RAW: Msg = msg(
    "ip_opts_raw_entry",
    &[
        f(1, "hdrincl", Ty::Bool),
        f(2, "nodefrag", Ty::Bool),
        f(3, "checksum", Ty::Bool),
        f(4, "icmpv_filter", Ty::Hex),
    ],
    &[],
);

static IP_OPTS: Msg = msg(
    "ip_opts_entry",
    &[
        f(1, "freebind", Ty::Bool),
        f(4, "raw", Ty::Msg(&IP_OPTS_RAW)),
        f(5, "pktinfo", Ty::Bool),
        f(6, "tos", Ty::UInt),
        f(7, "ttl", Ty::UInt),
    ],
    &[],
);

static TCP_OPTS: Msg = msg(
    "tcp_opts_entry",
    &[
        f(1, "cork", Ty::Bool),
        f(2, "nodelay", Ty::Bool),
        f(3, "keepcnt", Ty::UInt),
        f(4, "keepidle", Ty::UInt),
        f(5, "keepintvl", Ty::UInt),
    ],
    &[],
);

static TTY_FILE_ENTRY: Msg = msg(
    "tty_file_entry",
    &[
        f(1, "id", Ty::UInt),
        f(2, "tty_info_id", Ty::UInt),
        f(3, "flags", Ty::Flags(OPEN_FLAGS)),
        f(4, "fown", Ty::Msg(&FOWN_ENTRY)),
        f(6, "regf_id", Ty::UInt),
    ],
    &[2],
);

static FILE_ENTRY: Msg = msg(
    "file_entry",
    &[
        f(1, "type", Ty::Enum(FD_TYPES)),
        f(2, "id", Ty::UInt),
        f(3, "reg", Ty::Msg(&REG_FILE_ENTRY)),
        f(4, "isk", Ty::Msg(&INET_SK_ENTRY)),
        f(5, "nsf", Ty::Msg(&NS_FILE_ENTRY)),
        f(6, "psk", Ty::Msg(U)),
        f(7, "nlsk", Ty::Msg(U)),
        f(8, "efd", Ty::Msg(&EVENTFD_ENTRY)),
        f(9, "epfd", Ty::Msg(&EVENTPOLL_FILE)),
        f(10, "sgfd", Ty::Msg(&SIGNALFD_ENTRY)),
        f(11, "tunf", Ty::Msg(U)),
        f(12, "tfd", Ty::Msg(&TIMERFD_ENTRY)),
        f(13, "ify", Ty::Msg(&INOTIFY_FILE)),
        f(14, "ffy", Ty::Msg(&FANOTIFY_FILE)),
        f(15, "ext", Ty::Msg(U)),
        f(16, "usk", Ty::Msg(&UNIX_SK_ENTRY)),
        f(17, "fifo", Ty::Msg(&FIFO_ENTRY)),
        f(18, "pipe", Ty::Msg(&PIPE_ENTRY)),
        f(19, "tty", Ty::Msg(&TTY_FILE_ENTRY)),
        f(20, "memfd", Ty::Msg(U)),
        f(21, "bpf", Ty::Msg(U)),
        f(22, "pidfd", Ty::Msg(U)),
    ],
    &[1, 2],
);

static FS_ENTRY: Msg = msg(
    "fs_entry",
    &[
        f(1, "cwd_id", Ty::UInt),
        f(2, "root_id", Ty::UInt),
        f(3, "umask", Ty::UInt),
    ],
    &[1, 2],
);

static TIMEVAL: Msg = msg(
    "timeval",
    &[f(1, "tv_sec", Ty::Time), f(2, "tv_usec", Ty::UInt)],
    &[],
);

static GHOST_FILE_ENTRY: Msg = msg(
    "ghost_file_entry",
    &[
        f(1, "uid", Ty::UInt),
        f(2, "gid", Ty::UInt),
        f(3, "mode", Ty::Hex),
        f(4, "dev", Ty::Hex),
        f(5, "ino", Ty::UInt),
        f(6, "rdev", Ty::Hex),
        f(7, "atim", Ty::Msg(&TIMEVAL)),
        f(8, "mtim", Ty::Msg(&TIMEVAL)),
        f(9, "chunks", Ty::Bool),
        f(10, "size", Ty::UInt),
        f(11, "symlnk_target", Ty::Str),
    ],
    &[10],
);

static GHOST_CHUNK_ENTRY: Msg = msg(
    "ghost_chunk_entry",
    &[f(1, "len", Ty::UInt), f(2, "off", Ty::UInt)],
    &[2, 1],
);

static MNT_ENTRY: Msg = msg(
    "mnt_entry",
    &[
        f(1, "fstype", Ty::UInt),
        f(2, "mnt_id", Ty::UInt),
        f(3, "root_dev", Ty::Hex),
        f(4, "parent_mnt_id", Ty::UInt),
        f(5, "flags", Ty::Hex),
        f(6, "root", Ty::Str),
        f(7, "mountpoint", Ty::Str),
        f(8, "source", Ty::Str),
        f(9, "options", Ty::Str),
        f(10, "shared_id", Ty::UInt),
        f(11, "master_id", Ty::UInt),
        f(12, "with_plugin", Ty::Bool),
        f(13, "ext_mount", Ty::Bool),
        f(14, "fsname", Ty::Str),
        f(15, "internal_sharing", Ty::Bool),
        f(16, "deleted", Ty::Bool),
        f(17, "sb_flags", Ty::Hex),
        f(18, "ext_key", Ty::Str),
    ],
    &[7, 14],
);

// --- namespaces, sockets, misc -----------------------------------------------------

static UTSNS_ENTRY: Msg = msg(
    "utsns_entry",
    &[f(1, "nodename", Ty::Str), f(2, "domainname", Ty::Str)],
    &[1],
);

static TIMESPEC: Msg = msg(
    "timespec",
    &[
        f(1, "tv_sec", Ty::Duration(1)),
        f(2, "tv_nsec", Ty::Duration(1_000_000_000)),
    ],
    &[],
);

static TIMENS_ENTRY: Msg = msg(
    "timens_entry",
    &[
        f(1, "monotonic", Ty::Msg(&TIMESPEC)),
        f(2, "boottime", Ty::Msg(&TIMESPEC)),
    ],
    &[],
);

static PIDNS_ENTRY: Msg = msg("pidns_entry", &[f(1, "ext_key", Ty::Str)], &[1]);

static UID_GID_EXTENT: Msg = msg(
    "uid_gid_extent",
    &[
        f(1, "first", Ty::UInt),
        f(2, "lower_first", Ty::UInt),
        f(3, "count", Ty::UInt),
    ],
    &[],
);

static USERNS_ENTRY: Msg = msg(
    "userns_entry",
    &[
        f(1, "uid_map", Ty::Msg(&UID_GID_EXTENT)),
        f(2, "gid_map", Ty::Msg(&UID_GID_EXTENT)),
    ],
    &[],
);

static IPC_VAR_ENTRY: Msg = msg(
    "ipc_var_entry",
    &[
        f(1, "sem_ctls", Ty::Packed(Elem::Varint)),
        f(2, "msg_ctlmax", Ty::UInt),
        f(3, "msg_ctlmnb", Ty::UInt),
        f(4, "msg_ctlmni", Ty::UInt),
        f(5, "auto_msgmni", Ty::UInt),
        f(6, "shm_ctlmax", Ty::UInt),
        f(7, "shm_ctlall", Ty::UInt),
        f(8, "shm_ctlmni", Ty::UInt),
        f(9, "shm_rmid_forced", Ty::UInt),
        f(10, "mq_queues_max", Ty::UInt),
        f(11, "mq_msg_max", Ty::UInt),
        f(12, "mq_msgsize_max", Ty::UInt),
        f(13, "mq_msg_default", Ty::UInt),
        f(14, "mq_msgsize_default", Ty::UInt),
        f(15, "msg_next_id", Ty::UInt),
        f(16, "sem_next_id", Ty::UInt),
        f(17, "shm_next_id", Ty::UInt),
    ],
    &[],
);

static IPC_DESC: Msg = msg(
    "ipc_desc_entry",
    &[
        f(1, "key", Ty::Hex),
        f(2, "uid", Ty::UInt),
        f(3, "gid", Ty::UInt),
        f(4, "cuid", Ty::UInt),
        f(5, "cgid", Ty::UInt),
        f(6, "mode", Ty::Hex),
        f(7, "id", Ty::UInt),
    ],
    &[1, 7],
);

static IPC_SHM_ENTRY: Msg = msg(
    "ipc_shm_entry",
    &[
        f(1, "desc", Ty::Msg(&IPC_DESC)),
        f(2, "size", Ty::UInt),
        f(3, "in_pagemaps", Ty::Bool),
        f(4, "hugetlb_flag", Ty::Hex),
    ],
    &[2],
);

static IPC_SEM_ENTRY: Msg = msg(
    "ipc_sem_entry",
    &[f(1, "desc", Ty::Msg(&IPC_DESC)), f(2, "nsems", Ty::UInt)],
    &[2],
);

static IPC_MSG_ENTRY: Msg = msg(
    "ipc_msg_entry",
    &[
        f(1, "desc", Ty::Msg(&IPC_DESC)),
        f(2, "qbytes", Ty::UInt),
        f(3, "qnum", Ty::UInt),
    ],
    &[3],
);

static SCM_ENTRY: Msg = msg(
    "scm_entry",
    &[
        f(1, "type", Ty::UInt),
        f(2, "rights", Ty::Packed(Elem::Varint)),
    ],
    &[],
);

static SK_PACKET_ENTRY: Msg = msg(
    "sk_packet_entry",
    &[
        f(1, "id_for", Ty::UInt),
        f(2, "length", Ty::UInt),
        f(4, "scm", Ty::Msg(&SCM_ENTRY)),
    ],
    &[1, 2],
);

static TCP_STREAM_ENTRY: Msg = msg(
    "tcp_stream_entry",
    &[
        f(1, "inq_len", Ty::UInt),
        f(2, "inq_seq", Ty::UInt),
        f(3, "outq_len", Ty::UInt),
        f(4, "outq_seq", Ty::UInt),
        f(5, "opt_mask", Ty::Hex),
        f(6, "snd_wscale", Ty::UInt),
        f(7, "mss_clamp", Ty::UInt),
        f(8, "rcv_wscale", Ty::UInt),
        f(9, "timestamp", Ty::UInt),
        f(10, "cork", Ty::Bool),
        f(11, "nodelay", Ty::Bool),
        f(12, "unsq_len", Ty::UInt),
        f(13, "snd_wl1", Ty::UInt),
        f(14, "snd_wnd", Ty::UInt),
        f(15, "max_window", Ty::UInt),
        f(16, "rcv_wnd", Ty::UInt),
        f(17, "rcv_wup", Ty::UInt),
    ],
    &[1, 3],
);

static BPFMAP_DATA_ENTRY: Msg = msg(
    "bpfmap_data_entry",
    &[
        f(1, "map_id", Ty::UInt),
        f(2, "keys_bytes", Ty::UInt),
        f(3, "values_bytes", Ty::UInt),
        f(4, "count", Ty::UInt),
    ],
    &[1, 4],
);

static CG_MEMBER: Msg = msg(
    "cg_member_entry",
    &[
        f(1, "name", Ty::Str),
        f(2, "path", Ty::Str),
        f(3, "cgns_prefix", Ty::UInt),
    ],
    &[1, 2],
);

static CG_SET: Msg = msg(
    "cg_set_entry",
    &[f(1, "id", Ty::UInt), f(2, "ctls", Ty::Msg(&CG_MEMBER))],
    &[1],
);

static CGROUP_ENTRY: Msg = msg(
    "cgroup_entry",
    &[
        f(1, "sets", Ty::Msg(&CG_SET)),
        f(2, "controllers", Ty::Msg(U)),
    ],
    &[],
);

static SECCOMP_FILTER: Msg = msg(
    "seccomp_filter",
    &[
        f(1, "filter", Ty::Bytes),
        f(2, "prev", Ty::UInt),
        f(3, "flags", Ty::Hex),
    ],
    &[],
);

static SECCOMP_ENTRY: Msg = msg(
    "seccomp_entry",
    &[f(1, "seccomp_filters", Ty::Msg(&SECCOMP_FILTER))],
    &[],
);

static DUMP_STATS: Msg = msg(
    "dump_stats_entry",
    &[
        f(1, "freezing_time", Ty::UInt),
        f(2, "frozen_time", Ty::UInt),
        f(3, "memdump_time", Ty::UInt),
        f(4, "memwrite_time", Ty::UInt),
        f(5, "pages_scanned", Ty::UInt),
        f(6, "pages_skipped_parent", Ty::UInt),
        f(7, "pages_written", Ty::UInt),
        f(8, "irmap_resolve", Ty::UInt),
        f(9, "pages_lazy", Ty::UInt),
        f(10, "page_pipes", Ty::UInt),
        f(11, "page_pipe_bufs", Ty::UInt),
        f(12, "shpages_scanned", Ty::UInt),
        f(13, "shpages_skipped_parent", Ty::UInt),
        f(14, "shpages_written", Ty::UInt),
    ],
    &[],
);

static RESTORE_STATS: Msg = msg(
    "restore_stats_entry",
    &[
        f(1, "pages_compared", Ty::UInt),
        f(2, "pages_skipped_cow", Ty::UInt),
        f(3, "forking_time", Ty::UInt),
        f(4, "restore_time", Ty::UInt),
        f(5, "pages_restored", Ty::UInt),
    ],
    &[],
);

static STATS_ENTRY: Msg = msg(
    "stats_entry",
    &[
        f(1, "dump", Ty::Msg(&DUMP_STATS)),
        f(2, "restore", Ty::Msg(&RESTORE_STATS)),
    ],
    &[],
);

// --- event and notification files, terminals, locks ---------------------------

/// CRIU's own `NETWORK_LOCK_METHOD` (`criu/include/cr_options.h`, from 0;
/// not `rpc.proto`'s, from 1): a `--network-lock skip` dump records 2.
const NETWORK_LOCK: EnumTable = &[(0, "IPTABLES"), (1, "NFTABLES"), (2, "SKIP")];

const EPOLL_EVENTS: FlagTable = &[
    flag(0x1, "EPOLLIN"),
    flag(0x2, "EPOLLPRI"),
    flag(0x4, "EPOLLOUT"),
    flag(0x8, "EPOLLERR"),
    flag(0x10, "EPOLLHUP"),
    flag(0x40, "EPOLLRDNORM"),
    flag(0x80, "EPOLLRDBAND"),
    flag(0x100, "EPOLLWRNORM"),
    flag(0x200, "EPOLLWRBAND"),
    flag(0x400, "EPOLLMSG"),
    flag(0x2000, "EPOLLRDHUP"),
    flag(1 << 28, "EPOLLEXCLUSIVE"),
    flag(1 << 29, "EPOLLWAKEUP"),
    flag(1 << 30, "EPOLLONESHOT"),
    flag(1 << 31, "EPOLLET"),
];

static EVENTPOLL_TFD: Msg = msg(
    "eventpoll_tfd_entry",
    &[
        f(1, "id", Ty::UInt),
        f(2, "tfd", Ty::UInt),
        f(3, "events", Ty::Flags(EPOLL_EVENTS)),
        f(4, "data", Ty::Hex),
        f(5, "dev", Ty::Hex),
        f(6, "inode", Ty::UInt),
        f(7, "pos", Ty::UInt),
    ],
    &[2, 3],
);

static EVENTPOLL_FILE: Msg = msg(
    "eventpoll_file_entry",
    &[
        f(1, "id", Ty::UInt),
        f(2, "flags", Ty::Flags(OPEN_FLAGS)),
        f(3, "fown", Ty::Msg(&FOWN_ENTRY)),
        f(4, "tfd", Ty::Msg(&EVENTPOLL_TFD)),
    ],
    &[1],
);

const INOTIFY_MASK: FlagTable = &[
    flag(0x1, "IN_ACCESS"),
    flag(0x2, "IN_MODIFY"),
    flag(0x4, "IN_ATTRIB"),
    flag(0x8, "IN_CLOSE_WRITE"),
    flag(0x10, "IN_CLOSE_NOWRITE"),
    flag(0x20, "IN_OPEN"),
    flag(0x40, "IN_MOVED_FROM"),
    flag(0x80, "IN_MOVED_TO"),
    flag(0x100, "IN_CREATE"),
    flag(0x200, "IN_DELETE"),
    flag(0x400, "IN_DELETE_SELF"),
    flag(0x800, "IN_MOVE_SELF"),
    flag(0x2000, "IN_UNMOUNT"),
    flag(0x4000, "IN_Q_OVERFLOW"),
    flag(0x8000, "IN_IGNORED"),
    flag(0x100_0000, "IN_ONLYDIR"),
    flag(0x200_0000, "IN_DONT_FOLLOW"),
    flag(0x400_0000, "IN_EXCL_UNLINK"),
    flag(0x1000_0000, "IN_MASK_CREATE"),
    flag(0x2000_0000, "IN_MASK_ADD"),
    flag(0x4000_0000, "IN_ISDIR"),
    flag(0x8000_0000, "IN_ONESHOT"),
];

/// A file handle (`images/fh.proto`).
static FH_ENTRY: Msg = msg(
    "fh_entry",
    &[
        f(1, "bytes", Ty::UInt),
        f(2, "type", Ty::UInt),
        f(3, "handle", Ty::Hex),
        f(4, "path", Ty::Str),
        f(5, "mnt_id", Ty::UInt),
    ],
    &[4],
);

static INOTIFY_WD: Msg = msg(
    "inotify_wd_entry",
    &[
        f(1, "id", Ty::UInt),
        f(2, "i_ino", Ty::UInt),
        f(3, "mask", Ty::Flags(INOTIFY_MASK)),
        f(4, "ignored_mask", Ty::Flags(INOTIFY_MASK)),
        f(5, "s_dev", Ty::Hex),
        f(6, "wd", Ty::UInt),
        f(7, "f_handle", Ty::Msg(&FH_ENTRY)),
    ],
    &[6, 3],
);

static INOTIFY_FILE: Msg = msg(
    "inotify_file_entry",
    &[
        f(1, "id", Ty::UInt),
        f(2, "flags", Ty::Flags(OPEN_FLAGS)),
        f(4, "fown", Ty::Msg(&FOWN_ENTRY)),
        f(5, "wd", Ty::Msg(&INOTIFY_WD)),
    ],
    &[1],
);

static FANOTIFY_INODE_MARK: Msg = msg(
    "fanotify_inode_mark_entry",
    &[
        f(1, "i_ino", Ty::UInt),
        f(2, "f_handle", Ty::Msg(&FH_ENTRY)),
    ],
    &[],
);

static FANOTIFY_MOUNT_MARK: Msg = msg(
    "fanotify_mount_mark_entry",
    &[f(1, "mnt_id", Ty::UInt), f(2, "path", Ty::Str)],
    &[2],
);

static FANOTIFY_MARK: Msg = msg(
    "fanotify_mark_entry",
    &[
        f(1, "id", Ty::UInt),
        f(2, "type", Ty::Enum(&[(1, "INODE"), (2, "MOUNT")])),
        f(3, "mflags", Ty::Hex),
        f(4, "mask", Ty::Hex),
        f(5, "ignored_mask", Ty::Hex),
        f(6, "s_dev", Ty::Hex),
        f(7, "ie", Ty::Msg(&FANOTIFY_INODE_MARK)),
        f(8, "me", Ty::Msg(&FANOTIFY_MOUNT_MARK)),
    ],
    &[2],
);

static FANOTIFY_FILE: Msg = msg(
    "fanotify_file_entry",
    &[
        f(1, "id", Ty::UInt),
        f(2, "flags", Ty::Flags(OPEN_FLAGS)),
        f(3, "fown", Ty::Msg(&FOWN_ENTRY)),
        f(4, "faflags", Ty::Hex),
        f(5, "evflags", Ty::Hex),
        f(6, "mark", Ty::Msg(&FANOTIFY_MARK)),
    ],
    &[1],
);

const TTY_TYPE: EnumTable = &[
    (0, "UNKNOWN"),
    (1, "PTY"),
    (2, "CONSOLE"),
    (3, "VT"),
    (4, "CTTY"),
    (5, "EXT_TTY"),
    (6, "SERIAL"),
];

static WINSIZE: Msg = msg(
    "winsize_entry",
    &[
        f(1, "ws_row", Ty::UInt),
        f(2, "ws_col", Ty::UInt),
        f(3, "ws_xpixel", Ty::UInt),
        f(4, "ws_ypixel", Ty::UInt),
    ],
    &[1, 2],
);

/// `c_cc` holds the termios control characters packed four to an element
/// (little-endian); CRIU 4.2.1 fills the elements past the kernel's
/// `NCCS` bytes with whatever was in memory (external fixture).
static TERMIOS: Msg = msg(
    "termios_entry",
    &[
        f(1, "c_iflag", Ty::Hex),
        f(2, "c_oflag", Ty::Hex),
        f(3, "c_cflag", Ty::Hex),
        f(4, "c_lflag", Ty::Hex),
        f(5, "c_line", Ty::UInt),
        f(6, "c_ispeed", Ty::UInt),
        f(7, "c_ospeed", Ty::UInt),
        f(8, "c_cc", Ty::Hex),
    ],
    &[],
);

static TTY_PTY: Msg = msg("tty_pty_entry", &[f(1, "index", Ty::UInt)], &[1]);

static TTY_INFO: Msg = msg(
    "tty_info_entry",
    &[
        f(1, "id", Ty::UInt),
        f(2, "type", Ty::Enum(TTY_TYPE)),
        f(3, "locked", Ty::Bool),
        f(4, "exclusive", Ty::Bool),
        f(5, "packet_mode", Ty::Bool),
        f(6, "sid", Ty::UInt),
        f(7, "pgrp", Ty::UInt),
        f(8, "rdev", Ty::Hex),
        f(9, "termios", Ty::Msg(&TERMIOS)),
        f(10, "termios_locked", Ty::Msg(&TERMIOS)),
        f(11, "winsize", Ty::Msg(&WINSIZE)),
        f(12, "pty", Ty::Msg(&TTY_PTY)),
        f(13, "dev", Ty::Hex),
        f(14, "uid", Ty::UInt),
        f(15, "gid", Ty::UInt),
    ],
    &[2, 1],
);

static TTY_DATA: Msg = msg(
    "tty_data_entry",
    &[f(1, "tty_id", Ty::UInt), f(2, "data", Ty::Bytes)],
    &[1],
);

/// Lock kinds: the kernel's `fl_flags` bits CRIU records.
const LOCK_FLAGS: FlagTable = &[
    flag(1, "FL_POSIX"),
    flag(2, "FL_FLOCK"),
    flag(32, "FL_LEASE"),
    flag(1024, "FL_OFDLCK"),
];

static FILE_LOCK: Msg = msg(
    "file_lock_entry",
    &[
        f(1, "flag", Ty::Flags(LOCK_FLAGS)),
        f(
            2,
            "type",
            Ty::Enum(&[(0, "F_RDLCK"), (1, "F_WRLCK"), (2, "F_UNLCK")]),
        ),
        f(3, "pid", Ty::Int),
        f(4, "fd", Ty::Int),
        f(5, "start", Ty::Int),
        f(6, "len", Ty::Int),
    ],
    &[1, 2],
);

// --- x86 FPU state and TLS ----------------------------------------------------

static X86_CET: Msg = msg(
    "user_x86_cet_entry",
    &[f(1, "cet", Ty::Hex), f(2, "ssp", Ty::Hex)],
    &[],
);

static X86_XSAVE: Msg = msg(
    "user_x86_xsave_entry",
    &[
        f(1, "xstate_bv", Ty::Hex),
        f(2, "ymmh_space", Ty::Hex),
        f(3, "bndreg_state", Ty::Hex),
        f(4, "bndcsr_state", Ty::Hex),
        f(5, "opmask_reg", Ty::Hex),
        f(6, "zmm_upper", Ty::Hex),
        f(7, "hi16_zmm", Ty::Hex),
        f(8, "pkru", Ty::Hex),
        f(9, "cet", Ty::Msg(&X86_CET)),
    ],
    &[],
);

static X86_FPREGS: Msg = msg(
    "user_x86_fpregs_entry",
    &[
        f(1, "cwd", Ty::Hex),
        f(2, "swd", Ty::Hex),
        f(3, "twd", Ty::Hex),
        f(4, "fop", Ty::Hex),
        f(5, "rip", Ty::Hex),
        f(6, "rdp", Ty::Hex),
        f(7, "mxcsr", Ty::Hex),
        f(8, "mxcsr_mask", Ty::Hex),
        f(9, "st_space", Ty::Hex),
        f(10, "xmm_space", Ty::Hex),
        f(11, "padding", Ty::Hex),
        f(13, "xsave", Ty::Msg(&X86_XSAVE)),
    ],
    &[],
);

static USER_DESC: Msg = msg(
    "user_desc_t",
    &[
        f(1, "entry_number", Ty::UInt),
        f(2, "base_addr", Ty::Hex),
        f(3, "limit", Ty::Hex),
        f(4, "seg_32bit", Ty::Bool),
        f(5, "contents_h", Ty::Bool),
        f(6, "contents_l", Ty::Bool),
        f(7, "read_exec_only", Ty::Bool),
        f(8, "limit_in_pages", Ty::Bool),
        f(9, "seg_not_present", Ty::Bool),
        f(10, "usable", Ty::Bool),
    ],
    &[1],
);
