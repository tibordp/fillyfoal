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
//! data, System V IPC contents, and the file data of ghost files; the
//! pagemap image starts with a `pagemap_head` and continues with
//! `pagemap_entry` records. `pages-<n>.img` holds only raw page data (no
//! magic, no entries; the pagemap says which pages it holds), so it is not
//! identified as this format.
//!
//! Message schemas (field numbers, names, types, enum values, flag names)
//! follow CRIU's `images/*.proto` and the flag tables of `crit`
//! (`pycriu`), read for these facts; the magic numbers are those of
//! `criu/include/magic.h`. Types whose schema is not listed here are shown
//! by wire type. Checked against images written by `criu dump` 4.1.1
//! (external fixtures).

use crate::bytes::{u32_be, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::fmt::{clip, plural};
use crate::formats::util::wire::protobuf::{self as proto, Elem, Msg, Ty, f, fields_in, varint_in};
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, decode_flags, flag, lookup};

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
    /// Two such fields added up.
    Fields(u64, u64),
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
        Extra::Fields(1, 3),
    ),
    t(0x4452_3722, "EVENTFD_FILE", "eventfds", &EVENTFD_ENTRY),
    t(0x4502_3858, "EVENTPOLL_FILE", "epoll instances", U),
    t(0x4443_3746, "EVENTPOLL_TFD", "epoll targets", U),
    t(0x5732_3820, "SIGNALFD", "signalfds", &SIGNALFD_ENTRY),
    t(0x4842_4431, "INOTIFY_FILE", "inotify instances", U),
    t(0x5456_2009, "INOTIFY_WD", "inotify watches", U),
    t(0x5556_3928, "MNTS", "mount points", &MNT_ENTRY),
    t(0x5737_3951, "NETDEV", "network devices", U),
    t(0x5593_3752, "NETNS", "network namespace", U),
    t(0x5943_3025, "TTY_FILES", "terminals", &TTY_FILE_ENTRY),
    t(0x5945_3036, "TTY_INFO", "terminal settings", U),
    t(0x5941_3026, "TTY_DATA", "terminal buffers", U),
    t(0x5432_3616, "FILE_LOCKS", "file locks", U),
    t(0x5711_3925, "RLIMIT", "resource limits", &RLIMIT_ENTRY),
    t(0x5509_6122, "FANOTIFY_FILE", "fanotify instances", U),
    t(0x5650_6035, "FANOTIFY_MARK", "fanotify marks", U),
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
        Extra::Fields(2, 3),
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
    let (pos, mut index, mut phase) = match cx.resume::<(u64, u64, Phase)>() {
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
                        name: Some(ty.name),
                    })
                    .summary(ty.title),
            );
            cx.annotate(format!("CRIU {} image ({})", ty.name, ty.title));
            (at, 0u64, Phase::First)
        }
    };
    let mut cur = Cursor::new(&cx, file, endian);
    cur.seek(pos);
    while !cur.at_end() {
        let start = cur.pos();
        let state = (start, index, phase);
        cx.mark(move || state);
        cx.progress_in(file, file.offset.saturating_add(start));
        // Raw data that is the rest of a ghost file.
        if phase == Phase::GhostData {
            let rest = cur.span(cur.remaining());
            cx.push(Node::new("File data").span(rest)).await;
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
        let data = if size <= TITLE_MAX {
            cx.read(body).await?
        } else {
            Vec::new()
        };
        let title = entry_title(&data, msg);
        let entry_span = cur.since(start);
        let mut node = Node::new(format!("{label} [{index}]"))
            .span(entry_span)
            .summary(if title.is_empty() {
                plural(size, "byte")
            } else {
                title
            })
            .lazy(entry, (start, body, msg, endian));
        // Raw data after the entry.
        let extra = match (ty.extra, phase) {
            (Extra::Field(n), _) => varint_in(&data, n).unwrap_or(0),
            (Extra::Fields(a, b), _) => varint_in(&data, a)
                .unwrap_or(0)
                .saturating_add(varint_in(&data, b).unwrap_or(0)),
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
            }
        }
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
        index = index.saturating_add(1);
    }
    Ok(())
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
        name: lookup(table, raw.into()),
    }
}

/// An entry: its size, its message, and raw data after it.
async fn entry(
    cx: Cx,
    (start, body, msg, endian): (u64, Span, &'static Msg, Endian),
) -> Result<()> {
    let size_span = Span::new(body.source, body.offset.saturating_sub(4), 4);
    let raw = cx.read(size_span).await?;
    let size = match endian {
        Endian::Little => u32_le(&raw, 0),
        Endian::Big => u32_be(&raw, 0),
    }
    .unwrap_or(0);
    let _ = start;
    cx.emit(Node::new("Size").span(size_span).value(Value::UInt {
        value: size.into(),
        bits: 32,
        radix: crate::value::Radix::Dec,
    }));
    cx.emit(
        Node::new(msg.name)
            .span(body)
            .lazy(proto::message, (body, msg, 0u32)),
    );
    Ok(())
}

/// A summary of an entry from its schema's title fields.
fn entry_title(data: &[u8], msg: &'static Msg) -> String {
    let mut parts = Vec::new();
    for &num in msg.title {
        let Some(spec) = msg.fields.iter().find(|f| f.num == num) else {
            continue;
        };
        let part = match spec.ty {
            Ty::Str => fields_in(data)
                .find(|r| r.number == num && r.wire == proto::LEN)
                .map(|r| clip(&String::from_utf8_lossy(r.payload(data)), 80)),
            Ty::Hex => varint_in(data, num).map(|v| format!("{}={v:#x}", spec.name)),
            Ty::Enum(table) => varint_in(data, num)
                .map(|v| lookup(table, v).map_or_else(|| v.to_string(), str::to_owned)),
            Ty::Flags(table) => varint_in(data, num).map(|v| {
                let (set, unknown) = decode_flags(table, v);
                let mut s = set.join("|");
                if unknown != 0 || s.is_empty() {
                    if !s.is_empty() {
                        s.push('|');
                    }
                    s.push_str(&format!("{unknown:#x}"));
                }
                s
            }),
            Ty::Int | Ty::Packed(Elem::Varint) => {
                varint_in(data, num).map(|v| format!("{}={v}", spec.name))
            }
            _ => None,
        };
        if let Some(p) = part.filter(|p| !p.is_empty()) {
            parts.push(p);
        }
    }
    parts.join(", ")
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
const TASK_STATE: EnumTable = &[(1, "Alive"), (3, "Zombie"), (6, "Stopped")];
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
        f(1, "vm_id", Ty::Int),
        f(2, "files_id", Ty::Int),
        f(3, "fs_id", Ty::Int),
        f(4, "sighand_id", Ty::Int),
        f(5, "pid_ns_id", Ty::Int),
        f(6, "net_ns_id", Ty::Int),
        f(7, "ipc_ns_id", Ty::Int),
        f(8, "uts_ns_id", Ty::Int),
        f(9, "mnt_ns_id", Ty::Int),
        f(10, "user_ns_id", Ty::Int),
        f(11, "cgroup_ns_id", Ty::Int),
        f(12, "time_ns_id", Ty::Int),
    ],
    &[],
);

static PLUGINS_ENTRY: Msg = msg("plugins_entry", &[f(12, "plugins", Ty::Str)], &[]);

static INVENTORY_ENTRY: Msg = msg(
    "inventory_entry",
    &[
        f(1, "img_version", Ty::Int),
        f(2, "fdinfo_per_id", Ty::Bool),
        f(3, "root_ids", Ty::Msg(&IDS_ENTRY)),
        f(4, "ns_per_id", Ty::Bool),
        f(5, "root_cg_set", Ty::Int),
        f(6, "lsmtype", Ty::Enum(LSMTYPE)),
        f(8, "dump_uptime", Ty::Int),
        f(9, "pre_dump_mode", Ty::Int),
        f(10, "tcp_close", Ty::Bool),
        f(11, "network_lock_method", Ty::Int),
        f(12, "plugins_entry", Ty::Msg(&PLUGINS_ENTRY)),
        f(13, "dump_criu_run_id", Ty::Str),
    ],
    &[1, 6],
);

static PSTREE_ENTRY: Msg = msg(
    "pstree_entry",
    &[
        f(1, "pid", Ty::Int),
        f(2, "ppid", Ty::Int),
        f(3, "pgid", Ty::Int),
        f(4, "sid", Ty::Int),
        f(5, "threads", Ty::Packed(Elem::Varint)),
    ],
    &[1, 2],
);

static FDINFO_ENTRY: Msg = msg(
    "fdinfo_entry",
    &[
        f(1, "id", Ty::Int),
        f(2, "flags", Ty::Hex),
        f(3, "type", Ty::Enum(FD_TYPES)),
        f(4, "fd", Ty::Int),
        f(5, "xattr_security_selinux", Ty::Str),
    ],
    &[4, 3, 1],
);

static PAGEMAP_HEAD: Msg = msg("pagemap_head", &[f(1, "pages_id", Ty::Int)], &[1]);

static PAGEMAP_ENTRY: Msg = msg(
    "pagemap_entry",
    &[
        f(1, "vaddr", Ty::Hex),
        f(2, "nr_pages", Ty::Int),
        f(3, "in_parent", Ty::Bool),
        f(4, "flags", Ty::Flags(PMAP_FLAGS)),
    ],
    &[1, 2, 4],
);

// --- core ------------------------------------------------------------------

static ITIMER_ENTRY: Msg = msg(
    "itimer_entry",
    &[
        f(1, "isec", Ty::Int),
        f(2, "iusec", Ty::Int),
        f(3, "vsec", Ty::Int),
        f(4, "vusec", Ty::Int),
    ],
    &[],
);

static POSIX_TIMER_ENTRY: Msg = msg(
    "posix_timer_entry",
    &[
        f(1, "it_id", Ty::Int),
        f(2, "clock_id", Ty::Int),
        f(3, "si_signo", Ty::Int),
        f(4, "it_sigev_notify", Ty::Int),
        f(5, "sival_ptr", Ty::Hex),
        f(6, "overrun", Ty::Int),
        f(7, "isec", Ty::Int),
        f(8, "insec", Ty::Int),
        f(9, "vsec", Ty::Int),
        f(10, "vnsec", Ty::Int),
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

static RLIMIT_ENTRY: Msg = msg(
    "rlimit_entry",
    &[f(1, "cur", Ty::Int), f(2, "max", Ty::Int)],
    &[],
);

static TASK_RLIMITS: Msg = msg(
    "task_rlimits_entry",
    &[f(1, "rlimits", Ty::Msg(&RLIMIT_ENTRY))],
    &[],
);

static SIGINFO: Msg = msg("siginfo_entry", &[f(1, "siginfo", Ty::Bytes)], &[]);
static SIGNAL_QUEUE: Msg = msg(
    "signal_queue_entry",
    &[f(1, "signals", Ty::Msg(&SIGINFO))],
    &[],
);

static SA_ENTRY: Msg = msg(
    "sa_entry",
    &[
        f(1, "sigaction", Ty::Hex),
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
        f(2, "exit_code", Ty::Int),
        f(3, "personality", Ty::Hex),
        f(4, "flags", Ty::Hex),
        f(5, "blk_sigset", Ty::Hex),
        f(6, "comm", Ty::Str),
        f(7, "timers", Ty::Msg(&TASK_TIMERS)),
        f(8, "rlimits", Ty::Msg(&TASK_RLIMITS)),
        f(9, "cg_set", Ty::Int),
        f(10, "signals_s", Ty::Msg(&SIGNAL_QUEUE)),
        f(11, "old_seccomp_mode", Ty::Enum(SECCOMP_MODE)),
        f(12, "old_seccomp_filter", Ty::Int),
        f(13, "loginuid", Ty::Int),
        f(14, "oom_score_adj", Ty::Int),
        f(15, "sigactions", Ty::Msg(&SA_ENTRY)),
        f(18, "child_subreaper", Ty::Bool),
        f(20, "blk_sigset_extended", Ty::Hex),
        f(21, "stop_signo", Ty::Int),
        f(22, "membarrier_registration_mask", Ty::Hex),
    ],
    &[6, 1],
);

static CREDS_ENTRY: Msg = msg(
    "creds_entry",
    &[
        f(1, "uid", Ty::Int),
        f(2, "gid", Ty::Int),
        f(3, "euid", Ty::Int),
        f(4, "egid", Ty::Int),
        f(5, "suid", Ty::Int),
        f(6, "sgid", Ty::Int),
        f(7, "fsuid", Ty::Int),
        f(8, "fsgid", Ty::Int),
        f(9, "cap_inh", Ty::Hex),
        f(10, "cap_prm", Ty::Hex),
        f(11, "cap_eff", Ty::Hex),
        f(12, "cap_bnd", Ty::Hex),
        f(13, "secbits", Ty::Hex),
        f(14, "groups", Ty::Packed(Elem::Varint)),
        f(15, "lsm_profile", Ty::Str),
        f(16, "lsm_sockcreate", Ty::Str),
        f(17, "apparmor_data", Ty::Bytes),
        f(18, "no_new_privs", Ty::Int),
        f(19, "cap_amb", Ty::Hex),
    ],
    &[1, 2],
);

static THREAD_SAS: Msg = msg(
    "thread_sas_entry",
    &[
        f(1, "ss_sp", Ty::Hex),
        f(2, "ss_size", Ty::Int),
        f(3, "ss_flags", Ty::Hex),
    ],
    &[],
);

static RSEQ_ENTRY: Msg = msg(
    "rseq_entry",
    &[
        f(1, "rseq_abi_pointer", Ty::Hex),
        f(2, "rseq_abi_size", Ty::Int),
        f(3, "signature", Ty::Hex),
        f(4, "rseq_cs_pointer", Ty::Hex),
    ],
    &[],
);

static THREAD_CORE: Msg = msg(
    "thread_core_entry",
    &[
        f(1, "futex_rla", Ty::Hex),
        f(2, "futex_rla_len", Ty::Int),
        f(3, "sched_nice", Ty::SInt),
        f(4, "sched_policy", Ty::Int),
        f(5, "sched_prio", Ty::Int),
        f(6, "blk_sigset", Ty::Hex),
        f(7, "sas", Ty::Msg(&THREAD_SAS)),
        f(8, "pdeath_sig", Ty::Int),
        f(9, "signals_p", Ty::Msg(&SIGNAL_QUEUE)),
        f(10, "creds", Ty::Msg(&CREDS_ENTRY)),
        f(11, "seccomp_mode", Ty::Enum(SECCOMP_MODE)),
        f(12, "seccomp_filter", Ty::Int),
        f(13, "comm", Ty::Str),
        f(14, "blk_sigset_extended", Ty::Hex),
        f(15, "rseq_entry", Ty::Msg(&RSEQ_ENTRY)),
        f(16, "cg_set", Ty::Int),
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
        f(3, "fpregs", Ty::Msg(U)),
        f(4, "tls", Ty::Msg(U)),
    ],
    &[],
);

static AARCH64_REGS: Msg = msg(
    "user_aarch64_regs_entry",
    &[
        f(1, "regs", Ty::Hex),
        f(2, "sp", Ty::Hex),
        f(3, "pc", Ty::Hex),
        f(4, "pstate", Ty::Hex),
    ],
    &[3],
);

static AARCH64_FPSIMD: Msg = msg(
    "user_aarch64_fpsimd_context_entry",
    &[
        f(1, "vregs", Ty::Hex),
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
        f(3, "pgoff", Ty::Int),
        f(4, "shmid", Ty::Int),
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
        f(1, "id", Ty::Int),
        f(2, "nr_req", Ty::Int),
        f(3, "ring_len", Ty::Int),
    ],
    &[],
);

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
        f(12, "exe_file_id", Ty::Int),
        f(13, "mm_saved_auxv", Ty::Packed(Elem::Varint)),
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
        f(1, "uid", Ty::Int),
        f(2, "euid", Ty::Int),
        f(3, "signum", Ty::Int),
        f(4, "pid_type", Ty::Int),
        f(5, "pid", Ty::Int),
    ],
    &[],
);

static REG_FILE_ENTRY: Msg = msg(
    "reg_file_entry",
    &[
        f(1, "id", Ty::Int),
        f(2, "flags", Ty::Flags(OPEN_FLAGS)),
        f(3, "pos", Ty::Int),
        f(5, "fown", Ty::Msg(&FOWN_ENTRY)),
        f(6, "name", Ty::Str),
        f(7, "mnt_id", Ty::SInt),
        f(8, "size", Ty::Int),
        f(9, "ext", Ty::Bool),
        f(10, "mode", Ty::Hex),
        f(11, "build_id", Ty::Hex),
        f(12, "checksum", Ty::Hex),
        f(13, "checksum_config", Ty::Int),
        f(14, "checksum_parameter", Ty::Int),
    ],
    &[6],
);

static PIPE_ENTRY: Msg = msg(
    "pipe_entry",
    &[
        f(1, "id", Ty::Int),
        f(2, "pipe_id", Ty::Int),
        f(3, "flags", Ty::Flags(OPEN_FLAGS)),
        f(4, "fown", Ty::Msg(&FOWN_ENTRY)),
    ],
    &[2],
);

static PIPE_DATA_ENTRY: Msg = msg(
    "pipe_data_entry",
    &[
        f(1, "pipe_id", Ty::Int),
        f(2, "bytes", Ty::Int),
        f(3, "size", Ty::Int),
    ],
    &[1, 2],
);

static FIFO_ENTRY: Msg = msg(
    "fifo_entry",
    &[
        f(1, "id", Ty::Int),
        f(2, "pipe_id", Ty::Int),
        f(3, "regf_id", Ty::Int),
    ],
    &[2],
);

static NS_FILE_ENTRY: Msg = msg(
    "ns_file_entry",
    &[
        f(1, "id", Ty::Int),
        f(2, "ns_id", Ty::Int),
        f(3, "ns_cflag", Ty::Hex),
        f(4, "flags", Ty::Flags(OPEN_FLAGS)),
    ],
    &[2],
);

static EVENTFD_ENTRY: Msg = msg(
    "eventfd_file_entry",
    &[
        f(1, "id", Ty::Int),
        f(2, "flags", Ty::Flags(OPEN_FLAGS)),
        f(3, "fown", Ty::Msg(&FOWN_ENTRY)),
        f(4, "counter", Ty::Int),
    ],
    &[4],
);

static SIGNALFD_ENTRY: Msg = msg(
    "signalfd_entry",
    &[
        f(1, "id", Ty::Int),
        f(2, "flags", Ty::Hex),
        f(3, "fown", Ty::Msg(&FOWN_ENTRY)),
        f(4, "sigmask", Ty::Hex),
    ],
    &[4],
);

static TIMERFD_ENTRY: Msg = msg(
    "timerfd_entry",
    &[
        f(1, "id", Ty::Int),
        f(2, "flags", Ty::Hex),
        f(3, "fown", Ty::Msg(&FOWN_ENTRY)),
        f(4, "clockid", Ty::Int),
        f(5, "ticks", Ty::Int),
        f(6, "settime_flags", Ty::Hex),
        f(7, "vsec", Ty::Int),
        f(8, "vnsec", Ty::Int),
        f(9, "isec", Ty::Int),
        f(10, "insec", Ty::Int),
    ],
    &[4],
);

static SK_OPTS: Msg = msg(
    "sk_opts_entry",
    &[
        f(1, "so_sndbuf", Ty::Int),
        f(2, "so_rcvbuf", Ty::Int),
        f(3, "so_snd_tmo_sec", Ty::Int),
        f(4, "so_snd_tmo_usec", Ty::Int),
        f(5, "so_rcv_tmo_sec", Ty::Int),
        f(6, "so_rcv_tmo_usec", Ty::Int),
        f(7, "reuseaddr", Ty::Bool),
        f(8, "so_priority", Ty::Int),
        f(9, "so_rcvlowat", Ty::Int),
        f(10, "so_mark", Ty::Int),
        f(11, "so_passcred", Ty::Bool),
        f(12, "so_passsec", Ty::Bool),
        f(13, "so_dontroute", Ty::Bool),
        f(14, "so_no_check", Ty::Bool),
        f(15, "so_bound_dev", Ty::Str),
        f(17, "so_reuseport", Ty::Bool),
        f(18, "so_broadcast", Ty::Bool),
        f(19, "so_keepalive", Ty::Bool),
        f(20, "tcp_keepcnt", Ty::Int),
        f(21, "tcp_keepidle", Ty::Int),
        f(22, "tcp_keepintvl", Ty::Int),
        f(23, "so_oobinline", Ty::Int),
        f(24, "so_linger", Ty::Int),
        f(25, "so_buf_lock", Ty::Int),
    ],
    &[],
);

static FILE_PERMS: Msg = msg(
    "file_perms_entry",
    &[
        f(1, "mode", Ty::Hex),
        f(2, "uid", Ty::Int),
        f(3, "gid", Ty::Int),
    ],
    &[],
);

static UNIX_SK_ENTRY: Msg = msg(
    "unix_sk_entry",
    &[
        f(1, "id", Ty::Int),
        f(2, "ino", Ty::Int),
        f(3, "type", Ty::Enum(SK_TYPE)),
        f(4, "state", Ty::Int),
        f(5, "flags", Ty::Hex),
        f(6, "uflags", Ty::Hex),
        f(7, "backlog", Ty::Int),
        f(8, "peer", Ty::Int),
        f(9, "fown", Ty::Msg(&FOWN_ENTRY)),
        f(10, "opts", Ty::Msg(&SK_OPTS)),
        f(11, "name", Ty::Bytes),
        f(12, "shutdown", Ty::Int),
        f(13, "file_perms", Ty::Msg(&FILE_PERMS)),
        f(14, "name_dir", Ty::Str),
        f(15, "deleted", Ty::Bool),
        f(16, "ns_id", Ty::Int),
        f(17, "mnt_id", Ty::SInt),
    ],
    &[3, 2],
);

static INET_SK_ENTRY: Msg = msg(
    "inet_sk_entry",
    &[
        f(1, "id", Ty::Int),
        f(2, "ino", Ty::Int),
        f(3, "family", Ty::Enum(SK_FAMILY)),
        f(4, "type", Ty::Enum(SK_TYPE)),
        f(5, "proto", Ty::Int),
        f(6, "state", Ty::Int),
        f(7, "src_port", Ty::Int),
        f(8, "dst_port", Ty::Int),
        f(9, "flags", Ty::Hex),
        f(10, "backlog", Ty::Int),
        f(11, "src_addr", Ty::Hex),
        f(12, "dst_addr", Ty::Hex),
        f(13, "fown", Ty::Msg(&FOWN_ENTRY)),
        f(14, "opts", Ty::Msg(&SK_OPTS)),
        f(15, "v6only", Ty::Bool),
        f(16, "ip_opts", Ty::Msg(U)),
        f(17, "ifname", Ty::Str),
        f(18, "ns_id", Ty::Int),
        f(19, "shutdown", Ty::Int),
        f(20, "tcp_opts", Ty::Msg(U)),
    ],
    &[3, 4, 7, 8],
);

static TTY_FILE_ENTRY: Msg = msg(
    "tty_file_entry",
    &[
        f(1, "id", Ty::Int),
        f(2, "tty_info_id", Ty::Int),
        f(3, "flags", Ty::Flags(OPEN_FLAGS)),
        f(4, "fown", Ty::Msg(&FOWN_ENTRY)),
        f(6, "regf_id", Ty::Int),
    ],
    &[2],
);

static FILE_ENTRY: Msg = msg(
    "file_entry",
    &[
        f(1, "type", Ty::Enum(FD_TYPES)),
        f(2, "id", Ty::Int),
        f(3, "reg", Ty::Msg(&REG_FILE_ENTRY)),
        f(4, "isk", Ty::Msg(&INET_SK_ENTRY)),
        f(5, "nsf", Ty::Msg(&NS_FILE_ENTRY)),
        f(6, "psk", Ty::Msg(U)),
        f(7, "nlsk", Ty::Msg(U)),
        f(8, "efd", Ty::Msg(&EVENTFD_ENTRY)),
        f(9, "epfd", Ty::Msg(U)),
        f(10, "sgfd", Ty::Msg(&SIGNALFD_ENTRY)),
        f(11, "tunf", Ty::Msg(U)),
        f(12, "tfd", Ty::Msg(&TIMERFD_ENTRY)),
        f(13, "ify", Ty::Msg(U)),
        f(14, "ffy", Ty::Msg(U)),
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
        f(1, "cwd_id", Ty::Int),
        f(2, "root_id", Ty::Int),
        f(3, "umask", Ty::Int),
    ],
    &[1, 2],
);

static TIMEVAL: Msg = msg(
    "timeval",
    &[f(1, "tv_sec", Ty::Int), f(2, "tv_usec", Ty::Int)],
    &[],
);

static GHOST_FILE_ENTRY: Msg = msg(
    "ghost_file_entry",
    &[
        f(1, "uid", Ty::Int),
        f(2, "gid", Ty::Int),
        f(3, "mode", Ty::Hex),
        f(4, "dev", Ty::Hex),
        f(5, "ino", Ty::Int),
        f(6, "rdev", Ty::Hex),
        f(7, "atim", Ty::Msg(&TIMEVAL)),
        f(8, "mtim", Ty::Msg(&TIMEVAL)),
        f(9, "chunks", Ty::Bool),
        f(10, "size", Ty::Int),
        f(11, "symlnk_target", Ty::Str),
    ],
    &[10],
);

static GHOST_CHUNK_ENTRY: Msg = msg(
    "ghost_chunk_entry",
    &[f(1, "len", Ty::Int), f(2, "off", Ty::Int)],
    &[2, 1],
);

static MNT_ENTRY: Msg = msg(
    "mnt_entry",
    &[
        f(1, "fstype", Ty::Int),
        f(2, "mnt_id", Ty::Int),
        f(3, "root_dev", Ty::Hex),
        f(4, "parent_mnt_id", Ty::Int),
        f(5, "flags", Ty::Hex),
        f(6, "root", Ty::Str),
        f(7, "mountpoint", Ty::Str),
        f(8, "source", Ty::Str),
        f(9, "options", Ty::Str),
        f(10, "shared_id", Ty::Int),
        f(11, "master_id", Ty::Int),
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
    &[f(1, "tv_sec", Ty::Int), f(2, "tv_nsec", Ty::Int)],
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
        f(1, "first", Ty::Int),
        f(2, "lower_first", Ty::Int),
        f(3, "count", Ty::Int),
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
        f(2, "msg_ctlmax", Ty::Int),
        f(3, "msg_ctlmnb", Ty::Int),
        f(4, "msg_ctlmni", Ty::Int),
        f(5, "auto_msgmni", Ty::Int),
        f(6, "shm_ctlmax", Ty::Int),
        f(7, "shm_ctlall", Ty::Int),
        f(8, "shm_ctlmni", Ty::Int),
        f(9, "shm_rmid_forced", Ty::Int),
        f(10, "mq_queues_max", Ty::Int),
        f(11, "mq_msg_max", Ty::Int),
        f(12, "mq_msgsize_max", Ty::Int),
        f(13, "mq_msg_default", Ty::Int),
        f(14, "mq_msgsize_default", Ty::Int),
        f(15, "msg_next_id", Ty::Int),
        f(16, "sem_next_id", Ty::Int),
        f(17, "shm_next_id", Ty::Int),
    ],
    &[],
);

static IPC_DESC: Msg = msg(
    "ipc_desc_entry",
    &[
        f(1, "key", Ty::Hex),
        f(2, "uid", Ty::Int),
        f(3, "gid", Ty::Int),
        f(4, "cuid", Ty::Int),
        f(5, "cgid", Ty::Int),
        f(6, "mode", Ty::Hex),
        f(7, "id", Ty::Int),
    ],
    &[],
);

static IPC_SHM_ENTRY: Msg = msg(
    "ipc_shm_entry",
    &[
        f(1, "desc", Ty::Msg(&IPC_DESC)),
        f(2, "size", Ty::Int),
        f(3, "in_pagemaps", Ty::Bool),
        f(4, "hugetlb_flag", Ty::Hex),
    ],
    &[2],
);

static IPC_SEM_ENTRY: Msg = msg(
    "ipc_sem_entry",
    &[f(1, "desc", Ty::Msg(&IPC_DESC)), f(2, "nsems", Ty::Int)],
    &[2],
);

static IPC_MSG_ENTRY: Msg = msg(
    "ipc_msg_entry",
    &[
        f(1, "desc", Ty::Msg(&IPC_DESC)),
        f(2, "qbytes", Ty::Int),
        f(3, "qnum", Ty::Int),
    ],
    &[3],
);

static SCM_ENTRY: Msg = msg(
    "scm_entry",
    &[
        f(1, "type", Ty::Int),
        f(2, "rights", Ty::Packed(Elem::Varint)),
    ],
    &[],
);

static SK_PACKET_ENTRY: Msg = msg(
    "sk_packet_entry",
    &[
        f(1, "id_for", Ty::Int),
        f(2, "length", Ty::Int),
        f(4, "scm", Ty::Msg(&SCM_ENTRY)),
    ],
    &[1, 2],
);

static TCP_STREAM_ENTRY: Msg = msg(
    "tcp_stream_entry",
    &[
        f(1, "inq_len", Ty::Int),
        f(2, "inq_seq", Ty::Int),
        f(3, "outq_len", Ty::Int),
        f(4, "outq_seq", Ty::Int),
        f(5, "opt_mask", Ty::Hex),
        f(6, "snd_wscale", Ty::Int),
        f(7, "mss_clamp", Ty::Int),
        f(8, "rcv_wscale", Ty::Int),
        f(9, "timestamp", Ty::Int),
        f(10, "cork", Ty::Bool),
        f(11, "nodelay", Ty::Bool),
        f(12, "unsq_len", Ty::Int),
        f(13, "snd_wl1", Ty::Int),
        f(14, "snd_wnd", Ty::Int),
        f(15, "max_window", Ty::Int),
        f(16, "rcv_wnd", Ty::Int),
        f(17, "rcv_wup", Ty::Int),
    ],
    &[1, 3],
);

static BPFMAP_DATA_ENTRY: Msg = msg(
    "bpfmap_data_entry",
    &[
        f(1, "map_id", Ty::Int),
        f(2, "keys_bytes", Ty::Int),
        f(3, "values_bytes", Ty::Int),
        f(4, "count", Ty::Int),
    ],
    &[1, 4],
);

static CG_MEMBER: Msg = msg(
    "cg_member_entry",
    &[
        f(1, "name", Ty::Str),
        f(2, "path", Ty::Str),
        f(3, "cgns_prefix", Ty::Int),
    ],
    &[1, 2],
);

static CG_SET: Msg = msg(
    "cg_set_entry",
    &[f(1, "id", Ty::Int), f(2, "ctls", Ty::Msg(&CG_MEMBER))],
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
        f(2, "prev", Ty::Int),
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
        f(1, "freezing_time", Ty::Int),
        f(2, "frozen_time", Ty::Int),
        f(3, "memdump_time", Ty::Int),
        f(4, "memwrite_time", Ty::Int),
        f(5, "pages_scanned", Ty::Int),
        f(6, "pages_skipped_parent", Ty::Int),
        f(7, "pages_written", Ty::Int),
        f(8, "irmap_resolve", Ty::Int),
        f(9, "pages_lazy", Ty::Int),
        f(10, "page_pipes", Ty::Int),
        f(11, "page_pipe_bufs", Ty::Int),
        f(12, "shpages_scanned", Ty::Int),
        f(13, "shpages_skipped_parent", Ty::Int),
        f(14, "shpages_written", Ty::Int),
    ],
    &[],
);

static RESTORE_STATS: Msg = msg(
    "restore_stats_entry",
    &[
        f(1, "pages_compared", Ty::Int),
        f(2, "pages_skipped_cow", Ty::Int),
        f(3, "forking_time", Ty::Int),
        f(4, "restore_time", Ty::Int),
        f(5, "pages_restored", Ty::Int),
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
