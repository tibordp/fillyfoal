//! sysstat system activity files (`/var/log/sysstat/saDD`, `/var/log/sa/saDD`),
//! written by `sadc` and read by `sar` and `sadf`.
//!
//! The file starts with `struct file_magic`: the sysstat magic `0xd596`
//! (byte-swapped when written on a machine of the other byte order), the
//! format magic (`0x2175` since sysstat 11.7.1, earlier `0x2171` and
//! `0x2173`), the sysstat version, the size of the file header and the
//! composition of that header, then padding. Format `0x2175` follows with
//! `struct file_header` (creation time, HZ, CPU and activity counts, the
//! composition and size of the structures below, `uname` fields, time
//! zone), one `struct file_activity` per activity saved (ID, magic, item
//! counts, item size and composition: counts of `long long`, `long` and
//! `int` fields), optional chains of extra structures, then records: a
//! `struct record_header` (uptime, time, record type) followed, for a
//! statistics record, by each activity's items in the order of the activity
//! list (preceded by their count for activities whose count varies), for a
//! restart record by the CPU count, for a comment by the comment.
//!
//! Every structure is self-describing in size and composition, so every
//! item is shown even when its layout is unknown (as its `long long`,
//! `long` and `int` fields, then its remaining bytes). Field names come
//! from sysstat 12.7's `rd_stats.h` and `rd_sensors.h` (facts only) and are
//! used only when the file's item size and composition match that layout
//! exactly. Files of the older format magics are identified and their
//! header shown.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::binutil::get;
use crate::formats::util::fmt::plural;
use crate::formats::util::val::{int, text, uint};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

pub static FORMAT: Format = Format {
    name: "sysstat-sa",
    title: "sysstat system activity file",
    extensions: &["sa"],
    mime: "application/x-sysstat-sa",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

const SYSSTAT_MAGIC: u16 = 0xd596;
const FORMAT_CURRENT: u16 = 0x2175;
const FORMATS_KNOWN: [u16; 3] = [0x2171, 0x2173, 0x2175];
/// `sizeof(struct file_magic)` for format 0x2175.
const FILE_MAGIC_SIZE: u64 = 76;
const MAX_HEADER: u32 = 8192;
const MAX_ACT_SIZE: u32 = 1024;
const MAX_ITEM_SIZE: u32 = 1024;
const MAX_ACTIVITIES: u32 = 256;
const MAX_COMMENT_LEN: u64 = 64;
const UTSNAME_LEN: u64 = 65;

fn probe(h: &Head) -> bool {
    let endian = if h.starts_with(&SYSSTAT_MAGIC.to_le_bytes()) {
        Endian::Little
    } else if h.starts_with(&SYSSTAT_MAGIC.to_be_bytes()) {
        Endian::Big
    } else {
        return false;
    };
    let Some(format) = get::<u16>(h.data, 2, endian) else {
        return false;
    };
    if !FORMATS_KNOWN.contains(&format) {
        return false;
    }
    // A plausible version (sysstat 9 to 19).
    let version = h.data.get(4).copied().unwrap_or(0);
    if !(9..=19).contains(&version) {
        return false;
    }
    if format == FORMAT_CURRENT {
        let header = get::<u32>(h.data, 8, endian).unwrap_or(0);
        return header > 0 && header <= MAX_HEADER;
    }
    true
}

/// What the record walk and item nodes share.
#[derive(Clone)]
struct Sa {
    endian: Endian,
    long: u64,
    acts: Arc<Vec<Activity>>,
    rec_size: u64,
}

#[derive(Clone, Copy, Debug)]
struct Activity {
    id: u32,
    nr: i32,
    nr2: i32,
    has_nr: bool,
    size: u32,
    types: [u32; 3],
}

const ACTIVITIES: EnumTable = &[
    (1, "A_CPU"),
    (2, "A_PCSW"),
    (3, "A_IRQ"),
    (4, "A_SWAP"),
    (5, "A_PAGE"),
    (6, "A_IO"),
    (7, "A_MEMORY"),
    (8, "A_KTABLES"),
    (9, "A_QUEUE"),
    (10, "A_SERIAL"),
    (11, "A_DISK"),
    (12, "A_NET_DEV"),
    (13, "A_NET_EDEV"),
    (14, "A_NET_NFS"),
    (15, "A_NET_NFSD"),
    (16, "A_NET_SOCK"),
    (17, "A_NET_IP"),
    (18, "A_NET_EIP"),
    (19, "A_NET_ICMP"),
    (20, "A_NET_EICMP"),
    (21, "A_NET_TCP"),
    (22, "A_NET_ETCP"),
    (23, "A_NET_UDP"),
    (24, "A_NET_SOCK6"),
    (25, "A_NET_IP6"),
    (26, "A_NET_EIP6"),
    (27, "A_NET_ICMP6"),
    (28, "A_NET_EICMP6"),
    (29, "A_NET_UDP6"),
    (30, "A_PWR_CPU"),
    (31, "A_PWR_FAN"),
    (32, "A_PWR_TEMP"),
    (33, "A_PWR_IN"),
    (34, "A_HUGE"),
    (35, "A_PWR_FREQ"),
    (36, "A_PWR_USB"),
    (37, "A_FS"),
    (38, "A_NET_FC"),
    (39, "A_NET_SOFT"),
    (40, "A_PSI_CPU"),
    (41, "A_PSI_IO"),
    (42, "A_PSI_MEM"),
    (43, "A_PWR_BAT"),
];

const DESCRIPTIONS: EnumTable = &[
    (1, "CPU utilisation"),
    (2, "task creation and context switches"),
    (3, "interrupts"),
    (4, "swapping"),
    (5, "paging"),
    (6, "I/O and transfer rates"),
    (7, "memory"),
    (8, "inode, file and kernel tables"),
    (9, "run queue and load average"),
    (10, "serial lines"),
    (11, "block devices"),
    (12, "network interfaces"),
    (13, "network interface errors"),
    (14, "NFS client"),
    (15, "NFS server"),
    (16, "sockets"),
    (17, "IPv4"),
    (18, "IPv4 errors"),
    (19, "ICMPv4"),
    (20, "ICMPv4 errors"),
    (21, "TCPv4"),
    (22, "TCPv4 errors"),
    (23, "UDPv4"),
    (24, "IPv6 sockets"),
    (25, "IPv6"),
    (26, "IPv6 errors"),
    (27, "ICMPv6"),
    (28, "ICMPv6 errors"),
    (29, "UDPv6"),
    (30, "CPU frequency"),
    (31, "fans"),
    (32, "temperature sensors"),
    (33, "voltage inputs"),
    (34, "huge pages"),
    (35, "CPU frequency residency"),
    (36, "USB devices"),
    (37, "file systems"),
    (38, "Fibre Channel hosts"),
    (39, "software-based network processing"),
    (40, "CPU pressure"),
    (41, "I/O pressure"),
    (42, "memory pressure"),
    (43, "batteries"),
];

const RECORD_TYPES: EnumTable = &[
    (1, "R_STATS"),
    (2, "R_RESTART"),
    (3, "R_LAST_STATS"),
    (4, "R_COMMENT"),
];

/// A field kind of an item layout.
#[derive(Clone, Copy)]
enum K {
    /// `unsigned long long`.
    Q,
    /// `unsigned long`, aligned to 8.
    L,
    /// `unsigned int`.
    I,
    /// `unsigned int` aligned to 8.
    I8,
    /// `double`, aligned to 8.
    D,
    /// `char[n]`.
    S(u64),
    /// `char[n]` aligned to 8.
    S8(u64),
    /// `char`.
    C,
}

use K::*;

type Layout = &'static [(K, &'static str)];

const CPU: Layout = &[
    (Q, "cpu_user"),
    (Q, "cpu_nice"),
    (Q, "cpu_sys"),
    (Q, "cpu_idle"),
    (Q, "cpu_iowait"),
    (Q, "cpu_steal"),
    (Q, "cpu_hardirq"),
    (Q, "cpu_softirq"),
    (Q, "cpu_guest"),
    (Q, "cpu_guest_nice"),
];
const PCSW: Layout = &[(Q, "context_switch"), (L, "processes")];
const IRQ: Layout = &[(I, "irq_nr"), (S(8), "irq_name")];
const SWAP: Layout = &[(L, "pswpin"), (L, "pswpout")];
const PAGING: Layout = &[
    (L, "pgpgin"),
    (L, "pgpgout"),
    (L, "pgfault"),
    (L, "pgmajfault"),
    (L, "pgfree"),
    (L, "pgscan_kswapd"),
    (L, "pgscan_direct"),
    (L, "pgsteal"),
    (L, "pgpromote"),
    (L, "pgdemote"),
];
const IO: Layout = &[
    (Q, "dk_drive"),
    (Q, "dk_drive_rio"),
    (Q, "dk_drive_wio"),
    (Q, "dk_drive_rblk"),
    (Q, "dk_drive_wblk"),
    (Q, "dk_drive_dio"),
    (Q, "dk_drive_dblk"),
];
const MEMORY: Layout = &[
    (Q, "frmkb"),
    (Q, "bufkb"),
    (Q, "camkb"),
    (Q, "tlmkb"),
    (Q, "frskb"),
    (Q, "tlskb"),
    (Q, "caskb"),
    (Q, "comkb"),
    (Q, "activekb"),
    (Q, "inactkb"),
    (Q, "dirtykb"),
    (Q, "anonpgkb"),
    (Q, "slabkb"),
    (Q, "kstackkb"),
    (Q, "pgtblkb"),
    (Q, "vmusedkb"),
    (Q, "availablekb"),
];
const KTABLES: Layout = &[
    (Q, "file_used"),
    (Q, "inode_used"),
    (Q, "dentry_stat"),
    (Q, "pty_nr"),
];
const QUEUE: Layout = &[
    (Q, "nr_running"),
    (Q, "procs_blocked"),
    (Q, "nr_threads"),
    (I, "load_avg_1"),
    (I, "load_avg_5"),
    (I, "load_avg_15"),
];
const SERIAL: Layout = &[
    (I, "rx"),
    (I, "tx"),
    (I, "frame"),
    (I, "parity"),
    (I, "brk"),
    (I, "overrun"),
    (I, "line"),
];
const DISK: Layout = &[
    (Q, "nr_ios"),
    (Q, "wwn[0]"),
    (Q, "wwn[1]"),
    (L, "rd_sect"),
    (L, "wr_sect"),
    (L, "dc_sect"),
    (I8, "rd_ticks"),
    (I, "wr_ticks"),
    (I, "tot_ticks"),
    (I, "rq_ticks"),
    (I, "major"),
    (I, "minor"),
    (I, "dc_ticks"),
    (I, "part_nr"),
];
const NET_DEV: Layout = &[
    (Q, "rx_packets"),
    (Q, "tx_packets"),
    (Q, "rx_bytes"),
    (Q, "tx_bytes"),
    (Q, "rx_compressed"),
    (Q, "tx_compressed"),
    (Q, "multicast"),
    (I, "speed"),
    (S(16), "interface"),
    (C, "duplex"),
];
const NET_EDEV: Layout = &[
    (Q, "collisions"),
    (Q, "rx_errors"),
    (Q, "tx_errors"),
    (Q, "rx_dropped"),
    (Q, "tx_dropped"),
    (Q, "rx_fifo_errors"),
    (Q, "tx_fifo_errors"),
    (Q, "rx_frame_errors"),
    (Q, "tx_carrier_errors"),
    (S(16), "interface"),
];
const NET_NFS: Layout = &[
    (I, "nfs_rpccnt"),
    (I, "nfs_rpcretrans"),
    (I, "nfs_readcnt"),
    (I, "nfs_writecnt"),
    (I, "nfs_accesscnt"),
    (I, "nfs_getattcnt"),
];
const NET_NFSD: Layout = &[
    (I, "nfsd_rpccnt"),
    (I, "nfsd_rpcbad"),
    (I, "nfsd_netcnt"),
    (I, "nfsd_netudpcnt"),
    (I, "nfsd_nettcpcnt"),
    (I, "nfsd_rchits"),
    (I, "nfsd_rcmisses"),
    (I, "nfsd_readcnt"),
    (I, "nfsd_writecnt"),
    (I, "nfsd_accesscnt"),
    (I, "nfsd_getattcnt"),
];
const NET_SOCK: Layout = &[
    (I, "sock_inuse"),
    (I, "tcp_inuse"),
    (I, "tcp_tw"),
    (I, "udp_inuse"),
    (I, "raw_inuse"),
    (I, "frag_inuse"),
];
const NET_IP: Layout = &[
    (Q, "InReceives"),
    (Q, "ForwDatagrams"),
    (Q, "InDelivers"),
    (Q, "OutRequests"),
    (Q, "ReasmReqds"),
    (Q, "ReasmOKs"),
    (Q, "FragOKs"),
    (Q, "FragCreates"),
];
const NET_EIP: Layout = &[
    (Q, "InHdrErrors"),
    (Q, "InAddrErrors"),
    (Q, "InUnknownProtos"),
    (Q, "InDiscards"),
    (Q, "OutDiscards"),
    (Q, "OutNoRoutes"),
    (Q, "ReasmFails"),
    (Q, "FragFails"),
];
const NET_ICMP: Layout = &[
    (L, "InMsgs"),
    (L, "OutMsgs"),
    (L, "InEchos"),
    (L, "InEchoReps"),
    (L, "OutEchos"),
    (L, "OutEchoReps"),
    (L, "InTimestamps"),
    (L, "InTimestampReps"),
    (L, "OutTimestamps"),
    (L, "OutTimestampReps"),
    (L, "InAddrMasks"),
    (L, "InAddrMaskReps"),
    (L, "OutAddrMasks"),
    (L, "OutAddrMaskReps"),
];
const NET_EICMP: Layout = &[
    (L, "InErrors"),
    (L, "OutErrors"),
    (L, "InDestUnreachs"),
    (L, "OutDestUnreachs"),
    (L, "InTimeExcds"),
    (L, "OutTimeExcds"),
    (L, "InParmProbs"),
    (L, "OutParmProbs"),
    (L, "InSrcQuenchs"),
    (L, "OutSrcQuenchs"),
    (L, "InRedirects"),
    (L, "OutRedirects"),
];
const NET_TCP: Layout = &[
    (L, "ActiveOpens"),
    (L, "PassiveOpens"),
    (L, "InSegs"),
    (L, "OutSegs"),
];
const NET_ETCP: Layout = &[
    (L, "AttemptFails"),
    (L, "EstabResets"),
    (L, "RetransSegs"),
    (L, "InErrs"),
    (L, "OutRsts"),
];
const NET_UDP: Layout = &[
    (L, "InDatagrams"),
    (L, "OutDatagrams"),
    (L, "NoPorts"),
    (L, "InErrors"),
];
const NET_SOCK6: Layout = &[
    (I, "tcp6_inuse"),
    (I, "udp6_inuse"),
    (I, "raw6_inuse"),
    (I, "frag6_inuse"),
];
const NET_IP6: Layout = &[
    (Q, "InReceives6"),
    (Q, "OutForwDatagrams6"),
    (Q, "InDelivers6"),
    (Q, "OutRequests6"),
    (Q, "ReasmReqds6"),
    (Q, "ReasmOKs6"),
    (Q, "InMcastPkts6"),
    (Q, "OutMcastPkts6"),
    (Q, "FragOKs6"),
    (Q, "FragCreates6"),
];
const NET_EIP6: Layout = &[
    (Q, "InHdrErrors6"),
    (Q, "InAddrErrors6"),
    (Q, "InUnknownProtos6"),
    (Q, "InTooBigErrors6"),
    (Q, "InDiscards6"),
    (Q, "OutDiscards6"),
    (Q, "InNoRoutes6"),
    (Q, "OutNoRoutes6"),
    (Q, "ReasmFails6"),
    (Q, "FragFails6"),
    (Q, "InTruncatedPkts6"),
];
const NET_ICMP6: Layout = &[
    (L, "InMsgs6"),
    (L, "OutMsgs6"),
    (L, "InEchos6"),
    (L, "InEchoReplies6"),
    (L, "OutEchoReplies6"),
    (L, "InGroupMembQueries6"),
    (L, "InGroupMembResponses6"),
    (L, "OutGroupMembResponses6"),
    (L, "InGroupMembReductions6"),
    (L, "OutGroupMembReductions6"),
    (L, "InRouterSolicits6"),
    (L, "OutRouterSolicits6"),
    (L, "InRouterAdvertisements6"),
    (L, "InNeighborSolicits6"),
    (L, "OutNeighborSolicits6"),
    (L, "InNeighborAdvertisements6"),
    (L, "OutNeighborAdvertisements6"),
];
const NET_EICMP6: Layout = &[
    (L, "InErrors6"),
    (L, "InDestUnreachs6"),
    (L, "OutDestUnreachs6"),
    (L, "InTimeExcds6"),
    (L, "OutTimeExcds6"),
    (L, "InParmProblems6"),
    (L, "OutParmProblems6"),
    (L, "InRedirects6"),
    (L, "OutRedirects6"),
    (L, "InPktTooBigs6"),
    (L, "OutPktTooBigs6"),
];
const NET_UDP6: Layout = &[
    (L, "InDatagrams6"),
    (L, "OutDatagrams6"),
    (L, "NoPorts6"),
    (L, "InErrors6"),
];
const PWR_CPUFREQ: Layout = &[(L, "cpufreq")];
const PWR_FAN: Layout = &[(D, "rpm"), (D, "rpm_min"), (S8(20), "device")];
const PWR_TEMP: Layout = &[
    (D, "temp"),
    (D, "temp_min"),
    (D, "temp_max"),
    (S8(20), "device"),
];
const PWR_IN: Layout = &[(D, "in"), (D, "in_min"), (D, "in_max"), (S8(20), "device")];
const HUGE: Layout = &[(Q, "frhkb"), (Q, "tlhkb"), (Q, "rsvdhkb"), (Q, "surphkb")];
const PWR_WGHFREQ: Layout = &[(Q, "time_in_state"), (L, "freq")];
const PWR_USB: Layout = &[
    (I, "bus_nr"),
    (I, "vendor_id"),
    (I, "product_id"),
    (I, "bmaxpower"),
    (S(24), "manufacturer"),
    (S(48), "product"),
];
const FILESYSTEM: Layout = &[
    (Q, "f_blocks"),
    (Q, "f_bfree"),
    (Q, "f_bavail"),
    (Q, "f_files"),
    (Q, "f_ffree"),
    (S(128), "fs_name"),
    (S(128), "mountp"),
];
const FCHOST: Layout = &[
    (L, "f_rxframes"),
    (L, "f_txframes"),
    (L, "f_rxwords"),
    (L, "f_txwords"),
    (S8(16), "fchost_name"),
];
const SOFTNET: Layout = &[
    (I, "processed"),
    (I, "dropped"),
    (I, "time_squeeze"),
    (I, "received_rps"),
    (I, "flow_limit"),
    (I, "backlog_len"),
];
const PSI_CPU: Layout = &[
    (Q, "some_cpu_total"),
    (L, "some_acpu_10"),
    (L, "some_acpu_60"),
    (L, "some_acpu_300"),
];
const PSI_IO: Layout = &[
    (Q, "some_io_total"),
    (Q, "full_io_total"),
    (L, "some_aio_10"),
    (L, "some_aio_60"),
    (L, "some_aio_300"),
    (L, "full_aio_10"),
    (L, "full_aio_60"),
    (L, "full_aio_300"),
];
const PSI_MEM: Layout = &[
    (Q, "some_mem_total"),
    (Q, "full_mem_total"),
    (L, "some_amem_10"),
    (L, "some_amem_60"),
    (L, "some_amem_300"),
    (L, "full_amem_10"),
    (L, "full_amem_60"),
    (L, "full_amem_300"),
];
const PWR_BAT: Layout = &[(C, "bat_id"), (C, "capacity"), (C, "status")];

fn layout(id: u32) -> Option<Layout> {
    Some(match id {
        1 => CPU,
        2 => PCSW,
        3 => IRQ,
        4 => SWAP,
        5 => PAGING,
        6 => IO,
        7 => MEMORY,
        8 => KTABLES,
        9 => QUEUE,
        10 => SERIAL,
        11 => DISK,
        12 => NET_DEV,
        13 => NET_EDEV,
        14 => NET_NFS,
        15 => NET_NFSD,
        16 => NET_SOCK,
        17 => NET_IP,
        18 => NET_EIP,
        19 => NET_ICMP,
        20 => NET_EICMP,
        21 => NET_TCP,
        22 => NET_ETCP,
        23 => NET_UDP,
        24 => NET_SOCK6,
        25 => NET_IP6,
        26 => NET_EIP6,
        27 => NET_ICMP6,
        28 => NET_EICMP6,
        29 => NET_UDP6,
        30 => PWR_CPUFREQ,
        31 => PWR_FAN,
        32 => PWR_TEMP,
        33 => PWR_IN,
        34 => HUGE,
        35 => PWR_WGHFREQ,
        36 => PWR_USB,
        37 => FILESYSTEM,
        38 => FCHOST,
        39 => SOFTNET,
        40 => PSI_CPU,
        41 => PSI_IO,
        42 => PSI_MEM,
        43 => PWR_BAT,
        _ => return None,
    })
}

/// Size and alignment of a field kind on a 64-bit writer.
fn kind_size(k: K) -> (u64, u64) {
    match k {
        Q | L | D => (8, 8),
        I => (4, 4),
        I8 => (4, 8),
        S(n) => (n, 1),
        S8(n) => (n, 8),
        C => (1, 1),
    }
}

/// Offsets of a layout's fields and its size, laid out as a C compiler
/// does, and its composition (counts of `long long`, `long`, `int`).
fn place(l: Layout) -> (Vec<u64>, u64, [u32; 3]) {
    let mut offsets = Vec::with_capacity(l.len());
    let (mut off, mut max_align) = (0u64, 1u64);
    let mut types = [0u32; 3];
    for &(k, _) in l {
        let (size, align) = kind_size(k);
        off = off.next_multiple_of(align);
        offsets.push(off);
        off = off.saturating_add(size);
        max_align = max_align.max(align);
        let slot = match k {
            Q | D => Some(0),
            L => Some(1),
            I | I8 => Some(2),
            _ => None,
        };
        if let Some(t) = slot.and_then(|s: usize| types.get_mut(s)) {
            *t = t.saturating_add(1);
        }
    }
    (offsets, off.next_multiple_of(max_align), types)
}

/// The named layout of an activity, if the file's items have exactly its
/// size and composition (64-bit writers only).
fn named_layout(act: &Activity, long: u64) -> Option<(Layout, Vec<u64>)> {
    let l = layout(act.id)?;
    let (offsets, size, types) = place(l);
    (long == 8 && size == u64::from(act.size) && types == act.types).then_some((l, offsets))
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 4)).await?;
    let endian = if head.starts_with(&SYSSTAT_MAGIC.to_le_bytes()) {
        Endian::Little
    } else {
        Endian::Big
    };
    let format = get::<u16>(&head, 2, endian).unwrap_or(0);
    let mspan = file.sub(0, FILE_MAGIC_SIZE);
    cx.emit(
        Node::new("File Magic")
            .span(mspan)
            .lazy(file_magic, (mspan, endian, format)),
    );
    if format != FORMAT_CURRENT {
        cx.annotate(format!("sysstat activity file, old format {format:#x}"));
        cx.emit(
            Node::new("Data")
                .span(file.tail(8))
                .diag(Diagnostic::unsupported(format!(
                    "format {format:#x} (sysstat before 11.7.1)"
                ))),
        );
        return Ok(());
    }
    let m = cx.read(mspan).await?;
    let header_size = get::<u32>(&m, 8, endian).unwrap_or(0);
    if header_size == 0 || header_size > MAX_HEADER {
        return Err(Diagnostic::malformed(format!(
            "file header size {header_size} out of range"
        )));
    }
    let hspan = file.sub(FILE_MAGIC_SIZE, header_size.into());
    let h = cx.read(hspan).await?;
    let u32_at = |off: usize| get::<u32>(&h, off, endian).unwrap_or(0);
    let long = u64::from(h.get(66).copied().unwrap_or(8));
    let act_nr = u32_at(20);
    let act_size = u32_at(52);
    let rec_size = u32_at(56);
    let extra_next = u32_at(60);
    let utsname = |i: u64| {
        let start = to_usize(67u64.saturating_add(i.saturating_mul(UTSNAME_LEN)));
        let b = h
            .get(start..start.saturating_add(to_usize(UTSNAME_LEN)))
            .unwrap_or_default();
        crate::text::until_nul(b)
    };
    let (sysname, nodename, release, machine) = (utsname(0), utsname(1), utsname(2), utsname(3));
    let cpus = u32_at(16).saturating_sub(1);
    let year = 1900i64.saturating_add(i64::from(u32_at(24) as i32));
    let (day, month) = (
        h.get(64).copied().unwrap_or(0),
        h.get(65).copied().unwrap_or(0),
    );
    let date = format!("{year:04}-{:02}-{day:02}", month.saturating_add(1));
    cx.emit(
        Node::new("File Header")
            .span(hspan)
            .summary(format!(
                "{sysname} {release} ({nodename}), {machine}, {date}"
            ))
            .lazy(file_header, (hspan, endian)),
    );
    if act_nr > MAX_ACTIVITIES || !(36..=MAX_ACT_SIZE).contains(&act_size) {
        return Err(Diagnostic::malformed("implausible activity list"));
    }
    if !(24..=512).contains(&rec_size) {
        return Err(Diagnostic::malformed("implausible record header size"));
    }
    let list = file.sub(
        FILE_MAGIC_SIZE.saturating_add(header_size.into()),
        u64::from(act_nr).saturating_mul(act_size.into()),
    );
    let lb = cx.read(list).await?;
    let mut acts = Vec::new();
    for i in 0..act_nr {
        let base = to_usize(u64::from(i).saturating_mul(act_size.into()));
        let w = |k: usize| get::<u32>(&lb, base.saturating_add(k.saturating_mul(4)), endian);
        let (Some(id), Some(nr), Some(nr2), Some(has_nr), Some(size)) =
            (w(0), w(2), w(3), w(4), w(5))
        else {
            break;
        };
        acts.push(Activity {
            id,
            nr: nr as i32,
            nr2: nr2 as i32,
            has_nr: has_nr != 0,
            size,
            types: [w(6).unwrap_or(0), w(7).unwrap_or(0), w(8).unwrap_or(0)],
        });
    }
    cx.emit(
        Node::new("Activities")
            .span(list)
            .summary(plural(act_nr, "activity"))
            .lazy(activity_list, (list, endian, act_size, long)),
    );
    let mut pos = list.end().saturating_sub(file.offset);
    if extra_next != 0 {
        let start = pos;
        pos = skip_extras(&cx, file, pos, endian).await?;
        let span = file.sub(start, pos.saturating_sub(start));
        cx.emit(
            Node::new("Extra Structures")
                .span(span)
                .lazy(extras, (span, endian)),
        );
    }
    // Records cannot be walked past an activity whose items have no size
    // (and a count of empty items would be unbounded).
    if acts.iter().any(|a| a.size == 0 || a.size > MAX_ITEM_SIZE) {
        return Err(Diagnostic::malformed(
            "an activity's item size is out of range",
        ));
    }
    let sa = Sa {
        endian,
        long,
        acts: Arc::new(acts),
        rec_size: rec_size.into(),
    };
    let records = file.tail(pos);
    cx.emit(
        Node::new("Records")
            .span(records)
            .lazy(record_list, (sa, records)),
    );
    cx.annotate(format!(
        "sysstat {}.{}.{} activity file, {nodename}, {date}, {}, {}",
        m.get(4).copied().unwrap_or(0),
        m.get(5).copied().unwrap_or(0),
        m.get(6).copied().unwrap_or(0),
        plural(cpus, "CPU"),
        plural(act_nr, "activity")
    ));
    Ok(())
}

async fn file_magic(cx: Cx, (span, endian, format): (Span, Endian, u16)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, endian);
    f.u16("sysstat_magic").hex().emit()?;
    f.u16("format_magic")
        .hex()
        .enumeration(&[
            (0x2171, "sysstat 9.1.6 to 10.x"),
            (0x2173, "sysstat 11.0 to 11.7.0"),
            (0x2175, "sysstat 11.7.1 and later"),
        ])
        .emit()?;
    f.u8("sysstat_version").emit()?;
    f.u8("sysstat_patchlevel").emit()?;
    f.u8("sysstat_sublevel").emit()?;
    f.u8("sysstat_extraversion").emit()?;
    if format != FORMAT_CURRENT {
        return Ok(());
    }
    f.u32("header_size").emit()?;
    f.u32("upgraded")
        .desc("Non-zero if converted by sadf -c from an older format")
        .emit()?;
    f.u32("hdr_types_nr[0]")
        .desc("long long fields in the file header")
        .emit()?;
    f.u32("hdr_types_nr[1]").desc("long fields").emit()?;
    f.u32("hdr_types_nr[2]").desc("int fields").emit()?;
    f.bytes("pad", 48).emit()?;
    Ok(())
}

async fn file_header(cx: Cx, (span, endian): (Span, Endian)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, endian);
    f.u64("sa_ust_time").timestamp().emit()?;
    f.u64("sa_hz").desc("Clock ticks per second").emit()?;
    f.u32("sa_cpu_nr")
        .desc("CPUs plus one (the \"all\" CPU)")
        .emit()?;
    f.u32("sa_act_nr").emit()?;
    f.int::<i32>("sa_year").desc("Years since 1900").emit()?;
    for name in ["act_types_nr[0]", "act_types_nr[1]", "act_types_nr[2]"] {
        f.u32(name).emit()?;
    }
    for name in ["rec_types_nr[0]", "rec_types_nr[1]", "rec_types_nr[2]"] {
        f.u32(name).emit()?;
    }
    f.u32("act_size").emit()?;
    f.u32("rec_size").emit()?;
    f.u32("extra_next").emit()?;
    f.u8("sa_day").emit()?;
    f.u8("sa_month").desc("0 for January").emit()?;
    f.u8("sa_sizeof_long").emit()?;
    for name in ["sa_sysname", "sa_nodename", "sa_release", "sa_machine"] {
        let b = f.bytes(name, UTSNAME_LEN);
        let span = b.span();
        let v = b.get()?;
        cx.emit(
            Node::new(name)
                .span(span)
                .value(text(crate::text::until_nul(&v))),
        );
    }
    let b = f.bytes("sa_tzname", 8);
    let span = b.span();
    let v = b.get()?;
    cx.emit(
        Node::new("sa_tzname")
            .span(span)
            .value(text(crate::text::until_nul(&v))),
    );
    Ok(())
}

async fn activity_list(cx: Cx, (list, endian, size, long): (Span, Endian, u32, u64)) -> Result<()> {
    let n = list.len.checked_div(size.into()).unwrap_or(0);
    for i in 0..n {
        let span = list.sub(i.saturating_mul(size.into()), size.into());
        let b = cx.read(span).await?;
        let w = |k: usize| get::<u32>(&b, k.saturating_mul(4), endian).unwrap_or(0);
        let id = w(0);
        let name =
            lookup(ACTIVITIES, id.into()).map_or_else(|| format!("activity {id}"), str::to_string);
        let nr = w(2) as i32;
        let nr2 = w(3) as i32;
        let mut summary = format!(
            "{}{}, {} bytes each{}",
            lookup(DESCRIPTIONS, id.into()).map_or(String::new(), |d| format!("{d}, ")),
            if nr2 > 1 {
                format!("{nr}×{nr2} items")
            } else {
                plural(nr, "item")
            },
            w(5),
            if w(4) != 0 { ", count per record" } else { "" }
        );
        let act = Activity {
            id,
            nr,
            nr2,
            has_nr: w(4) != 0,
            size: w(5),
            types: [w(6), w(7), w(8)],
        };
        if named_layout(&act, long).is_none() {
            summary.push_str(", layout unknown: fields unnamed");
        }
        cx.push(
            Node::new(name)
                .span(span)
                .summary(summary)
                .lazy(activity_fields, (span, endian)),
        )
        .await;
    }
    Ok(())
}

async fn activity_fields(cx: Cx, (span, endian): (Span, Endian)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, endian);
    f.u32("id").enumeration(ACTIVITIES).emit()?;
    f.u32("magic").hex().emit()?;
    f.int::<i32>("nr")
        .desc("Items when the file was created")
        .emit()?;
    f.int::<i32>("nr2").desc("Sub-items per item").emit()?;
    f.u32("has_nr")
        .desc("Non-zero if each record gives the item count first")
        .emit()?;
    f.u32("size").desc("Size of an item").emit()?;
    f.u32("types_nr[0]").desc("long long fields").emit()?;
    f.u32("types_nr[1]").desc("long fields").emit()?;
    f.u32("types_nr[2]").desc("int fields").emit()?;
    Ok(())
}

/// Skips a chain of extra structures starting with an `extra_desc` at
/// `pos`; returns the position after it.
async fn skip_extras(cx: &Cx, file: Span, mut pos: u64, endian: Endian) -> Result<u64> {
    for _ in 0..64 {
        let d = cx.read(file.sub_exact(pos, 24)?).await?;
        let nr = get::<u32>(&d, 0, endian).unwrap_or(0);
        let size = get::<u32>(&d, 4, endian).unwrap_or(0);
        let next = get::<u32>(&d, 8, endian).unwrap_or(0);
        if nr > 8192 || size > 1024 {
            return Err(Diagnostic::malformed("implausible extra structures").at(file.sub(pos, 24)));
        }
        pos = pos
            .saturating_add(24)
            .saturating_add(u64::from(nr).saturating_mul(size.into()));
        if pos > file.len {
            return Err(Diagnostic::truncated(file.sub(pos, 0), file.len));
        }
        if next == 0 {
            return Ok(pos);
        }
    }
    Err(Diagnostic::limit("too many chained extra structures"))
}

async fn extras(cx: Cx, (span, endian): (Span, Endian)) -> Result<()> {
    let mut pos = 0u64;
    while pos < span.len {
        let dspan = span.sub(pos, 24);
        let d = cx.read(dspan).await?;
        let nr = get::<u32>(&d, 0, endian).unwrap_or(0);
        let size = get::<u32>(&d, 4, endian).unwrap_or(0);
        let next = get::<u32>(&d, 8, endian).unwrap_or(0);
        cx.push(
            Node::new("extra_desc")
                .span(dspan)
                .summary(format!("{}, {} bytes each", plural(nr, "structure"), size))
                .lazy(extra_desc, (dspan, endian)),
        )
        .await;
        let len = u64::from(nr).saturating_mul(size.into());
        cx.push(Node::new("Extra data").span(span.sub(pos.saturating_add(24), len)))
            .await;
        pos = pos.saturating_add(24).saturating_add(len);
        if next == 0 {
            break;
        }
    }
    Ok(())
}

async fn extra_desc(cx: Cx, (span, endian): (Span, Endian)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, endian);
    f.u32("extra_nr").emit()?;
    f.u32("extra_size").emit()?;
    f.u32("extra_next").emit()?;
    f.u32("extra_types_nr[0]").emit()?;
    f.u32("extra_types_nr[1]").emit()?;
    f.u32("extra_types_nr[2]").emit()?;
    Ok(())
}

/// One activity's items within a statistics record.
#[derive(Clone, Copy, Debug)]
struct Block {
    act: usize,
    /// Offset of the count (if any) or the items, within the records.
    start: u64,
    /// Offset of the first item.
    items: u64,
    count: u64,
}

async fn record_list(cx: Cx, (sa, records): (Sa, Span)) -> Result<()> {
    let e = sa.endian;
    let (mut pos, mut index) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    while pos < records.len {
        let at = (pos, index);
        cx.mark(move || at);
        let hspan = records.sub(pos, sa.rec_size);
        let h = cx.read(hspan).await?;
        if to_u64(h.len()) < sa.rec_size {
            cx.push(
                Node::new("Truncated record")
                    .span(hspan)
                    .diag(Diagnostic::truncated(hspan, to_u64(h.len()))),
            )
            .await;
            break;
        }
        let time = get::<u64>(&h, 8, e).unwrap_or(0);
        let extra_next = get::<u32>(&h, 16, e).unwrap_or(0);
        let rtype = h.get(20).copied().unwrap_or(0);
        let (hh, mm, ss) = (
            h.get(21).copied().unwrap_or(0),
            h.get(22).copied().unwrap_or(0),
            h.get(23).copied().unwrap_or(0),
        );
        let mut p = pos.saturating_add(sa.rec_size);
        let mut blocks = Vec::new();
        let mut detail = String::new();
        let file = records;
        let result: Result<()> = async {
            match rtype {
                1 | 3 => {
                    if extra_next != 0 {
                        p = skip_extras(&cx, file, p, e).await?;
                    }
                    for (i, a) in sa.acts.iter().enumerate() {
                        let start = p;
                        let count = if a.has_nr {
                            let b = cx.read(file.sub_exact(p, 4)?).await?;
                            p = p.saturating_add(4);
                            u64::from(get::<u32>(&b, 0, e).unwrap_or(0))
                        } else {
                            u64::try_from(a.nr.max(0)).unwrap_or(0)
                        };
                        let per = u64::try_from(a.nr2.max(1)).unwrap_or(1);
                        let len = count.saturating_mul(per).saturating_mul(a.size.into());
                        if p.saturating_add(len) > file.len {
                            return Err(Diagnostic::truncated(
                                file.sub(p, len),
                                file.len.saturating_sub(p),
                            ));
                        }
                        blocks.push(Block {
                            act: i,
                            start,
                            items: p,
                            count: count.saturating_mul(per),
                        });
                        p = p.saturating_add(len);
                    }
                }
                2 => {
                    let b = cx.read(file.sub_exact(p, 4)?).await?;
                    let n = get::<u32>(&b, 0, e).unwrap_or(0);
                    detail = plural(n.saturating_sub(1), "CPU");
                    p = p.saturating_add(4);
                    if extra_next != 0 {
                        p = skip_extras(&cx, file, p, e).await?;
                    }
                }
                4 => {
                    let b = cx.read(file.sub_exact(p, MAX_COMMENT_LEN)?).await?;
                    detail = crate::text::until_nul(&b);
                    p = p.saturating_add(MAX_COMMENT_LEN);
                    if extra_next != 0 {
                        p = skip_extras(&cx, file, p, e).await?;
                    }
                }
                5..=15 => {
                    if extra_next != 0 {
                        p = skip_extras(&cx, file, p, e).await?;
                    }
                }
                _ => {
                    return Err(Diagnostic::malformed(format!(
                        "unknown record type {rtype}"
                    )));
                }
            }
            Ok(())
        }
        .await;
        let span = records.sub(pos, p.saturating_sub(pos));
        let kind = lookup(RECORD_TYPES, rtype.into()).unwrap_or("R_EXTRA");
        let mut node = Node::new(format!("[{index}] {hh:02}:{mm:02}:{ss:02} {kind}"))
            .span(span)
            .value(Value::Timestamp {
                unix_seconds: i64::try_from(time).unwrap_or(0),
            })
            .summary(if blocks.is_empty() {
                detail
            } else {
                plural(blocks.len(), "activity")
            })
            .lazy(record_node, (sa.clone(), records, pos, Arc::new(blocks)));
        let failed = result.is_err();
        if let Err(err) = result {
            node = node.diag(err);
        }
        cx.push(node).await;
        cx.progress_in(records, records.offset.saturating_add(p));
        if failed || p <= pos {
            break;
        }
        pos = p;
        index = index.saturating_add(1);
    }
    Ok(())
}

async fn record_node(
    cx: Cx,
    (sa, records, pos, blocks): (Sa, Span, u64, Arc<Vec<Block>>),
) -> Result<()> {
    let hspan = records.sub(pos, sa.rec_size);
    let block = cx.block(hspan).await?;
    let mut f = Fields::emitting(&cx, &block, sa.endian);
    f.u64("uptime_cs")
        .with(|&v, n| n.summary(format!("{}.{:02} s", v / 100, v % 100)))
        .emit()?;
    f.u64("ust_time").timestamp().emit()?;
    f.u32("extra_next").emit()?;
    let rtype = f.u8("record_type").enumeration(RECORD_TYPES).emit()?;
    f.u8("hour").emit()?;
    f.u8("minute").emit()?;
    f.u8("second").emit()?;
    let body = pos.saturating_add(sa.rec_size);
    match rtype {
        2 => {
            let b = cx.block(records.sub(body, 4)).await?;
            Fields::emitting(&cx, &b, sa.endian)
                .u32("cpu_nr")
                .desc("CPUs plus one (the \"all\" CPU)")
                .emit()?;
        }
        4 => {
            let span = records.sub(body, MAX_COMMENT_LEN);
            let b = cx.read(span).await?;
            cx.emit(
                Node::new("comment")
                    .span(span)
                    .value(text(crate::text::until_nul(&b))),
            );
        }
        _ => {}
    }
    for b in blocks.iter() {
        let Some(act) = sa.acts.get(b.act) else {
            continue;
        };
        let name = lookup(ACTIVITIES, act.id.into())
            .map_or_else(|| format!("activity {}", act.id), str::to_string);
        let len = b.count.saturating_mul(act.size.into());
        let span = records.sub(b.start, b.items.saturating_sub(b.start).saturating_add(len));
        let mut node = Node::new(name)
            .span(span)
            .summary(plural(b.count, "item"))
            .lazy(items, (sa.clone(), records, *b));
        if let Some(d) = lookup(DESCRIPTIONS, act.id.into()) {
            node = node.desc(d);
        }
        cx.emit(node);
    }
    Ok(())
}

async fn items(cx: Cx, (sa, records, b): (Sa, Span, Block)) -> Result<()> {
    let Some(act) = sa.acts.get(b.act).copied() else {
        return Ok(());
    };
    if b.items > b.start {
        cx.emit(
            Node::new("count")
                .span(records.sub(b.start, 4))
                .value(uint(b.count, 32)),
        );
    }
    let named = named_layout(&act, sa.long);
    let size = u64::from(act.size);
    let per = u64::try_from(act.nr2.max(1)).unwrap_or(1);
    let i0 = cx.resume::<u64>().unwrap_or(0);
    for i in i0..b.count {
        cx.mark(move || i);
        let span = records.sub(b.items.saturating_add(i.saturating_mul(size)), size);
        let data = cx.read(span).await?;
        let label = item_label(&act, i, per, named.as_ref(), &data);
        cx.push(
            Node::new(label)
                .span(span)
                .lazy(item_fields, (sa.clone(), act, span)),
        )
        .await;
    }
    Ok(())
}

/// What an item is called: its CPU, interface, device or mount point.
fn item_label(
    act: &Activity,
    i: u64,
    per: u64,
    named: Option<&(Layout, Vec<u64>)>,
    data: &[u8],
) -> String {
    let (major, minor) = (
        i.checked_div(per).unwrap_or(0),
        i.checked_rem(per).unwrap_or(0),
    );
    let string_field = |field: &str| {
        let (l, offs) = named?;
        let (idx, &(k, _)) = l.iter().enumerate().find(|(_, (_, n))| *n == field)?;
        let off = to_usize(*offs.get(idx)?);
        let len = match k {
            S(n) | S8(n) => to_usize(n),
            _ => return None,
        };
        let s = crate::text::until_nul(data.get(off..off.saturating_add(len))?);
        (!s.is_empty()).then_some(s)
    };
    match act.id {
        1 | 30 | 35 | 39 if per == 1 => {
            if i == 0 {
                "all".to_string()
            } else {
                format!("cpu{}", i.saturating_sub(1))
            }
        }
        // One row per CPU, "all" first, of one item per interrupt.
        3 => {
            let cpu = if major == 0 {
                "all".to_string()
            } else {
                format!("cpu{}", major.saturating_sub(1))
            };
            match string_field("irq_name") {
                Some(n) => format!("[{cpu}] {n}"),
                None => format!("[{cpu}] #{minor}"),
            }
        }
        12 | 13 => string_field("interface").unwrap_or_else(|| format!("[{i}]")),
        37 => string_field("mountp").unwrap_or_else(|| format!("[{i}]")),
        31..=33 => string_field("device").unwrap_or_else(|| format!("[{i}]")),
        36 => string_field("product").unwrap_or_else(|| format!("[{i}]")),
        38 => string_field("fchost_name").unwrap_or_else(|| format!("[{i}]")),
        11 => match named {
            Some((l, offs)) => {
                let at = |name: &str| {
                    l.iter()
                        .position(|(_, n)| *n == name)
                        .and_then(|p| offs.get(p))
                        .and_then(|&o| get::<u32>(data, to_usize(o), Endian::Little))
                };
                match (at("major"), at("minor")) {
                    (Some(a), Some(b)) => format!("dev{a}-{b}"),
                    _ => format!("[{i}]"),
                }
            }
            None => format!("[{i}]"),
        },
        _ if per > 1 => format!("[{major}.{minor}]"),
        _ => format!("[{i}]"),
    }
}

/// Fields sysstat keeps multiplied by 100: the load averages (`sar -q`
/// prints `ldavg-1` as `load_avg_1 / 100`) and the CPU clock (`cpufreq`,
/// MHz × 100), shown as the value they stand for.
fn hundredths(name: &str, data: &[u8], o: usize, e: Endian) -> Option<String> {
    let v = match name {
        "load_avg_1" | "load_avg_5" | "load_avg_15" => u64::from(get::<u32>(data, o, e)?),
        "cpufreq" => get::<u64>(data, o, e)?,
        _ => return None,
    };
    let s = format!("{}.{:02}", v / 100, v % 100);
    Some(if name == "cpufreq" {
        format!("{s} MHz")
    } else {
        s
    })
}

async fn item_fields(cx: Cx, (sa, act, span): (Sa, Activity, Span)) -> Result<()> {
    let data = cx.read(span).await?;
    let e = sa.endian;
    if let Some((l, offs)) = named_layout(&act, sa.long) {
        for (&(k, name), &off) in l.iter().zip(offs.iter()) {
            let (size, _) = kind_size(k);
            let o = to_usize(off);
            let value = match k {
                Q | L => get::<u64>(&data, o, e).map(|v| uint(v, 64)),
                I | I8 => get::<u32>(&data, o, e).map(|v| uint(v, 32)),
                D => get::<f64>(&data, o, e).map(Value::Float),
                S(n) | S8(n) => data
                    .get(o..o.saturating_add(to_usize(n)))
                    .map(|b| text(crate::text::until_nul(b))),
                C => data.get(o).map(|&b| int(i64::from(b as i8), 8)),
            };
            if let Some(v) = value {
                let mut node = Node::new(name).span(span.sub(off, size)).value(v);
                if let Some(s) = hundredths(name, &data, o, e) {
                    node = node.summary(s);
                }
                cx.emit(node);
            }
        }
        return Ok(());
    }
    // Unknown layout: the fields by composition, then the rest.
    let [q, l, n] = act.types;
    let long = if sa.long == 4 { 4u64 } else { 8 };
    let mut off = 0u64;
    for (count, width, label) in [(q, 8u64, "long long"), (l, long, "long"), (n, 4, "int")] {
        for j in 0..count.min(256) {
            let o = to_usize(off);
            let v = match width {
                8 => get::<u64>(&data, o, e).map(|v| uint(v, 64)),
                _ => get::<u32>(&data, o, e).map(|v| uint(v, 32)),
            };
            let Some(v) = v else {
                break;
            };
            cx.emit(
                Node::new(format!("{label} [{j}]"))
                    .span(span.sub(off, width))
                    .value(v),
            );
            off = off.saturating_add(width);
        }
    }
    if off < span.len {
        cx.emit(Node::new("Other bytes").span(span.tail(off)));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    /// A_IRQ rows are CPUs, "all" first; only that row names interrupts.
    #[test]
    fn irq_items_name_their_cpu() {
        let act = Activity {
            id: 3,
            nr: 19,
            nr2: 28,
            has_nr: true,
            size: 12,
            types: [0, 0, 1],
        };
        let named = named_layout(&act, 8);
        assert!(named.is_some());
        let mut sum = vec![0u8; 12];
        sum[4..7].copy_from_slice(b"sum");
        let label = |i: u64, data: &[u8]| item_label(&act, i, 28, named.as_ref(), data);
        assert_eq!(label(0, &sum), "[all] sum");
        assert_eq!(label(29, &[0u8; 12]), "[cpu0] #1");
        assert_eq!(label(28 * 18 + 3, &sum), "[cpu17] sum");
    }

    /// sysstat keeps load averages and the CPU clock multiplied by 100.
    #[test]
    fn hundredths_read_as_sar_prints_them() {
        let load = 20u32.to_le_bytes();
        assert_eq!(
            hundredths("load_avg_1", &load, 0, Endian::Little).as_deref(),
            Some("0.20")
        );
        let freq = 240_050u64.to_le_bytes();
        assert_eq!(
            hundredths("cpufreq", &freq, 0, Endian::Little).as_deref(),
            Some("2400.50 MHz")
        );
        assert_eq!(hundredths("nr_running", &freq, 0, Endian::Little), None);
    }

    /// The layouts agree with sysstat's own composition constants.
    #[test]
    fn layouts_match_sysstat_counts() {
        let expect: &[(u32, [u32; 3], u64)] = &[
            (1, [10, 0, 0], 80),
            (2, [1, 1, 0], 16),
            (3, [0, 0, 1], 12),
            (11, [3, 3, 8], 80),
            (12, [7, 0, 1], 80),
            (13, [9, 0, 0], 88),
            (9, [3, 0, 3], 40),
            (31, [2, 0, 0], 40),
        ];
        for &(id, types, size) in expect {
            let (_, s, t) = place(layout(id).unwrap());
            assert_eq!((t, s), (types, size), "activity {id}");
        }
    }
}
