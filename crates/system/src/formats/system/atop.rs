//! atop raw logs (`atop -w`, `/var/log/atop/atop_YYYYMMDD`).
//!
//! A raw log is a `struct rawheader` (magic `0xfeedbeef` in the writer's
//! byte order, the creating atop version with its top bit set, the sizes of
//! the header, record and statistics structures, clock ticks per second,
//! `uname` fields, page size, the features in use and the kernel release
//! numbers) followed by one sample after another: a `struct rawrecord`
//! (time, flags, interval, task counts and the lengths of what follows),
//! the system-level statistics (`struct sstat`) compressed with zlib, the
//! process-level statistics (one `struct tstat` per task) compressed with
//! zlib, and, when cgroup v2 statistics were gathered, the cgroup
//! statistics and the cgroup PID list, each compressed with zlib.
//!
//! The header and record layouts are those of atop 2.11's `rawlog.h`
//! (facts only); their sizes are recorded in the header, which is checked.
//! The decompressed structures change with every atop version (atop keeps
//! the old layouts in `prev/` to convert files), so only the parts that
//! have kept their place in atop 2.0 to 2.11 are decoded: the start of
//! `struct cpustat` (CPU count, interrupts, context switches, load averages,
//! the all-CPU times) and the start of each task's `struct gen` (IDs, name,
//! state, start time, command line, thread counts); the rest is shown as
//! data. Only 64-bit writers' layouts are decoded. Counters are what atop
//! stores: the change since the previous sample (since boot in the first
//! sample of a log, flagged `RRBOOT`).

use crate::bytes::{to_u64, to_usize};
use crate::codec::Codec;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::binutil::get;
use crate::formats::util::fmt::{plural, size};
use crate::formats::util::val::{int, text};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{FlagTable, Value, flag};

pub static FORMAT: Format = Format {
    name: "atop-raw",
    title: "atop raw log",
    extensions: &[],
    mime: "application/x-atop-raw",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

const MAGIC: u32 = 0xfeed_beef;
/// `sizeof(struct rawheader)` and `sizeof(struct rawrecord)` on 64-bit
/// writers of atop 2.x.
const RAWHEADLEN: u64 = 480;
const RAWRECLEN: u64 = 96;
/// Longest structure accepted from the header.
const MAX_STRUCT: u32 = 64 << 20;

fn probe(h: &Head) -> bool {
    let endian = if h.starts_with(&MAGIC.to_le_bytes()) {
        Endian::Little
    } else if h.starts_with(&MAGIC.to_be_bytes()) {
        Endian::Big
    } else {
        return false;
    };
    let w = |off: usize| get::<u16>(h.data, off, endian).unwrap_or(0);
    let (aversion, headlen, reclen) = (w(4), w(10), w(12));
    aversion & 0x8000 != 0
        && (aversion >> 8) & 0x7f >= 1
        && (64..=4096).contains(&headlen)
        && (32..=1024).contains(&reclen)
}

const RECORD_FLAGS: FlagTable = &[
    flag(0x0001, "RRBOOT"),
    flag(0x0002, "RRLAST"),
    flag(0x0004, "RRNETATOP"),
    flag(0x0008, "RRNETATOPD"),
    flag(0x0010, "RRACCTACTIVE"),
    flag(0x0020, "RRIOSTAT"),
    flag(0x0040, "RRCONTAINERSTAT"),
    flag(0x0080, "RRGPUSTAT"),
    flag(0x0100, "RRCGRSTAT"),
];

const SUPPORT_FLAGS: FlagTable = &[
    flag(0x0001, "ACCTACTIVE"),
    flag(0x0004, "IOSTAT"),
    flag(0x0010, "NETATOP"),
    flag(0x0020, "NETATOPD"),
    flag(0x0040, "CONTAINERSTAT"),
    flag(0x0080, "GPUSTAT"),
    flag(0x0100, "CGROUPV2"),
    flag(0x1000, "NETATOPBPF"),
];

/// What the record walk and its nodes share.
#[derive(Clone, Copy)]
struct Log {
    endian: Endian,
    reclen: u64,
    sstatlen: u64,
    tstatlen: u64,
    /// The layouts decoded here are those of a 64-bit writer.
    wide: bool,
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let m = cx.read(file.sub(0, 4)).await?;
    let endian = if m == MAGIC.to_le_bytes() {
        Endian::Little
    } else {
        Endian::Big
    };
    let h = cx.read(file.sub(0, RAWHEADLEN)).await?;
    let w16 = |off: usize| u64::from(get::<u16>(&h, off, endian).unwrap_or(0));
    let w32 = |off: usize| get::<u32>(&h, off, endian).unwrap_or(0);
    let aversion = w16(4);
    let headlen = w16(10);
    let reclen = w16(12);
    let sstatlen = w32(28);
    let tstatlen = w32(32);
    let hspan = file.sub(0, headlen);
    let wide = headlen == RAWHEADLEN && reclen == RAWRECLEN;
    cx.emit(
        Node::new("Raw Header")
            .span(hspan)
            .summary(format!(
                "atop {}.{}",
                (aversion >> 8) & 0x7f,
                aversion & 0xff
            ))
            .lazy(raw_header, (hspan, endian, wide)),
    );
    if sstatlen > MAX_STRUCT || tstatlen > MAX_STRUCT {
        return Err(Diagnostic::malformed(
            "implausible statistics structure sizes",
        ));
    }
    if !wide {
        cx.diag(Diagnostic::unsupported(format!(
            "header of {headlen} and records of {reclen} bytes: only the 64-bit layout of atop 2.x is decoded"
        )));
    }
    let utsname = |i: u64| {
        let start = to_usize(36u64.saturating_add(i.saturating_mul(65)));
        crate::text::until_nul(h.get(start..start.saturating_add(65)).unwrap_or_default())
    };
    let log = Log {
        endian,
        reclen,
        sstatlen: sstatlen.into(),
        tstatlen: tstatlen.into(),
        wide,
    };
    let records = file.tail(headlen);
    cx.emit(
        Node::new("Samples")
            .span(records)
            .lazy(samples, (input, log, records)),
    );
    cx.annotate(format!(
        "atop {}.{} raw log, {} ({} {}, {})",
        (aversion >> 8) & 0x7f,
        aversion & 0xff,
        utsname(1),
        utsname(0),
        utsname(2),
        utsname(4)
    ));
    Ok(())
}

async fn raw_header(cx: Cx, (span, endian, wide): (Span, Endian, bool)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, endian);
    f.u32("magic").hex().emit()?;
    f.u16("aversion")
        .hex()
        .with(|&v, n| {
            n.summary(format!(
                "atop {}.{}{}",
                (v >> 8) & 0x7f,
                v & 0xff,
                if v & 0x8000 != 0 {
                    ""
                } else {
                    " (no version flag)"
                }
            ))
        })
        .emit()?;
    f.u16("future1").emit()?;
    f.u16("future2").emit()?;
    f.u16("rawheadlen").emit()?;
    f.u16("rawreclen").emit()?;
    f.u16("hertz").desc("Clock ticks per second").emit()?;
    f.u16("pidwidth").desc("Digits shown for PIDs").emit()?;
    f.bytes("sfuture", 10).emit()?;
    f.u32("sstatlen").desc("Size of struct sstat").emit()?;
    f.u32("tstatlen").desc("Size of struct tstat").emit()?;
    if !wide {
        return Ok(());
    }
    for name in [
        "sysname",
        "nodename",
        "release",
        "version",
        "machine",
        "domainname",
    ] {
        let b = f.bytes(name, 65);
        let s = b.span();
        let v = b.get()?;
        cx.emit(
            Node::new(name)
                .span(s)
                .value(text(crate::text::until_nul(&v))),
        );
    }
    f.bytes("cfuture", 8).emit()?;
    f.skip(2);
    f.u32("pagesize").emit()?;
    f.u32("supportflags").flags(SUPPORT_FLAGS).emit()?;
    f.int::<i32>("osrel").emit()?;
    f.int::<i32>("osvers").emit()?;
    f.int::<i32>("ossub").emit()?;
    f.int::<i32>("cstatlen")
        .desc("Size of struct cstat")
        .emit()?;
    f.bytes("ifuture", 20).emit()?;
    Ok(())
}

/// One sample's record header, as the walk needs it.
struct Rec {
    time: i64,
    flags: u16,
    interval: u32,
    ndeviat: u32,
    scomp: u64,
    pcomp: u64,
    ccomp: u64,
    corig: u64,
    ncgpids: u64,
    icomp: u64,
}

fn decode_rec(b: &[u8], e: Endian) -> Option<Rec> {
    let w = |off: usize| get::<u32>(b, off, e);
    Some(Rec {
        time: get::<i64>(b, 0, e)?,
        flags: get::<u16>(b, 8, e)?,
        scomp: w(16)?.into(),
        pcomp: w(20)?.into(),
        interval: w(24)?,
        ndeviat: w(28)?,
        ccomp: w(72)?.into(),
        corig: w(76)?.into(),
        ncgpids: w(80)?.into(),
        icomp: w(84)?.into(),
    })
}

impl Rec {
    /// Bytes of compressed data after the record header.
    fn body(&self) -> u64 {
        let mut n = self.scomp.saturating_add(self.pcomp);
        if self.flags & 0x100 != 0 {
            n = n.saturating_add(self.ccomp).saturating_add(self.icomp);
        }
        n
    }
}

async fn samples(cx: Cx, (input, log, records): (Input, Log, Span)) -> Result<()> {
    if !log.wide {
        cx.emit(Node::new("Data").span(records));
        return Ok(());
    }
    let (mut pos, mut index) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    while pos < records.len {
        let at = (pos, index);
        cx.mark(move || at);
        let rspan = records.sub(pos, log.reclen);
        let b = cx.read(rspan).await?;
        let Some(r) = decode_rec(&b, log.endian) else {
            cx.push(
                Node::new("Truncated sample")
                    .span(rspan)
                    .diag(Diagnostic::truncated(rspan, to_u64(b.len()))),
            )
            .await;
            break;
        };
        let len = log.reclen.saturating_add(r.body());
        let span = records.sub(pos, len);
        let mut node = Node::new(format!("Sample {index}"))
            .span(span)
            .value(Value::Timestamp {
                unix_seconds: r.time,
            })
            .summary(format!(
                "{}, {}{}",
                plural(r.interval, "second"),
                plural(r.ndeviat, "task"),
                if r.flags & 1 != 0 { ", since boot" } else { "" }
            ))
            .lazy(sample, (input, log, span));
        if span.len < len {
            node = node.diag(Diagnostic::truncated(span, span.len));
        }
        cx.push(node).await;
        cx.progress_in(records, records.offset.saturating_add(pos));
        if span.len < len {
            break;
        }
        pos = pos.saturating_add(len);
        index = index.saturating_add(1);
    }
    Ok(())
}

async fn sample(cx: Cx, (input, log, span): (Input, Log, Span)) -> Result<()> {
    let rspan = span.sub(0, log.reclen);
    let b = cx.read(rspan).await?;
    let r =
        decode_rec(&b, log.endian).ok_or_else(|| Diagnostic::truncated(rspan, to_u64(b.len())))?;
    cx.emit(
        Node::new("Record Header")
            .span(rspan)
            .lazy(record_header, (rspan, log.endian)),
    );
    let mut pos = log.reclen;
    let sspan = span.sub(pos, r.scomp);
    pos = pos.saturating_add(r.scomp);
    cx.emit(
        Node::new("System Statistics")
            .span(sspan)
            .summary(format!(
                "{} zlib, {} decompressed",
                size(sspan.len),
                size(log.sstatlen)
            ))
            .lazy(system_stats, (input, log, sspan)),
    );
    let pspan = span.sub(pos, r.pcomp);
    pos = pos.saturating_add(r.pcomp);
    let plen = u64::from(r.ndeviat).saturating_mul(log.tstatlen);
    cx.emit(
        Node::new("Process Statistics")
            .span(pspan)
            .summary(format!(
                "{}, {} zlib",
                plural(r.ndeviat, "task"),
                size(pspan.len)
            ))
            .lazy(process_stats, (log, pspan, plen)),
    );
    if r.flags & 0x100 != 0 {
        let cspan = span.sub(pos, r.ccomp);
        pos = pos.saturating_add(r.ccomp);
        cx.emit(
            Node::new("Cgroup Statistics")
                .span(cspan)
                .summary(format!(
                    "{} zlib, {} decompressed",
                    size(cspan.len),
                    size(r.corig)
                ))
                .lazy(decoded_data, (cspan, r.corig)),
        );
        let ispan = span.sub(pos, r.icomp);
        cx.emit(
            Node::new("Cgroup PIDs")
                .span(ispan)
                .summary(plural(r.ncgpids, "PID"))
                .lazy(cgroup_pids, (log, ispan, r.ncgpids)),
        );
    }
    Ok(())
}

async fn record_header(cx: Cx, (span, endian): (Span, Endian)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, endian);
    f.int::<i64>("curtime")
        .with(|&v, n| n.value(Value::Timestamp { unix_seconds: v }))
        .emit()?;
    f.u16("flags").flags(RECORD_FLAGS).emit()?;
    f.u16("ncgroups").emit()?;
    f.bytes("sfuture", 4).emit()?;
    f.u32("scomplen")
        .desc("Compressed size of the system statistics")
        .emit()?;
    f.u32("pcomplen")
        .desc("Compressed size of the task statistics")
        .emit()?;
    f.u32("interval")
        .desc("Seconds since the previous sample")
        .emit()?;
    f.u32("ndeviat").desc("Tasks in the list").emit()?;
    f.u32("nactproc")
        .desc("Active processes in the list")
        .emit()?;
    f.u32("ntask").emit()?;
    f.u32("totproc").emit()?;
    f.u32("totrun").emit()?;
    f.u32("totslpi").emit()?;
    f.u32("totslpu").emit()?;
    f.u32("totzomb").emit()?;
    f.u32("nexit").emit()?;
    f.u32("noverflow").emit()?;
    f.u32("totidle").emit()?;
    f.u32("ccomplen").emit()?;
    f.u32("coriglen").emit()?;
    f.u32("ncgpids").emit()?;
    f.u32("icomplen").emit()?;
    f.u32("ifuture").emit()?;
    Ok(())
}

/// The decompressed bytes of a zlib stream, as a node.
async fn decoded_data(cx: Cx, (span, len): (Span, u64)) -> Result<()> {
    let decoded = cx.decode_lazy(span, &Codec::Zlib, len)?;
    cx.emit(Node::new("Data").span(decoded).summary(size(len)));
    Ok(())
}

async fn system_stats(cx: Cx, (_input, log, span): (Input, Log, Span)) -> Result<()> {
    let decoded = cx.decode_lazy(span, &Codec::Zlib, log.sstatlen)?;
    // The start of struct cpustat, unchanged since atop 2.0.
    let head = decoded.sub(0, 160);
    let block = cx.block(head).await?;
    let mut f = Fields::emitting(&cx, &block, log.endian);
    f.u64("cpu.nrcpu").desc("Number of CPUs").emit()?;
    f.u64("cpu.devint").desc("Device interrupts").emit()?;
    f.u64("cpu.csw").desc("Context switches").emit()?;
    f.u64("cpu.nprocs").desc("Processes started").emit()?;
    f.f32("cpu.lavg1").emit()?;
    f.f32("cpu.lavg5").emit()?;
    f.f32("cpu.lavg15").emit()?;
    f.skip(4 + 32);
    f.int::<i32>("cpu.all.cpunr").emit()?;
    f.skip(4);
    for name in [
        "cpu.all.stime",
        "cpu.all.utime",
        "cpu.all.ntime",
        "cpu.all.itime",
        "cpu.all.wtime",
        "cpu.all.Itime",
        "cpu.all.Stime",
        "cpu.all.steal",
        "cpu.all.guest",
    ] {
        f.u64(name).desc("Clock ticks").emit()?;
    }
    cx.emit(
        Node::new("Data")
            .span(decoded)
            .summary(format!("struct sstat, {}", size(log.sstatlen))),
    );
    Ok(())
}

async fn process_stats(cx: Cx, (log, span, len): (Log, Span, u64)) -> Result<()> {
    let decoded = cx.decode_lazy(span, &Codec::Zlib, len)?;
    let n = len.checked_div(log.tstatlen).unwrap_or(0);
    cx.set_count(Count::Exact(n));
    let i0 = cx.resume::<u64>().unwrap_or(0);
    for i in i0..n {
        cx.mark(move || i);
        let tspan = decoded.sub(i.saturating_mul(log.tstatlen), log.tstatlen);
        let g = cx.read(tspan.sub(0, GEN_PREFIX)).await?;
        let pid = get::<i32>(&g, 4, log.endian).unwrap_or(0);
        let name = crate::text::until_nul(g.get(48..64).unwrap_or_default());
        let state = g.get(65).copied().unwrap_or(b'?');
        let isproc = g.get(64).copied().unwrap_or(0) != 0;
        let cmdline = crate::text::until_nul(g.get(88..344).unwrap_or_default());
        cx.push(
            Node::new(format!("{pid} {name}"))
                .span(tspan)
                .summary(format!(
                    "{} {}{}",
                    if isproc { "process" } else { "thread" },
                    char::from(state),
                    if cmdline.is_empty() {
                        String::new()
                    } else {
                        format!(", {}", crate::formats::util::fmt::clip(&cmdline, 80))
                    }
                ))
                .lazy(task, (log, tspan)),
        )
        .await;
    }
    Ok(())
}

/// Bytes of `struct gen` decoded: up to `nthrrun`, the part unchanged
/// since atop 2.0.
const GEN_PREFIX: u64 = 356;

async fn task(cx: Cx, (log, span): (Log, Span)) -> Result<()> {
    let block = cx.block(span.sub(0, GEN_PREFIX)).await?;
    let mut f = Fields::emitting(&cx, &block, log.endian);
    for name in [
        "gen.tgid",
        "gen.pid",
        "gen.ppid",
        "gen.ruid",
        "gen.euid",
        "gen.suid",
        "gen.fsuid",
        "gen.rgid",
        "gen.egid",
        "gen.sgid",
        "gen.fsgid",
        "gen.nthr",
    ] {
        f.int::<i32>(name).emit()?;
    }
    let b = f.bytes("gen.name", 16);
    let s = b.span();
    let v = b.get()?;
    cx.emit(
        Node::new("gen.name")
            .span(s)
            .value(text(crate::text::until_nul(&v))),
    );
    f.u8("gen.isproc")
        .desc("Non-zero for a process, zero for a thread")
        .emit()?;
    let st = f.bytes("gen.state", 1);
    let s = st.span();
    let v = st.get()?;
    cx.emit(
        Node::new("gen.state")
            .span(s)
            .value(text(String::from_utf8_lossy(&v).into_owned()))
            .desc("E: exited"),
    );
    f.skip(2);
    f.int::<i32>("gen.excode").emit()?;
    f.int::<i64>("gen.btime")
        .with(|&v, n| n.value(Value::Timestamp { unix_seconds: v }))
        .emit()?;
    f.int::<i64>("gen.elaps").desc("Clock ticks").emit()?;
    let b = f.bytes("gen.cmdline", 256);
    let s = b.span();
    let v = b.get()?;
    cx.emit(
        Node::new("gen.cmdline")
            .span(s)
            .value(text(crate::text::until_nul(&v))),
    );
    f.int::<i32>("gen.nthrslpi").emit()?;
    f.int::<i32>("gen.nthrslpu").emit()?;
    f.int::<i32>("gen.nthrrun").emit()?;
    cx.emit(
        Node::new("Rest")
            .span(span.tail(GEN_PREFIX))
            .desc("The rest of struct tstat, whose layout depends on the atop version"),
    );
    Ok(())
}

async fn cgroup_pids(cx: Cx, (log, span, n): (Log, Span, u64)) -> Result<()> {
    let len = n.saturating_mul(4);
    let decoded = cx.decode_lazy(span, &Codec::Zlib, len)?;
    cx.set_count(Count::Exact(n));
    let i0 = cx.resume::<u64>().unwrap_or(0);
    for i in i0..n {
        cx.mark(move || i);
        let s = decoded.sub(i.saturating_mul(4), 4);
        let b = cx.read(s).await?;
        let Some(pid) = get::<i32>(&b, 0, log.endian) else {
            break;
        };
        cx.push(Node::new(format!("[{i}]")).span(s).value(int(pid, 32)))
            .await;
    }
    Ok(())
}
