//! Compiled terminfo entries (`/usr/share/terminfo/x/xterm`).
//!
//! A header of six 16-bit counts is followed by the terminal names, boolean
//! flags, numbers (16-bit, or 32-bit in the newer format), string offsets
//! and the string table; ncurses may append an extended section with
//! user-defined capabilities, which carries its own names.

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::datakit::clip;
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "terminfo",
    title: "Compiled terminfo entry",
    extensions: &[],
    mime: "application/x-terminfo",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

/// Magic 0432 (16-bit numbers) or 01036 (32-bit numbers), sane counts, and
/// a NUL-terminated name section that looks like `name|alias|description`.
fn probe(h: &Head<'_>) -> bool {
    let get = |i: usize| crate::bytes::u16_le(h.data, i.saturating_mul(2));
    let (Some(magic), Some(names), Some(bools), Some(nums), Some(strs)) =
        (get(0), get(1), get(2), get(3), get(4))
    else {
        return false;
    };
    let name_bytes = h.data.get(12..12usize.saturating_add(usize::from(names)));
    matches!(magic, 0o432 | 0o1036)
        && (2..=4096).contains(&names)
        && bools <= 512
        && nums <= 512
        && strs <= 4096
        && name_bytes.is_some_and(|n| {
            n.last() == Some(&0)
                && n.iter()
                    .take(n.len().saturating_sub(1))
                    .all(|&b| b.is_ascii_graphic() || b == b' ')
        })
}

const BOOLEANS: &[&str] = &[
    "bw", "am", "xsb", "xhp", "xenl", "eo", "gn", "hc", "km", "hs", "in", "db", "da", "mir",
    "msgr", "os", "eslok", "xt", "hz", "ul", "xon", "nxon", "mc5i", "chts", "nrrmc", "npc",
    "ndscr", "ccc", "bce", "hls", "xhpa", "crxm", "daisy", "xvpa", "sam", "cpix", "lpix", "OTbs",
    "OTns", "OTnc", "OTMT", "OTNL", "OTpt", "OTxr",
];

const NUMBERS: &[&str] = &[
    "cols", "it", "lines", "lm", "xmc", "pb", "vt", "wsl", "nlab", "lh", "lw", "ma", "wnum",
    "colors", "pairs", "ncv", "bufsz", "spinv", "spinh", "maddr", "mjump", "mcs", "mls", "npins",
    "orc", "orl", "orhi", "orvi", "cps", "widcs", "btns", "bitwin", "bitype", "OTug", "OTdC",
    "OTdN", "OTdB", "OTdT", "OTkn",
];

const STRINGS: &[&str] = &[
    "cbt", "bel", "cr", "csr", "tbc", "clear", "el", "ed", "hpa", "cmdch", "cup", "cud1", "home",
    "civis", "cub1", "mrcup", "cnorm", "cuf1", "ll", "cuu1", "cvvis", "dch1", "dl1", "dsl", "hd",
    "smacs", "blink", "bold", "smcup", "smdc", "dim", "smir", "invis", "prot", "rev", "smso",
    "smul", "ech", "rmacs", "sgr0", "rmcup", "rmdc", "rmir", "rmso", "rmul", "flash", "ff", "fsl",
    "is1", "is2", "is3", "if", "ich1", "il1", "ip", "kbs", "ktbc", "kclr", "kctab", "kdch1",
    "kdl1", "kcud1", "krmir", "kel", "ked", "kf0", "kf1", "kf10", "kf2", "kf3", "kf4", "kf5",
    "kf6", "kf7", "kf8", "kf9", "khome", "kich1", "kil1", "kcub1", "kll", "knp", "kpp", "kcuf1",
    "kind", "kri", "khts", "kcuu1", "rmkx", "smkx", "lf0", "lf1", "lf10", "lf2", "lf3", "lf4",
    "lf5", "lf6", "lf7", "lf8", "lf9", "rmm", "smm", "nel", "pad", "dch", "dl", "cud", "ich",
    "indn", "il", "cub", "cuf", "rin", "cuu", "pfkey", "pfloc", "pfx", "mc0", "mc4", "mc5", "rep",
    "rs1", "rs2", "rs3", "rf", "rc", "vpa", "sc", "ind", "ri", "sgr", "hts", "wind", "ht", "tsl",
    "uc", "hu", "iprog", "ka1", "ka3", "kb2", "kc1", "kc3", "mc5p", "rmp", "acsc", "pln", "kcbt",
    "smxon", "rmxon", "smam", "rmam", "xonc", "xoffc", "enacs", "smln", "rmln", "kbeg", "kcan",
    "kclo", "kcmd", "kcpy", "kcrt", "kend", "kent", "kext", "kfnd", "khlp", "kmrk", "kmsg", "kmov",
    "knxt", "kopn", "kopt", "kprv", "kprt", "krdo", "kref", "krfr", "krpl", "krst", "kres", "ksav",
    "kspd", "kund", "kBEG", "kCAN", "kCMD", "kCPY", "kCRT", "kDC", "kDL", "kslt", "kEND", "kEOL",
    "kEXT", "kFND", "kHLP", "kHOM", "kIC", "kLFT", "kMSG", "kMOV", "kNXT", "kOPT", "kPRV", "kPRT",
    "kRDO", "kRPL", "kRIT", "kRES", "kSAV", "kSPD", "kUND", "rfi", "kf11", "kf12", "kf13", "kf14",
    "kf15", "kf16", "kf17", "kf18", "kf19", "kf20", "kf21", "kf22", "kf23", "kf24", "kf25", "kf26",
    "kf27", "kf28", "kf29", "kf30", "kf31", "kf32", "kf33", "kf34", "kf35", "kf36", "kf37", "kf38",
    "kf39", "kf40", "kf41", "kf42", "kf43", "kf44", "kf45", "kf46", "kf47", "kf48", "kf49", "kf50",
    "kf51", "kf52", "kf53", "kf54", "kf55", "kf56", "kf57", "kf58", "kf59", "kf60", "kf61", "kf62",
    "kf63", "el1", "mgc", "smgl", "smgr", "fln", "sclk", "dclk", "rmclk", "cwin", "wingo", "hup",
    "dial", "qdial", "tone", "pulse", "hook", "pause", "wait", "u0", "u1", "u2", "u3", "u4", "u5",
    "u6", "u7", "u8", "u9", "op", "oc", "initc", "initp", "scp", "setf", "setb", "cpi", "lpi",
    "chr", "cvr", "defc", "swidm", "sdrfq", "sitm", "slm", "smicm", "snlq", "snrmq", "sshm",
    "ssubm", "ssupm", "sum", "rwidm", "ritm", "rlm", "rmicm", "rshm", "rsubm", "rsupm", "rum",
    "mhpa", "mcud1", "mcub1", "mcuf1", "mvpa", "mcuu1", "porder", "mcud", "mcub", "mcuf", "mcuu",
    "scs", "smgb", "smgbp", "smglp", "smgrp", "smgt", "smgtp", "sbim", "scsd", "rbim", "rcsd",
    "subcs", "supcs", "docr", "zerom", "csnm", "kmous", "minfo", "reqmp", "getm", "setaf", "setab",
    "pfxl", "devt", "csin", "s0ds", "s1ds", "s2ds", "s3ds", "smglr", "smgtb", "birep", "binel",
    "bicr", "colornm", "defbi", "endbi", "setcolor", "slines", "dispc", "smpch", "rmpch", "smsc",
    "rmsc", "pctrm", "scesc", "scesa", "ehhlm", "elhlm", "elohlm", "erhlm", "ethlm", "evhlm",
    "sgr1", "slength", "OTi2", "OTrs", "OTnl", "OTbc", "OTko", "OTma", "OTG2", "OTG3", "OTG1",
    "OTG4", "OTGR", "OTGL", "OTGU", "OTGD", "OTGH", "OTGV", "OTGC", "meml", "memu", "box1",
];

/// Escapes control characters the way terminfo sources write them.
fn escape(s: &[u8]) -> String {
    let mut out = String::new();
    for &b in s {
        match b {
            0x1b => out.push_str("\\E"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x08 => out.push_str("\\b"),
            0x0c => out.push_str("\\f"),
            0x00..=0x1f => {
                out.push('^');
                out.push(char::from(b.saturating_add(0x40)));
            }
            0x7f => out.push_str("^?"),
            _ => out.push(char::from(b)),
        }
    }
    out
}

/// Section layout, computed from the header.
#[derive(Clone, Copy, Debug)]
struct Layout {
    wide: bool,
    names: u64,
    bools: u64,
    nums: u64,
    strs: u64,
    table: u64,
}

impl Layout {
    fn num_size(&self) -> u64 {
        if self.wide { 4 } else { 2 }
    }
    fn names_at(&self) -> u64 {
        12
    }
    fn bools_at(&self) -> u64 {
        self.names_at().saturating_add(self.names)
    }
    fn nums_at(&self) -> u64 {
        let end = self.bools_at().saturating_add(self.bools);
        end.saturating_add(end & 1)
    }
    fn strs_at(&self) -> u64 {
        self.nums_at()
            .saturating_add(self.nums.saturating_mul(self.num_size()))
    }
    fn table_at(&self) -> u64 {
        self.strs_at().saturating_add(self.strs.saturating_mul(2))
    }
    fn end(&self) -> u64 {
        self.table_at().saturating_add(self.table)
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 12)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    let magic = f
        .u16("Magic")
        .with(|&m, n| {
            n.summary(if m == 0o1036 {
                "0o1036, 32-bit numbers"
            } else {
                "0o432, 16-bit numbers"
            })
        })
        .emit()?;
    let names = f.u16("Names size").emit()?;
    let bools = f.u16("Booleans").emit()?;
    let nums = f.u16("Numbers").emit()?;
    let strs = f.u16("Strings").emit()?;
    let table = f.u16("String table size").emit()?;
    let l = Layout {
        wide: magic == 0o1036,
        names: names.into(),
        bools: bools.into(),
        nums: nums.into(),
        strs: strs.into(),
        table: table.into(),
    };
    let names_span = file.sub(l.names_at(), l.names);
    let name_text = crate::text::until_nul(&cx.read(names_span).await?);
    let primary = name_text.split('|').next().unwrap_or_default().to_owned();
    let description = name_text.rsplit('|').next().unwrap_or_default().to_owned();
    cx.annotate(format!("terminfo {primary}, {}", clip(&description, 80)));
    cx.emit(
        Node::new("Names")
            .span(names_span)
            .value(Value::Text(name_text)),
    );
    cx.emit(
        Node::new("Booleans")
            .span(file.sub(l.bools_at(), l.bools))
            .lazy(booleans, (file, l)),
    );
    cx.emit(
        Node::new("Numbers")
            .span(file.sub(l.nums_at(), l.nums.saturating_mul(l.num_size())))
            .lazy(numbers, (file, l)),
    );
    cx.emit(
        Node::new("Strings")
            .span(file.sub(l.strs_at(), l.strs.saturating_mul(2)))
            .lazy(strings, (file, l)),
    );
    cx.emit(Node::new("String table").span(file.sub(l.table_at(), l.table)));
    let ext_at = l.end().saturating_add(l.end() & 1);
    if ext_at < file.len {
        let ext = file.tail(ext_at);
        cx.emit(
            Node::new("Extended capabilities")
                .span(ext)
                .lazy(extended, (ext, l.wide)),
        );
    }
    Ok(())
}

async fn booleans(cx: Cx, (file, l): (Span, Layout)) -> Result<()> {
    let span = file.sub_exact(l.bools_at(), l.bools)?;
    let data = cx.read(span).await?;
    for (i, &b) in data.iter().enumerate() {
        if b == 1 {
            let name = BOOLEANS
                .get(i)
                .map_or_else(|| format!("bool {i}"), |n| (*n).to_owned());
            cx.emit(
                Node::new(name)
                    .span(span.sub(to_u64(i), 1))
                    .value(Value::Bool(true)),
            );
        }
    }
    Ok(())
}

fn number(data: &[u8], wide: bool, i: usize) -> Option<i32> {
    if wide {
        crate::bytes::i32_le(data, i.saturating_mul(4))
    } else {
        crate::bytes::i16_le(data, i.saturating_mul(2)).map(i32::from)
    }
}

async fn numbers(cx: Cx, (file, l): (Span, Layout)) -> Result<()> {
    let span = file.sub_exact(l.nums_at(), l.nums.saturating_mul(l.num_size()))?;
    let data = cx.read(span).await?;
    for i in 0..to_usize(l.nums) {
        let Some(v) = number(&data, l.wide, i) else {
            break;
        };
        if v < 0 {
            continue; // absent or cancelled
        }
        let name = NUMBERS
            .get(i)
            .map_or_else(|| format!("num {i}"), |n| (*n).to_owned());
        cx.emit(
            Node::new(name)
                .span(span.sub(to_u64(i).saturating_mul(l.num_size()), l.num_size()))
                .value(Value::Int {
                    value: v.into(),
                    bits: 32,
                }),
        );
    }
    Ok(())
}

async fn strings(cx: Cx, (file, l): (Span, Layout)) -> Result<()> {
    let span = file.sub_exact(l.strs_at(), l.strs.saturating_mul(2))?;
    let offsets = cx.read(span).await?;
    let table_span = file.sub_exact(l.table_at(), l.table)?;
    let table = cx.read(table_span).await?;
    for i in 0..to_usize(l.strs) {
        // Each value is a scan of up to the whole table.
        cx.checkpoint().await;
        let Some(off) = crate::bytes::i16_le(&offsets, i.saturating_mul(2)) else {
            break;
        };
        let Ok(off) = usize::try_from(off) else {
            continue;
        };
        let rest = table.get(off..).unwrap_or_default();
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        let value = rest.get(..end).unwrap_or_default();
        let name = STRINGS
            .get(i)
            .map_or_else(|| format!("str {i}"), |n| (*n).to_owned());
        cx.emit(
            Node::new(name)
                .span(table_span.sub(to_u64(off), to_u64(end)))
                .value(Value::Text(escape(value))),
        );
    }
    Ok(())
}

/// The extended section: counts, values, then names in one string table.
async fn extended(cx: Cx, (span, wide): (Span, bool)) -> Result<()> {
    let head = cx.block(span.sub(0, 10)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    let bools = u64::from(f.u16("Extended booleans").emit()?);
    let nums = u64::from(f.u16("Extended numbers").emit()?);
    let strs = u64::from(f.u16("Extended strings").emit()?);
    f.u16("String table entries").emit()?;
    let table_size = u64::from(f.u16("String table size").emit()?);
    let num_size: u64 = if wide { 4 } else { 2 };
    let bools_at = 10u64;
    let nums_at = bools_at.saturating_add(bools).saturating_add(bools & 1);
    let offs_at = nums_at.saturating_add(nums.saturating_mul(num_size));
    let names_count = bools.saturating_add(nums).saturating_add(strs);
    let table_at = offs_at.saturating_add(strs.saturating_add(names_count).saturating_mul(2));
    let bool_data = cx.read(span.sub_exact(bools_at, bools)?).await?;
    let num_data = cx
        .read(span.sub_exact(nums_at, nums.saturating_mul(num_size))?)
        .await?;
    let offs = cx
        .read(span.sub_exact(offs_at, strs.saturating_add(names_count).saturating_mul(2))?)
        .await?;
    let table_span = span.sub_exact(table_at, table_size)?;
    let table = cx.read(table_span).await?;
    let get_off = |i: u64| crate::bytes::i16_le(&offs, to_usize(i).saturating_mul(2));
    let text_at = |off: usize| {
        let rest = table.get(off..).unwrap_or_default();
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        rest.get(..end).unwrap_or_default().to_vec()
    };
    // String values come first in the table; names follow them.
    let mut values_end = 0usize;
    for i in 0..strs {
        // Each lookup below is a scan of up to the whole table.
        cx.checkpoint().await;
        if let Some(Ok(o)) = get_off(i).map(usize::try_from) {
            values_end = values_end.max(o.saturating_add(text_at(o).len()).saturating_add(1));
        }
    }
    let name_of = |k: u64| -> String {
        match get_off(strs.saturating_add(k)).map(usize::try_from) {
            Some(Ok(o)) => {
                String::from_utf8_lossy(&text_at(values_end.saturating_add(o))).into_owned()
            }
            _ => format!("#{k}"),
        }
    };
    for i in 0..bools {
        cx.checkpoint().await;
        if bool_data.get(to_usize(i)) == Some(&1) {
            cx.emit(
                Node::new(name_of(i))
                    .span(span.sub(bools_at.saturating_add(i), 1))
                    .value(Value::Bool(true)),
            );
        }
    }
    for i in 0..nums {
        cx.checkpoint().await;
        if let Some(v) = number(&num_data, wide, to_usize(i))
            && v >= 0
        {
            cx.emit(
                Node::new(name_of(bools.saturating_add(i)))
                    .span(span.sub(nums_at.saturating_add(i.saturating_mul(num_size)), num_size))
                    .value(Value::Int {
                        value: v.into(),
                        bits: 32,
                    }),
            );
        }
    }
    for i in 0..strs {
        cx.checkpoint().await;
        let name = name_of(bools.saturating_add(nums).saturating_add(i));
        match get_off(i).map(usize::try_from) {
            Some(Ok(o)) => {
                let value = text_at(o);
                cx.emit(
                    Node::new(name)
                        .span(table_span.sub(to_u64(o), to_u64(value.len())))
                        .value(Value::Text(escape(&value))),
                );
            }
            _ => continue,
        }
    }
    if values_end > table.len() {
        cx.diag(Diagnostic::malformed(
            "extended string values overrun the table",
        ));
    }
    Ok(())
}
