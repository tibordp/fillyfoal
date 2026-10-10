//! Backups and database dumps: Microsoft Tape Format (MTF/BKF), Oracle
//! export, PostgreSQL custom dumps, MySQL FRM, MyISAM indexes, H2 MVStore
//! and FileMaker.

use crate::bytes::{to_u64, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::text::scan::head_lines;
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

fn uint(value: u64, bits: u8) -> Value {
    Value::UInt {
        value,
        bits,
        radix: Radix::Dec,
    }
}

fn zstr(b: &[u8]) -> String {
    crate::text::until_nul(b)
}

// ---------------------------------------------------------------------------
// Backups and database dumps

declare_format!(pub MTF = "mtf", "Microsoft Tape Format (BKF / SQL Server backup)", ["bkf", "bak"], "application/x-mtf",
    Probe::Magic(&[(0, b"TAPE")]), mtf);

const MTF_DBLKS: &[&[u8; 4]] = &[
    b"TAPE", b"SSET", b"VOLB", b"DIRB", b"FILE", b"CFIL", b"ESPB", b"ESET", b"EOTM", b"SFMB",
    b"MSCI", b"MSDA", b"MQDA",
];

async fn mtf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 0x80)).await?;
    // After the 52-byte common header: media family ID, attributes,
    // sequence, password encryption, soft filemark size, catalog type, then
    // (size, offset) pairs for the tape name, description, password and
    // software name, the logical block size, vendor, date and MTF version.
    let block_size = u64::from(u16_le(&head, 0x54).unwrap_or(1024)).max(512);
    let name_size = u64::from(u16_le(&head, 0x44).unwrap_or(0));
    let name_at = u64::from(u16_le(&head, 0x46).unwrap_or(0));
    let string_type = head.get(0x2e).copied().unwrap_or(1);
    let raw_name = cx.read_avail(file.sub(name_at, name_size.min(512))).await?;
    let name = if string_type == 2 {
        crate::text::utf16z(&raw_name, LE).0
    } else {
        zstr(&raw_name)
    };
    let major = head.get(0x5d).copied().unwrap_or(0);
    let mut pos = 0u64;
    let mut counts: Vec<(String, u32)> = Vec::new();
    while pos.saturating_add(4) <= file.len {
        cx.progress(pos, file.len);
        let id = cx.read(file.sub(pos, 4)).await?;
        let id_arr: [u8; 4] = id
            .get(..4)
            .and_then(|s| s.try_into().ok())
            .unwrap_or([0; 4]);
        if MTF_DBLKS.contains(&&id_arr) {
            // A descriptor block: common header (52 bytes) + type-specific.
            let h = cx.read(file.sub_exact(pos, 52)?).await?;
            let first = u64::from(u16_le(&h, 8).unwrap_or(0)).max(52);
            let kind = String::from_utf8_lossy(&id).into_owned();
            match counts.iter_mut().find(|(k, _)| *k == kind) {
                Some((_, n)) => *n = n.saturating_add(1),
                None => counts.push((kind.clone(), 1)),
            }
            cx.push(
                Node::new(kind)
                    .span(file.sub(pos, first))
                    .summary(format!("descriptor block, streams at +{first:#x}")),
            )
            .await;
            pos = pos.saturating_add(first);
            if id_arr == *b"SFMB" || id_arr == *b"EOTM" {
                pos = pos
                    .saturating_add(1)
                    .checked_next_multiple_of(block_size)
                    .unwrap_or(u64::MAX);
            }
        } else {
            // A stream: id, attributes, u64 length, encryption,
            // compression, checksum (22 bytes), data, 4-byte aligned.
            let h = cx.read(file.sub_exact(pos, 22)?).await?;
            let len = u64_le(&h, 8).unwrap_or(0);
            let kind = String::from_utf8_lossy(&id).into_owned();
            if !id.iter().all(|b| b.is_ascii_alphanumeric()) {
                cx.push(Node::new("Unparsed data").span(file.tail(pos)).diag(
                    Diagnostic::malformed("expected a descriptor block or stream header"),
                ))
                .await;
                break;
            }
            let total = 22u64.saturating_add(len);
            cx.push(
                Node::new(format!("Stream {kind}"))
                    .span(file.sub(pos, total))
                    .summary(format!("{len} bytes")),
            )
            .await;
            pos = pos.saturating_add(total);
            pos = pos.checked_next_multiple_of(4).unwrap_or(u64::MAX);
        }
    }
    let list: Vec<String> = counts.iter().map(|(k, n)| format!("{n}× {k}")).collect();
    cx.annotate(format!(
        "MTF {major}.x media {name:?}, {block_size}-byte blocks: {}",
        list.join(", ")
    ));
    Ok(())
}

fn oracle_probe(h: &Head<'_>) -> bool {
    h.at(2, b"EXPORT:V")
}

declare_format!(pub ORACLE_EXP = "oracle-exp", "Oracle export dump (exp)", ["dmp"], "application/x-oracle-dump",
    Probe::Custom(oracle_probe), oracle_exp);

async fn oracle_exp(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let all = head_lines(&cx, file.tail(2), 512).await?;
    let labels = ["Export version", "User", "Mode", "Buffer"];
    let mut version = String::new();
    let mut user = String::new();
    for (i, (line, span)) in all.iter().take(4).enumerate() {
        let value = if i == 0 {
            line.trim_start_matches("EXPORT:").to_owned()
        } else {
            line.get(1..).unwrap_or_default().to_owned()
        };
        if i == 0 {
            version = value.clone();
        } else if i == 1 {
            user = value.clone();
        }
        cx.emit(
            Node::new(labels.get(i).copied().unwrap_or("Line"))
                .span(*span)
                .value(text(value)),
        );
    }
    cx.emit(Node::new("Dump body").span(file.tail(512)));
    cx.annotate(format!("Oracle export {version}, user {user}"));
    Ok(())
}

declare_format!(pub PG_DUMP = "pg-dump", "PostgreSQL custom-format dump", ["dump", "backup", "pgdump"], "application/x-pg-dump",
    Probe::Magic(&[(0, b"PGDMP")]), pg_dump);

async fn pg_dump(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 11)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 5).emit()?;
    let major = f.u8("Major version").emit()?;
    let minor = f.u8("Minor version").emit()?;
    let rev = f.u8("Revision").emit()?;
    let int_size = f.u8("Integer size").emit()?;
    f.u8("Offset size").emit()?;
    let format = f
        .u8("Format")
        .enumeration(&[
            (1, "custom"),
            (2, "files"),
            (3, "tar"),
            (4, "null"),
            (5, "directory"),
        ])
        .emit()?;
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(11);
    let int_size = u64::from(int_size).clamp(1, 8);
    // Integers: a sign byte, then `int_size` little-endian bytes.
    async fn int(cur: &mut Cursor<'_>, size: u64) -> Result<i64> {
        let sign = cur.u8().await?;
        let b = cur.bytes(size).await?;
        let v = b
            .iter()
            .rev()
            .fold(0i64, |a, &x| a.wrapping_shl(8) | i64::from(x));
        Ok(if sign != 0 { v.wrapping_neg() } else { v })
    }
    async fn string(cur: &mut Cursor<'_>, size: u64) -> Result<(String, Span)> {
        let len = int(cur, size).await?;
        if len < 0 {
            return Ok((String::new(), cur.span(0)));
        }
        let len = u64::try_from(len).unwrap_or(0);
        let span = cur.span(len);
        let s = String::from_utf8_lossy(&cur.bytes(len).await?).into_owned();
        Ok((s, span))
    }
    let at = cur.pos();
    let compression = if (major, minor) >= (1, 15) {
        i64::from(cur.u8().await?)
    } else {
        int(&mut cur, int_size).await?
    };
    cx.emit(
        Node::new("Compression")
            .span(cur.since(at))
            .value(Value::Int {
                value: compression,
                bits: 32,
            }),
    );
    let at = cur.pos();
    let mut t = [0i64; 7];
    for v in &mut t {
        *v = int(&mut cur, int_size).await?;
    }
    let [sec, min, hour, mday, mon, year, _] = t;
    cx.emit(Node::new("Created").span(cur.since(at)).value(text(format!(
        "{:04}-{:02}-{:02} {hour:02}:{min:02}:{sec:02}",
        year.saturating_add(1900),
        mon.saturating_add(1),
        mday
    ))));
    let (db, span) = string(&mut cur, int_size).await?;
    cx.emit(Node::new("Database").span(span).value(text(db.clone())));
    let (server, span) = string(&mut cur, int_size).await?;
    cx.emit(
        Node::new("Server version")
            .span(span)
            .value(text(server.clone())),
    );
    let (tool, span) = string(&mut cur, int_size).await?;
    cx.emit(Node::new("pg_dump version").span(span).value(text(tool)));
    let at = cur.pos();
    let entries = int(&mut cur, int_size).await?;
    cx.emit(
        Node::new("TOC entries")
            .span(cur.since(at))
            .value(Value::Int {
                value: entries,
                bits: 32,
            }),
    );
    cx.emit(Node::new("Table of contents and data").span(file.tail(cur.pos())));
    let _ = format;
    cx.annotate(format!(
        "PostgreSQL dump v{major}.{minor}.{rev} of {db:?} (server {server}), {entries} TOC entries"
    ));
    Ok(())
}

const MYSQL_ENGINES: EnumTable = &[
    (6, "HEAP"),
    (9, "MyISAM"),
    (10, "MRG_MyISAM"),
    (11, "BerkeleyDB"),
    (12, "InnoDB"),
    (14, "NDB Cluster"),
    (16, "ARCHIVE"),
    (17, "CSV"),
    (18, "FEDERATED"),
    (19, "BLACKHOLE"),
    (20, "partitioned"),
    (27, "Aria"),
    (28, "PERFORMANCE_SCHEMA"),
    (42, "dynamic"),
];

declare_format!(pub MYSQL_FRM = "mysql-frm", "MySQL table definition (FRM)", ["frm"], "application/x-mysql-frm",
    Probe::Magic(&[(0, b"\xfe\x01\x09"), (0, b"\xfe\x01\x0a"), (0, b"\xfe\x01\x0b"), (0, b"\xfe\x01\x0c")]), mysql_frm);

async fn mysql_frm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 0x40)).await?;
    cx.emit(Node::new("Signature").span(file.sub(0, 2)));
    cx.emit(
        Node::new("FRM version")
            .span(file.sub(2, 1))
            .value(uint(head.get(2).copied().unwrap_or(0).into(), 8)),
    );
    let engine = head.get(3).copied().unwrap_or(0);
    let name = MYSQL_ENGINES
        .iter()
        .find(|(k, _)| *k == u64::from(engine))
        .map(|(_, v)| *v);
    cx.emit(Node::new("Engine").span(file.sub(3, 1)).value(Value::Enum {
        raw: engine.into(),
        bits: 8,
        name,
    }));
    cx.emit(
        Node::new("I/O size")
            .span(file.sub(4, 2))
            .value(uint(u16_le(&head, 4).unwrap_or(0).into(), 16)),
    );
    cx.emit(
        Node::new("Record length")
            .span(file.sub(0x10, 2))
            .value(uint(u16_le(&head, 0x10).unwrap_or(0).into(), 16)),
    );
    let version = u32_le(&head, 0x33).unwrap_or(0);
    cx.emit(
        Node::new("MySQL version")
            .span(file.sub(0x33, 4))
            .value(text(format!(
                "{}.{}.{}",
                version / 10000,
                version / 100 % 100,
                version % 100
            ))),
    );
    cx.emit(Node::new("Key and column definitions").span(file.tail(0x40)));
    cx.annotate(format!(
        "MySQL table definition, {} engine, written by {}.{}.{}",
        name.unwrap_or("unknown"),
        version / 10000,
        version / 100 % 100,
        version % 100
    ));
    Ok(())
}

declare_format!(pub MYISAM = "myisam-index", "MyISAM index (MYI)", ["myi"], "application/x-myisam",
    Probe::Magic(&[(0, b"\xfe\xfe\x07\x01"), (0, b"\xfe\xfe\x0b\x01")]), myisam);

async fn myisam(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 36)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.bytes("Signature", 4).emit()?;
    f.u16("Options").hex().emit()?;
    f.u16("Header length").emit()?;
    f.u16("State info length").emit()?;
    f.u16("Base info length").emit()?;
    f.u16("Base position").emit()?;
    f.u16("Key parts").emit()?;
    f.u16("Unique key parts").emit()?;
    let keys = f.u8("Keys").emit()?;
    f.u8("Uniques").emit()?;
    f.u8("Language").emit()?;
    f.u8("Max block size index").emit()?;
    f.u8("Full-text keys").emit()?;
    f.u8("Unused").emit()?;
    f.u16("Open count").emit()?;
    f.u8("Changed").emit()?;
    f.u8("Sort key").emit()?;
    let records = f.u64("Records").emit()?;
    cx.emit(Node::new("State, base and key definitions").span(file.tail(36)));
    cx.annotate(format!("MyISAM index, {keys} keys, {records} records"));
    Ok(())
}

declare_format!(pub H2 = "h2-mvstore", "H2 database (MVStore)", ["db", "mv.db"], "application/x-h2",
    Probe::Magic(&[(0, b"H:2,")]), h2);

async fn h2(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 4096)).await?;
    let end = head.iter().position(|&b| b == b'\n').unwrap_or(head.len());
    let header = String::from_utf8_lossy(head.get(..end).unwrap_or_default()).into_owned();
    let mut pos = 0u64;
    let mut pairs = Vec::new();
    for pair in header.split(',') {
        let len = to_u64(pair.len());
        if let Some((k, v)) = pair.split_once(':') {
            let decoded = u64::from_str_radix(v, 16).ok();
            let node = Node::new(k.to_owned()).span(file.sub(pos, len));
            cx.emit(match (k, decoded) {
                ("created" | "blockSize" | "version" | "format" | "block" | "chunk", Some(d)) => {
                    node.value(uint(d, 64)).summary(format!("hex {v}"))
                }
                _ => node.value(text(v)),
            });
            pairs.push((k.to_owned(), v.to_owned()));
        }
        pos = pos.saturating_add(len).saturating_add(1);
    }
    cx.emit(Node::new("Second store header").span(file.sub(4096, 4096)));
    cx.emit(Node::new("Chunks").span(file.tail(8192)));
    let get = |k: &str| {
        pairs
            .iter()
            .find(|(a, _)| a == k)
            .map_or("?", |(_, v)| v.as_str())
    };
    cx.annotate(format!(
        "H2 MVStore, format {}, version {}",
        get("format"),
        get("version")
    ));
    Ok(())
}

fn filemaker_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"\x00\x01\x00\x00\x00\x02\x00\x01\x00\x05\x00\x02\x00\x02\xc0")
        && h.at(15, b"HBAM")
}

declare_format!(pub FILEMAKER = "filemaker", "FileMaker Pro database", ["fp7", "fmp12", "fp5"], "application/x-filemaker",
    Probe::Custom(filemaker_probe), filemaker);

async fn filemaker(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 1024)).await?;
    cx.emit(Node::new("Signature").span(file.sub(0, 15)));
    let kind = String::from_utf8_lossy(head.get(15..20).unwrap_or_default()).into_owned();
    cx.emit(
        Node::new("Format")
            .span(file.sub(15, 5))
            .value(text(kind.clone())),
    );
    // A Pascal-string application version sits in the first block.
    let version = head
        .windows(4)
        .position(|w| w == b"Pro " || w == b"Fil ")
        .and_then(|p| head.get(p..).map(|r| zstr(r.get(..32).unwrap_or_default())))
        .unwrap_or_default();
    if !version.is_empty() {
        cx.emit(Node::new("Application").value(text(version.clone())));
    }
    cx.emit(
        Node::new("Blocks")
            .span(file.tail(1024))
            .summary("4 KiB blocks"),
    );
    cx.annotate(format!(
        "FileMaker {kind} database{}",
        if version.is_empty() {
            String::new()
        } else {
            format!(" ({version})")
        }
    ));
    Ok(())
}
