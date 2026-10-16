//! MSBuild binary logs (`.binlog`, `dotnet build -bl`, `msbuild -bl`).
//!
//! A binlog is a gzip stream; the format registered here is what it
//! holds (the gzip dissector hands the decompressed stream over by
//! content; a `.binlog` opened as this format is decompressed first). The
//! stream starts with the file format version and, since version 18, the
//! minimum reader version (32-bit little-endian), then records: a kind
//! and, since version 18, the length of the rest, as 7-bit encoded
//! integers (LEB128). String records define deduplicated strings, numbered
//! from 10 in order (0 is null, 1 the empty string); name-value list
//! records define lists of string pairs (properties, metadata), numbered
//! from 10 too; a project import archive record holds a ZIP of the project
//! files the build read. Every other record is a build event: a flags
//! word saying which common fields follow (message, build event context,
//! thread, sender, timestamp, code, file and positions, arguments,
//! importance), then fields of its own kind.
//!
//! Records are listed in pages; strings and lists are resolved through an
//! index of the string and list records seen so far, built as the listing
//! goes (and extended on demand for records expanded out of order). The
//! fields of the common event kinds are decoded; a record whose decoding
//! does not end exactly at its length says so.
//!
//! Layout from MSBuild's `BinaryLogger`, `BuildEventArgsReader` and
//! `BinaryLogRecordKind` (MIT, dotnet/msbuild), checked against logs that
//! MSBuild 17.11 (.NET SDK 8.0.425) wrote. Versions before 18 have no
//! record lengths, so records cannot be skipped without decoding every
//! kind exactly; only their header is shown. Timestamps are shown with
//! their `DateTimeKind`: events carry the machine's local time, whose
//! zone the log does not record (checked on a log written with
//! `TZ=Asia/Tokyo`). The numbering of the enums `TargetBuiltReason`,
//! `TargetSkipReason`, `TaskParameterMessageKind` and
//! `AssemblyLoadingContext` is from memory, consistent with the values
//! the fixtures hold.

use std::sync::{Arc, Mutex};

use crate::bytes::{to_u64, to_usize, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::binutil::Reader;
use crate::formats::util::fmt::{clip, plural};
use crate::formats::{Codec, Format, Head, Input, Probe, embedded};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Time, Value, Zone};

const LE: Endian = Endian::Little;
/// The first version with record lengths.
const MIN_VERSION: u32 = 18;
/// String records are numbered from this index (as are name-value lists).
const FIRST_INDEX: u64 = 10;
/// Largest record decoded in memory.
const MAX_RECORD: u64 = 16 << 20;
/// Characters of a string shown.
const TEXT_MAX: usize = 1024;
/// Bytes of a string read (UTF-8 can take four per character).
const TEXT_BYTES: u64 = 4096;

pub static FORMAT: Format = Format {
    name: "msbuild-binlog",
    title: "MSBuild binary log",
    extensions: &["binlog"],
    mime: "application/x-msbuild-binlog",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

/// The decompressed record stream: a version from 18 on, a minimum reader
/// version from 18 to the version, then a string record (MSBuild writes
/// the strings an event uses before it, so a log starts with one) whose
/// text is printable UTF-8, and records whose kinds are known and whose
/// framing holds as far as the probe window goes.
fn probe(h: &Head<'_>) -> bool {
    let d = h.data;
    let (Some(version), Some(min)) = (u32_le(d, 0), u32_le(d, 4)) else {
        return false;
    };
    if !(MIN_VERSION..=63).contains(&version) || !(MIN_VERSION..=version).contains(&min) {
        return false;
    }
    let mut r = Reader::at(d, 8);
    if r.uleb() != Some(K_STRING) {
        return false;
    }
    let Some(first) = r
        .uleb()
        .and_then(|l| usize::try_from(l).ok())
        .filter(|&l| (1..=4096).contains(&l))
        .and_then(|l| r.bytes(l))
    else {
        return false;
    };
    let printable = std::str::from_utf8(first).is_ok_and(|s| {
        s.chars()
            .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
    });
    if !printable {
        return false;
    }
    let mut records = 1u32;
    while records < 16 && !r.at_end() {
        let Some(kind) = r.uleb() else {
            return true;
        };
        if kind == 0 {
            return true;
        }
        if kind > 63 {
            return false;
        }
        let Some(len) = r.uleb().and_then(|l| usize::try_from(l).ok()) else {
            return true;
        };
        match r.bytes(len) {
            Some(b) => {
                if kind == K_STRING && std::str::from_utf8(b).is_err() {
                    return false;
                }
            }
            // The record runs past the probe window (or the file). With
            // the length unknown, `h.len` is only an upper bound: a head
            // shorter than the window is all there is.
            None => {
                let more = if h.len_known {
                    to_u64(d.len()) < h.len
                } else {
                    to_u64(d.len()) >= crate::formats::HEAD_LEN
                };
                return more || records > 1;
            }
        }
        records = records.saturating_add(1);
    }
    records >= 2
}

const KIND: EnumTable = &[
    (0, "EndOfFile"),
    (1, "BuildStarted"),
    (2, "BuildFinished"),
    (3, "ProjectStarted"),
    (4, "ProjectFinished"),
    (5, "TargetStarted"),
    (6, "TargetFinished"),
    (7, "TaskStarted"),
    (8, "TaskFinished"),
    (9, "Error"),
    (10, "Warning"),
    (11, "Message"),
    (12, "TaskCommandLine"),
    (13, "CriticalBuildMessage"),
    (14, "ProjectEvaluationStarted"),
    (15, "ProjectEvaluationFinished"),
    (16, "ProjectImported"),
    (17, "ProjectImportArchive"),
    (18, "TargetSkipped"),
    (19, "PropertyReassignment"),
    (20, "UninitializedPropertyRead"),
    (21, "EnvironmentVariableRead"),
    (22, "PropertyInitialValueSet"),
    (23, "NameValueList"),
    (24, "String"),
    (25, "TaskParameter"),
    (26, "ResponseFileUsed"),
    (27, "AssemblyLoad"),
    (28, "BuildCheckMessage"),
    (29, "BuildCheckWarning"),
    (30, "BuildCheckError"),
    (31, "BuildCheckTracing"),
    (32, "BuildCheckAcquisition"),
    (33, "BuildSubmissionStarted"),
    (34, "BuildCanceled"),
    (35, "LoggersRegistered"),
    (36, "MSBuildServerLifecycle"),
    (37, "AssemblyResolutionSearchTrace"),
    (38, "AssemblyConflictDependencyDetails"),
    (39, "AssemblyConflictWarning"),
];

const K_STRING: u64 = 24;
const K_LIST: u64 = 23;
const K_ARCHIVE: u64 = 17;

const FIELD_FLAGS: crate::value::FlagTable = &[
    crate::value::flag(1 << 0, "BuildEventContext"),
    crate::value::flag(1 << 1, "HelpKeyword"),
    crate::value::flag(1 << 2, "Message"),
    crate::value::flag(1 << 3, "SenderName"),
    crate::value::flag(1 << 4, "ThreadId"),
    crate::value::flag(1 << 5, "Timestamp"),
    crate::value::flag(1 << 6, "Subcategory"),
    crate::value::flag(1 << 7, "Code"),
    crate::value::flag(1 << 8, "File"),
    crate::value::flag(1 << 9, "ProjectFile"),
    crate::value::flag(1 << 10, "LineNumber"),
    crate::value::flag(1 << 11, "ColumnNumber"),
    crate::value::flag(1 << 12, "EndLineNumber"),
    crate::value::flag(1 << 13, "EndColumnNumber"),
    crate::value::flag(1 << 14, "Arguments"),
    crate::value::flag(1 << 15, "Importance"),
    crate::value::flag(1 << 16, "Extended"),
];

const IMPORTANCE: EnumTable = &[(0, "High"), (1, "Normal"), (2, "Low")];
/// `TargetBuiltReason` (Microsoft.Build.Framework; numbering from memory,
/// consistent with the fixtures: a target built through `DependsOnTargets`
/// says 2).
const BUILT_REASON: EnumTable = &[
    (0, "None"),
    (1, "BeforeTargets"),
    (2, "DependsOn"),
    (3, "AfterTargets"),
];
/// `TargetSkipReason` (numbering from memory).
const SKIP_REASON: EnumTable = &[
    (0, "None"),
    (1, "PreviouslyBuiltSuccessfully"),
    (2, "PreviouslyBuiltUnsuccessfully"),
    (3, "OutputsUpToDate"),
    (4, "ConditionWasFalse"),
];
/// `TaskParameterMessageKind` (numbering from memory, consistent with the
/// fixtures: a task's inputs say 0).
const PARAMETER_KIND: EnumTable = &[
    (0, "TaskInput"),
    (1, "TaskOutput"),
    (2, "AddItem"),
    (3, "RemoveItem"),
    (4, "SkippedTargetInputs"),
    (5, "SkippedTargetOutputs"),
];
/// `AssemblyLoadingContext` (numbering from memory, consistent with the
/// fixtures: loads during evaluation say 1).
const LOADING_CONTEXT: EnumTable = &[
    (0, "TaskRun"),
    (1, "Evaluation"),
    (2, "SdkResolution"),
    (3, "LoggerInitialization"),
];

// ---------------------------------------------------------------------------
// String and list index

/// The string and name-value list records seen so far: offsets and
/// lengths of their bodies in the stream, in order.
#[derive(Default)]
struct Table {
    /// The stream position up to which records were scanned.
    scanned: u64,
    strings: Vec<(u64, u32)>,
    lists: Vec<(u64, u32)>,
}

#[derive(Default)]
struct Index(Mutex<Table>);

impl Index {
    fn lock(&self) -> std::sync::MutexGuard<'_, Table> {
        match self.0.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Ctx {
    input: Input,
    version: u32,
}

/// The index, scanned at least up to `upto` (a record start).
async fn index_upto(cx: &Cx, ctx: &Ctx, upto: u64) -> Result<Arc<Index>> {
    let stream = ctx.input.span;
    let index = match cx.cached::<Index>(stream, "binlog-strings") {
        Some(i) => i,
        None => {
            let i = Arc::new(Index::default());
            i.lock().scanned = 8;
            cx.cache(stream, "binlog-strings", i.clone());
            i
        }
    };
    let start = index.lock().scanned;
    if start >= upto {
        return Ok(index);
    }
    let mut pos = start;
    let mut strings = Vec::new();
    let mut lists = Vec::new();
    while pos < upto {
        let Ok(rec) = read_record(cx, stream, pos).await else {
            break;
        };
        match rec.kind {
            K_STRING => strings.push((
                rec.body.offset,
                u32::try_from(rec.body.len).unwrap_or(u32::MAX),
            )),
            K_LIST => lists.push((
                rec.body.offset,
                u32::try_from(rec.body.len).unwrap_or(u32::MAX),
            )),
            0 => break,
            _ => {}
        }
        let next = rec.end;
        if next <= pos {
            break;
        }
        pos = next;
        if strings.len().is_multiple_of(1024) {
            cx.checkpoint().await;
        }
    }
    {
        let mut t = index.lock();
        // Another expansion may have extended it meanwhile.
        if t.scanned == start {
            t.strings.extend(strings);
            t.lists.extend(lists);
            t.scanned = pos;
        }
    }
    Ok(index)
}

/// String `i` (null for 0, empty for 1), read from the stream.
async fn string(cx: &Cx, ctx: &Ctx, index: &Index, i: u64) -> Result<Option<String>> {
    if i == 0 {
        return Ok(None);
    }
    if i == 1 {
        return Ok(Some(String::new()));
    }
    let entry = {
        let t = index.lock();
        i.checked_sub(FIRST_INDEX)
            .and_then(|k| t.strings.get(to_usize(k)).copied())
    };
    let Some((off, len)) = entry else {
        return Ok(Some(format!("<string #{i} not defined>")));
    };
    let span = Span::new(ctx.input.span.source, off, u64::from(len).min(TEXT_BYTES));
    let bytes = cx.read(span).await?;
    let s = String::from_utf8_lossy(&bytes);
    Ok(Some(clip(&s, TEXT_MAX)))
}

fn list_span(ctx: &Ctx, index: &Index, i: u64) -> Option<Span> {
    let t = index.lock();
    let (off, len) = t
        .lists
        .get(to_usize(i.checked_sub(FIRST_INDEX)?))
        .copied()?;
    Some(Span::new(ctx.input.span.source, off, len.into()))
}

// ---------------------------------------------------------------------------
// Records

#[derive(Clone, Copy, Debug)]
struct Record {
    kind: u64,
    /// The record, from its kind.
    span: Span,
    /// After the kind and length.
    body: Span,
    end: u64,
}

/// Reads the record framing at `pos` (relative to the stream).
async fn read_record(cx: &Cx, stream: Span, pos: u64) -> Result<Record> {
    let h = cx.read(stream.sub(pos, 20)).await?;
    let mut r = Reader::new(&h);
    let kind = r
        .uleb()
        .ok_or_else(|| Diagnostic::truncated(stream.sub(pos, 1), 0))?;
    if kind == 0 {
        let span = stream.sub(pos, to_u64(r.pos()));
        return Ok(Record {
            kind,
            span,
            body: stream.sub(pos.saturating_add(to_u64(r.pos())), 0),
            end: pos.saturating_add(to_u64(r.pos())),
        });
    }
    let len = r.uleb().ok_or_else(|| {
        Diagnostic::malformed("record length cut short").at(stream.sub(pos, to_u64(h.len())))
    })?;
    let body_at = pos.saturating_add(to_u64(r.pos()));
    let body = stream.sub_exact(body_at, len)?;
    let end = body_at.saturating_add(len);
    Ok(Record {
        kind,
        span: stream.sub(pos, end.saturating_sub(pos)),
        body,
        end,
    })
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let stream = input.span;
    let head = cx.read(stream.sub(0, 8)).await?;
    if head.starts_with(&[0x1f, 0x8b]) {
        // The .binlog file itself: decompress, then dissect the records.
        cx.emit(
            crate::formats::content_named(
                "Records",
                input,
                stream,
                Codec::Gzip,
                None,
                "msbuild-binlog",
            )
            .summary("gzip-compressed record stream"),
        );
        cx.annotate("MSBuild binary log (gzip)");
        return Ok(());
    }
    let version = u32_le(&head, 0).unwrap_or(0);
    let hlen = if version >= MIN_VERSION { 8 } else { 4 };
    cx.emit(struct_node(
        "Header",
        stream.sub(0, hlen),
        LE,
        version,
        |f: &mut Fields<'_>, &v: &u32| {
            f.u32("FileFormatVersion").emit()?;
            if v >= MIN_VERSION {
                f.u32("MinimumReaderVersion")
                    .desc("Oldest reader version that can read this log")
                    .emit()?;
            }
            Ok(())
        },
    ));
    if version < MIN_VERSION {
        cx.emit(
            Node::new("Records")
                .span(stream.tail(hlen))
                .diag(Diagnostic::unsupported(format!(
                    "binlog format {version}: records have no lengths before version 18"
                ))),
        );
        cx.annotate(format!("MSBuild binary log, format {version}"));
        return Ok(());
    }
    let ctx = Ctx { input, version };
    cx.emit(Node::new("Records").span(stream.tail(8)).lazy(records, ctx));
    let msbuild = match msbuild_version(&cx, stream).await? {
        Some(v) => format!("MSBuild {v}, "),
        None => String::new(),
    };
    let result = match build_result(&cx, &ctx).await? {
        Some(r) => format!("build {r}, "),
        None => String::new(),
    };
    cx.annotate(format!(
        "MSBuild binary log, {msbuild}{result}format {version}"
    ));
    Ok(())
}

/// Logs whose records are walked for the build's result.
const RESULT_SCAN: u64 = 64 << 20;

/// Whether the build succeeded, from its BuildFinished record near the
/// end: only for a log already decoded (or read from the host), so
/// reaching the end does not decode the whole stream just for this.
async fn build_result(cx: &Cx, ctx: &Ctx) -> Result<Option<&'static str>> {
    let stream = ctx.input.span;
    if stream.len > RESULT_SCAN || !cx.read_is_cheap(stream) {
        return Ok(None);
    }
    let mut pos = 8u64;
    let mut n = 0u32;
    while pos < stream.len {
        let Ok(rec) = read_record(cx, stream, pos).await else {
            return Ok(None);
        };
        if rec.kind == 0 || rec.end <= pos {
            return Ok(None);
        }
        if rec.kind == 2 {
            let index = index_upto(cx, ctx, pos).await?;
            let summary = event_summary(cx, ctx, &index, rec).await?;
            return Ok(if summary.ends_with("(succeeded)") {
                Some("succeeded")
            } else if summary.ends_with("(failed)") {
                Some("failed")
            } else {
                None
            });
        }
        pos = rec.end;
        n = n.wrapping_add(1);
        if n.is_multiple_of(256) {
            cx.checkpoint().await;
        }
    }
    Ok(None)
}

/// The MSBuild version the log names in its first records (the message
/// `MSBuild version = "17.11.48+02bf66295"`, without the commit), if
/// the start of the stream has it.
async fn msbuild_version(cx: &Cx, stream: Span) -> Result<Option<String>> {
    const PREFIX: &[u8] = b"MSBuild version = \"";
    let head = cx.read(stream.sub(8, 64 * 1024)).await?;
    let mut r = Reader::new(&head);
    for _ in 0..256 {
        let (Some(kind), Some(len)) = (r.uleb(), r.uleb()) else {
            break;
        };
        let Some(body) = usize::try_from(len).ok().and_then(|l| r.bytes(l)) else {
            break;
        };
        if kind == 0 {
            break;
        }
        if kind == K_STRING
            && let Some(rest) = body.strip_prefix(PREFIX)
        {
            let v = rest
                .iter()
                .take_while(|&&b| b.is_ascii_graphic() && b != b'"' && b != b'+')
                .map(|&b| char::from(b))
                .collect::<String>();
            if !v.is_empty() && v.len() <= 64 {
                return Ok(Some(v));
            }
        }
    }
    Ok(None)
}

/// The record listing: strings, lists, the archive and events.
async fn records(cx: Cx, ctx: Ctx) -> Result<()> {
    let stream = ctx.input.span;
    let (mut pos, mut strings, mut lists) = cx.resume::<(u64, u64, u64)>().unwrap_or((8, 0, 0));
    while pos < stream.len {
        let at = (pos, strings, lists);
        cx.mark(move || at);
        cx.progress_in(stream, pos);
        let rec = match read_record(&cx, stream, pos).await {
            Ok(r) => r,
            Err(e) => {
                cx.diag(e);
                break;
            }
        };
        let index = index_upto(&cx, &ctx, pos).await?;
        let kind_name = crate::value::lookup(KIND, rec.kind).unwrap_or("Unknown record");
        let node = match rec.kind {
            0 => Node::new("EndOfFile").span(rec.span),
            K_STRING => {
                let id = FIRST_INDEX.saturating_add(strings);
                strings = strings.saturating_add(1);
                let bytes = cx.read(rec.body.sub(0, TEXT_BYTES)).await?;
                Node::new(format!("String {id}"))
                    .span(rec.span)
                    .value(Value::Text(clip(
                        &String::from_utf8_lossy(&bytes),
                        TEXT_MAX,
                    )))
            }
            K_LIST => {
                let id = FIRST_INDEX.saturating_add(lists);
                lists = lists.saturating_add(1);
                let count = cx
                    .read(rec.body.sub(0, 10))
                    .await
                    .ok()
                    .and_then(|b| crate::bytes::uleb128(&b).map(|(v, _)| v))
                    .unwrap_or(0);
                Node::new(format!("NameValueList {id}"))
                    .span(rec.span)
                    .summary(plural(count, "pair"))
                    .lazy(list_record, (ctx, rec, pos))
            }
            K_ARCHIVE => Node::new("ProjectImportArchive")
                .span(rec.span)
                .summary(format!(
                    "ZIP of the project files read, {} bytes",
                    rec.body.len
                ))
                .lazy(archive, (ctx, rec)),
            _ => {
                let summary = event_summary(&cx, &ctx, &index, rec).await?;
                let mut node = Node::new(kind_name).span(rec.span);
                if !summary.is_empty() {
                    node = node.summary(summary);
                }
                node.lazy(event, (ctx, rec, pos))
            }
        };
        cx.push(node).await;
        if rec.kind == 0 {
            if rec.end < stream.len {
                cx.diag(
                    Diagnostic::note(format!(
                        "{} bytes after the end of the log",
                        stream.len.saturating_sub(rec.end)
                    ))
                    .at(stream.tail(rec.end)),
                );
            }
            break;
        }
        if rec.end <= pos {
            break;
        }
        pos = rec.end;
    }
    Ok(())
}

async fn archive(cx: Cx, (ctx, rec): (Ctx, Record)) -> Result<()> {
    let head_len = rec.body.offset.saturating_sub(rec.span.offset);
    cx.emit(framing(rec, head_len));
    cx.emit(
        embedded("Archive", ctx.input.nested(rec.body)).summary(format!("{} bytes", rec.body.len)),
    );
    Ok(())
}

/// The kind and length of a record.
fn framing(rec: Record, head_len: u64) -> Node {
    Node::new("Kind and length")
        .span(rec.span.sub(0, head_len))
        .value(Value::Enum {
            raw: rec.kind,
            bits: 32,
            name: crate::value::lookup(KIND, rec.kind).map(Into::into),
        })
        .summary(format!("{} bytes follow", rec.body.len))
}

async fn list_record(cx: Cx, (ctx, rec, pos): (Ctx, Record, u64)) -> Result<()> {
    let index = index_upto(&cx, &ctx, pos).await?;
    let head_len = rec.body.offset.saturating_sub(rec.span.offset);
    cx.emit(framing(rec, head_len));
    pairs(&cx, &ctx, &index, rec.body).await
}

/// The pairs of a name-value list body (a count, then key and value
/// string indexes).
async fn pairs(cx: &Cx, ctx: &Ctx, index: &Index, body: Span) -> Result<()> {
    if body.len > MAX_RECORD {
        return Err(Diagnostic::limit("name-value list too large to show").at(body));
    }
    let b = cx.read(body).await?;
    let mut r = Reader::new(&b);
    let count = r.uleb().unwrap_or(0);
    let mut i = 0u64;
    while i < count && !r.at_end() {
        let s = r.pos();
        let (Some(k), Some(v)) = (r.uleb(), r.uleb()) else {
            cx.diag(Diagnostic::truncated(body.tail(to_u64(s)), 0));
            break;
        };
        let key = string(cx, ctx, index, k).await?.unwrap_or_default();
        let value = string(cx, ctx, index, v).await?;
        cx.push(
            Node::new(if key.is_empty() {
                format!("[{i}]")
            } else {
                key
            })
            .span(body.sub(to_u64(s), to_u64(r.pos().saturating_sub(s))))
            .value(match value {
                Some(v) => Value::Text(v),
                None => Value::Text("(null)".into()),
            }),
        )
        .await;
        i = i.saturating_add(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Events

/// How a field of an event is encoded.
#[derive(Clone, Copy, Debug)]
enum Ty {
    /// A string index.
    Str,
    Bool,
    Int,
    /// An integer naming a value of the table.
    Enum(EnumTable),
    /// A name-value list index (0: none).
    List,
    /// A flag, then a build event context (7-bit integers) if set.
    OptContext,
    /// A flag, then a build event context of fixed 32-bit integers if set.
    OptContextFixed,
    Guid,
    /// A count, then items: a string and a name-value list each.
    Items,
    /// Item types, each followed by its items, until an empty type.
    ProjectItems,
}

/// An event kind's own fields: name, type, first format version.
type Schema = &'static [(&'static str, Ty, u32)];

fn schema(kind: u64) -> Option<Schema> {
    use Ty::*;
    Some(match kind {
        1 => &[("BuildEnvironment", List, 0)],
        2 => &[("Succeeded", Bool, 0)],
        3 => &[
            ("ParentProjectBuildEventContext", OptContext, 0),
            ("ProjectFile", Str, 0),
            ("ProjectId", Int, 0),
            ("TargetNames", Str, 0),
            ("ToolsVersion", Str, 0),
            ("GlobalProperties", List, 0),
            ("Properties", List, 0),
            ("Items", ProjectItems, 0),
        ],
        4 => &[("ProjectFile", Str, 0), ("Succeeded", Bool, 0)],
        5 => &[
            ("TargetName", Str, 0),
            ("ProjectFile", Str, 0),
            ("TargetFile", Str, 0),
            ("ParentTarget", Str, 0),
            ("BuildReason", Enum(BUILT_REASON), 0),
        ],
        6 => &[
            ("Succeeded", Bool, 0),
            ("ProjectFile", Str, 0),
            ("TargetFile", Str, 0),
            ("TargetName", Str, 0),
            ("TargetOutputs", Items, 0),
        ],
        7 => &[
            ("TaskName", Str, 0),
            ("ProjectFile", Str, 0),
            ("TaskFile", Str, 0),
            ("TaskAssemblyLocation", Str, 20),
        ],
        8 => &[
            ("Succeeded", Bool, 0),
            ("TaskName", Str, 0),
            ("ProjectFile", Str, 0),
            ("TaskFile", Str, 0),
        ],
        9 | 10 => &[
            ("Subcategory", Str, 0),
            ("Code", Str, 0),
            ("File", Str, 0),
            ("ProjectFile", Str, 0),
            ("LineNumber", Int, 0),
            ("ColumnNumber", Int, 0),
            ("EndLineNumber", Int, 0),
            ("EndColumnNumber", Int, 0),
        ],
        11 | 13 => &[],
        12 => &[("CommandLine", Str, 0), ("TaskName", Str, 0)],
        14 => &[("ProjectFile", Str, 0)],
        15 => &[
            ("ProjectFile", Str, 0),
            ("GlobalProperties", List, 0),
            ("Properties", List, 0),
            ("Items", ProjectItems, 0),
            ("HasProfileData", Bool, 0),
        ],
        16 => &[
            ("ImportIgnored", Bool, 0),
            ("ImportedProjectFile", Str, 0),
            ("UnexpandedProject", Str, 0),
        ],
        18 => &[
            ("TargetFile", Str, 0),
            ("TargetName", Str, 0),
            ("ParentTarget", Str, 0),
            ("Condition", Str, 0),
            ("EvaluatedCondition", Str, 0),
            ("OriginallySucceeded", Bool, 0),
            ("BuildReason", Enum(BUILT_REASON), 0),
            ("SkipReason", Enum(SKIP_REASON), 0),
            ("OriginalBuildEventContext", OptContextFixed, 0),
        ],
        19 => &[
            ("PropertyName", Str, 0),
            ("PreviousValue", Str, 0),
            ("NewValue", Str, 0),
            ("Location", Str, 0),
        ],
        20 => &[("PropertyName", Str, 0)],
        21 => &[
            ("EnvironmentVariableName", Str, 0),
            ("Line", Int, 22),
            ("Column", Int, 22),
            ("File", Str, 22),
        ],
        22 => &[
            ("PropertyName", Str, 0),
            ("PropertyValue", Str, 0),
            ("PropertySource", Str, 0),
        ],
        25 => &[
            ("Kind", Enum(PARAMETER_KIND), 0),
            ("ItemType", Str, 0),
            ("Items", Items, 0),
            ("ParameterName", Str, 21),
            ("PropertyName", Str, 21),
        ],
        26 => &[("ResponseFilePath", Str, 0)],
        27 => &[
            ("LoadingContext", Enum(LOADING_CONTEXT), 0),
            ("LoadingInitiator", Str, 0),
            ("AssemblyName", Str, 0),
            ("AssemblyPath", Str, 0),
            ("MVID", Guid, 0),
            ("AppDomainName", Str, 0),
        ],
        34 => &[],
        _ => return None,
    })
}

/// A decoded field: label, offset and length in the record body, value,
/// and what it refers to (a name-value list, or items).
#[derive(Clone, Debug)]
struct Item {
    label: String,
    off: usize,
    len: usize,
    value: Value,
    /// A name-value list to expand, by index.
    list: Option<u64>,
}

/// What decoding a record found: the common fields, the kind's fields, and
/// how far it got.
struct Decoded {
    items: Vec<Item>,
    message: Option<String>,
    /// Bytes decoded; equal to the body length when all went well.
    used: usize,
    complete: bool,
}

const TICKS_AT_UNIX_EPOCH: i64 = 621_355_968_000_000_000;

/// A .NET `DateTime` as MSBuild writes it (ticks of 100 ns since
/// 0001-01-01, then its `DateTimeKind`), to the tick. Events carry local
/// time (`BuildEventArgs.Timestamp` converts to it), so the kind says
/// whether the clock is UTC: 1 is, 2 is the machine's local time (its zone
/// is not recorded), 0 is unspecified (shown as a local time too).
fn timestamp(ticks: i64, kind: u64) -> Value {
    let since = ticks.saturating_sub(TICKS_AT_UNIX_EPOCH);
    let t = Time::utc(since.div_euclid(10_000_000)).frac(
        u32::try_from(since.rem_euclid(10_000_000))
            .unwrap_or(0)
            .saturating_mul(100),
        7,
    );
    match kind {
        1 => Value::Timestamp(t),
        0 | 2 => Value::Timestamp(Time {
            zone: Zone::Local,
            ..t
        }),
        k => Value::Text(format!("{} (DateTimeKind {k})", t.iso8601())),
    }
}

/// Decodes a record body: the common fields, then the kind's own.
async fn decode(cx: &Cx, ctx: &Ctx, index: &Index, kind: u64, body: &[u8]) -> Result<Decoded> {
    let mut r = Reader::new(body);
    let mut items = Vec::new();
    let mut message = None;
    macro_rules! push {
        ($label:expr, $s:expr, $value:expr) => {
            items.push(Item {
                label: $label.into(),
                off: $s,
                len: r.pos().saturating_sub($s),
                value: $value,
                list: None,
            })
        };
    }
    let fail = |items: Vec<Item>, message: Option<String>, used: usize| Decoded {
        items,
        message,
        used,
        complete: false,
    };
    let s = r.pos();
    let Some(flags) = r.uleb() else {
        return Ok(fail(items, message, 0));
    };
    push!(
        "Flags",
        s,
        crate::formats::util::val::flagsv(flags, 32, FIELD_FLAGS)
    );
    let has = |bit: u32| flags & (1u64 << bit) != 0;
    // Base fields, in the order the reader takes them.
    if has(2) {
        let s = r.pos();
        let Some(i) = r.uleb() else {
            return Ok(fail(items, message, s));
        };
        message = string(cx, ctx, index, i).await?;
        push!("Message", s, text_or_null(message.clone()));
    }
    if has(0) {
        let s = r.pos();
        let mut parts = Vec::new();
        for _ in 0..7 {
            let Some(v) = r.uleb() else {
                return Ok(fail(items, message, s));
            };
            parts.push(i32::from_ne_bytes((v as u32).to_ne_bytes()));
        }
        push!(
            "BuildEventContext",
            s,
            Value::Text(format!(
                "node {}, project context {}, target {}, task {}, submission {}, project instance {}, evaluation {}",
                parts.first().copied().unwrap_or(0),
                parts.get(1).copied().unwrap_or(0),
                parts.get(2).copied().unwrap_or(0),
                parts.get(3).copied().unwrap_or(0),
                parts.get(4).copied().unwrap_or(0),
                parts.get(5).copied().unwrap_or(0),
                parts.get(6).copied().unwrap_or(0)
            ))
        );
    }
    if has(4) {
        let s = r.pos();
        let Some(v) = r.uleb() else {
            return Ok(fail(items, message, s));
        };
        push!("ThreadId", s, uint(v));
    }
    if has(1) {
        let s = r.pos();
        let Some(i) = r.uleb() else {
            return Ok(fail(items, message, s));
        };
        let v = string(cx, ctx, index, i).await?;
        push!("HelpKeyword", s, text_or_null(v));
    }
    if has(3) {
        let s = r.pos();
        let Some(i) = r.uleb() else {
            return Ok(fail(items, message, s));
        };
        let v = string(cx, ctx, index, i).await?;
        push!("SenderName", s, text_or_null(v));
    }
    if has(5) {
        let s = r.pos();
        let (Some(ticks), Some(kind)) = (r.int::<i64>(LE), r.uleb()) else {
            return Ok(fail(items, message, s));
        };
        push!("Timestamp", s, timestamp(ticks, kind));
    }
    if has(16) {
        let s = r.pos();
        let (Some(t), Some(m), Some(d)) = (r.uleb(), r.uleb(), r.uleb()) else {
            return Ok(fail(items, message, s));
        };
        let t = string(cx, ctx, index, t).await?;
        let d = string(cx, ctx, index, d).await?;
        push!(
            "Extended",
            s,
            Value::Text(format!(
                "type {}, data {}",
                t.unwrap_or_default(),
                d.unwrap_or_default()
            ))
        );
        if m != 0
            && let Some(last) = items.last_mut()
        {
            last.list = Some(m);
        }
    }
    for (bit, name) in [
        (6, "Subcategory"),
        (7, "Code"),
        (8, "File"),
        (9, "ProjectFile"),
    ] {
        if has(bit) {
            let s = r.pos();
            let Some(i) = r.uleb() else {
                return Ok(fail(items, message, s));
            };
            let v = string(cx, ctx, index, i).await?;
            push!(name, s, text_or_null(v));
        }
    }
    for (bit, name) in [
        (10, "LineNumber"),
        (11, "ColumnNumber"),
        (12, "EndLineNumber"),
        (13, "EndColumnNumber"),
    ] {
        if has(bit) {
            let s = r.pos();
            let Some(v) = r.uleb() else {
                return Ok(fail(items, message, s));
            };
            push!(name, s, uint(v));
        }
    }
    if has(14) {
        let s = r.pos();
        let Some(n) = r.uleb() else {
            return Ok(fail(items, message, s));
        };
        push!("Arguments", s, uint(n));
        for k in 0..n.min(4096) {
            let s = r.pos();
            let Some(i) = r.uleb() else {
                return Ok(fail(items, message, s));
            };
            let v = string(cx, ctx, index, i).await?;
            push!(format!("Argument {k}"), s, text_or_null(v));
        }
    }
    if has(15) {
        let s = r.pos();
        let Some(v) = r.uleb() else {
            return Ok(fail(items, message, s));
        };
        push!(
            "Importance",
            s,
            Value::Enum {
                raw: v,
                bits: 32,
                name: crate::value::lookup(IMPORTANCE, v).map(Into::into),
            }
        );
    }
    let Some(fields) = schema(kind) else {
        let used = r.pos();
        return Ok(Decoded {
            items,
            message,
            used,
            complete: false,
        });
    };
    for &(name, ty, since) in fields {
        if ctx.version < since {
            continue;
        }
        let s = r.pos();
        match ty {
            Ty::Str => {
                let Some(i) = r.uleb() else {
                    return Ok(fail(items, message, s));
                };
                let v = string(cx, ctx, index, i).await?;
                push!(name, s, text_or_null(v));
            }
            Ty::Bool => {
                let Some(b) = r.u8() else {
                    return Ok(fail(items, message, s));
                };
                push!(name, s, Value::Bool(b != 0));
                if name == "HasProfileData" && b != 0 {
                    // Profiler data: not decoded.
                    let used = r.pos();
                    return Ok(Decoded {
                        items,
                        message,
                        used,
                        complete: false,
                    });
                }
            }
            Ty::Int => {
                let Some(v) = r.uleb() else {
                    return Ok(fail(items, message, s));
                };
                push!(name, s, uint(v));
            }
            Ty::Enum(table) => {
                let Some(v) = r.uleb() else {
                    return Ok(fail(items, message, s));
                };
                push!(
                    name,
                    s,
                    Value::Enum {
                        raw: v,
                        bits: 32,
                        name: crate::value::lookup(table, v).map(Into::into),
                    }
                );
            }
            Ty::List => {
                let Some(i) = r.uleb() else {
                    return Ok(fail(items, message, s));
                };
                push!(
                    name,
                    s,
                    if i == 0 {
                        Value::Text("(none)".into())
                    } else {
                        uint(i)
                    }
                );
                if i != 0
                    && let Some(last) = items.last_mut()
                {
                    last.list = Some(i);
                    last.value = Value::Text(format!("name-value list {i}"));
                }
            }
            Ty::OptContext | Ty::OptContextFixed => {
                let Some(b) = r.u8() else {
                    return Ok(fail(items, message, s));
                };
                let fixed = matches!(ty, Ty::OptContextFixed);
                if b != 0 {
                    for _ in 0..7 {
                        let ok = if fixed {
                            r.int::<i32>(LE).is_some()
                        } else {
                            r.uleb().is_some()
                        };
                        if !ok {
                            return Ok(fail(items, message, s));
                        }
                    }
                }
                push!(
                    name,
                    s,
                    Value::Text(if b != 0 {
                        "present".into()
                    } else {
                        "none".into()
                    })
                );
            }
            Ty::Guid => {
                let Some(g) = r.bytes(16) else {
                    return Ok(fail(items, message, s));
                };
                // System.Guid's byte layout: three little-endian fields,
                // then eight bytes as they are.
                push!(name, s, Value::guid(g));
            }
            Ty::Items => {
                let Some(n) = r.uleb() else {
                    return Ok(fail(items, message, s));
                };
                push!(name, s, uint(n));
                for k in 0..n.min(1 << 20) {
                    let s = r.pos();
                    let (Some(spec), Some(list)) = (r.uleb(), r.uleb()) else {
                        return Ok(fail(items, message, s));
                    };
                    let spec = string(cx, ctx, index, spec).await?;
                    push!(format!("{name}[{k}]"), s, text_or_null(spec));
                    if list != 0
                        && let Some(last) = items.last_mut()
                    {
                        last.list = Some(list);
                    }
                    if k.is_multiple_of(256) {
                        cx.checkpoint().await;
                    }
                }
            }
            Ty::ProjectItems => loop {
                let s = r.pos();
                let Some(t) = r.uleb() else {
                    return Ok(fail(items, message, s));
                };
                let ty_name = string(cx, ctx, index, t).await?.unwrap_or_default();
                if ty_name.is_empty() {
                    push!("End of items", s, Value::Text(String::new()));
                    break;
                }
                let Some(n) = r.uleb() else {
                    return Ok(fail(items, message, s));
                };
                push!(format!("Item type {ty_name}"), s, uint(n));
                for k in 0..n.min(1 << 20) {
                    let s = r.pos();
                    let (Some(spec), Some(list)) = (r.uleb(), r.uleb()) else {
                        return Ok(fail(items, message, s));
                    };
                    let spec = string(cx, ctx, index, spec).await?;
                    push!(format!("{ty_name}[{k}]"), s, text_or_null(spec));
                    if list != 0
                        && let Some(last) = items.last_mut()
                    {
                        last.list = Some(list);
                    }
                    if k.is_multiple_of(256) {
                        cx.checkpoint().await;
                    }
                }
            },
        }
    }
    let used = r.pos();
    Ok(Decoded {
        items,
        message,
        used,
        complete: used == body.len(),
    })
}

fn text_or_null(v: Option<String>) -> Value {
    Value::Text(v.unwrap_or_else(|| "(null)".into()))
}

fn uint(value: u64) -> Value {
    Value::UInt {
        value,
        bits: 32,
        radix: Radix::Dec,
    }
}

/// A one-line summary of an event: its message, or its main names.
async fn event_summary(cx: &Cx, ctx: &Ctx, index: &Index, rec: Record) -> Result<String> {
    if rec.body.len > MAX_RECORD {
        return Ok(format!("{} bytes", rec.body.len));
    }
    // Only the start is needed for the summary fields.
    let body = cx.read(rec.body.sub(0, 4096)).await?;
    let d = decode(cx, ctx, index, rec.kind, &body).await?;
    cx.charge(to_u64(d.items.len())).await;
    let get = |name: &str| {
        d.items
            .iter()
            .find(|i| i.label == name)
            .and_then(|i| match &i.value {
                Value::Text(t) if t != "(null)" => Some(t.clone()),
                _ => None,
            })
    };
    let s = match rec.kind {
        5 | 6 => get("TargetName"),
        7 | 8 => get("TaskName"),
        3 | 4 | 14 | 15 => get("ProjectFile"),
        16 => get("ImportedProjectFile"),
        19 | 20 | 22 => get("PropertyName"),
        21 => get("EnvironmentVariableName"),
        25 => get("ParameterName").or_else(|| get("ItemType")),
        _ => None,
    };
    let mut out = s.or(d.message).unwrap_or_default();
    if matches!(rec.kind, 2 | 4 | 6 | 8)
        && let Some(item) = d.items.iter().find(|i| i.label == "Succeeded")
    {
        out.push_str(if item.value == Value::Bool(true) {
            " (succeeded)"
        } else {
            " (failed)"
        });
    }
    Ok(clip(out.trim(), 160))
}

/// One event: framing, its fields, and what was not decoded.
async fn event(cx: Cx, (ctx, rec, pos): (Ctx, Record, u64)) -> Result<()> {
    let index = index_upto(&cx, &ctx, pos).await?;
    let head_len = rec.body.offset.saturating_sub(rec.span.offset);
    cx.emit(framing(rec, head_len));
    if rec.body.len > MAX_RECORD {
        cx.emit(
            Node::new("Payload")
                .span(rec.body)
                .diag(Diagnostic::limit("record too large to decode").at(rec.body)),
        );
        return Ok(());
    }
    let body = cx.read(rec.body).await?;
    let d = decode(&cx, &ctx, &index, rec.kind, &body).await?;
    cx.charge(to_u64(d.items.len())).await;
    for item in d.items {
        let span = rec.body.sub(to_u64(item.off), to_u64(item.len));
        let mut node = Node::new(item.label).span(span).value(item.value);
        if let Some(l) = item.list
            && let Some(ls) = list_span(&ctx, &index, l)
        {
            node = node.lazy(list_pairs, (ctx, ls, pos));
        }
        cx.push(node).await;
    }
    if !d.complete {
        let rest = rec.body.tail(to_u64(d.used));
        let mut node = Node::new("Undecoded").span(rest);
        node = if schema(rec.kind).is_none() {
            node.desc("Fields of a record kind not decoded here")
        } else if d.used < body.len() && rest.len > 0 {
            node.diag(Diagnostic::malformed("the record's fields do not fill its length").at(rest))
        } else {
            node.diag(Diagnostic::truncated(rest, 0))
        };
        cx.push(node).await;
    }
    Ok(())
}

async fn list_pairs(cx: Cx, (ctx, body, pos): (Ctx, Span, u64)) -> Result<()> {
    let index = index_upto(&cx, &ctx, pos).await?;
    pairs(&cx, &ctx, &index, body).await
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_say_their_kind() {
        // 2026-10-16 08:25:10.4829999 as .NET ticks.
        let ticks = TICKS_AT_UNIX_EPOCH + 1_792_139_110 * 10_000_000 + 4_829_999;
        let shown = |k| crate::render::value(&timestamp(ticks, k));
        assert_eq!(shown(1), "2026-10-16 08:25:10.4829999 UTC");
        assert_eq!(shown(2), "2026-10-16 08:25:10.4829999 (local time)");
        assert_eq!(shown(0), "2026-10-16 08:25:10.4829999 (local time)");
        assert_eq!(
            crate::render::value(&timestamp(0, 1)),
            "0001-01-01 00:00:00 UTC"
        );
    }

    /// A first record that runs past the end of a short stream is no
    /// evidence when the stream's length is only an upper bound.
    #[test]
    fn an_unknown_length_does_not_make_a_record_fit() {
        // Version 21, minimum 18, the string "hi", then a record claiming
        // 100 bytes of which 2 are there.
        let mut d = vec![21, 0, 0, 0, 18, 0, 0, 0, 24, 2, b'h', b'i', 9, 100, 1, 2];
        let head = |data: &[u8], len_known| {
            probe(&Head {
                data,
                tail: data,
                len: 1 << 20,
                len_known,
            })
        };
        assert!(head(&d, true));
        assert!(!head(&d, false));
        // A full window: the record may well go on.
        d.resize(crate::formats::HEAD_LEN as usize, 0);
        assert!(head(&d, false));
    }
}
