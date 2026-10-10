//! Locating, reading and decoding indirect objects: by file offset, inside
//! object streams, and the cross-reference sections that say where they are.

use std::collections::{BTreeMap, BTreeSet};

use super::syntax::{self, Error as ParseError, Item, Obj, Parser, Reader};
use crate::bytes::{to_u64, to_usize};
use std::sync::Arc;

use super::crypt::Security;
use crate::codec::{self, Codec};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::span::Span;

/// Largest object (dictionary part) we are prepared to read.
const MAX_OBJECT: u64 = 16 << 20;
/// Cross-reference sections followed through /Prev.
pub const MAX_SECTIONS: usize = 256;

/// Where an object lives, according to the cross-reference data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Loc {
    /// A free entry: the next free object number (the free list) and the
    /// generation the object gets if it is reused.
    Free {
        next: u64,
        generation: u16,
    },
    Offset {
        offset: u64,
        generation: u16,
    },
    Compressed {
        stream: u32,
        index: u32,
    },
}

pub type Xref = BTreeMap<u32, Loc>;

/// A parsed object: the item, the span its offsets are relative to, its
/// stream data (if a stream), and the whole `N G obj ... endobj` range.
#[derive(Clone, Debug)]
pub struct Located {
    /// The object number and generation (indirect objects only).
    pub id: Option<(u32, u16)>,
    pub item: Item,
    pub base: Span,
    pub data: Option<Span>,
    pub whole: Span,
}

fn parse_error(e: ParseError, window: Span) -> Diagnostic {
    match e {
        ParseError::Stop(d) => d,
        ParseError::Malformed(msg, at) => Diagnostic::malformed(msg).at(window.sub(to_u64(at), 1)),
    }
}

/// Parses something at `offset` in `region` with `body`, an async block
/// using the reader `p`, which reads as much as it needs (an object of at
/// most [`MAX_OBJECT`] bytes). Evaluates to the value and the span read,
/// which positions are relative to.
macro_rules! parse_at {
    ($cx:expr, $region:expr, $offset:expr, |$p:ident| $body:block) => {{
        let mut $p = Reader::for_object($cx, $region, $offset, MAX_OBJECT);
        let result: syntax::PResult<_> = async { $body }.await;
        match result {
            Ok(v) => Ok((v, $p.window())),
            Err(e) => Err(parse_error(e, $p.window())),
        }
    }};
}

/// An indirect object at `offset`: header, object, and stream data.
/// `/Length` references are resolved through `xref` when given.
pub async fn object_at(
    cx: &Cx,
    region: Span,
    offset: u64,
    xref: Option<&Xref>,
) -> Result<(u32, u16, Located)> {
    let ((num, generation, item, stream), span) = parse_at!(cx, region, offset, |p| {
        let (num, generation) = p.object_header().await?;
        let item = p.object().await?;
        let stream = if item.is_dict() {
            p.stream_start().await?
        } else {
            None
        };
        Ok((num, generation, item, stream))
    })?;
    let base = span;
    let mut end = to_u64(item.end);
    let mut stream_data = None;
    if let Some(start) = stream {
        let start = to_u64(start);
        let declared = match item.get("Length").map(|l| &l.obj) {
            Some(Obj::Int(n)) => u64::try_from(*n).ok(),
            Some(Obj::Ref(n, _)) => match xref.and_then(|x| x.get(n)) {
                Some(&Loc::Offset { offset, .. }) => length_object(cx, region, offset).await,
                _ => None,
            },
            _ => None,
        };
        let data_start = offset.saturating_add(start);
        let len = match declared {
            Some(len) if ends_stream(cx, region, data_start.saturating_add(len)).await => len,
            _ => find_endstream(cx, region, data_start).await?,
        };
        stream_data = Some(region.sub(data_start, len));
        end = start.saturating_add(len);
    }
    // Include "endstream"/"endobj" when they follow.
    let tail = cx
        .read_avail(region.sub(offset.saturating_add(end), 64))
        .await?;
    let mut p = Parser::new(&tail);
    let mut consumed = 0usize;
    if stream_data.is_some() && p.keyword(b"endstream") {
        consumed = p.pos;
    }
    if p.keyword(b"endobj") {
        consumed = p.pos;
    }
    end = end.saturating_add(to_u64(consumed));
    Ok((
        num,
        generation,
        Located {
            id: Some((num, generation)),
            item,
            base,
            data: stream_data,
            whole: region.sub(offset, end),
        },
    ))
}

/// The integer object a `/Length` reference points to.
async fn length_object(cx: &Cx, region: Span, offset: u64) -> Option<u64> {
    let ((_, item), _) = parse_at!(cx, region, offset, |p| {
        let header = p.object_header().await?;
        Ok((header, p.object().await?))
    })
    .ok()?;
    item.int().and_then(|n| u64::try_from(n).ok())
}

/// Whether `endstream` follows `at` (after optional end-of-line).
async fn ends_stream(cx: &Cx, region: Span, at: u64) -> bool {
    let Ok(data) = cx.read_avail(region.sub(at, 32)).await else {
        return false;
    };
    Parser::new(&data).keyword(b"endstream")
}

/// The data length of a stream whose `/Length` is missing or wrong: up to
/// the next `endstream`, without the end-of-line before it.
async fn find_endstream(cx: &Cx, region: Span, start: u64) -> Result<u64> {
    const PIECE: u64 = 1 << 16;
    let mut pos = start;
    loop {
        cx.checkpoint().await;
        let span = region.sub(pos, PIECE.saturating_add(16));
        let data = cx.read_avail(span).await?;
        if let Some(i) = crate::bytes::find(&data, b"endstream", 0) {
            let mut len = pos.saturating_add(to_u64(i)).saturating_sub(start);
            let before = cx
                .read_avail(region.sub(start.saturating_add(len).saturating_sub(2), 2))
                .await?;
            if before.ends_with(b"\r\n") {
                len = len.saturating_sub(2);
            } else if before.ends_with(b"\n") || before.ends_with(b"\r") {
                len = len.saturating_sub(1);
            }
            return Ok(len);
        }
        if to_u64(data.len()) < span.len {
            return Err(
                Diagnostic::malformed("stream without 'endstream'").at(region.sub(start, 0))
            );
        }
        if pos.saturating_sub(start) > MAX_OBJECT.saturating_mul(16) {
            return Err(Diagnostic::limit("no 'endstream' within 256 MiB").at(region.sub(start, 0)));
        }
        pos = pos.saturating_add(PIECE);
    }
}

// ---------------------------------------------------------------------------
// Stream filters

/// The filter names of a stream dictionary.
pub fn filters(dict: &Item) -> Vec<String> {
    match dict.get("Filter").map(|f| &f.obj) {
        Some(Obj::Name(n)) => vec![n.clone()],
        Some(Obj::Array(items)) => items
            .iter()
            .filter_map(|i| i.name().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

/// The `/DecodeParms` dictionary of filter `index` (a single dictionary or
/// an array aligned with `/Filter`).
pub fn parms(dict: &Item, index: usize) -> Option<&Item> {
    let parms = dict.get("DecodeParms").or_else(|| dict.get("DP"))?;
    match &parms.obj {
        Obj::Array(items) => items.get(index).filter(|i| !matches!(i.obj, Obj::Null)),
        _ if index == 0 => Some(parms),
        _ => None,
    }
}

/// The predictor stage that follows a Flate or LZW filter, if any.
fn predictor(parms: Option<&Item>) -> std::result::Result<Option<Codec>, String> {
    let Some(parms) = parms else { return Ok(None) };
    let get = |k: &str, d: i64| parms.get(k).and_then(Item::int).unwrap_or(d);
    let predictor = get("Predictor", 1);
    if predictor <= 1 {
        return Ok(None);
    }
    let (colors, bits, columns) = (
        get("Colors", 1),
        get("BitsPerComponent", 8),
        get("Columns", 1),
    );
    let bits_per_pixel = colors
        .checked_mul(bits)
        .filter(|&b| b > 0)
        .ok_or("bad predictor parameters")?;
    let bpp = usize::try_from(bits_per_pixel.saturating_add(7) / 8)
        .map_err(|_| "bad predictor parameters")?;
    let row = columns
        .checked_mul(bits_per_pixel)
        .and_then(|b| usize::try_from(b.saturating_add(7) / 8).ok())
        .filter(|&r| r > 0 && r < 1 << 24)
        .ok_or("bad predictor parameters")?;
    match predictor {
        2 if bits == 8 => Ok(Some(Codec::TiffPredictor { bpp, row })),
        2 => Err(format!("TIFF predictor with {bits}-bit components")),
        10..=15 => Ok(Some(Codec::PngPredictor { bpp, row })),
        p => Err(format!("predictor {p}")),
    }
}

/// The codec chain that decodes a stream (`/Filter` with its
/// `/DecodeParms`), and the filter names. Image codecs (DCT, JPX, JBIG2,
/// CCITT) end the chain: their output is the image file itself.
pub fn codec(dict: &Item) -> std::result::Result<(Codec, Vec<String>), String> {
    let names = filters(dict);
    let mut stages = Vec::new();
    for (i, name) in names.iter().enumerate() {
        let last = i.saturating_add(1) == names.len();
        match name.as_str() {
            "FlateDecode" | "Fl" => {
                stages.push(Codec::Zlib);
                stages.extend(predictor(parms(dict, i))?);
            }
            "LZWDecode" | "LZW" => {
                let early = parms(dict, i)
                    .and_then(|p| p.get("EarlyChange"))
                    .and_then(Item::int)
                    .unwrap_or(1);
                stages.push(Codec::Lzw {
                    early_change: early != 0,
                });
                stages.extend(predictor(parms(dict, i))?);
            }
            "ASCIIHexDecode" | "AHx" => stages.push(Codec::AsciiHex),
            "ASCII85Decode" | "A85" => stages.push(Codec::Ascii85),
            "RunLengthDecode" | "RL" => stages.push(Codec::RunLength),
            "Crypt" => {}
            "DCTDecode" | "DCT" | "JPXDecode" | "JBIG2Decode" | "CCITTFaxDecode" | "CCF"
                if last => {}
            other => return Err(format!("stream filter /{other}")),
        }
    }
    let codec = match stages.len() {
        0 => Codec::Stored,
        1 => stages.pop().unwrap_or(Codec::Stored),
        _ => Codec::chain("pdf-filters", "pdf-filters (lazy)", stages),
    };
    Ok((codec, names))
}

/// Whether the stream of `located` is encrypted under `security`.
pub fn is_encrypted(located: &Located, security: Option<&Arc<Security>>) -> bool {
    let Some(security) = security else {
        return false;
    };
    let kind = located.item.get("Type").and_then(Item::name);
    let own_crypt = filters(&located.item).iter().any(|f| f == "Crypt");
    located.id.is_some()
        && located.data.is_some()
        && security.streams != super::crypt::Method::Identity
        && kind != Some("XRef")
        && !(kind == Some("Metadata") && !security.encrypt_metadata)
        && !own_crypt
}

/// The decryption stage for the stream of `located` (asking for the
/// password if needed); `None` if it is not encrypted.
pub async fn decryption(
    cx: &Cx,
    located: &Located,
    security: Option<&Arc<Security>>,
) -> Result<Option<Codec>> {
    let (Some(security), Some(id)) = (security, located.id) else {
        return Ok(None);
    };
    if !is_encrypted(located, Some(security)) {
        return Ok(None);
    }
    let Some(key) = super::crypt::file_key(cx, security, true).await else {
        return Err(
            Diagnostic::unsupported("encrypted stream (no password, or a wrong one)")
                .at(located.data.unwrap_or(located.whole)),
        );
    };
    Ok(security.stream_codec(&key, id))
}

/// Decodes a stream's data into a span (all filters except the image
/// codecs, whose output is the image file).
pub async fn decode(cx: &Cx, located: &Located, security: Option<&Arc<Security>>) -> Result<Span> {
    let Some(data) = located.data else {
        return Err(Diagnostic::malformed("not a stream"));
    };
    let (codec, _) = codec(&located.item).map_err(|e| Diagnostic::unsupported(e).at(data))?;
    let codec = match decryption(cx, located, security).await? {
        Some(decrypt) => match codec {
            Codec::Stored => decrypt,
            Codec::Chain { stages, .. } => Codec::chain(
                "pdf-decrypt+filters",
                "pdf-decrypt+filters (lazy)",
                std::iter::once(decrypt)
                    .chain(stages.iter().cloned())
                    .collect::<Vec<_>>(),
            ),
            single => Codec::chain(
                "pdf-decrypt+filters",
                "pdf-decrypt+filters (lazy)",
                vec![decrypt, single],
            ),
        },
        None => codec,
    };
    if codec == Codec::Stored {
        return Ok(data);
    }
    let decoded = codec::decode_span(cx, data, &codec, None).await?;
    if let Some(e) = &decoded.error
        && decoded.span.is_empty()
    {
        return Err(e.clone());
    }
    Ok(decoded.span)
}

// ---------------------------------------------------------------------------
// Object streams

/// Object `index` of object stream `stream` (located at `offset`).
pub async fn in_object_stream(
    cx: &Cx,
    region: Span,
    xref: &Xref,
    stream: u32,
    index: u32,
    security: Option<&Arc<Security>>,
) -> Result<(u32, Located)> {
    let Some(&Loc::Offset { offset, .. }) = xref.get(&stream) else {
        return Err(Diagnostic::malformed(format!(
            "object stream {stream} is not stored at a file offset"
        )));
    };
    let (_, _, objstm) = object_at(cx, region, offset, Some(xref)).await?;
    let decoded = decode(cx, &objstm, security).await?;
    let first = objstm
        .item
        .get("First")
        .and_then(Item::int)
        .and_then(|n| u64::try_from(n).ok())
        .ok_or_else(|| Diagnostic::malformed("object stream without /First").at(objstm.whole))?;
    let n = objstm.item.get("N").and_then(Item::int).unwrap_or(0);
    if i64::from(index) >= n {
        return Err(Diagnostic::malformed(format!(
            "object stream {stream} has only {n} objects"
        )));
    }
    let index_of = object_stream_index_of(cx, decoded, first).await?;
    let Some(&(num, at)) = index_of.entries.get(to_usize(u64::from(index))) else {
        let (msg, at) = index_of.stop.clone();
        return Err(parse_error(
            ParseError::Malformed(msg, at),
            decoded.sub(0, first),
        ));
    };
    Ok((
        u32::try_from(num).unwrap_or(u32::MAX),
        object_in(cx, decoded, at).await?,
    ))
}

/// The object at `at` in the decoded data of an object stream (a direct
/// object, without `obj`/`endobj`).
pub async fn object_in(cx: &Cx, decoded: Span, at: u64) -> Result<Located> {
    let (item, span) = parse_at!(cx, decoded, at, |p| { p.object().await })?;
    let whole = span.sub(
        to_u64(item.start),
        to_u64(item.end.saturating_sub(item.start)),
    );
    Ok(Located {
        id: None,
        item,
        base: span,
        data: None,
        whole,
    })
}

/// What ends a revision: `startxref`, the offset after it, and `%%EOF`.
#[derive(Clone, Copy, Debug)]
pub struct Tail {
    /// The keyword and the offset.
    pub startxref: Span,
    pub value: u64,
    pub eof: Option<Span>,
    /// Where the revision ends: after `%%EOF` and its end-of-line.
    pub end: u64,
}

/// The `startxref` … `%%EOF` lines at `at` (after whitespace), if there.
pub async fn tail_at(cx: &Cx, region: Span, at: u64) -> Option<Tail> {
    let data = cx.read_avail(region.sub(at, 256)).await.ok()?;
    let white = |from: usize| {
        from.saturating_add(
            data.get(from..)
                .unwrap_or_default()
                .iter()
                .take_while(|&&b| syntax::is_white(b))
                .count(),
        )
    };
    let keyword = white(0);
    if !data.get(keyword..)?.starts_with(b"startxref") {
        return None;
    }
    let digits_at = white(keyword.saturating_add(9));
    let digits = data
        .get(digits_at..)?
        .iter()
        .take_while(|b| b.is_ascii_digit())
        .count();
    let value = std::str::from_utf8(data.get(digits_at..digits_at.saturating_add(digits))?)
        .ok()?
        .parse()
        .ok()?;
    let after = digits_at.saturating_add(digits);
    let startxref = region.sub(
        at.saturating_add(to_u64(keyword)),
        to_u64(after.saturating_sub(keyword)),
    );
    let marker = white(after);
    let (eof, end) = if data.get(marker..).is_some_and(|r| r.starts_with(b"%%EOF")) {
        let k = marker.saturating_add(5);
        let eol = match data.get(k..) {
            Some([b'\r', b'\n', ..]) => 2,
            Some([b'\r' | b'\n', ..]) => 1,
            _ => 0,
        };
        (
            Some(region.sub(at.saturating_add(to_u64(marker)), 5)),
            k.saturating_add(eol),
        )
    } else {
        (None, after)
    };
    Some(Tail {
        startxref,
        value,
        eof,
        end: at.saturating_add(to_u64(end)),
    })
}

/// The header of an object stream: where its objects are.
#[derive(Debug)]
pub struct ObjStmIndex {
    /// Object numbers and offsets in the decoded stream (after `/First`).
    pub entries: Vec<(u64, u64)>,
    /// Where each pair of `entries` is written: start and end in the
    /// decoded stream.
    pub pairs: Vec<(u64, u64)>,
    /// Why the header ends there: the error reading the next entry.
    stop: (String, usize),
}

/// The header of the object stream decoded into `decoded`, parsed once per
/// stream (resolving each of its objects needs it).
async fn object_stream_index_of(cx: &Cx, decoded: Span, first: u64) -> Result<Arc<ObjStmIndex>> {
    const KIND: &str = "pdf-objstm-index";
    if let Some(found) = cx.cached::<ObjStmIndex>(decoded, KIND) {
        return Ok(found);
    }
    let header = decoded.sub_exact(0, first.min(MAX_OBJECT))?;
    let mut p = Reader::pieces(cx, header);
    let mut entries = Vec::new();
    let mut pairs = Vec::new();
    let stop = loop {
        let start = match p.skip_ws().await {
            Ok(()) => p.pos,
            Err(ParseError::Stop(e)) => return Err(e),
            Err(ParseError::Malformed(msg, at)) => break (msg, at),
        };
        let num = p.uint().await;
        let off = p.uint().await;
        match (num, off) {
            (Ok(num), Ok(off)) => {
                entries.push((num, first.saturating_add(off)));
                pairs.push((to_u64(start), to_u64(p.pos)));
            }
            (Err(ParseError::Stop(e)), _) | (_, Err(ParseError::Stop(e))) => return Err(e),
            (Err(ParseError::Malformed(msg, at)), _) | (_, Err(ParseError::Malformed(msg, at))) => {
                break (msg, at);
            }
        }
        p.release(p.pos);
    };
    let index = Arc::new(ObjStmIndex {
        entries,
        pairs,
        stop,
    });
    cx.cache(decoded, KIND, index.clone());
    Ok(index)
}

/// The objects contained in an object stream: `(number, offset)` pairs.
pub async fn object_stream_index(
    cx: &Cx,
    objstm: &Located,
    decoded: Span,
) -> Result<Arc<ObjStmIndex>> {
    let first = objstm
        .item
        .get("First")
        .and_then(Item::int)
        .and_then(|n| u64::try_from(n).ok())
        .unwrap_or(0);
    object_stream_index_of(cx, decoded, first).await
}

// ---------------------------------------------------------------------------
// Cross-reference sections

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SectionKind {
    Table,
    Stream,
}

/// A run of consecutive object numbers in a section.
#[derive(Clone, Copy, Debug)]
pub struct Subsection {
    /// The first object number.
    pub first: u64,
    /// Entries `index..index + len` of [`Section::entries`].
    pub index: usize,
    pub len: usize,
    /// The `first count` line (tables only).
    pub header: Option<Span>,
    /// The header and the entries (for streams, the rows of the decoded
    /// data).
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct Section {
    pub kind: SectionKind,
    pub offset: u64,
    /// The table (from `xref` to the trailer) or the stream object.
    pub span: Span,
    pub entries: Vec<(u32, Loc)>,
    /// Where each entry is written: its line of the table, or its row of
    /// the decoded stream.
    pub spans: Vec<Span>,
    pub subsections: Vec<Subsection>,
    /// The trailer dictionary (from the `trailer` keyword on), or the
    /// stream object.
    pub trailer: Option<Located>,
    /// Streams: the decoded rows, and the field widths (`/W`).
    pub rows: Option<(Span, [usize; 3])>,
    /// Hybrid-reference files: the stream named by the trailer's `/XRefStm`,
    /// whose entries come after the table's.
    pub hybrid: Option<Box<Section>>,
}

impl Section {
    pub fn prev(&self) -> Option<u64> {
        self.trailer
            .as_ref()?
            .item
            .get("Prev")?
            .int()
            .and_then(|n| u64::try_from(n).ok())
    }

    pub fn xref_stream(&self) -> Option<u64> {
        self.trailer
            .as_ref()?
            .item
            .get("XRefStm")?
            .int()
            .and_then(|n| u64::try_from(n).ok())
    }

    /// The entries in the order they take effect: the table's, then those
    /// of its hybrid stream.
    pub fn all_entries(&self) -> impl Iterator<Item = &(u32, Loc)> {
        self.entries.iter().chain(
            self.hybrid
                .as_deref()
                .map(|h| h.entries.as_slice())
                .unwrap_or_default(),
        )
    }
}

/// The cross-reference section at `offset`.
pub async fn section(cx: &Cx, region: Span, offset: u64) -> Result<Section> {
    let head = cx.read_avail(region.sub(offset, 4)).await?;
    if head == b"xref" {
        table(cx, region, offset).await
    } else {
        stream_section(cx, region, offset).await
    }
}

async fn table(cx: &Cx, region: Span, offset: u64) -> Result<Section> {
    let mut entries = Vec::new();
    let mut spans = Vec::new();
    let mut subsections = Vec::new();
    let mut pos = offset.saturating_add(4);
    loop {
        // A subsection header (`start count`), or the trailer keyword.
        let (header, _) = parse_at!(cx, region, pos, |p| {
            p.skip_ws().await?;
            let at = p.pos;
            if p.keyword(b"trailer").await? {
                return Ok(None);
            }
            let start = p.uint().await?;
            let count = p.uint().await?;
            let end = p.pos;
            // The entries start on the next line.
            p.skip_ws().await?;
            Ok(Some((start, count, at, end, p.pos)))
        })?;
        let Some((start, count, at, end, used)) = header else {
            break;
        };
        let header_at = pos.saturating_add(to_u64(at));
        let header = region.sub(header_at, to_u64(end.saturating_sub(at)));
        pos = pos.saturating_add(to_u64(used));
        let bytes = count.saturating_mul(20);
        let body = region.sub_exact(pos, bytes)?;
        let mut p = Reader::pieces(cx, body);
        let index = entries.len();
        // Where the previous entry starts: it ends where the next begins,
        // after at most 20 bytes.
        let mut last: Option<u64> = None;
        for i in 0..count {
            cx.checkpoint().await;
            p.release(p.pos);
            p.skip_ws().await.map_err(|e| parse_error(e, body))?;
            let entry_at = to_u64(p.pos);
            if let Some(prev) = last.replace(entry_at) {
                spans.push(body.sub(prev, entry_at.saturating_sub(prev).min(20)));
            }
            let off = p.uint().await;
            let generation = p.uint().await;
            let (off, generation) = match (off, generation) {
                (Ok(off), Ok(generation)) => (off, generation),
                (Err(ParseError::Stop(e)), _) | (_, Err(ParseError::Stop(e))) => return Err(e),
                _ => {
                    return Err(Diagnostic::malformed("invalid cross-reference entry")
                        .at(body.sub(i.saturating_mul(20), 20)));
                }
            };
            p.skip_ws().await.map_err(|e| parse_error(e, body))?;
            let at = p.pos;
            let kind = match p.word().await {
                Ok(_) => p.slice(at, p.pos),
                Err(_) => b"",
            };
            let num = u32::try_from(start.saturating_add(i)).unwrap_or(u32::MAX);
            let generation = u16::try_from(generation).unwrap_or(u16::MAX);
            let loc = match kind {
                b"n" => Loc::Offset {
                    offset: off,
                    generation,
                },
                b"f" => Loc::Free {
                    next: off,
                    generation,
                },
                _ => {
                    return Err(Diagnostic::malformed(
                        "cross-reference entry is neither 'n' nor 'f'",
                    )
                    .at(body.sub(i.saturating_mul(20), 20)));
                }
            };
            entries.push((num, loc));
        }
        let mut end = pos.saturating_add(to_u64(p.pos));
        if let Some(prev) = last {
            spans.push(body.sub(prev, 20));
            end = end.max(pos.saturating_add(prev.saturating_add(20).min(bytes)));
        }
        subsections.push(Subsection {
            first: start,
            index,
            len: entries.len().saturating_sub(index),
            header: Some(header),
            span: region.sub(header_at, end.saturating_sub(header_at)),
        });
        pos = end;
    }
    // The trailer dictionary.
    let ((keyword_at, item), span) = parse_at!(cx, region, pos, |p| {
        p.skip_ws().await?;
        let keyword_at = p.pos;
        if !p.keyword(b"trailer").await? {
            return Err(ParseError::Malformed(
                "expected 'trailer'".to_owned(),
                p.pos,
            ));
        }
        p.skip_ws().await?;
        Ok((keyword_at, p.object().await?))
    })?;
    let base = span;
    let whole = base.sub(
        to_u64(keyword_at),
        to_u64(item.end.saturating_sub(keyword_at)),
    );
    let table_end = pos.saturating_add(to_u64(keyword_at));
    Ok(Section {
        kind: SectionKind::Table,
        offset,
        span: region.sub(offset, table_end.saturating_sub(offset)),
        entries,
        spans,
        subsections,
        trailer: Some(Located {
            id: None,
            item,
            base,
            data: None,
            whole,
        }),
        rows: None,
        hybrid: None,
    })
}

async fn stream_section(cx: &Cx, region: Span, offset: u64) -> Result<Section> {
    let (_, _, located) = object_at(cx, region, offset, None).await?;
    if located.item.get("Type").and_then(Item::name) != Some("XRef") {
        return Err(
            Diagnostic::malformed("expected 'xref' or a cross-reference stream")
                .at(region.sub(offset, 4)),
        );
    }
    let width = |w: &Item| w.int().and_then(|n| usize::try_from(n).ok()).unwrap_or(0);
    let [w0, w1, w2] = located
        .item
        .get("W")
        .and_then(Item::array)
        .unwrap_or_default()
    else {
        return Err(Diagnostic::malformed("/W must have three entries").at(located.whole));
    };
    let (w0, w1, w2) = (width(w0), width(w1), width(w2));
    let row = w0.saturating_add(w1).saturating_add(w2);
    if row == 0 || w0 > 8 || w1 > 8 || w2 > 8 {
        return Err(Diagnostic::malformed("invalid /W field widths").at(located.whole));
    }
    let size = located.item.get("Size").and_then(Item::int).unwrap_or(0);
    let index: Vec<i64> = match located.item.get("Index").and_then(Item::array) {
        Some(items) => {
            let mut index = Vec::with_capacity(items.len());
            for (i, item) in items.iter().enumerate() {
                if i % 1024 == 1023 {
                    cx.checkpoint().await;
                }
                index.extend(item.int());
            }
            index
        }
        None => vec![0, size],
    };
    let decoded = decode(cx, &located, None).await?;
    let data = codec::read_all(cx, decoded).await?;
    let field = |bytes: &[u8]| bytes.iter().fold(0u64, |acc, &b| acc << 8 | u64::from(b));
    let row_len = to_u64(row);
    let mut entries = Vec::new();
    let mut spans = Vec::new();
    let mut subsections = Vec::new();
    let mut rows = data.chunks_exact(row);
    let mut row_index = 0u64;
    for pair in index.as_chunks::<2>().0 {
        let [start, count] = *pair;
        let first_row = row_index;
        let first_entry = entries.len();
        for i in 0..count.max(0) {
            cx.checkpoint().await;
            let Some(r) = rows.next() else {
                break;
            };
            let row_span = decoded.sub(row_index.saturating_mul(row_len), row_len);
            row_index = row_index.saturating_add(1);
            let (a, rest) = r.split_at(w0.min(r.len()));
            let (b, c) = rest.split_at(w1.min(rest.len()));
            // Without a type field, every entry is type 1.
            let kind = if w0 == 0 { 1 } else { field(a) };
            let (b, c) = (field(b), field(c));
            let num = u32::try_from(start.saturating_add(i)).unwrap_or(u32::MAX);
            let loc = match kind {
                0 => Loc::Free {
                    next: b,
                    generation: u16::try_from(c).unwrap_or(u16::MAX),
                },
                1 => Loc::Offset {
                    offset: b,
                    generation: u16::try_from(c).unwrap_or(u16::MAX),
                },
                2 => Loc::Compressed {
                    stream: u32::try_from(b).unwrap_or(u32::MAX),
                    index: u32::try_from(c).unwrap_or(u32::MAX),
                },
                // Other types are references to the null object.
                _ => continue,
            };
            entries.push((num, loc));
            spans.push(row_span);
        }
        subsections.push(Subsection {
            first: u64::try_from(start).unwrap_or(0),
            index: first_entry,
            len: entries.len().saturating_sub(first_entry),
            header: None,
            span: decoded.sub(
                first_row.saturating_mul(row_len),
                row_index.saturating_sub(first_row).saturating_mul(row_len),
            ),
        });
    }
    let span = located.whole;
    Ok(Section {
        kind: SectionKind::Stream,
        offset,
        span,
        entries,
        spans,
        subsections,
        trailer: Some(located),
        rows: Some((decoded, [w0, w1, w2])),
        hybrid: None,
    })
}

/// Follows the chain of sections from `startxref`, newest first. Problems
/// end the chain; whatever was read is kept.
pub async fn chain(cx: &Cx, region: Span, start: u64) -> (Vec<Section>, Option<Diagnostic>) {
    let mut sections: Vec<Section> = Vec::new();
    let mut seen = BTreeSet::new();
    let mut next = Some(start);
    while let Some(offset) = next {
        if !seen.insert(offset) {
            return (
                sections,
                Some(Diagnostic::malformed(format!(
                    "/Prev chain revisits offset {offset:#x}"
                ))),
            );
        }
        if sections.len() >= MAX_SECTIONS {
            return (
                sections,
                Some(Diagnostic::limit(format!(
                    "more than {MAX_SECTIONS} cross-reference sections"
                ))),
            );
        }
        let mut section = match section(cx, region, offset).await {
            Ok(s) => s,
            Err(e) => return (sections, Some(e)),
        };
        // Hybrid files: the table's trailer points at a stream with more.
        if section.kind == SectionKind::Table
            && let Some(extra) = section.xref_stream()
            && seen.insert(extra)
            && let Ok(more) = stream_section(cx, region, extra).await
        {
            section.hybrid = Some(Box::new(more));
        }
        next = section.prev();
        sections.push(section);
    }
    (sections, None)
}

/// Without usable cross-reference data: finds `N G obj` by scanning, the
/// last `trailer` dictionary, and where `xref` tables start (at the start of
/// a line).
pub async fn scan(cx: &Cx, region: Span) -> Result<(Xref, Option<Located>, BTreeSet<u64>)> {
    const PIECE: u64 = 1 << 20;
    const MAX_SCAN: u64 = 256 << 20;
    let mut xref = Xref::new();
    let mut tables = BTreeSet::new();
    let mut trailer = None;
    let mut pos = 0u64;
    while pos < region.len.min(MAX_SCAN) {
        cx.checkpoint().await;
        // Overlap pieces so a header split between them is still seen.
        let span = region.sub(pos.saturating_sub(32), PIECE.saturating_add(32));
        let base = span.offset.saturating_sub(region.offset);
        let data = cx.read_avail(span).await?;
        cx.progress_in(region, region.offset.saturating_add(pos));
        let mut from = 0usize;
        let mut hits = 0u32;
        while let Some(at) = crate::bytes::find(&data, b"obj", from) {
            from = at.saturating_add(3);
            hits = hits.wrapping_add(1);
            if hits.is_multiple_of(1024) {
                cx.checkpoint().await;
            }
            if let Some((num, start)) = object_header_before(&data, at) {
                let offset = base.saturating_add(to_u64(start));
                xref.insert(
                    num,
                    Loc::Offset {
                        offset,
                        generation: 0,
                    },
                );
            }
        }
        let mut from = 0usize;
        while let Some(at) = crate::bytes::find(&data, b"xref", from) {
            from = at.saturating_add(4);
            hits = hits.wrapping_add(1);
            if hits.is_multiple_of(1024) {
                cx.checkpoint().await;
            }
            let line_start = at
                .checked_sub(1)
                .and_then(|i| data.get(i))
                .is_none_or(|&b| b == b'\n' || b == b'\r');
            if line_start && tables.len() < MAX_SECTIONS {
                tables.insert(base.saturating_add(to_u64(at)));
            }
        }
        if let Some(at) = crate::bytes::rfind(&data, b"trailer") {
            trailer = Some(base.saturating_add(to_u64(at)));
        }
        pos = pos.saturating_add(PIECE);
    }
    let trailer = match trailer {
        Some(at) => parse_at!(cx, region, at, |p| {
            p.keyword(b"trailer").await?;
            p.skip_ws().await?;
            let start = p.pos;
            Ok((start, p.object().await?))
        })
        .ok()
        .map(|((start, item), base)| {
            let whole = base.sub(to_u64(start), to_u64(item.end.saturating_sub(start)));
            Located {
                id: None,
                item,
                base,
                data: None,
                whole,
            }
        }),
        None => None,
    };
    Ok((xref, trailer, tables))
}

/// For `obj` at `at`: the object number and where `N G` starts, if the bytes
/// before it are `N G ` preceded by whitespace or the start.
fn object_header_before(data: &[u8], at: usize) -> Option<(u32, usize)> {
    let before = data.get(..at)?;
    let after = data.get(at.saturating_add(3)).copied();
    if after.is_some_and(|b| !syntax::is_white(b) && !b"<[/(%".contains(&b)) {
        return None;
    }
    let mut i = before.len();
    let skip_ws = |i: &mut usize| {
        while *i > 0
            && before
                .get(i.saturating_sub(1))
                .is_some_and(|&b| syntax::is_white(b))
        {
            *i = i.saturating_sub(1);
        }
    };
    let digits = |i: &mut usize| {
        let end = *i;
        while *i > 0
            && before
                .get(i.saturating_sub(1))
                .is_some_and(u8::is_ascii_digit)
        {
            *i = i.saturating_sub(1);
        }
        before
            .get(*i..end)
            .filter(|d| !d.is_empty() && d.len() <= 10)
    };
    skip_ws(&mut i);
    digits(&mut i)?;
    let gen_start = i;
    skip_ws(&mut i);
    if i == gen_start {
        return None;
    }
    let num = digits(&mut i)?;
    if i > 0
        && !before
            .get(i.saturating_sub(1))
            .is_some_and(|&b| syntax::is_white(b))
    {
        return None;
    }
    let num = std::str::from_utf8(num).ok()?.parse().ok()?;
    Some((num, to_usize(to_u64(i))))
}
