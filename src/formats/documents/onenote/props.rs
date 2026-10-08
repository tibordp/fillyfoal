//! ObjectSpaceObjectPropSet: the streams of object, object space and context
//! IDs, and the PropertySet whose ObjectID-typed properties draw from them.

use crate::bytes::{to_usize, u16_le, u32_le, u64_le};
use crate::error::{Diagnostic, Result};

use super::store::CompactId;
use super::tables::{RICH_EDIT_TEXT_UNICODE, TEXT_EXTENDED_ASCII};

/// How deeply PropertyValue / ArrayOfPropertyValues may nest.
const MAX_DEPTH: u32 = 16;

/// Which ID stream a reference property draws from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stream {
    Objects,
    Spaces,
    Contexts,
}

#[derive(Clone, Debug)]
pub enum PValue {
    NoData,
    Bool(bool),
    /// An integer of 1, 2, 4 or 8 bytes.
    Int(u64, u8),
    /// FourBytesOfLengthFollowedByData: offset and length of the data.
    Bytes(usize, usize),
    /// IDs drawn from a stream (`None` where the stream ran out).
    Ids {
        stream: Stream,
        array: bool,
        ids: Vec<Option<CompactId>>,
    },
    Array(Vec<PropSet>),
    Set(PropSet),
}

#[derive(Clone, Debug)]
pub struct Prop {
    pub raw_id: u32,
    /// Offset of the PropertyID.
    pub id_at: usize,
    /// Offset and length of the property's data in rgData (possibly 0).
    pub data_at: usize,
    pub data_len: usize,
    pub value: PValue,
}

impl Prop {
    pub fn kind(&self) -> u32 {
        (self.raw_id >> 26) & 0x1F
    }
}

#[derive(Clone, Debug, Default)]
pub struct PropSet {
    pub at: usize,
    pub len: usize,
    pub props: Vec<Prop>,
}

#[derive(Clone, Debug)]
pub struct IdStream {
    pub at: usize,
    pub header: u32,
    pub ids: Vec<CompactId>,
}

impl IdStream {
    pub fn len(&self) -> usize {
        4usize.saturating_add(self.ids.len().saturating_mul(4))
    }
}

#[derive(Clone, Debug)]
pub struct ObjectPropSet {
    pub oids: IdStream,
    pub osids: Option<IdStream>,
    pub contexts: Option<IdStream>,
    pub body: PropSet,
}

/// Work (IDs copied, properties read) between two suspension points.
const STEP_WORK: usize = 4096;

fn need(data: &[u8], pos: usize, n: usize) -> Result<()> {
    if pos.saturating_add(n) > data.len() {
        return Err(Diagnostic::malformed(format!(
            "property data at {pos:#x} runs past the end of the property set"
        )));
    }
    Ok(())
}

fn read_u32(data: &[u8], pos: &mut usize) -> Result<u32> {
    need(data, *pos, 4)?;
    let v = u32_le(data, *pos).unwrap_or(0);
    *pos = pos.saturating_add(4);
    Ok(v)
}

/// What a property whose value is still being read waits for.
enum Wait {
    /// IDs still to copy from a stream (`next` has already moved past them).
    Ids {
        stream: Stream,
        array: bool,
        start: usize,
        count: usize,
        ids: Vec<Option<CompactId>>,
    },
    /// Nested property sets still to read (`single`: a PropertyValue).
    Sets {
        left: u32,
        single: bool,
        sets: Vec<PropSet>,
    },
}

struct Pending {
    raw_id: u32,
    id_at: usize,
    data_at: usize,
    wait: Wait,
}

/// A property set being read.
struct Frame {
    at: usize,
    depth: u32,
    ids: Vec<(usize, u32)>,
    next: usize,
    props: Vec<Prop>,
    pending: Option<Pending>,
}

/// An ID stream being read.
struct Fill {
    which: usize,
    at: usize,
    header: u32,
    count: usize,
    ids: Vec<CompactId>,
}

/// A resumable parse of an ObjectSpaceObjectPropSet: [`Parser::step`] does
/// a bounded amount of work per call (nested property sets are kept on an
/// explicit stack), so a property set of any size is read in steps.
pub struct Parser<'a> {
    data: &'a [u8],
    pos: usize,
    /// The object, object space and context ID streams.
    streams: [Option<IdStream>; 3],
    fill: Option<Fill>,
    /// Next unused ID of each stream.
    next: [usize; 3],
    frames: Vec<Frame>,
    started: bool,
}

impl<'a> Parser<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Parser {
            data,
            pos: 0,
            streams: [None, None, None],
            fill: None,
            next: [0; 3],
            frames: Vec::new(),
            started: false,
        }
    }

    fn start_fill(&mut self, which: usize) -> Result<()> {
        let at = self.pos;
        let header = u32_le(self.data, at)
            .ok_or_else(|| Diagnostic::malformed("ID stream header runs past the property set"))?;
        let count = to_usize((header & 0x00FF_FFFF).into());
        if at.saturating_add(4).saturating_add(count.saturating_mul(4)) > self.data.len() {
            return Err(Diagnostic::malformed(format!(
                "ID stream of {count} entries runs past the property set"
            )));
        }
        self.fill = Some(Fill {
            which,
            at,
            header,
            count,
            ids: Vec::with_capacity(count),
        });
        Ok(())
    }

    /// Reads the header and PropertyIDs of a property set.
    fn start_frame(&mut self, depth: u32) -> Result<(Frame, usize)> {
        if depth > MAX_DEPTH {
            return Err(Diagnostic::limit("property sets nested too deeply"));
        }
        let at = self.pos;
        need(self.data, self.pos, 2)?;
        let count = usize::from(u16_le(self.data, self.pos).unwrap_or(0));
        self.pos = self.pos.saturating_add(2);
        need(self.data, self.pos, count.saturating_mul(4))?;
        let mut ids = Vec::with_capacity(count);
        for _ in 0..count {
            let id_at = self.pos;
            ids.push((id_at, read_u32(self.data, &mut self.pos)?));
        }
        let frame = Frame {
            at,
            depth,
            ids,
            next: 0,
            props: Vec::with_capacity(count),
            pending: None,
        };
        Ok((frame, count.saturating_add(1)))
    }

    /// Reads the next property of a set: its value, or what it waits for.
    fn property(&mut self, id_at: usize, raw_id: u32) -> Result<Result<Prop, Pending>> {
        let data_at = self.pos;
        let kind = (raw_id >> 26) & 0x1F;
        let value = match kind {
            0x1 => PValue::NoData,
            0x2 => PValue::Bool(raw_id & 0x8000_0000 != 0),
            0x3..=0x6 => {
                let width: usize = match kind {
                    0x3 => 1,
                    0x4 => 2,
                    0x5 => 4,
                    _ => 8,
                };
                need(self.data, self.pos, width)?;
                let v = match width {
                    1 => self.data.get(self.pos).copied().unwrap_or(0).into(),
                    2 => u16_le(self.data, self.pos).unwrap_or(0).into(),
                    4 => u32_le(self.data, self.pos).unwrap_or(0).into(),
                    _ => u64_le(self.data, self.pos).unwrap_or(0),
                };
                self.pos = self.pos.saturating_add(width);
                PValue::Int(v, width as u8)
            }
            0x7 => {
                let cb = to_usize(read_u32(self.data, &mut self.pos)?.into());
                need(self.data, self.pos, cb)?;
                let v = PValue::Bytes(self.pos, cb);
                self.pos = self.pos.saturating_add(cb);
                v
            }
            0x8..=0xD => {
                let stream = match kind {
                    0x8 | 0x9 => Stream::Objects,
                    0xA | 0xB => Stream::Spaces,
                    _ => Stream::Contexts,
                };
                let array = kind & 1 == 1;
                let count = if array {
                    read_u32(self.data, &mut self.pos)?
                } else {
                    1
                };
                let i = stream as usize;
                let len = self
                    .streams
                    .get(i)
                    .and_then(|s| s.as_ref())
                    .map_or(0, |s| s.ids.len());
                let start = self.next.get(i).copied().unwrap_or(0);
                let count = to_usize(count.into());
                // A count beyond what the stream holds cannot be satisfied;
                // reject it rather than allocating for it.
                if count > len.saturating_sub(start).saturating_add(64) {
                    return Err(Diagnostic::malformed(format!(
                        "{count} IDs referenced, the stream holds {len}"
                    )));
                }
                if let Some(n) = self.next.get_mut(i) {
                    *n = start.saturating_add(count);
                }
                return Ok(Err(Pending {
                    raw_id,
                    id_at,
                    data_at,
                    wait: Wait::Ids {
                        stream,
                        array,
                        start,
                        count,
                        ids: Vec::new(),
                    },
                }));
            }
            0x10 => {
                let n = read_u32(self.data, &mut self.pos)?;
                if n > 0 {
                    let _prid = read_u32(self.data, &mut self.pos)?;
                }
                return Ok(Err(Pending {
                    raw_id,
                    id_at,
                    data_at,
                    wait: Wait::Sets {
                        left: n,
                        single: false,
                        sets: Vec::new(),
                    },
                }));
            }
            0x11 => {
                return Ok(Err(Pending {
                    raw_id,
                    id_at,
                    data_at,
                    wait: Wait::Sets {
                        left: 1,
                        single: true,
                        sets: Vec::new(),
                    },
                }));
            }
            _ => {
                return Err(Diagnostic::malformed(format!(
                    "property {raw_id:#010x} has unknown type {kind:#x}"
                )));
            }
        };
        Ok(Ok(Prop {
            raw_id,
            id_at,
            data_at,
            data_len: self.pos.saturating_sub(data_at),
            value,
        }))
    }

    /// Advances the parse by a bounded amount of work. Returns the property
    /// set once it is complete.
    pub fn step(&mut self) -> Result<Option<ObjectPropSet>> {
        let mut work = 0usize;
        while work < STEP_WORK {
            if let Some(fill) = &mut self.fill {
                let start = fill.at.saturating_add(4);
                let from = fill.ids.len();
                let end = fill.count.min(from.saturating_add(STEP_WORK));
                for i in from..end {
                    let at = start.saturating_add(i.saturating_mul(4));
                    fill.ids
                        .push(CompactId::from_raw(u32_le(self.data, at).unwrap_or(0)));
                }
                work = work.saturating_add(end.saturating_sub(from).max(1));
                if fill.ids.len() < fill.count {
                    continue;
                }
                let Some(fill) = self.fill.take() else {
                    continue;
                };
                let header = fill.header;
                let which = fill.which;
                let stream = IdStream {
                    at: fill.at,
                    header,
                    ids: fill.ids,
                };
                self.pos = self.pos.saturating_add(stream.len());
                if let Some(slot) = self.streams.get_mut(which) {
                    *slot = Some(stream);
                }
                // The OSID stream follows unless the OID stream says it is
                // absent; the extended streams flag is in the OSID header.
                match which {
                    0 if header & 0x8000_0000 == 0 => self.start_fill(1)?,
                    1 if header & 0x4000_0000 != 0 => self.start_fill(2)?,
                    _ => {}
                }
                continue;
            }
            if !self.started {
                if self.streams.first().is_some_and(Option::is_none) {
                    self.start_fill(0)?;
                    continue;
                }
                self.started = true;
                let (frame, w) = self.start_frame(0)?;
                work = work.saturating_add(w);
                self.frames.push(frame);
                continue;
            }
            let Some(top) = self.frames.last_mut() else {
                return Err(Diagnostic::malformed("property set parse ended early"));
            };
            let depth = top.depth;
            if let Some(p) = &mut top.pending {
                let done = match &mut p.wait {
                    Wait::Ids {
                        stream,
                        start,
                        count,
                        ids,
                        ..
                    } => {
                        let src = self
                            .streams
                            .get(*stream as usize)
                            .and_then(|s| s.as_ref())
                            .map_or(&[][..], |s| &s.ids[..]);
                        let from = ids.len();
                        let end = (*count).min(from.saturating_add(STEP_WORK));
                        for k in from..end {
                            ids.push(src.get(start.saturating_add(k)).copied());
                        }
                        work = work.saturating_add(end.saturating_sub(from).max(1));
                        ids.len() >= *count
                    }
                    Wait::Sets { left: 0, .. } => true,
                    Wait::Sets { left, single, .. } => {
                        // Every set of an array takes at least two bytes.
                        if !*single {
                            need(self.data, self.pos, 2)?;
                        }
                        *left = left.saturating_sub(1);
                        false
                    }
                };
                if !done {
                    if matches!(p.wait, Wait::Sets { .. }) {
                        let (frame, w) = self.start_frame(depth.saturating_add(1))?;
                        work = work.saturating_add(w);
                        self.frames.push(frame);
                    }
                } else {
                    let Some(top) = self.frames.last_mut() else {
                        continue;
                    };
                    let Some(p) = top.pending.take() else {
                        continue;
                    };
                    let value = match p.wait {
                        Wait::Ids {
                            stream, array, ids, ..
                        } => PValue::Ids { stream, array, ids },
                        Wait::Sets {
                            single: true,
                            mut sets,
                            ..
                        } => PValue::Set(sets.pop().unwrap_or_default()),
                        Wait::Sets { sets, .. } => PValue::Array(sets),
                    };
                    top.props.push(Prop {
                        raw_id: p.raw_id,
                        id_at: p.id_at,
                        data_at: p.data_at,
                        data_len: self.pos.saturating_sub(p.data_at),
                        value,
                    });
                }
                continue;
            }
            if let Some(&(id_at, raw_id)) = top.ids.get(top.next) {
                top.next = top.next.saturating_add(1);
                work = work.saturating_add(4);
                match self.property(id_at, raw_id)? {
                    Ok(prop) => {
                        if let Some(top) = self.frames.last_mut() {
                            top.props.push(prop);
                        }
                    }
                    Err(pending) => {
                        if let Some(top) = self.frames.last_mut() {
                            top.pending = Some(pending);
                        }
                    }
                }
                continue;
            }
            // The set is complete.
            let Some(frame) = self.frames.pop() else {
                continue;
            };
            let set = PropSet {
                at: frame.at,
                len: self.pos.saturating_sub(frame.at),
                props: frame.props,
            };
            match self.frames.last_mut() {
                Some(parent) => {
                    if let Some(Pending {
                        wait: Wait::Sets { sets, .. },
                        ..
                    }) = &mut parent.pending
                    {
                        sets.push(set);
                    }
                }
                None => {
                    let [oids, osids, contexts] = std::mem::take(&mut self.streams);
                    let oids = oids.ok_or_else(|| Diagnostic::malformed("no OID stream"))?;
                    return Ok(Some(ObjectPropSet {
                        oids,
                        osids,
                        contexts,
                        body: set,
                    }));
                }
            }
        }
        Ok(None)
    }
}

/// Parses an ObjectSpaceObjectPropSet in one go.
#[cfg(test)]
pub fn parse(data: &[u8]) -> Result<ObjectPropSet> {
    let mut p = Parser::new(data);
    loop {
        if let Some(ps) = p.step()? {
            return Ok(ps);
        }
    }
}

impl PropSet {
    pub fn get(&self, id: u32) -> Option<&Prop> {
        self.props.iter().find(|p| p.raw_id & 0x7FFF_FFFF == id)
    }

    /// A UTF-16 string property (without trailing NULs).
    pub fn string(&self, data: &[u8], id: u32) -> Option<String> {
        match self.get(id)?.value {
            PValue::Bytes(at, len) => Some(utf16(data.get(at..at.saturating_add(len))?)),
            _ => None,
        }
    }

    /// The text of a rich text paragraph: Unicode or "extended ASCII".
    pub fn text(&self, data: &[u8]) -> Option<(String, usize, usize)> {
        if let Some(p) = self.get(RICH_EDIT_TEXT_UNICODE)
            && let PValue::Bytes(at, len) = p.value
        {
            return Some((utf16(data.get(at..at.saturating_add(len))?), at, len));
        }
        if let Some(p) = self.get(TEXT_EXTENDED_ASCII)
            && let PValue::Bytes(at, len) = p.value
        {
            return Some((ansi(data.get(at..at.saturating_add(len))?), at, len));
        }
        None
    }

    /// The first object ID of a reference property.
    pub fn object(&self, id: u32) -> Option<CompactId> {
        match &self.get(id)?.value {
            PValue::Ids { ids, .. } => ids.first().copied().flatten(),
            _ => None,
        }
    }
}

pub fn utf16(b: &[u8]) -> String {
    crate::text::utf16(b, crate::fields::Endian::Little)
        .trim_end_matches('\0')
        .to_owned()
}

pub fn ansi(b: &[u8]) -> String {
    let b = b.strip_suffix(&[0]).unwrap_or(b);
    crate::codec::charset::decode_label("windows-1252", b).unwrap_or_else(|| crate::text::latin1(b))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    fn le(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }

    #[test]
    fn nested_sets_share_the_id_streams() {
        let mut d = Vec::new();
        d.extend(le(2 | 0x8000_0000)); // two OIDs, no OSID stream
        d.extend(le(0x0000_0101));
        d.extend(le(0x0000_0102));
        d.extend(2u16.to_le_bytes());
        d.extend(le(0x2000_0001)); // ObjectID
        d.extend(le(0x4000_0002)); // ArrayOfPropertyValues
        d.extend(le(1)); // one element
        d.extend(le(0x4400_0003)); // prid (PropertyValue)
        d.extend(2u16.to_le_bytes());
        d.extend(le(0x2000_0004)); // ObjectID: takes the second OID
        d.extend(le(0x1C00_1C22)); // RichEditTextUnicode
        d.extend(le(4));
        d.extend(b"h\0i\0");
        let ps = parse(&d).unwrap();
        assert_eq!(ps.body.props.len(), 2);
        let sets = match &ps.body.props[1].value {
            PValue::Array(s) => s.clone(),
            _ => Vec::new(),
        };
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].object(0x2000_0004).unwrap().n, 2);
        assert_eq!(sets[0].text(&d).unwrap().0, "hi");
        assert_eq!(ps.body.object(0x2000_0001).unwrap().index, 1);
    }

    #[test]
    fn oversized_counts_are_rejected() {
        let mut d = Vec::new();
        d.extend(le(0x8000_0000));
        d.extend(1u16.to_le_bytes());
        d.extend(le(0x2400_0001)); // ArrayOfObjectIDs
        d.extend(le(0xFFFF_FFFF));
        assert!(parse(&d).is_err());
    }

    #[test]
    fn large_property_sets_are_read_in_steps() {
        // 200k OIDs, then an array of 100k sets each taking one of them.
        let n = 100_000u32;
        let mut d = Vec::new();
        d.extend(le((2 * n) | 0x8000_0000));
        for i in 0..2 * n {
            d.extend(le(i << 8));
        }
        d.extend(2u16.to_le_bytes());
        d.extend(le(0x2400_0001)); // ArrayOfObjectIDs
        d.extend(le(0x4000_0002)); // ArrayOfPropertyValues
        d.extend(le(n));
        d.extend(le(n)); // all OIDs of the first property
        d.extend(le(0x4400_0003)); // prid
        for _ in 0..n {
            d.extend(1u16.to_le_bytes());
            d.extend(le(0x2000_0004));
        }
        let mut p = Parser::new(&d);
        let mut steps = 0;
        let ps = loop {
            steps += 1;
            if let Some(ps) = p.step().unwrap() {
                break ps;
            }
        };
        assert!(steps > 100, "{steps}");
        assert_eq!(ps.oids.ids.len(), 2 * n as usize);
        let PValue::Array(sets) = &ps.body.props[1].value else {
            panic!("not an array");
        };
        assert_eq!(sets.len(), n as usize);
        assert_eq!(sets[5].object(0x2000_0004).unwrap().index, n + 5);
        assert_eq!(
            ps.body.props[1].data_len,
            d.len() - ps.body.props[1].data_at
        );
    }
}
