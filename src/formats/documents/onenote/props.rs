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

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    next: [usize; 3],
    streams: [&'a [CompactId]; 3],
}

impl Reader<'_> {
    fn need(&self, n: usize) -> Result<()> {
        if self.pos.saturating_add(n) > self.data.len() {
            return Err(Diagnostic::malformed(format!(
                "property data at {:#x} runs past the end of the property set",
                self.pos
            )));
        }
        Ok(())
    }

    fn u32(&mut self) -> Result<u32> {
        self.need(4)?;
        let v = u32_le(self.data, self.pos).unwrap_or(0);
        self.pos = self.pos.saturating_add(4);
        Ok(v)
    }

    fn take_ids(&mut self, stream: Stream, count: u32) -> Result<Vec<Option<CompactId>>> {
        let i = stream as usize;
        let ids = self.streams.get(i).copied().unwrap_or_default();
        let start = self.next.get(i).copied().unwrap_or(0);
        // A count beyond what the stream holds cannot be satisfied; reject
        // it rather than allocating for it.
        if to_usize(count.into()) > ids.len().saturating_sub(start).saturating_add(64) {
            return Err(Diagnostic::malformed(format!(
                "{count} IDs referenced, the stream holds {}",
                ids.len()
            )));
        }
        let mut out = Vec::new();
        for k in 0..to_usize(count.into()) {
            out.push(ids.get(start.saturating_add(k)).copied());
        }
        if let Some(n) = self.next.get_mut(i) {
            *n = start.saturating_add(to_usize(count.into()));
        }
        Ok(out)
    }

    fn set(&mut self, depth: u32) -> Result<PropSet> {
        if depth > MAX_DEPTH {
            return Err(Diagnostic::limit("property sets nested too deeply"));
        }
        let at = self.pos;
        self.need(2)?;
        let count = usize::from(u16_le(self.data, self.pos).unwrap_or(0));
        self.pos = self.pos.saturating_add(2);
        self.need(count.saturating_mul(4))?;
        let mut ids = Vec::with_capacity(count);
        for _ in 0..count {
            ids.push((self.pos, self.u32()?));
        }
        let mut props = Vec::with_capacity(count);
        for (id_at, raw_id) in ids {
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
                    self.need(width)?;
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
                    let cb = to_usize(self.u32()?.into());
                    self.need(cb)?;
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
                    let count = if array { self.u32()? } else { 1 };
                    PValue::Ids {
                        stream,
                        array,
                        ids: self.take_ids(stream, count)?,
                    }
                }
                0x10 => {
                    let n = self.u32()?;
                    let mut sets = Vec::new();
                    if n > 0 {
                        let _prid = self.u32()?;
                        for _ in 0..n {
                            // Every set takes at least two bytes.
                            self.need(2)?;
                            sets.push(self.set(depth.saturating_add(1))?);
                        }
                    }
                    PValue::Array(sets)
                }
                0x11 => PValue::Set(self.set(depth.saturating_add(1))?),
                _ => {
                    return Err(Diagnostic::malformed(format!(
                        "property {raw_id:#010x} has unknown type {kind:#x}"
                    )));
                }
            };
            props.push(Prop {
                raw_id,
                id_at,
                data_at,
                data_len: self.pos.saturating_sub(data_at),
                value,
            });
        }
        Ok(PropSet {
            at,
            len: self.pos.saturating_sub(at),
            props,
        })
    }
}

fn id_stream(data: &[u8], at: usize) -> Result<IdStream> {
    let header = u32_le(data, at)
        .ok_or_else(|| Diagnostic::malformed("ID stream header runs past the property set"))?;
    let count = to_usize((header & 0x00FF_FFFF).into());
    let start = at.saturating_add(4);
    if start.saturating_add(count.saturating_mul(4)) > data.len() {
        return Err(Diagnostic::malformed(format!(
            "ID stream of {count} entries runs past the property set"
        )));
    }
    let ids = (0..count)
        .map(|i| {
            CompactId::from_raw(
                u32_le(data, start.saturating_add(i.saturating_mul(4))).unwrap_or(0),
            )
        })
        .collect();
    Ok(IdStream { at, header, ids })
}

/// Parses an ObjectSpaceObjectPropSet.
pub fn parse(data: &[u8]) -> Result<ObjectPropSet> {
    let oids = id_stream(data, 0)?;
    let mut at = oids.len();
    let osids = if oids.header & 0x8000_0000 == 0 {
        let s = id_stream(data, at)?;
        at = at.saturating_add(s.len());
        Some(s)
    } else {
        None
    };
    // The extended streams flag is in the header of the OSID stream.
    let contexts = if osids.as_ref().is_some_and(|s| s.header & 0x4000_0000 != 0) {
        let s = id_stream(data, at)?;
        at = at.saturating_add(s.len());
        Some(s)
    } else {
        None
    };
    let empty: &[CompactId] = &[];
    let mut reader = Reader {
        data,
        pos: at,
        next: [0; 3],
        streams: [
            &oids.ids,
            osids.as_ref().map_or(empty, |s| &s.ids),
            contexts.as_ref().map_or(empty, |s| &s.ids),
        ],
    };
    let body = reader.set(0)?;
    Ok(ObjectPropSet {
        oids,
        osids,
        contexts,
        body,
    })
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
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
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
}
