//! Synchronous decoding of BER/DER over bytes in memory: TLV headers, the
//! universal primitive types, and a structural validity check. Used by the
//! probes, for summaries, and for the values of primitive nodes.

use crate::bytes::to_usize;
use crate::value::EnumTable;

pub const CLASS_UNIVERSAL: u8 = 0;
pub const CLASS_APPLICATION: u8 = 1;
pub const CLASS_CONTEXT: u8 = 2;

pub const BOOLEAN: u64 = 1;
pub const INTEGER: u64 = 2;
pub const BIT_STRING: u64 = 3;
pub const OCTET_STRING: u64 = 4;
pub const NULL: u64 = 5;
pub const OID: u64 = 6;
pub const ENUMERATED: u64 = 10;
pub const UTC_TIME: u64 = 23;
pub const GENERALIZED_TIME: u64 = 24;

pub const UNIVERSAL_TAGS: EnumTable = &[
    (0, "END-OF-CONTENTS"),
    (1, "BOOLEAN"),
    (2, "INTEGER"),
    (3, "BIT STRING"),
    (4, "OCTET STRING"),
    (5, "NULL"),
    (6, "OBJECT IDENTIFIER"),
    (7, "ObjectDescriptor"),
    (8, "EXTERNAL"),
    (9, "REAL"),
    (10, "ENUMERATED"),
    (11, "EMBEDDED PDV"),
    (12, "UTF8String"),
    (13, "RELATIVE-OID"),
    (14, "TIME"),
    (16, "SEQUENCE"),
    (17, "SET"),
    (18, "NumericString"),
    (19, "PrintableString"),
    (20, "T61String"),
    (21, "VideotexString"),
    (22, "IA5String"),
    (23, "UTCTime"),
    (24, "GeneralizedTime"),
    (25, "GraphicString"),
    (26, "VisibleString"),
    (27, "GeneralString"),
    (28, "UniversalString"),
    (29, "CHARACTER STRING"),
    (30, "BMPString"),
];

/// Deepest structure the validity check descends into.
const MAX_DEPTH: u32 = 48;

/// A decoded identifier and length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tlv {
    pub class: u8,
    pub constructed: bool,
    pub tag: u64,
    /// The first identifier octet (class, constructed bit and short tag).
    pub id: u8,
    /// Identifier and length octets.
    pub header: u64,
    /// Content length; `None` for the BER indefinite form.
    pub len: Option<u64>,
}

impl Tlv {
    pub fn is_universal(&self, tag: u64) -> bool {
        self.class == CLASS_UNIVERSAL && self.tag == tag
    }

    /// `header + len`, for definite lengths.
    pub fn total(&self) -> Option<u64> {
        self.header.checked_add(self.len?)
    }

    /// A short type label: `SEQUENCE`, `[0]`, `[APPLICATION 3]`, ...
    pub fn label(&self) -> String {
        match self.class {
            CLASS_UNIVERSAL => crate::value::lookup(UNIVERSAL_TAGS, self.tag)
                .map_or_else(|| format!("[UNIVERSAL {}]", self.tag), str::to_owned),
            CLASS_APPLICATION => format!("[APPLICATION {}]", self.tag),
            CLASS_CONTEXT => format!("[{}]", self.tag),
            _ => format!("[PRIVATE {}]", self.tag),
        }
    }
}

/// Decodes the TLV header at the start of `data`.
pub fn header(data: &[u8]) -> Option<Tlv> {
    let &id = data.first()?;
    let mut at = 1usize;
    let mut tag = u64::from(id & 0x1f);
    if tag == 0x1f {
        tag = 0;
        loop {
            let &b = data.get(at)?;
            at = at.checked_add(1)?;
            tag = tag.checked_mul(128)?.checked_add(u64::from(b & 0x7f))?;
            if b & 0x80 == 0 {
                break;
            }
            if at > 10 {
                return None;
            }
        }
    }
    let &first = data.get(at)?;
    at = at.checked_add(1)?;
    let constructed = id & 0x20 != 0;
    let len = if first < 0x80 {
        Some(u64::from(first))
    } else if first == 0x80 {
        if !constructed {
            return None;
        }
        None
    } else {
        let n = usize::from(first & 0x7f);
        if n > 8 {
            return None;
        }
        let mut len = 0u64;
        for _ in 0..n {
            let &b = data.get(at)?;
            at = at.checked_add(1)?;
            len = len.checked_mul(256)?.checked_add(u64::from(b))?;
        }
        Some(len)
    };
    Some(Tlv {
        class: id >> 6,
        constructed,
        tag,
        id,
        header: u64::try_from(at).ok()?,
        len,
    })
}

/// The complete, definite-length TLVs at the start of `data`, with their
/// contents. Stops at the first element that is incomplete or indefinite.
pub fn elements(data: &[u8]) -> impl Iterator<Item = (Tlv, &[u8])> {
    let mut rest = data;
    std::iter::from_fn(move || {
        let tlv = header(rest)?;
        let start = to_usize(tlv.header);
        let end = start.checked_add(to_usize(tlv.len?))?;
        let content = rest.get(start..end)?;
        rest = rest.get(end..)?;
        Some((tlv, content))
    })
}

/// The first element of `data` and its content, if complete.
pub fn first(data: &[u8]) -> Option<(Tlv, &[u8])> {
    elements(data).next()
}

/// Whether `data` is exactly a sequence of well-formed definite-length
/// TLVs, recursively.
pub fn is_der(data: &[u8]) -> bool {
    valid(data, 0)
}

/// Whether `data` holds exactly one constructed element that is valid DER,
/// the test used to look inside OCTET and BIT STRINGs.
pub fn is_nested_der(data: &[u8]) -> bool {
    data.len() >= 2
        && header(data).is_some_and(|t| t.constructed && t.total() == Some(data.len() as u64))
        && is_der(data)
}

fn valid(data: &[u8], depth: u32) -> bool {
    if depth > MAX_DEPTH {
        return false;
    }
    let mut rest = data;
    while !rest.is_empty() {
        let Some(tlv) = header(rest) else {
            return false;
        };
        let (Some(len), start) = (tlv.len, to_usize(tlv.header)) else {
            return false;
        };
        let Some(content) = start
            .checked_add(to_usize(len))
            .and_then(|end| rest.get(start..end))
        else {
            return false;
        };
        let ok = if tlv.constructed {
            valid(content, depth.saturating_add(1))
        } else if tlv.class == CLASS_UNIVERSAL {
            match tlv.tag {
                0 => false,
                BOOLEAN => content.len() == 1,
                NULL => content.is_empty(),
                INTEGER | ENUMERATED => !content.is_empty(),
                OID => oid(content).is_some(),
                BIT_STRING => content.first().is_some_and(|&b| b < 8),
                _ => true,
            }
        } else {
            true
        };
        if !ok {
            return false;
        }
        rest = rest.get(start.saturating_add(to_usize(len))..).unwrap_or_default();
    }
    true
}

/// Dotted notation of an OBJECT IDENTIFIER's content.
pub fn oid(content: &[u8]) -> Option<String> {
    if content.is_empty() || content.last().is_some_and(|&b| b & 0x80 != 0) {
        return None;
    }
    let mut out = String::new();
    let mut value = 0u64;
    let mut first = true;
    for &b in content {
        value = value.checked_mul(128)?.checked_add(u64::from(b & 0x7f))?;
        if b & 0x80 != 0 {
            continue;
        }
        if first {
            let (a, rest) = match value {
                0..40 => (0, value),
                40..80 => (1, value.saturating_sub(40)),
                _ => (2, value.saturating_sub(80)),
            };
            out = format!("{a}.{rest}");
            first = false;
        } else {
            out.push('.');
            out.push_str(&value.to_string());
        }
        value = 0;
    }
    Some(out)
}

/// The value of a two's-complement INTEGER, if it fits in 64 bits.
pub fn integer(content: &[u8]) -> Option<i64> {
    if content.is_empty() || content.len() > 8 {
        return None;
    }
    let negative = content.first().is_some_and(|&b| b & 0x80 != 0);
    let mut bytes = if negative { [0xff; 8] } else { [0; 8] };
    let pad = 8usize.saturating_sub(content.len());
    for (slot, &b) in bytes.iter_mut().skip(pad).zip(content) {
        *slot = b;
    }
    Some(i64::from_be_bytes(bytes))
}

/// Text of a character-string type, by universal tag.
pub fn string(tag: u64, content: &[u8]) -> Option<String> {
    Some(match tag {
        12 | 18 | 19 | 22 | 25 | 26 | 27 | 7 => String::from_utf8_lossy(content).into_owned(),
        20 | 21 => crate::text::latin1(content),
        30 => crate::text::utf16(content, crate::fields::Endian::Big),
        28 => content
            .as_chunks::<4>()
            .0
            .iter()
            .map(|&c| char::from_u32(u32::from_be_bytes(c)).unwrap_or('\u{fffd}'))
            .collect(),
        _ => return None,
    })
}

/// Seconds since the Unix epoch of a UTCTime or GeneralizedTime.
pub fn time(tag: u64, content: &[u8]) -> Option<i64> {
    let text = std::str::from_utf8(content).ok()?;
    let digits: Vec<u32> = text
        .chars()
        .map_while(|c| c.to_digit(10))
        .collect();
    let num = |from: usize, n: usize| -> Option<i64> {
        let part = digits.get(from..from.checked_add(n)?)?;
        Some(part.iter().fold(0i64, |acc, &d| {
            acc.saturating_mul(10).saturating_add(i64::from(d))
        }))
    };
    let (year, rest) = if tag == UTC_TIME {
        let yy = num(0, 2)?;
        (yy.saturating_add(if yy < 50 { 2000 } else { 1900 }), 2)
    } else {
        (num(0, 4)?, 4)
    };
    let month = num(rest, 2)?;
    let day = num(rest.checked_add(2)?, 2)?;
    let hour = num(rest.checked_add(4)?, 2)?;
    let minute = num(rest.checked_add(6)?, 2).unwrap_or(0);
    let second = num(rest.checked_add(8)?, 2).unwrap_or(0);
    let days = days_from_civil(year, month, day)?;
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    days.checked_mul(86_400)?
        .checked_add(hour.checked_mul(3600)?)?
        .checked_add(minute.checked_mul(60)?)?
        .checked_add(second)
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's
/// algorithm).
#[allow(clippy::arithmetic_side_effects)] // inputs are range-checked first
pub fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    if !(1..=9999).contains(&year) || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

/// `YYYY-MM-DD` of a Unix timestamp, for summaries.
#[allow(clippy::arithmetic_side_effects)] // i128 cannot overflow for i64 input
pub fn date(unix_seconds: i64) -> String {
    let days = i128::from(unix_seconds).div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i128::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// A one-line rendering of a primitive value, for summaries.
pub fn display(tlv: &Tlv, content: &[u8]) -> Option<String> {
    if tlv.class != CLASS_UNIVERSAL {
        return printable(content);
    }
    match tlv.tag {
        OID => oid(content).map(|o| super::oids::name(&o).map_or(o, str::to_owned)),
        INTEGER | ENUMERATED => integer(content).map(|v| v.to_string()),
        BOOLEAN => content.first().map(|&b| (b != 0).to_string()),
        UTC_TIME | GENERALIZED_TIME => time(tlv.tag, content).map(date),
        tag => string(tag, content),
    }
}

/// Bytes that are plainly printable ASCII, as text.
pub fn printable(content: &[u8]) -> Option<String> {
    (!content.is_empty() && content.iter().all(|&b| (0x20..0x7f).contains(&b)))
        .then(|| String::from_utf8_lossy(content).into_owned())
}

/// `CN=example, O=Org` for the content of an X.500 Name.
pub fn name(content: &[u8]) -> String {
    let mut parts = Vec::new();
    for (_, rdn) in elements(content) {
        for (_, atv) in elements(rdn) {
            let mut fields = elements(atv);
            let (Some((t, oid_bytes)), Some((vt, value))) = (fields.next(), fields.next()) else {
                continue;
            };
            if !t.is_universal(OID) {
                continue;
            }
            let dotted = oid(oid_bytes).unwrap_or_default();
            let key = super::oids::short_attribute(&dotted)
                .map_or_else(|| dotted.clone(), str::to_owned);
            let text = display(&vt, value).unwrap_or_else(|| "…".to_owned());
            parts.push(format!("{key}={text}"));
        }
    }
    parts.join(", ")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn headers_and_values() {
        let t = header(&[0x30, 0x82, 0x01, 0x00]).unwrap();
        assert_eq!((t.tag, t.header, t.len), (16, 4, Some(256)));
        assert!(header(&[0x04, 0x80]).is_none());
        assert_eq!(header(&[0x30, 0x80]).unwrap().len, None);
        assert_eq!(header(&[0x9f, 0x81, 0x00, 0x00]).unwrap().tag, 128);
        assert_eq!(
            oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]).unwrap(),
            "1.2.840.113549.1.1.11"
        );
        assert_eq!(integer(&[0xff, 0x7f]), Some(-129));
        assert_eq!(integer(&[0x00, 0x80]), Some(128));
        assert_eq!(time(UTC_TIME, b"700101000000Z"), Some(0));
        assert_eq!(time(GENERALIZED_TIME, b"20000301000000Z"), Some(951_868_800));
        assert_eq!(date(951_868_800), "2000-03-01");
        assert!(is_nested_der(&[0x30, 0x03, 0x02, 0x01, 0x05]));
        assert!(!is_nested_der(&[0x30, 0x03, 0x02, 0x01]));
    }
}
