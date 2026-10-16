//! Typed field values: the contract between dissectors and frontends.
//!
//! Values carry interpretation (enum names, decoded flags) next to the raw
//! number. The raw bytes themselves are available through the node's span.

use std::borrow::Cow;
use std::fmt::{self, Write as _};

/// How an unsigned number is shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Radix {
    Dec,
    Hex,
    /// Octal, `0o…`: Unix permission bits and other octal-natured fields.
    Oct,
    /// Binary, `0b…`: small bit fields where the pattern is the point.
    Bin,
}

/// A field's interpreted value.
///
/// Hosts keep a fallback arm (`_ => render::value(v)`): atoms are added over
/// time, and a host that predates one still shows it as text.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Value {
    Bool(bool),
    UInt {
        value: u64,
        bits: u8,
        radix: Radix,
    },
    Int {
        value: i64,
        bits: u8,
    },
    /// A number with a symbolic name, if known. The name usually comes from
    /// a static table ([`lookup`]); a computed one is `Cow::Owned`.
    Enum {
        raw: u64,
        bits: u8,
        name: Option<Cow<'static, str>>,
    },
    /// A bit set with the table that names its bits, so a host can draw
    /// every bit, set or not. [`Value::flag_names`] gives the matched names
    /// (a multi-bit field's entry for value 0 included) and the bits no
    /// entry accounts for. Construct with [`Value::flags`] (fields:
    /// `.flags(table)`).
    Flags {
        raw: u64,
        bits: u8,
        table: FlagTable,
    },
    /// A floating-point number. `bits` is the width the file stores it in
    /// (16, 32, 64 or 80). `value` is exact for every width but 80 (the
    /// nearest `f64`); text renderings use the shortest decimal that reads
    /// back to the stored width (`0.8`, not `0.800000011920929`, for an
    /// `f32`). Construct with [`Value::f32`], [`Value::f64`] and friends.
    Float {
        value: f64,
        bits: u8,
    },
    /// A point in time as the file records it: zone, resolution and
    /// sub-second part included. Construct with [`Value::utc`] or a
    /// [`Time`] constructor.
    Timestamp(Time),
    Text(String),
    Bytes(Vec<u8>),
    /// A GUID or UUID, with the byte order it is stored in.
    Guid(Guid),
    /// A network or hardware address: IPv4, IPv6, MAC (EUI-48), EUI-64.
    Addr(Addr),
    /// A colour in the file's own model and depth. Construct with the
    /// [`Color`] constructors.
    Color(Box<Color>),
    /// A stored check value (CRC, checksum, digest, MAC) with its algorithm
    /// and whether it was verified. Construct with [`Check::new`] and put it
    /// on a node with [`Node::checksum`](crate::Node::checksum), which also
    /// reports a mismatch as a diagnostic.
    Checksum(Box<Check>),
    /// A quantity of bytes: `n` bytes, or `n` blocks of a fixed size.
    /// `bits` is the width the file stores `n` in. Text shows the exact
    /// count first, then the approximation: `698 bytes`,
    /// `1536 bytes (1.5 KiB)`, `8 × 512 bytes (4 KiB)`. Construct with
    /// [`Value::size`] and [`Value::blocks`] (fields: `.size()`,
    /// `.size_in(block)`). Counts of other things stay `UInt`.
    Size {
        n: u64,
        unit: SizeUnit,
        bits: u8,
    },
    /// A span of time, exactly: `ticks` of `1/per_sec` second (`per_sec`
    /// is 1 for seconds, 1000 for milliseconds, 90000 for MPEG ticks, a
    /// track's timescale or a sample rate). Text is computed with integers
    /// only, in one style: `250 ms`, `1.48 s`, `0:01:05.500`, `2 days,
    /// 3:04:05`, with the ticks added when a tick is not a power-of-ten
    /// fraction of a second (`1.48 s (133200/90000 s)`). Construct with
    /// [`Value::duration`] (fields: `.duration(per_sec)`).
    Duration {
        ticks: i64,
        per_sec: u64,
    },
}

/// What a [`Value::Size`] counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SizeUnit {
    Bytes,
    /// Blocks (sectors, clusters, pages) of this many bytes.
    Blocks(u32),
}

impl SizeUnit {
    /// Bytes per unit.
    pub fn bytes(self) -> u64 {
        match self {
            SizeUnit::Bytes => 1,
            SizeUnit::Blocks(b) => u64::from(b),
        }
    }
}

impl Value {
    /// A 64-bit float.
    pub const fn f64(value: f64) -> Value {
        Value::Float { value, bits: 64 }
    }

    /// A 32-bit float, kept exact and rendered in its shortest `f32` form.
    pub fn f32(value: f32) -> Value {
        Value::Float {
            value: f64::from(value),
            bits: 32,
        }
    }

    /// A 16-bit (half-precision) float, already widened to `f64`.
    pub const fn f16(value: f64) -> Value {
        Value::Float { value, bits: 16 }
    }

    /// An 80-bit x87 extended float, as the nearest `f64`.
    pub const fn f80(value: f64) -> Value {
        Value::Float { value, bits: 80 }
    }

    /// A UTC timestamp in whole seconds since the Unix epoch.
    pub const fn utc(secs: i64) -> Value {
        Value::Timestamp(Time::utc(secs))
    }

    /// A Windows FILETIME (100 ns ticks since 1601, UTC), to the tick.
    pub fn filetime(ticks: u64) -> Value {
        Value::Timestamp(Time::filetime(ticks))
    }

    /// A size of `n` bytes.
    pub const fn size(n: u64) -> Value {
        Value::Size {
            n,
            unit: SizeUnit::Bytes,
            bits: 64,
        }
    }

    /// A size of `n` blocks of `block` bytes (a block of 1 byte is a size
    /// in bytes; one over 4 GiB, which no format has, is the product).
    pub fn blocks(n: u64, block: impl Into<u64>) -> Value {
        let block = block.into();
        match u32::try_from(block) {
            Ok(1) => Value::size(n),
            Ok(block) => Value::Size {
                n,
                unit: SizeUnit::Blocks(block),
                bits: 64,
            },
            Err(_) => Value::size(n.saturating_mul(block)),
        }
    }

    /// The same size, stored `bits` wide (the default is 64).
    pub fn bits(mut self, width: u8) -> Value {
        if let Value::Size { bits, .. } = &mut self {
            *bits = width;
        }
        self
    }

    /// A span of `ticks` of `1/per_sec` second (`per_sec` 0 is taken as 1).
    pub const fn duration(ticks: i64, per_sec: u64) -> Value {
        Value::Duration {
            ticks,
            per_sec: if per_sec == 0 { 1 } else { per_sec },
        }
    }

    /// A span of whole seconds.
    pub const fn secs(secs: i64) -> Value {
        Value::duration(secs, 1)
    }

    /// This number (unsigned, or signed and not negative) as a size of
    /// `block`-byte blocks, at its width; anything else unchanged.
    pub fn to_size(self, block: impl Into<u64>) -> Value {
        let n = match &self {
            Value::UInt { value, bits, .. } => Some((*value, *bits)),
            Value::Int { value, bits } => u64::try_from(*value).ok().map(|v| (v, *bits)),
            _ => None,
        };
        match n {
            Some((n, bits)) => Value::blocks(n, block).bits(bits),
            None => self,
        }
    }

    /// This number (signed or unsigned) as a span of ticks of `1/per_sec`
    /// second; anything else unchanged.
    pub fn to_duration(self, per_sec: u64) -> Value {
        match self {
            Value::Int { value, .. } => Value::duration(value, per_sec),
            Value::UInt { value, .. } => {
                Value::duration(i64::try_from(value).unwrap_or(i64::MAX), per_sec)
            }
            other => other,
        }
    }

    /// The size in bytes (blocks times their size; `None` on overflow) of
    /// a [`Value::Size`].
    pub fn size_bytes(&self) -> Option<u64> {
        match self {
            Value::Size { n, unit, .. } => n.checked_mul(unit.bytes()),
            _ => None,
        }
    }

    /// The number underneath an unsigned value: a number, an enum, flags,
    /// or a size's count.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::UInt { value, .. } => Some(*value),
            Value::Enum { raw, .. } | Value::Flags { raw, .. } => Some(*raw),
            Value::Size { n, .. } => Some(*n),
            Value::Int { value, .. } => u64::try_from(*value).ok(),
            Value::Duration { ticks, .. } => u64::try_from(*ticks).ok(),
            _ => None,
        }
    }

    /// A UUID stored in RFC 4122 (big-endian) order: the first 16 bytes
    /// of `b` (`Bytes` if there are fewer).
    pub fn uuid(b: &[u8]) -> Value {
        Guid::big_at(b).map_or_else(|| Value::Bytes(b.to_vec()), Value::Guid)
    }

    /// A GUID stored in Microsoft's mixed-endian layout: the first 16
    /// bytes of `b` (`Bytes` if there are fewer).
    pub fn guid(b: &[u8]) -> Value {
        Guid::mixed_at(b).map_or_else(|| Value::Bytes(b.to_vec()), Value::Guid)
    }

    /// A colour.
    pub fn color(c: Color) -> Value {
        Value::Color(Box::new(c))
    }

    /// A set of flags named by `table`.
    pub const fn flags(raw: u64, bits: u8, table: FlagTable) -> Value {
        Value::Flags { raw, bits, table }
    }

    /// For [`Value::Flags`]: the names of the matched entries and the set
    /// bits no entry accounts for.
    pub fn flag_names(&self) -> Option<(Vec<&'static str>, u64)> {
        match self {
            Value::Flags { raw, table, .. } => Some(decode_flags(table, *raw)),
            _ => None,
        }
    }

    /// An enum value with a computed name (one no static table holds).
    pub fn named(raw: u64, bits: u8, name: impl Into<Cow<'static, str>>) -> Value {
        Value::Enum {
            raw,
            bits,
            name: Some(name.into()),
        }
    }
}

/// Which clock a [`Time`] was recorded on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Zone {
    /// `secs` is the UTC instant.
    Utc,
    /// The file recorded the wall clock and its offset from UTC, in minutes
    /// east. `secs` is still the UTC instant; the wall clock is
    /// `secs + 60 * offset`.
    Offset(i16),
    /// A wall clock in an unrecorded zone (DOS dates, HFS, SYSTEMTIME...).
    /// `secs` is that wall clock read as if it were UTC. Hosts must not
    /// convert it: the instant is unknown.
    Local,
}

/// How precisely a [`Time`] was recorded, which is how much of it is shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Res {
    /// A date with no time of day.
    Day,
    Minute,
    Second,
    /// Fractions of a second, shown with this many digits (1 to 9: 3 for
    /// milliseconds, 6 for microseconds, 7 for FILETIME ticks, 9 for
    /// nanoseconds). The text leaves out a fraction that is zero
    /// (`03:04:05 UTC`, not `03:04:05.0000000 UTC`); ISO 8601 text keeps it.
    Sub(u8),
}

/// A timestamp: seconds since 1970-01-01 00:00:00, nanoseconds past them,
/// the zone it was recorded in and its resolution. Text renderings never
/// consult the host's zone: `2026-10-16 02:56:21 UTC`,
/// `2026-10-07 21:44:26 UTC+01:00` (the recorded wall clock),
/// `2016-09-27 12:42:06 (local time)`, `2024-01-01` for a date.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Time {
    /// For [`Zone::Utc`] and [`Zone::Offset`], the UTC instant; for
    /// [`Zone::Local`], the wall clock read as if UTC.
    pub secs: i64,
    /// `0..1_000_000_000`, past `secs`.
    pub nanos: u32,
    pub zone: Zone,
    pub res: Res,
}

impl Time {
    /// Whole seconds since the Unix epoch, UTC.
    pub const fn utc(secs: i64) -> Time {
        Time {
            secs,
            nanos: 0,
            zone: Zone::Utc,
            res: Res::Second,
        }
    }

    /// A wall clock in an unrecorded zone, as seconds since 1970-01-01
    /// 00:00:00 of that clock.
    pub const fn local(wall_secs: i64) -> Time {
        Time {
            secs: wall_secs,
            nanos: 0,
            zone: Zone::Local,
            res: Res::Second,
        }
    }

    /// A UTC instant recorded with its wall clock `minutes` east of UTC.
    pub const fn offset(utc_secs: i64, minutes: i16) -> Time {
        Time {
            secs: utc_secs,
            nanos: 0,
            zone: Zone::Offset(minutes),
            res: Res::Second,
        }
    }

    /// A wall clock `minutes` east of UTC, as seconds since 1970-01-01
    /// 00:00:00 of that clock: the instant is the wall clock less the
    /// offset.
    pub fn offset_wall(wall_secs: i64, minutes: i16) -> Time {
        Time::offset(
            wall_secs.saturating_sub(i64::from(minutes).saturating_mul(60)),
            minutes,
        )
    }

    /// Windows FILETIME: 100 ns ticks since 1601-01-01, UTC, shown to the
    /// tick.
    pub fn filetime(ticks: u64) -> Time {
        Time::utc(crate::text::filetime_to_unix(ticks)).frac(
            u32::try_from(ticks % 10_000_000)
                .unwrap_or(0)
                .saturating_mul(100),
            7,
        )
    }

    /// A count of `1/per_sec` units since the Unix epoch (negative counts
    /// are before 1970), UTC, shown to that unit. `per_sec` is a power of
    /// ten up to 10^9 (1000 for milliseconds).
    pub fn unix_scaled(count: i64, per_sec: u32) -> Time {
        let per_sec = per_sec.clamp(1, 1_000_000_000);
        let per = i64::from(per_sec);
        let t = Time::utc(count.div_euclid(per));
        let digits = u8::try_from(per_sec.ilog10()).unwrap_or(9);
        if digits == 0 {
            return t;
        }
        let nanos = count
            .rem_euclid(per)
            .saturating_mul(1_000_000_000i64.checked_div(per).unwrap_or(1));
        t.frac(u32::try_from(nanos).unwrap_or(0), digits)
    }

    /// Milliseconds since the Unix epoch, UTC.
    pub fn unix_millis(ms: i64) -> Time {
        Time::unix_scaled(ms, 1000)
    }

    /// Microseconds since the Unix epoch, UTC.
    pub fn unix_micros(us: i64) -> Time {
        Time::unix_scaled(us, 1_000_000)
    }

    /// Nanoseconds since the Unix epoch, UTC.
    pub fn unix_nanos(ns: i64) -> Time {
        Time::unix_scaled(ns, 1_000_000_000)
    }

    /// An MS-DOS date and time (local, 2-second steps), or `None` when the
    /// date is not a calendar date.
    pub fn dos(date: u16, time: u16) -> Option<Time> {
        let day = Time::dos_date(date)?;
        let secs = i64::from(time >> 11)
            .saturating_mul(3600)
            .saturating_add(i64::from((time >> 5) & 0x3f).saturating_mul(60))
            .saturating_add(i64::from(time & 0x1f).saturating_mul(2));
        Some(Time::local(day.secs.saturating_add(secs)))
    }

    /// An MS-DOS date with no time of day (local), or `None` when it is
    /// not a calendar date.
    pub fn dos_date(date: u16) -> Option<Time> {
        let days = crate::formats::util::civil::days_from_civil(
            1980i64.saturating_add(i64::from(date >> 9)),
            i64::from((date >> 5) & 0x0f),
            i64::from(date & 0x1f),
        )?;
        Some(Time::local(days.saturating_mul(86_400)).day())
    }

    /// The same time with a sub-second part of `nanos`, shown with
    /// `digits` (1..=9) fractional digits.
    pub fn frac(mut self, nanos: u32, digits: u8) -> Time {
        self.nanos = nanos.min(999_999_999);
        self.res = Res::Sub(digits.clamp(1, 9));
        self
    }

    /// The same time with a millisecond part.
    pub fn millis(self, ms: u32) -> Time {
        self.frac(ms.saturating_mul(1_000_000), 3)
    }

    /// The same time with a microsecond part.
    pub fn micros(self, us: u32) -> Time {
        self.frac(us.saturating_mul(1000), 6)
    }

    /// The same time with a nanosecond part.
    pub fn nanos(self, ns: u32) -> Time {
        self.frac(ns, 9)
    }

    /// The same time, recorded to the day.
    pub const fn day(mut self) -> Time {
        self.res = Res::Day;
        self
    }

    /// The same time, recorded to the minute.
    pub const fn minute(mut self) -> Time {
        self.res = Res::Minute;
        self
    }

    /// Seconds since 1970-01-01 00:00:00 of the clock the file recorded:
    /// UTC, the offset's wall clock, or the local wall clock.
    pub fn wall_secs(&self) -> i64 {
        match self.zone {
            Zone::Offset(m) => self.secs.saturating_add(i64::from(m).saturating_mul(60)),
            Zone::Utc | Zone::Local => self.secs,
        }
    }
}

impl Time {
    /// The recorded wall clock, `sep` between date and time:
    /// `2026-10-09 23:05:53.4961830`, or the date alone for [`Res::Day`].
    fn write_clock(&self, f: &mut impl fmt::Write, sep: char, zero_frac: bool) -> fmt::Result {
        let wall = self.wall_secs();
        let (year, month, day) = crate::formats::util::civil::civil(wall.div_euclid(86_400));
        write!(f, "{year:04}-{month:02}-{day:02}")?;
        let rem = wall.rem_euclid(86_400);
        let (h, m, s) = (rem / 3600, rem % 3600 / 60, rem % 60);
        match self.res {
            Res::Day => Ok(()),
            Res::Minute => write!(f, "{sep}{h:02}:{m:02}"),
            Res::Second => write!(f, "{sep}{h:02}:{m:02}:{s:02}"),
            Res::Sub(_) if self.nanos == 0 && !zero_frac => {
                write!(f, "{sep}{h:02}:{m:02}:{s:02}")
            }
            Res::Sub(digits) => {
                let digits = u32::from(digits.clamp(1, 9));
                let scale = 10u32.checked_pow(9u32.saturating_sub(digits)).unwrap_or(1);
                let shown = self.nanos.min(999_999_999).checked_div(scale).unwrap_or(0);
                let width = usize::try_from(digits).unwrap_or(9);
                write!(f, "{sep}{h:02}:{m:02}:{s:02}.{shown:0width$}")
            }
        }
    }

    /// `+01:00` for an offset in minutes east of UTC.
    fn write_offset(f: &mut impl fmt::Write, minutes: i16) -> fmt::Result {
        let sign = if minutes < 0 { '-' } else { '+' };
        let a = minutes.unsigned_abs();
        write!(f, "{sign}{:02}:{:02}", a / 60, a % 60)
    }

    /// The text form ([`Display`](fmt::Display)) with the fraction even
    /// when it is zero, for listings whose times should line up.
    pub fn text_full(&self) -> String {
        let mut out = String::new();
        let _ = self.write_clock(&mut out, ' ', true);
        let _ = self.write_zone(&mut out);
        out
    }

    fn write_zone(&self, f: &mut impl fmt::Write) -> fmt::Result {
        if self.res == Res::Day {
            return Ok(());
        }
        match self.zone {
            Zone::Utc => f.write_str(" UTC"),
            Zone::Offset(minutes) => {
                f.write_str(" UTC")?;
                Time::write_offset(f, minutes)
            }
            Zone::Local => f.write_str(" (local time)"),
        }
    }

    /// ISO 8601 / RFC 3339 text of the recorded clock:
    /// `2026-10-09T23:05:53.4961830Z`, `2026-10-07T21:44:26+01:00`, a local
    /// time with no designator, the date alone for [`Res::Day`].
    pub fn iso8601(&self) -> String {
        let mut out = String::new();
        let _ = self.write_clock(&mut out, 'T', true);
        if self.res != Res::Day {
            let _ = match self.zone {
                Zone::Utc => fmt::Write::write_str(&mut out, "Z"),
                Zone::Offset(minutes) => Time::write_offset(&mut out, minutes),
                Zone::Local => Ok(()),
            };
        }
        out
    }
}

impl From<Time> for Value {
    fn from(t: Time) -> Value {
        Value::Timestamp(t)
    }
}

impl fmt::Display for Time {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_clock(f, ' ', false)?;
        self.write_zone(f)
    }
}

/// A check value as stored: a small integer (CRCs, sums: shown in its
/// radix like any number, `0x…` unless the format writes it otherwise, as
/// tar's octal) or a byte string (digests, MACs: shown in full, as
/// lowercase hex in stored order).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Digest {
    Int { value: u64, bits: u8, radix: Radix },
    Bytes(Vec<u8>),
}

impl Digest {
    /// The digest's bytes, an integer big-endian at its width.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Digest::Int { value, bits, .. } => {
                let len = usize::from(bits.div_ceil(8)).clamp(1, 8);
                value
                    .to_be_bytes()
                    .get(8usize.saturating_sub(len)..)
                    .unwrap_or_default()
                    .to_vec()
            }
            Digest::Bytes(b) => b.clone(),
        }
    }

    /// The same check value, however each side is held.
    fn same(&self, other: &Digest) -> bool {
        match (self, other) {
            (Digest::Int { value: a, .. }, Digest::Int { value: b, .. }) => a == b,
            (Digest::Bytes(a), Digest::Bytes(b)) => a == b,
            _ => self.to_bytes() == other.to_bytes(),
        }
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Digest::Int { value, radix, .. } => match radix {
                Radix::Dec => write!(f, "{value}"),
                Radix::Hex => write!(f, "{value:#x}"),
                Radix::Oct => write!(f, "{value:#o}"),
                Radix::Bin => write!(f, "{value:#b}"),
            },
            Digest::Bytes(b) => b.iter().try_for_each(|byte| write!(f, "{byte:02x}")),
        }
    }
}

macro_rules! digest_from_int {
    ($($t:ty),*) => {$(
        impl From<$t> for Digest {
            fn from(value: $t) -> Digest {
                Digest::Int { value: u64::from(value), bits: <$t>::BITS as u8, radix: Radix::Hex }
            }
        }
    )*};
}
digest_from_int!(u8, u16, u32, u64);

impl From<Vec<u8>> for Digest {
    fn from(b: Vec<u8>) -> Digest {
        Digest::Bytes(b)
    }
}

impl From<&[u8]> for Digest {
    fn from(b: &[u8]) -> Digest {
        Digest::Bytes(b.to_vec())
    }
}

impl From<&Vec<u8>> for Digest {
    fn from(b: &Vec<u8>) -> Digest {
        Digest::Bytes(b.clone())
    }
}

impl<const N: usize> From<[u8; N]> for Digest {
    fn from(b: [u8; N]) -> Digest {
        Digest::Bytes(b.to_vec())
    }
}

impl<const N: usize> From<&[u8; N]> for Digest {
    fn from(b: &[u8; N]) -> Digest {
        Digest::Bytes(b.to_vec())
    }
}

/// What became of a stored check value.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Verdict {
    /// Recomputed, and it equals the stored value.
    Valid,
    /// Recomputed, and it differs; `computed` is what the data gives, when
    /// the dissector has it.
    Mismatch { computed: Option<Digest> },
    /// Not verified: the dissector doesn't compute this check.
    NotChecked,
    /// Not verified here, for the reason given ("encrypted", "over the read
    /// limit"...).
    Skipped(Cow<'static, str>),
    /// Verified where the data is decoded, not here: a mismatch is reported
    /// on the decoded content. Shows the stored value alone.
    Deferred,
}

/// A stored check value: the algorithm, the value and the verdict. Text:
/// `0xae426082 (CRC-32, valid)`, `0x1234 (CRC-16, mismatch: computed
/// 0x89ab)`, a digest in full (`d225e5…8f2a (SHA-256, not checked)`),
/// `… (MD5, skipped: encrypted)`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Check {
    /// The algorithm's usual name: "CRC-32", "CRC-32C", "Adler-32",
    /// "Fletcher-32", "SHA-256", "HMAC-SHA-256", or the format's own
    /// ("TCP checksum", "lookup3", "8-bit sum").
    pub algo: Cow<'static, str>,
    pub stored: Digest,
    pub verdict: Verdict,
}

impl Check {
    /// A stored check value, not (yet) verified.
    pub fn new(algo: impl Into<Cow<'static, str>>, stored: impl Into<Digest>) -> Check {
        Check {
            algo: algo.into(),
            stored: stored.into(),
            verdict: Verdict::NotChecked,
        }
    }

    /// Verified against `computed`: valid when it equals the stored value.
    /// An integer computed value is shown in the stored one's radix.
    pub fn verify(mut self, computed: impl Into<Digest>) -> Check {
        let mut computed = computed.into();
        if let (Digest::Int { radix: shown, .. }, Digest::Int { radix, .. }) =
            (&self.stored, &mut computed)
        {
            *radix = *shown;
        }
        self.verdict = if self.stored.same(&computed) {
            Verdict::Valid
        } else {
            Verdict::Mismatch {
                computed: Some(computed),
            }
        };
        self
    }

    /// [`Check::verify`] when the dissector could compute the value;
    /// unchanged (not checked) for `None`.
    pub fn verify_opt<D: Into<Digest>>(self, computed: Option<D>) -> Check {
        match computed {
            Some(c) => self.verify(c),
            None => self,
        }
    }

    /// Verified, by a comparison made elsewhere: valid or a mismatch whose
    /// computed value isn't at hand.
    pub fn verified(mut self, ok: bool) -> Check {
        self.verdict = if ok {
            Verdict::Valid
        } else {
            Verdict::Mismatch { computed: None }
        };
        self
    }

    /// Not verified, for `reason`.
    pub fn skipped(mut self, reason: impl Into<Cow<'static, str>>) -> Check {
        self.verdict = Verdict::Skipped(reason.into());
        self
    }

    /// A check of decoded data that the decoder verifies (and reports as a
    /// diagnostic of the decoded stream) rather than the dissector:
    /// Verified when the data is decoded (a mismatch is reported on the
    /// content): shows the stored value alone.
    pub fn on_decode(mut self) -> Check {
        self.verdict = Verdict::Deferred;
        self
    }

    pub fn is_valid(&self) -> bool {
        self.verdict == Verdict::Valid
    }

    pub fn is_mismatch(&self) -> bool {
        matches!(self.verdict, Verdict::Mismatch { .. })
    }

    /// What the data gives, when it was verified (the stored value when
    /// valid).
    pub fn computed(&self) -> Option<&Digest> {
        match &self.verdict {
            Verdict::Valid => Some(&self.stored),
            Verdict::Mismatch { computed } => computed.as_ref(),
            _ => None,
        }
    }

    /// This check as the one of the field at position `at`, for
    /// [`Record::checked_node`](crate::dsl::Record::checked_node) and
    /// [`Fields::verifying`](crate::Fields::verifying).
    pub fn at(&self, at: u64) -> Vec<(u64, Check)> {
        vec![(at, self.clone())]
    }

    /// The verdict alone: `valid`, `mismatch: computed 0x89ab`, `not
    /// checked`, `skipped: encrypted`.
    pub fn verdict_text(&self) -> String {
        match &self.verdict {
            Verdict::Valid => "valid".to_owned(),
            Verdict::Mismatch {
                computed: Some(c), ..
            } => format!("mismatch: computed {c}"),
            Verdict::Mismatch { computed: None } => "mismatch".to_owned(),
            Verdict::NotChecked => "not checked".to_owned(),
            Verdict::Skipped(reason) => format!("skipped: {reason}"),
            Verdict::Deferred => String::new(),
        }
    }

    /// The diagnostic message for a mismatch: `CRC-32 mismatch: stored
    /// 0x1234, computed 0x89ab`.
    pub fn mismatch_text(&self) -> Option<String> {
        match &self.verdict {
            Verdict::Mismatch { computed: Some(c) } => Some(format!(
                "{} mismatch: stored {}, computed {c}",
                self.algo, self.stored
            )),
            Verdict::Mismatch { computed: None } => {
                Some(format!("{} mismatch: stored {}", self.algo, self.stored))
            }
            _ => None,
        }
    }
}

impl From<Check> for Value {
    fn from(c: Check) -> Value {
        Value::Checksum(Box::new(c))
    }
}

impl fmt::Display for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.verdict == Verdict::Deferred {
            return write!(f, "{}", self.stored);
        }
        write!(
            f,
            "{} ({}, {})",
            self.stored,
            self.algo,
            self.verdict_text()
        )
    }
}

/// `(raw value, name)` pairs.
pub type EnumTable = &'static [(u64, &'static str)];

/// A flag matches when `raw & mask == value`. Single bits have
/// `mask == value`; multi-bit fields (e.g. alignment) use one entry per value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlagDef {
    pub mask: u64,
    pub value: u64,
    pub name: &'static str,
}

pub type FlagTable = &'static [FlagDef];

pub const fn flag(bit: u64, name: &'static str) -> FlagDef {
    FlagDef {
        mask: bit,
        value: bit,
        name,
    }
}

pub const fn field(mask: u64, value: u64, name: &'static str) -> FlagDef {
    FlagDef { mask, value, name }
}

/// A multi-bit field that holds a number (an offset, a count) rather than
/// flags: its bits are accounted for (never "unknown") but not named in the
/// text, and a host can show the number. Stored as a `value` outside the
/// mask, which no flag entry has.
pub const fn number(mask: u64, name: &'static str) -> FlagDef {
    FlagDef {
        mask,
        value: !mask,
        name,
    }
}

pub fn lookup(table: EnumTable, raw: u64) -> Option<&'static str> {
    table.iter().find(|(v, _)| *v == raw).map(|(_, n)| *n)
}

/// Returns matched flag names and the bits not covered by any match. An
/// entry matches when `raw & mask == value`, a value of 0 included (a
/// multi-bit field's `DICT_64K`, a single bit's "clear" meaning); an entry
/// with no mask never matches.
pub fn decode_flags(table: FlagTable, raw: u64) -> (Vec<&'static str>, u64) {
    let mut covered = 0u64;
    let mut set = Vec::new();
    for def in table {
        if def.is_number() {
            covered |= def.mask;
        } else if def.matches(raw) {
            set.push(def.name);
            covered |= def.mask;
        }
    }
    (set, raw & !covered)
}

impl FlagDef {
    /// Whether this entry describes `raw` (never, for a [`number`]).
    pub const fn matches(&self, raw: u64) -> bool {
        self.mask != 0 && raw & self.mask == self.value
    }

    /// Whether this entry is a [`number`] field rather than a flag.
    pub const fn is_number(&self) -> bool {
        self.value & !self.mask != 0
    }
}

/// The byte order a [`Guid`] is stored in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum GuidOrder {
    /// Microsoft's layout: the first three fields little-endian (Windows,
    /// COM, .NET, UEFI, GPT). Text is braced: `{00112233-4455-6677-8899-aabbccddeeff}`.
    Mixed,
    /// RFC 4122 / 9562 network order, every byte as written (Linux file
    /// systems, Apple, ISO BMFF, most of the rest). Text is unbraced:
    /// `00112233-4455-6677-8899-aabbccddeeff`.
    Big,
}

/// A GUID or UUID: its 16 bytes as stored and the order they are in.
/// Equality is of the stored form (the same identifier stored in the two
/// orders compares unequal; compare [`Guid::uuid`] for identity).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Guid {
    /// The bytes as stored in the file.
    pub bytes: [u8; 16],
    pub order: GuidOrder,
}

impl Guid {
    /// A Microsoft GUID from its fields (`{data1-data2-data3-data4}`),
    /// stored mixed-endian: for tables of known GUIDs.
    pub const fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Guid {
        let [a, b, c, d] = data1.to_le_bytes();
        let [e, f] = data2.to_le_bytes();
        let [g, h] = data3.to_le_bytes();
        let [i, j, k, l, m, n, o, p] = data4;
        Guid {
            bytes: [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p],
            order: GuidOrder::Mixed,
        }
    }

    /// 16 stored bytes in Microsoft's mixed-endian layout.
    pub const fn mixed(bytes: [u8; 16]) -> Guid {
        Guid {
            bytes,
            order: GuidOrder::Mixed,
        }
    }

    /// 16 stored bytes in RFC 4122 (big-endian) order.
    pub const fn big(bytes: [u8; 16]) -> Guid {
        Guid {
            bytes,
            order: GuidOrder::Big,
        }
    }

    /// The first 16 bytes of `b` in Microsoft's mixed-endian layout, or
    /// `None` if there are fewer.
    pub fn mixed_at(b: &[u8]) -> Option<Guid> {
        Some(Guid::mixed(b.get(..16)?.try_into().ok()?))
    }

    /// The first 16 bytes of `b` in RFC 4122 order, or `None` if there are
    /// fewer.
    pub fn big_at(b: &[u8]) -> Option<Guid> {
        Some(Guid::big(b.get(..16)?.try_into().ok()?))
    }

    /// The identifier in RFC 4122 byte order (the order of its text),
    /// whatever the stored order.
    pub const fn uuid(&self) -> [u8; 16] {
        match self.order {
            GuidOrder::Mixed => self.swapped(),
            GuidOrder::Big => self.bytes,
        }
    }

    /// The first field (`data1` of Microsoft's layout), as a number.
    pub const fn data1(&self) -> u32 {
        let [a, b, c, d, ..] = self.uuid();
        u32::from_be_bytes([a, b, c, d])
    }

    /// The second field, as a number.
    pub const fn data2(&self) -> u16 {
        let [_, _, _, _, e, f, ..] = self.uuid();
        u16::from_be_bytes([e, f])
    }

    /// The third field, as a number.
    pub const fn data3(&self) -> u16 {
        let [_, _, _, _, _, _, g, h, ..] = self.uuid();
        u16::from_be_bytes([g, h])
    }

    /// The last eight bytes.
    pub const fn data4(&self) -> [u8; 8] {
        let [_, _, _, _, _, _, _, _, i, j, k, l, m, n, o, p] = self.bytes;
        [i, j, k, l, m, n, o, p]
    }

    /// The identifier's 16 bytes in Windows' mixed-endian layout, whatever
    /// the stored order.
    pub const fn to_le_bytes(&self) -> [u8; 16] {
        match self.order {
            GuidOrder::Mixed => self.bytes,
            GuidOrder::Big => self.swapped(),
        }
    }

    /// The same 16 bytes with the first three fields reversed (an
    /// involution between the two layouts).
    const fn swapped(&self) -> [u8; 16] {
        let [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p] = self.bytes;
        [d, c, b, a, f, e, h, g, i, j, k, l, m, n, o, p]
    }

    /// The identifier as RFC 4122 text, lowercase and unbraced, whatever
    /// the stored order.
    pub fn uuid_text(&self) -> String {
        let mut out = String::with_capacity(36);
        for (i, byte) in self.uuid().iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                out.push('-');
            }
            let _ = write!(out, "{byte:02x}");
        }
        out
    }
}

impl fmt::Display for Guid {
    /// Braced for Microsoft's mixed-endian layout, unbraced for RFC 4122
    /// order: the text says which order the file stores.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.order {
            GuidOrder::Mixed => write!(f, "{{{}}}", self.uuid_text()),
            GuidOrder::Big => f.write_str(&self.uuid_text()),
        }
    }
}

/// A network or hardware address. Text: `192.0.2.1`, `2001:db8::1` (RFC
/// 5952), `00:1b:63:84:45:e6`, `00:1b:63:ff:fe:84:45:e6`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Addr {
    V4([u8; 4]),
    V6([u8; 16]),
    /// A MAC (EUI-48) address.
    Mac([u8; 6]),
    Eui64([u8; 8]),
}

impl Addr {
    /// The address bytes in network order.
    pub fn bytes(&self) -> &[u8] {
        match self {
            Addr::V4(b) => b,
            Addr::V6(b) => b,
            Addr::Mac(b) => b,
            Addr::Eui64(b) => b,
        }
    }

    /// An IPv4 address from 4 bytes in network order, `None` if `b` is
    /// shorter.
    pub fn v4_at(b: &[u8]) -> Option<Addr> {
        Some(Addr::V4(b.get(..4)?.try_into().ok()?))
    }

    /// An IPv6 address from 16 bytes in network order.
    pub fn v6_at(b: &[u8]) -> Option<Addr> {
        Some(Addr::V6(b.get(..16)?.try_into().ok()?))
    }

    /// A MAC address from 6 bytes.
    pub fn mac_at(b: &[u8]) -> Option<Addr> {
        Some(Addr::Mac(b.get(..6)?.try_into().ok()?))
    }

    /// An EUI-64 from 8 bytes.
    pub fn eui64_at(b: &[u8]) -> Option<Addr> {
        Some(Addr::Eui64(b.get(..8)?.try_into().ok()?))
    }

    /// An IPv4 address held as a number (`0xc0000201` is 192.0.2.1).
    pub const fn v4_u32(n: u32) -> Addr {
        Addr::V4(n.to_be_bytes())
    }
}

impl From<Addr> for Value {
    fn from(a: Addr) -> Value {
        Value::Addr(a)
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Addr::V4(b) => std::net::Ipv4Addr::from(*b).fmt(f),
            Addr::V6(b) => std::net::Ipv6Addr::from(*b).fmt(f),
            Addr::Mac(b) => colon_hex(f, b),
            Addr::Eui64(b) => colon_hex(f, b),
        }
    }
}

fn colon_hex(f: &mut fmt::Formatter<'_>, b: &[u8]) -> fmt::Result {
    for (i, byte) in b.iter().enumerate() {
        if i > 0 {
            f.write_str(":")?;
        }
        write!(f, "{byte:02x}")?;
    }
    Ok(())
}

/// How a [`Color`]'s components are to be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ColorModel {
    /// Red, green, blue.
    Rgb,
    /// One component, the lightness.
    Gray,
    /// Cyan, magenta, yellow, black.
    Cmyk,
    /// CIE L\*a\*b\* (D50): L in 0..100, a and b about -128..127.
    Lab,
    /// Hue (a fraction of the circle), saturation, brightness.
    Hsb,
}

impl ColorModel {
    /// How many of [`Color::components`] the model uses.
    pub const fn components(self) -> usize {
        match self {
            ColorModel::Gray => 1,
            ColorModel::Rgb | ColorModel::Lab | ColorModel::Hsb => 3,
            ColorModel::Cmyk => 4,
        }
    }
}

/// How the file stores a [`Color`]'s components.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ColorDepth {
    /// Unsigned integers of this many bits each (8 for `#rrggbb`; 4 for
    /// the Amiga's 12-bit colours, 16 for 48-bit).
    Bits(u8),
    /// Floats of this width (16, 32 or 64).
    Float(u8),
    /// Bit fields packed into one number, `raw` (`bits` wide, shown too),
    /// named by `layout` ("RGB565", "X1R5G5B5", "Atari ST"). Components
    /// were widened to 8 bits by bit replication.
    Packed {
        raw: u64,
        bits: u8,
        layout: &'static str,
    },
}

/// The colour space a [`Color`]'s RGB (or gray) components are in. No
/// colour management happens in the core: this records what the file
/// says, or what it implies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ColorSpace {
    /// sRGB, or assumed to be: what an untagged RGB value in a file is.
    Srgb,
    /// sRGB primaries with linear light (scene-referred floats, OpenEXR).
    LinearSrgb,
    DisplayP3,
    Rec2020,
    /// Device values with no stated space (a printer's CMYK, PDF's
    /// DeviceGray and DeviceRGB, an ink): shown as is, previewed
    /// approximately.
    Device,
}

/// A colour's alpha (opacity, 0 transparent to 1 opaque).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Alpha {
    pub value: f64,
    /// Whether the colour components are already multiplied by it.
    pub premultiplied: bool,
}

/// Whether [`Color::to_srgb8`] is the colour itself or a stand-in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Exactness {
    /// The sRGB value of the colour, rounded to 8 bits.
    Exact,
    /// A preview: CMYK, Lab, device values or out-of-gamut colours, which
    /// need a profile (or a clip) to show.
    Approximate,
}

/// A colour as the file stores it: model, components, depth, alpha,
/// space, and the name of a spot colour. Text follows CSS Color 4 in the
/// file's own terms: `#ff8800` / `#ff880080` for sRGB of 8 bits or fewer,
/// `#ff0000 (RGB565 0xf800)` for a packed one, `color(srgb-linear 1 0.5 0)`,
/// `device-cmyk(0 0.5 1 0)`, `lab(50 20 -30)`, `hsb(240 50% 100%)`, and a
/// named colour as `"PANTONE 186 C" (device-cmyk(…))`.
#[derive(Clone, Debug, PartialEq)]
pub struct Color {
    pub model: ColorModel,
    /// The components, normalised to 0..1 (Lab in its own ranges: L
    /// 0..100, a and b about ±128). Unused ones are 0.
    pub components: [f64; 4],
    pub depth: ColorDepth,
    pub alpha: Option<Alpha>,
    pub space: ColorSpace,
    /// A spot colour's or swatch's name.
    pub name: Option<Cow<'static, str>>,
}

impl Color {
    fn new(model: ColorModel, components: [f64; 4], depth: ColorDepth) -> Color {
        Color {
            model,
            components,
            depth,
            alpha: None,
            space: match model {
                ColorModel::Cmyk => ColorSpace::Device,
                _ => ColorSpace::Srgb,
            },
            name: None,
        }
    }

    /// An 8-bit sRGB colour: `#rrggbb`.
    pub fn rgb8(r: u8, g: u8, b: u8) -> Color {
        Color::new(
            ColorModel::Rgb,
            [unit8(r), unit8(g), unit8(b), 0.0],
            ColorDepth::Bits(8),
        )
    }

    /// An 8-bit sRGB colour with straight alpha: `#rrggbbaa`.
    pub fn rgba8(r: u8, g: u8, b: u8, a: u8) -> Color {
        Color::rgb8(r, g, b).alpha(unit8(a))
    }

    /// A Windows `COLORREF` (`0x00bbggrr`: red in the low byte), as a
    /// number read little-endian; the high byte is ignored.
    pub fn colorref(v: u32) -> Color {
        let [r, g, b, _] = v.to_le_bytes();
        Color::rgb8(r, g, b)
    }

    /// `0xrrggbb`, as a number (the high byte is ignored).
    pub fn rgb24(v: u32) -> Color {
        let [_, r, g, b] = v.to_be_bytes();
        Color::rgb8(r, g, b)
    }

    /// An RGB colour of `bits`-bit components (each in `0..2^bits`).
    pub fn rgb_bits(bits: u8, r: u64, g: u64, b: u64) -> Color {
        let u = |v| unit_bits(v, bits);
        Color::new(
            ColorModel::Rgb,
            [u(r), u(g), u(b), 0.0],
            ColorDepth::Bits(bits),
        )
    }

    /// An RGB colour of floats (normalised: 1.0 is full), stored `bits`
    /// wide.
    pub fn rgb_float(bits: u8, r: f64, g: f64, b: f64) -> Color {
        Color::new(ColorModel::Rgb, [r, g, b, 0.0], ColorDepth::Float(bits))
    }

    /// A gray of `bits`-bit lightness.
    pub fn gray_bits(bits: u8, v: u64) -> Color {
        Color::new(
            ColorModel::Gray,
            [unit_bits(v, bits), 0.0, 0.0, 0.0],
            ColorDepth::Bits(bits),
        )
    }

    /// A gray of float lightness (0..1), stored `bits` wide.
    pub fn gray_float(bits: u8, v: f64) -> Color {
        Color::new(
            ColorModel::Gray,
            [v, 0.0, 0.0, 0.0],
            ColorDepth::Float(bits),
        )
    }

    /// A CMYK colour of normalised components, in device space.
    pub fn cmyk(depth: ColorDepth, c: f64, m: f64, y: f64, k: f64) -> Color {
        Color::new(ColorModel::Cmyk, [c, m, y, k], depth)
    }

    /// A CIE L\*a\*b\* colour, in its own ranges.
    pub fn lab(depth: ColorDepth, l: f64, a: f64, b: f64) -> Color {
        Color::new(ColorModel::Lab, [l, a, b, 0.0], depth)
    }

    /// An HSB colour: hue as a fraction of the circle, saturation and
    /// brightness 0..1.
    pub fn hsb(depth: ColorDepth, h: f64, s: f64, b: f64) -> Color {
        Color::new(ColorModel::Hsb, [h, s, b, 0.0], depth)
    }

    /// A colour packed into the bit fields of `raw` (`bits` wide): red,
    /// green and blue are `(shift, width)` pairs, widened to 8 bits by bit
    /// replication. `layout` names the packing ("RGB565").
    pub fn packed(
        raw: u64,
        bits: u8,
        layout: &'static str,
        r: (u32, u32),
        g: (u32, u32),
        b: (u32, u32),
    ) -> Color {
        let ch = |(shift, width): (u32, u32)| {
            let v = raw.checked_shr(shift).unwrap_or(0) & mask(width);
            unit8(widen8(v, width))
        };
        Color::new(
            ColorModel::Rgb,
            [ch(r), ch(g), ch(b), 0.0],
            ColorDepth::Packed { raw, bits, layout },
        )
    }

    /// The same colour with straight (not premultiplied) alpha `a` (0..1).
    pub fn alpha(mut self, a: f64) -> Color {
        self.alpha = Some(Alpha {
            value: a,
            premultiplied: false,
        });
        self
    }

    /// The same colour with premultiplied alpha `a`.
    pub fn premultiplied(mut self, a: f64) -> Color {
        self.alpha = Some(Alpha {
            value: a,
            premultiplied: true,
        });
        self
    }

    /// The same colour in `space`.
    pub fn space(mut self, space: ColorSpace) -> Color {
        self.space = space;
        self
    }

    /// The same colour, named (a spot colour, a swatch).
    pub fn named(mut self, name: impl Into<Cow<'static, str>>) -> Color {
        self.name = Some(name.into());
        self
    }

    /// The 8-bit RGB value of an sRGB colour of 8 bits or fewer per
    /// component (what `#rrggbb` shows), else `None`.
    pub fn rgb8_exact(&self) -> Option<[u8; 3]> {
        if !self.is_hex() {
            return None;
        }
        let [c0, c1, c2, _] = self.components;
        Some(
            match self.model {
                ColorModel::Gray => [c0, c0, c0],
                _ => [c0, c1, c2],
            }
            .map(to8),
        )
    }

    /// The colour as an 8-bit sRGB swatch `[r, g, b, a]` (straight alpha)
    /// for a host to draw, and whether that is the colour or an
    /// approximation (CMYK, Lab, device values, clipped wide-gamut ones).
    /// `None` when a component is not a number.
    pub fn to_srgb8(&self) -> Option<([u8; 4], Exactness)> {
        if !self.components.iter().all(|c| c.is_finite()) {
            return None;
        }
        let [c0, c1, c2, c3] = self.components;
        let a = self.alpha.map_or(1.0, |a| a.value);
        // Undo premultiplication first: conversions work on the colour.
        let un = |c: f64| match self.alpha {
            Some(Alpha {
                premultiplied: true,
                value,
            }) if value > 0.0 => c / value,
            _ => c,
        };
        let (rgb, mut exact) = match self.model {
            ColorModel::Rgb => {
                let rgb = [un(c0), un(c1), un(c2)];
                match self.space {
                    ColorSpace::Srgb => (rgb, Exactness::Exact),
                    ColorSpace::LinearSrgb => (rgb.map(encode_srgb), Exactness::Exact),
                    ColorSpace::DisplayP3 => (
                        mul(&P3_TO_SRGB, rgb.map(decode_srgb)).map(encode_srgb),
                        Exactness::Exact,
                    ),
                    ColorSpace::Rec2020 => (
                        mul(&REC2020_TO_SRGB, rgb.map(decode_rec2020)).map(encode_srgb),
                        Exactness::Exact,
                    ),
                    ColorSpace::Device => (rgb, Exactness::Approximate),
                }
            }
            ColorModel::Gray => {
                let v = un(c0);
                match self.space {
                    ColorSpace::LinearSrgb => ([encode_srgb(v); 3], Exactness::Exact),
                    ColorSpace::Srgb => ([v; 3], Exactness::Exact),
                    _ => ([v; 3], Exactness::Approximate),
                }
            }
            ColorModel::Cmyk => {
                let k = 1.0 - c3;
                (
                    [(1.0 - c0) * k, (1.0 - c1) * k, (1.0 - c2) * k],
                    Exactness::Approximate,
                )
            }
            ColorModel::Lab => (lab_to_srgb(c0, c1, c2), Exactness::Approximate),
            ColorModel::Hsb => (hsb_to_rgb(c0, c1, c2), Exactness::Exact),
        };
        if rgb.iter().any(|c| !(-1e-6..=1.0 + 1e-6).contains(c)) {
            exact = Exactness::Approximate;
        }
        let [r, g, b] = rgb.map(to8);
        Some(([r, g, b, to8(a)], exact))
    }

    /// Whether the text is `#rrggbb[aa]`: sRGB (or gray) of 8 bits or
    /// fewer per component, straight alpha.
    fn is_hex(&self) -> bool {
        let small = match self.depth {
            ColorDepth::Bits(b) if b <= 8 => true,
            // 16-bit components that are exact 8-bit values (`0xffff`,
            // `0x8080`: 257 times one), as Photoshop writes them.
            ColorDepth::Bits(16) => {
                self.components
                    .iter()
                    .take(self.model.components())
                    .all(|&c| {
                        let v = c * 65535.0;
                        v == v.round() && v.rem_euclid(257.0) == 0.0
                    })
            }
            ColorDepth::Bits(_) | ColorDepth::Float(_) => false,
            ColorDepth::Packed { .. } => true,
        };
        small
            && matches!(self.model, ColorModel::Rgb | ColorModel::Gray)
            && self.space == ColorSpace::Srgb
            && !self.alpha.is_some_and(|a| a.premultiplied)
    }

    /// One component in the file's terms: the shortest decimal that reads
    /// back to the stored integer, or the float at its width.
    fn component(&self, v: f64, f: &mut impl fmt::Write) -> fmt::Result {
        match self.depth {
            ColorDepth::Float(bits) => f.write_str(&crate::render::float(v, bits)),
            ColorDepth::Bits(bits) if self.model != ColorModel::Lab => {
                f.write_str(&short_unit(v, bits))
            }
            // Lab from integers: its own units, to two decimals.
            _ => f.write_str(&trim_zeros(format!("{v:.2}"))),
        }
    }

    fn write_components(&self, f: &mut impl fmt::Write) -> fmt::Result {
        if self.model == ColorModel::Hsb {
            // Hue in degrees, saturation and brightness in percent, as
            // CSS's hsl() and Photoshop show them.
            let [h, s, b, _] = self.components;
            let n = |v: f64| trim_zeros(format!("{v:.2}"));
            write!(f, "{} {}% {}%", n(h * 360.0), n(s * 100.0), n(b * 100.0))?;
            if let Some(a) = self.alpha {
                write!(f, " / {}", n(a.value))?;
            }
            return Ok(());
        }
        for (i, &c) in self
            .components
            .iter()
            .take(self.model.components())
            .enumerate()
        {
            if i > 0 {
                f.write_char(' ')?;
            }
            self.component(c, f)?;
        }
        if let Some(a) = self.alpha {
            f.write_str(" / ")?;
            match self.depth {
                ColorDepth::Float(bits) => f.write_str(&crate::render::float(a.value, bits))?,
                _ => f.write_str(&short_unit(a.value, 8))?,
            }
        }
        Ok(())
    }

    fn write_plain(&self, f: &mut impl fmt::Write) -> fmt::Result {
        if let Some([r, g, b]) = self.rgb8_exact() {
            write!(f, "#{r:02x}{g:02x}{b:02x}")?;
            if let Some(a) = self.alpha {
                write!(f, "{:02x}", to8(a.value))?;
            }
        } else {
            f.write_str(match (self.model, self.space) {
                (ColorModel::Rgb | ColorModel::Gray, ColorSpace::LinearSrgb) => {
                    "color(srgb-linear "
                }
                (ColorModel::Rgb, ColorSpace::Srgb) => "color(srgb ",
                (ColorModel::Rgb, ColorSpace::DisplayP3) => "color(display-p3 ",
                (ColorModel::Rgb, ColorSpace::Rec2020) => "color(rec2020 ",
                (ColorModel::Rgb, _) => "device-rgb(",
                (ColorModel::Gray, ColorSpace::Device) => "device-gray(",
                (ColorModel::Gray, _) => "gray(",
                (ColorModel::Cmyk, _) => "device-cmyk(",
                (ColorModel::Lab, _) => "lab(",
                (ColorModel::Hsb, _) => "hsb(",
            })?;
            self.write_components(f)?;
            f.write_char(')')?;
        }
        if let ColorDepth::Packed { raw, layout, .. } = self.depth {
            write!(f, " ({layout} {raw:#x})")?;
        }
        Ok(())
    }
}

impl From<Color> for Value {
    fn from(c: Color) -> Value {
        Value::Color(Box::new(c))
    }
}

impl fmt::Display for Color {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.name {
            Some(name) => {
                write!(f, "{name:?} (")?;
                self.write_plain(f)?;
                f.write_char(')')
            }
            None => self.write_plain(f),
        }
    }
}

/// `v / 255`.
fn unit8(v: u8) -> f64 {
    f64::from(v) / 255.0
}

/// The low `width` bits.
fn mask(width: u32) -> u64 {
    1u64.checked_shl(width)
        .map_or(u64::MAX, |m| m.wrapping_sub(1))
}

/// `v / (2^bits - 1)`.
fn unit_bits(v: u64, bits: u8) -> f64 {
    let max = mask(u32::from(bits).clamp(1, 53));
    (v.min(max) as f64) / (max as f64)
}

/// A `width`-bit value widened to 8 bits by bit replication (`0x1f` of 5
/// bits is `0xff`, `0x10` is `0x84`).
fn widen8(v: u64, width: u32) -> u8 {
    let v = v & mask(width);
    if width == 0 {
        return 0;
    }
    let mut out = 0u64;
    let mut filled = 0u32;
    while filled < 8 {
        out = out.checked_shl(width).unwrap_or(0) | v;
        filled = filled.saturating_add(width);
    }
    u8::try_from(out.checked_shr(filled.saturating_sub(8)).unwrap_or(0) & 0xff).unwrap_or(u8::MAX)
}

/// A normalised component as 8 bits, clipped.
fn to8(c: f64) -> u8 {
    // In 0..=255 after the clamp.
    (c.clamp(0.0, 1.0) * 255.0).round() as u8
}

/// The shortest decimal (at most 6 digits after the point) that reads back
/// to the same `bits`-bit integer as `v`: 8-bit 128 is `0.502`.
fn short_unit(v: f64, bits: u8) -> String {
    let max = mask(u32::from(bits).clamp(1, 53)) as f64;
    let target = (v * max).round();
    for digits in 0..=6usize {
        let s = format!("{v:.digits$}");
        if s.parse::<f64>().is_ok_and(|p| (p * max).round() == target) {
            return trim_zeros(s);
        }
    }
    crate::render::float(v, 64)
}

/// `1.50` as `1.5`, `2.00` as `2`, `-0.00` as `0`.
fn trim_zeros(s: String) -> String {
    let t = if s.contains('.') {
        s.trim_end_matches('0').trim_end_matches('.').to_owned()
    } else {
        s
    };
    if t == "-0" { "0".to_owned() } else { t }
}

/// Linear light to the sRGB transfer function.
fn encode_srgb(c: f64) -> f64 {
    if c <= 0.003_130_8 {
        12.92 * c
    } else {
        1.055 * c.powf(1.0 / 2.4) - 0.055
    }
}

/// The sRGB transfer function (also Display P3's) to linear light.
fn decode_srgb(c: f64) -> f64 {
    if c <= 0.040_45 {
        c / 12.92
    } else {
        ((c + 0.055) / 1.055).powf(2.4)
    }
}

/// Rec. 2020's transfer function to linear light.
fn decode_rec2020(c: f64) -> f64 {
    const A: f64 = 1.099_296_826_809_44;
    const B: f64 = 0.018_053_968_510_807;
    if c < B * 4.5 {
        c / 4.5
    } else {
        ((c + A - 1.0) / A).powf(1.0 / 0.45)
    }
}

type Matrix = [[f64; 3]; 3];

/// Linear Display P3 to linear sRGB (both D65).
const P3_TO_SRGB: Matrix = [
    [1.224_940_2, -0.224_940_2, 0.0],
    [-0.042_056_9, 1.042_056_9, 0.0],
    [-0.019_637_6, -0.078_636_1, 1.098_273_7],
];

/// Linear Rec. 2020 to linear sRGB (both D65).
const REC2020_TO_SRGB: Matrix = [
    [1.660_491_0, -0.587_641_1, -0.072_849_9],
    [-0.124_550_5, 1.132_899_9, -0.008_349_4],
    [-0.018_150_8, -0.100_578_9, 1.118_729_7],
];

/// CIE XYZ (D65) to linear sRGB.
const XYZ_TO_SRGB: Matrix = [
    [3.240_969_9, -1.537_383_2, -0.498_610_8],
    [-0.969_243_6, 1.875_967_5, 0.041_555_1],
    [0.055_630_1, -0.203_976_9, 1.056_971_5],
];

fn mul(m: &Matrix, [x, y, z]: [f64; 3]) -> [f64; 3] {
    m.map(|[a, b, c]| a * x + b * y + c * z)
}

/// CIE L\*a\*b\* (D50, as CSS) to sRGB, through XYZ and a Bradford
/// adaptation to D65.
fn lab_to_srgb(l: f64, a: f64, b: f64) -> [f64; 3] {
    const D50: [f64; 3] = [0.964_22, 1.0, 0.825_21];
    const BRADFORD_D50_TO_D65: Matrix = [
        [0.955_576_6, -0.023_039_3, 0.063_163_6],
        [-0.028_289_5, 1.009_941_6, 0.021_007_7],
        [0.012_298_2, -0.020_483_0, 1.329_909_8],
    ];
    let fy = (l + 16.0) / 116.0;
    let finv = |t: f64| {
        if t > 6.0 / 29.0 {
            t * t * t
        } else {
            3.0 * (6.0f64 / 29.0).powi(2) * (t - 4.0 / 29.0)
        }
    };
    let [dx, dy, dz] = D50;
    let xyz50 = [
        dx * finv(fy + a / 500.0),
        dy * finv(fy),
        dz * finv(fy - b / 200.0),
    ];
    mul(&XYZ_TO_SRGB, mul(&BRADFORD_D50_TO_D65, xyz50)).map(encode_srgb)
}

/// HSB (hue as a fraction of the circle) to sRGB.
fn hsb_to_rgb(h: f64, s: f64, v: f64) -> [f64; 3] {
    let h6 = h.rem_euclid(1.0) * 6.0;
    let c = v * s;
    let x = c * (1.0 - ((h6 % 2.0) - 1.0).abs());
    let m = v - c;
    let (r, g, b) = match h6 {
        h if h < 1.0 => (c, x, 0.0),
        h if h < 2.0 => (x, c, 0.0),
        h if h < 3.0 => (0.0, c, x),
        h if h < 4.0 => (0.0, x, c),
        h if h < 5.0 => (x, 0.0, c),
        _ => (c, 0.0, x),
    };
    [r + m, g + m, b + m]
}
