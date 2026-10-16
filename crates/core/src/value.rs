//! Typed field values: the contract between dissectors and frontends.
//!
//! Values carry interpretation (enum names, decoded flags) next to the raw
//! number. The raw bytes themselves are available through the node's span.

use std::borrow::Cow;
use std::fmt;

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
    /// A bit set: the names of matched flags, and bits no flag accounts for.
    Flags {
        raw: u64,
        bits: u8,
        set: Vec<&'static str>,
        unknown: u64,
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
    Guid(Guid),
    /// A stored check value (CRC, checksum, digest, MAC) with its algorithm
    /// and whether it was verified. Construct with [`Check::new`] and put it
    /// on a node with [`Node::checksum`](crate::Node::checksum), which also
    /// reports a mismatch as a diagnostic.
    Checksum(Box<Check>),
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

/// A check value as stored: a small integer (CRCs, sums: shown `0x…` like
/// any hex number) or a byte string (digests, MACs: shown in full, as
/// lowercase hex in stored order).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Digest {
    Int { value: u64, bits: u8 },
    Bytes(Vec<u8>),
}

impl Digest {
    /// The digest's bytes, an integer big-endian at its width.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Digest::Int { value, bits } => {
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
            Digest::Int { value, .. } => write!(f, "{value:#x}"),
            Digest::Bytes(b) => b.iter().try_for_each(|byte| write!(f, "{byte:02x}")),
        }
    }
}

macro_rules! digest_from_int {
    ($($t:ty),*) => {$(
        impl From<$t> for Digest {
            fn from(value: $t) -> Digest {
                Digest::Int { value: u64::from(value), bits: <$t>::BITS as u8 }
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
    /// limit", "checked by the decoder"...).
    Skipped(Cow<'static, str>),
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
    pub fn verify(mut self, computed: impl Into<Digest>) -> Check {
        let computed = computed.into();
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
#[derive(Clone, Copy, Debug)]
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

pub fn lookup(table: EnumTable, raw: u64) -> Option<&'static str> {
    table.iter().find(|(v, _)| *v == raw).map(|(_, n)| *n)
}

/// Returns matched flag names and the bits not covered by any match.
pub fn decode_flags(table: FlagTable, raw: u64) -> (Vec<&'static str>, u64) {
    let mut covered = 0u64;
    let mut set = Vec::new();
    for def in table {
        if def.mask != 0 && def.value != 0 && raw & def.mask == def.value {
            set.push(def.name);
            covered |= def.mask;
        }
    }
    (set, raw & !covered)
}

/// A GUID in its conventional (Microsoft, mixed-endian) field layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Guid {
    /// The GUID's 16 bytes in Windows' mixed-endian order (the first three
    /// fields little-endian), the inverse of `datakit::guid_le`.
    pub fn to_le_bytes(&self) -> [u8; 16] {
        let [a, b, c, d] = self.data1.to_le_bytes();
        let [e, f] = self.data2.to_le_bytes();
        let [g, h] = self.data3.to_le_bytes();
        let [i, j, k, l, m, n, o, p] = self.data4;
        [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p]
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let d = &self.data4;
        write!(
            f,
            "{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
            self.data1, self.data2, self.data3, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
        )
    }
}
