//! Reading FlatBuffers without generated code.
//!
//! A FlatBuffer is a graph of tables addressed by 32-bit offsets. Each table
//! starts with a signed offset to its vtable, which lists where each field
//! (by index) lives inside the table, or 0 if absent. [`Fb`] reads tables,
//! scalars, strings and vectors on demand through the context, so a model
//! with gigabytes of weights costs only the tables that are looked at.
//! Every offset is checked against the buffer before it is followed.
//! [`mem`] is the same for small buffers already held in memory (headers,
//! footers, per-record metadata).

use crate::bytes::{to_u64, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::node::Node;
use crate::span::Span;
use crate::value::{Radix, Value};

/// A table: its position and its vtable (both relative to the buffer).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Table {
    pub pos: u64,
    pub vtable: u64,
    /// Size of the vtable in bytes (4 + 2 per field slot).
    pub vtable_len: u16,
    /// Size of the table's inline data.
    pub size: u16,
}

impl Table {
    pub fn slots(&self) -> u16 {
        self.vtable_len.saturating_sub(4) / 2
    }
}

/// A vector: where its elements start and how many there are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vector {
    pub start: u64,
    pub len: u32,
}

/// A FlatBuffer in `buf`.
#[derive(Clone, Copy)]
pub struct Fb<'a> {
    pub cx: &'a Cx,
    pub buf: Span,
}

impl<'a> Fb<'a> {
    pub fn new(cx: &'a Cx, buf: Span) -> Self {
        Fb { cx, buf }
    }

    pub async fn bytes(&self, pos: u64, len: u64) -> Result<Vec<u8>> {
        self.cx.read(self.buf.sub_exact(pos, len)?).await
    }

    pub async fn u8_at(&self, pos: u64) -> Result<u8> {
        Ok(self.bytes(pos, 1).await?.first().copied().unwrap_or(0))
    }

    pub async fn u16_at(&self, pos: u64) -> Result<u16> {
        Ok(u16_le(&self.bytes(pos, 2).await?, 0).unwrap_or(0))
    }

    pub async fn u32_at(&self, pos: u64) -> Result<u32> {
        Ok(u32_le(&self.bytes(pos, 4).await?, 0).unwrap_or(0))
    }

    pub async fn u64_at(&self, pos: u64) -> Result<u64> {
        Ok(u64_le(&self.bytes(pos, 8).await?, 0).unwrap_or(0))
    }

    /// Follows the unsigned offset stored at `pos`.
    pub async fn deref(&self, pos: u64) -> Result<u64> {
        let off = self.u32_at(pos).await?;
        let target = pos.saturating_add(off.into());
        if target >= self.buf.len {
            return Err(Diagnostic::malformed(format!(
                "offset {off:#x} points outside the buffer"
            ))
            .at(self.buf.sub(pos, 4)));
        }
        Ok(target)
    }

    /// The table at `pos`.
    pub async fn table(&self, pos: u64) -> Result<Table> {
        let soff = i32::from_ne_bytes(self.u32_at(pos).await?.to_ne_bytes());
        let vtable = if soff >= 0 {
            pos.checked_sub(u64::from(soff.unsigned_abs()))
        } else {
            pos.checked_add(u64::from(soff.unsigned_abs()))
        }
        .ok_or_else(|| {
            Diagnostic::malformed("vtable offset out of range").at(self.buf.sub(pos, 4))
        })?;
        let vtable_len = self.u16_at(vtable).await?;
        let size = self.u16_at(vtable.saturating_add(2)).await?;
        if vtable_len < 4 || vtable_len % 2 != 0 {
            return Err(Diagnostic::malformed(format!("vtable size {vtable_len}"))
                .at(self.buf.sub(vtable, 2)));
        }
        // The whole vtable must be inside the buffer.
        self.buf.sub_exact(vtable, vtable_len.into())?;
        Ok(Table {
            pos,
            vtable,
            vtable_len,
            size,
        })
    }

    /// The root table (offset at the start of the buffer).
    pub async fn root(&self) -> Result<Table> {
        let pos = self.deref(0).await?;
        self.table(pos).await
    }

    /// Where field `slot` of `t` is, if present.
    pub async fn field(&self, t: &Table, slot: u16) -> Result<Option<u64>> {
        let at = 4u16.saturating_add(slot.saturating_mul(2));
        if at.saturating_add(2) > t.vtable_len {
            return Ok(None);
        }
        let off = self.u16_at(t.vtable.saturating_add(at.into())).await?;
        Ok((off != 0).then(|| t.pos.saturating_add(off.into())))
    }

    pub async fn u8_field(&self, t: &Table, slot: u16) -> Result<Option<u8>> {
        match self.field(t, slot).await? {
            Some(p) => Ok(Some(self.u8_at(p).await?)),
            None => Ok(None),
        }
    }

    pub async fn u32_field(&self, t: &Table, slot: u16) -> Result<Option<u32>> {
        match self.field(t, slot).await? {
            Some(p) => Ok(Some(self.u32_at(p).await?)),
            None => Ok(None),
        }
    }

    pub async fn i32_field(&self, t: &Table, slot: u16) -> Result<Option<i32>> {
        Ok(self
            .u32_field(t, slot)
            .await?
            .map(|v| i32::from_ne_bytes(v.to_ne_bytes())))
    }

    pub async fn u64_field(&self, t: &Table, slot: u16) -> Result<Option<u64>> {
        match self.field(t, slot).await? {
            Some(p) => Ok(Some(self.u64_at(p).await?)),
            None => Ok(None),
        }
    }

    /// A string at `pos` (the position of its length): text and span,
    /// keeping at most `max` bytes.
    pub async fn string_at(&self, pos: u64, max: u64) -> Result<(String, Span)> {
        let len = u64::from(self.u32_at(pos).await?);
        let span = self.buf.sub_exact(pos.saturating_add(4), len)?;
        let data = self.cx.read(span.sub(0, max)).await?;
        Ok((String::from_utf8_lossy(&data).into_owned(), span))
    }

    /// String field `slot` of `t`.
    pub async fn string(&self, t: &Table, slot: u16) -> Result<Option<String>> {
        Ok(self.string_span(t, slot).await?.map(|(s, _)| s))
    }

    pub async fn string_span(&self, t: &Table, slot: u16) -> Result<Option<(String, Span)>> {
        match self.field(t, slot).await? {
            Some(p) => {
                let at = self.deref(p).await?;
                Ok(Some(self.string_at(at, 1024).await?))
            }
            None => Ok(None),
        }
    }

    /// Vector field `slot` of `t`, whose elements are `elem` bytes each.
    pub async fn vector(&self, t: &Table, slot: u16, elem: u64) -> Result<Option<Vector>> {
        let Some(p) = self.field(t, slot).await? else {
            return Ok(None);
        };
        let at = self.deref(p).await?;
        let len = self.u32_at(at).await?;
        let start = at.saturating_add(4);
        // Reject counts that cannot fit before reading any element.
        self.buf
            .sub_exact(start, u64::from(len).saturating_mul(elem))?;
        Ok(Some(Vector { start, len }))
    }

    /// The span of the elements of `v` (`elem` bytes each).
    pub fn vector_span(&self, v: Vector, elem: u64) -> Span {
        self.buf.sub(v.start, u64::from(v.len).saturating_mul(elem))
    }

    /// Element `i` of a vector of tables.
    pub async fn table_in(&self, v: Vector, i: u32) -> Result<Table> {
        let at = v.start.saturating_add(u64::from(i).saturating_mul(4));
        let pos = self.deref(at).await?;
        self.table(pos).await
    }

    /// Element `i` of a vector of strings.
    pub async fn string_in(&self, v: Vector, i: u32) -> Result<String> {
        let at = v.start.saturating_add(u64::from(i).saturating_mul(4));
        let pos = self.deref(at).await?;
        Ok(self.string_at(pos, 1024).await?.0)
    }

    /// The first `max` elements of a vector of 32-bit integers.
    pub async fn i32s(&self, v: Vector, max: u32) -> Result<Vec<i32>> {
        let n = v.len.min(max);
        let data = self.bytes(v.start, u64::from(n).saturating_mul(4)).await?;
        Ok(data
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| i32::from_le_bytes(*c))
            .collect())
    }

    /// The span a table occupies (from its vtable-offset to its inline end).
    pub fn table_span(&self, t: &Table) -> Span {
        self.buf.sub(t.pos, t.size.into())
    }
}

/// Formats `[1, 224, 224, 3]` (with "…" if `total` exceeds the shown values).
pub fn dims(values: &[i32], total: u32) -> String {
    let shown: Vec<String> = values.iter().map(i32::to_string).collect();
    let more = if to_u64(values.len()) < u64::from(total) {
        ", …"
    } else {
        ""
    };
    format!("[{}{more}]", shown.join(", "))
}

/// A node listing the raw field slots of a table (for tables whose schema
/// is not known).
pub async fn raw_table(cx: Cx, (buf, t): (Span, Table)) -> Result<()> {
    let fb = Fb::new(&cx, buf);
    cx.emit(
        Node::new("vtable")
            .span(buf.sub(t.vtable, t.vtable_len.into()))
            .summary(format!("{} slots, table size {}", t.slots(), t.size)),
    );
    for slot in 0..t.slots() {
        if let Some(at) = fb.field(&t, slot).await? {
            let raw = fb.bytes(at, 4).await.unwrap_or_default();
            let value = u32_le(&raw, 0).unwrap_or(0);
            cx.push(
                Node::new(format!("field {slot}"))
                    .span(buf.sub(at, 4))
                    .value(Value::UInt {
                        value: value.into(),
                        bits: 32,
                        radix: Radix::Hex,
                    }),
            )
            .await;
        }
    }
    Ok(())
}

/// Reading a FlatBuffer held in memory (small buffers: headers, footers,
/// per-record metadata). Accessors return `None` for absent fields and for
/// anything that does not fit in the buffer.
pub mod mem {
    use crate::bytes::{i32_le, u16_le, u32_le, u64_le};

    /// A table: its position and its vtable.
    #[derive(Clone, Copy, Debug)]
    pub struct Table {
        pub pos: usize,
        vtable: usize,
        vlen: usize,
    }

    /// The root table of a buffer.
    pub fn root(data: &[u8]) -> Option<Table> {
        table(data, deref(data, 0)?)
    }

    /// The table at `pos`.
    pub fn table(data: &[u8], pos: usize) -> Option<Table> {
        let soffset = i64::from(i32_le(data, pos)?);
        let vtable = usize::try_from(i64::try_from(pos).ok()?.checked_sub(soffset)?).ok()?;
        let vlen = usize::from(u16_le(data, vtable)?);
        (vlen >= 4 && vlen % 2 == 0).then_some(Table { pos, vtable, vlen })
    }

    /// The position an unsigned offset at `at` points to.
    pub fn deref(data: &[u8], at: usize) -> Option<usize> {
        at.checked_add(usize::try_from(u32_le(data, at)?).ok()?)
    }

    impl Table {
        /// Absolute position of field `i`, if present.
        pub fn field(&self, data: &[u8], i: usize) -> Option<usize> {
            let entry = 4usize.checked_add(i.checked_mul(2)?)?;
            if entry.checked_add(2)? > self.vlen {
                return None;
            }
            let off = u16_le(data, self.vtable.checked_add(entry)?)?;
            (off != 0).then(|| self.pos.saturating_add(usize::from(off)))
        }

        pub fn u8(&self, data: &[u8], i: usize) -> Option<u8> {
            data.get(self.field(data, i)?).copied()
        }

        pub fn u16(&self, data: &[u8], i: usize) -> Option<u16> {
            u16_le(data, self.field(data, i)?)
        }

        pub fn i16(&self, data: &[u8], i: usize) -> Option<i16> {
            self.u16(data, i).map(u16::cast_signed)
        }

        pub fn i32(&self, data: &[u8], i: usize) -> Option<i32> {
            i32_le(data, self.field(data, i)?)
        }

        pub fn u64(&self, data: &[u8], i: usize) -> Option<u64> {
            u64_le(data, self.field(data, i)?)
        }

        pub fn i64(&self, data: &[u8], i: usize) -> Option<i64> {
            self.u64(data, i).map(u64::cast_signed)
        }

        /// The table field `i` refers to.
        pub fn table(&self, data: &[u8], i: usize) -> Option<Table> {
            table(data, deref(data, self.field(data, i)?)?)
        }

        /// A string: its text and byte range.
        pub fn string(&self, data: &[u8], i: usize) -> Option<(String, usize, usize)> {
            let at = deref(data, self.field(data, i)?)?;
            let len = usize::try_from(u32_le(data, at)?).ok()?;
            let start = at.checked_add(4)?;
            let end = start.checked_add(len)?;
            Some((
                String::from_utf8_lossy(data.get(start..end)?).into_owned(),
                start,
                end,
            ))
        }

        /// A vector: element count and the position of the first element.
        /// The count is checked against the buffer for elements of `width`
        /// bytes.
        pub fn vector(&self, data: &[u8], i: usize, width: usize) -> Option<(usize, usize)> {
            let at = deref(data, self.field(data, i)?)?;
            let n = usize::try_from(u32_le(data, at)?).ok()?;
            let start = at.checked_add(4)?;
            let end = start.checked_add(n.checked_mul(width)?)?;
            (end <= data.len()).then_some((n, start))
        }

        /// The `j`th table of a vector of tables starting at `start`.
        pub fn vector_table(data: &[u8], start: usize, j: usize) -> Option<Table> {
            table(data, deref(data, start.checked_add(j.checked_mul(4)?)?)?)
        }
    }
}
