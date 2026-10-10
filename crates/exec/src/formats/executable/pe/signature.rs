//! Signature blobs (ECMA-335 partition II, 23.2 and 23.3): method, field,
//! property, local variable, type and method instantiation signatures, and
//! custom attribute values.
//!
//! Decoding is synchronous and bounded by the blob; types defined by
//! metadata rows come out as [`Piece::Type`] placeholders that the caller
//! names (which takes reads).

/// What a blob holds, from the column that refers to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SigKind {
    Field,
    Method,
    /// A MemberRef signature: a field (0x06) or a method.
    MemberRef,
    Property,
    /// A StandAloneSig: local variables (0x07) or a method (calli).
    StandAlone,
    TypeSpec,
    MethodSpec,
    CustomAttribute,
    Constant,
    Marshal,
    Permission,
    DocumentName,
    Bytes,
}

impl SigKind {
    pub fn label(self) -> &'static str {
        match self {
            SigKind::Field => "field signature",
            SigKind::Method => "method signature",
            SigKind::MemberRef => "member reference signature",
            SigKind::Property => "property signature",
            SigKind::StandAlone => "stand-alone signature",
            SigKind::TypeSpec => "type specification",
            SigKind::MethodSpec => "method instantiation",
            SigKind::CustomAttribute => "custom attribute value",
            SigKind::Constant => "constant value",
            SigKind::Marshal => "marshalling descriptor",
            SigKind::Permission => "permission set",
            SigKind::DocumentName => "document name",
            SigKind::Bytes => "",
        }
    }
}

/// Rendered text, or a TypeDef / TypeRef / TypeSpec row to be named.
#[derive(Clone, Debug)]
pub(super) enum Piece {
    Text(String),
    Type(usize, u32),
}

const MAX_DEPTH: u32 = 32;

struct Dec<'a> {
    data: &'a [u8],
    pos: usize,
    out: Vec<Piece>,
}

impl Dec<'_> {
    fn text(&mut self, s: &str) {
        match self.out.last_mut() {
            Some(Piece::Text(t)) => t.push_str(s),
            _ => self.out.push(Piece::Text(s.to_owned())),
        }
    }

    fn u8(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos = self.pos.saturating_add(1);
        Some(b)
    }

    fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    fn compressed(&mut self) -> Option<u32> {
        let (v, used) = super::metadata::compressed(self.data.get(self.pos..)?)?;
        self.pos = self.pos.saturating_add(used);
        Some(v)
    }

    /// A compressed signed integer (array lower bounds).
    fn signed(&mut self) -> Option<i64> {
        let start = self.pos;
        let raw = self.compressed()?;
        let used = self.pos.saturating_sub(start);
        let magnitude = i64::from(raw >> 1);
        if raw & 1 == 0 {
            return Some(magnitude);
        }
        let bias: i64 = match used {
            1 => 0x40,
            2 => 0x2000,
            _ => 0x1000_0000,
        };
        Some(magnitude.saturating_sub(bias))
    }

    /// A TypeDefOrRefOrSpecEncoded token.
    fn type_token(&mut self) -> Option<()> {
        let v = self.compressed()?;
        let table = match v & 3 {
            0 => 0x02,
            1 => 0x01,
            2 => 0x1b,
            _ => {
                self.text("<bad token>");
                return None;
            }
        };
        self.out.push(Piece::Type(table, v >> 2));
        Some(())
    }

    fn ty(&mut self, depth: u32) -> Option<()> {
        if depth > MAX_DEPTH {
            self.text("…");
            return None;
        }
        let b = self.u8()?;
        let name = match b {
            0x01 => "void",
            0x02 => "bool",
            0x03 => "char",
            0x04 => "int8",
            0x05 => "uint8",
            0x06 => "int16",
            0x07 => "uint16",
            0x08 => "int32",
            0x09 => "uint32",
            0x0a => "int64",
            0x0b => "uint64",
            0x0c => "float32",
            0x0d => "float64",
            0x0e => "string",
            0x16 => "typedref",
            0x18 => "native int",
            0x19 => "native uint",
            0x1c => "object",
            _ => "",
        };
        if !name.is_empty() {
            self.text(name);
            return Some(());
        }
        let next = depth.saturating_add(1);
        match b {
            0x0f => {
                self.ty(next)?;
                self.text("*");
            }
            0x10 => {
                self.ty(next)?;
                self.text("&");
            }
            0x11 => {
                self.text("valuetype ");
                self.type_token()?;
            }
            0x12 => {
                self.text("class ");
                self.type_token()?;
            }
            0x13 => {
                let n = self.compressed()?;
                self.text(&format!("!{n}"));
            }
            0x1e => {
                let n = self.compressed()?;
                self.text(&format!("!!{n}"));
            }
            0x14 => {
                self.ty(next)?;
                let rank = self.compressed()?;
                let sizes_n = self.compressed()?;
                let mut sizes = Vec::new();
                for _ in 0..sizes_n.min(rank).min(64) {
                    sizes.push(self.compressed()?);
                }
                let lows_n = self.compressed()?;
                let mut lows = Vec::new();
                for _ in 0..lows_n.min(rank).min(64) {
                    lows.push(self.signed()?);
                }
                let dims: Vec<String> = (0..usize::try_from(rank.min(64)).unwrap_or(0))
                    .map(|i| {
                        let low = lows.get(i).copied();
                        match (low, sizes.get(i)) {
                            (Some(l), Some(&s)) => {
                                format!(
                                    "{l}...{}",
                                    l.saturating_add(i64::from(s)).saturating_sub(1)
                                )
                            }
                            (None, Some(&s)) => format!("{s}"),
                            (Some(l), None) => format!("{l}..."),
                            (None, None) => String::new(),
                        }
                    })
                    .collect();
                self.text(&format!("[{}]", dims.join(",")));
            }
            0x15 => {
                // GENERICINST (CLASS | VALUETYPE) TypeDefOrRef count types
                let _ = self.u8()?;
                self.type_token()?;
                let count = self.compressed()?;
                self.text("<");
                for i in 0..count.min(256) {
                    if i > 0 {
                        self.text(", ");
                    }
                    self.ty(next)?;
                }
                self.text(">");
            }
            0x1b => {
                self.text("method ");
                self.method(next)?;
            }
            0x1d => {
                self.ty(next)?;
                self.text("[]");
            }
            0x1f | 0x20 => {
                self.text(if b == 0x1f { "modreq(" } else { "modopt(" });
                self.type_token()?;
                self.text(") ");
                self.ty(next)?;
            }
            0x41 => {
                self.text("..., ");
                self.ty(next)?;
            }
            0x45 => {
                self.ty(next)?;
                self.text(" pinned");
            }
            0x51 => self.text("object"),
            _ => {
                self.text(&format!("<element type {b:#04x}>"));
                return None;
            }
        }
        Some(())
    }

    /// A method signature (MethodDefSig, MethodRefSig, StandAloneMethodSig).
    fn method(&mut self, depth: u32) -> Option<()> {
        let conv = self.u8()?;
        if conv & 0x20 != 0 {
            self.text("instance ");
        }
        if conv & 0x40 != 0 {
            self.text("explicit ");
        }
        match conv & 0x0f {
            1 => self.text("unmanaged cdecl "),
            2 => self.text("unmanaged stdcall "),
            3 => self.text("unmanaged thiscall "),
            4 => self.text("unmanaged fastcall "),
            5 => self.text("vararg "),
            _ => {}
        }
        let generic = if conv & 0x10 != 0 {
            Some(self.compressed()?)
        } else {
            None
        };
        let count = self.compressed()?;
        if let Some(n) = generic {
            self.text(&format!("generic<{n}> "));
        }
        self.ty(depth)?;
        self.text("(");
        self.params(count, depth)?;
        self.text(")");
        Some(())
    }

    fn params(&mut self, count: u32, depth: u32) -> Option<()> {
        for i in 0..count.min(1024) {
            if i > 0 {
                self.text(", ");
            }
            if self.peek() == Some(0x41) {
                self.pos = self.pos.saturating_add(1);
                self.text("..., ");
            }
            self.ty(depth)?;
        }
        Some(())
    }
}

/// Decodes a signature blob of `kind` into text and type placeholders.
pub(super) fn decode(data: &[u8], kind: SigKind) -> Vec<Piece> {
    let mut d = Dec {
        data,
        pos: 0,
        out: Vec::new(),
    };
    let first = data.first().copied().unwrap_or(0);
    let _ = match kind {
        SigKind::Field => field(&mut d),
        SigKind::MemberRef if first & 0x0f == 0x06 => field(&mut d),
        SigKind::Method | SigKind::MemberRef => d.method(0),
        SigKind::StandAlone if first == 0x07 => locals(&mut d),
        SigKind::StandAlone => d.method(0),
        SigKind::Property => property(&mut d),
        SigKind::TypeSpec => d.ty(0),
        SigKind::MethodSpec => method_spec(&mut d),
        _ => None,
    };
    if d.out.is_empty() && !data.is_empty() {
        d.out.push(Piece::Text(format!("<{} bytes>", data.len())));
    }
    d.out
}

fn field(d: &mut Dec<'_>) -> Option<()> {
    let _ = d.u8()?;
    d.ty(0)
}

fn property(d: &mut Dec<'_>) -> Option<()> {
    let conv = d.u8()?;
    if conv & 0x20 != 0 {
        d.text("instance ");
    }
    let count = d.compressed()?;
    d.ty(0)?;
    if count > 0 {
        d.text("[");
        d.params(count, 0)?;
        d.text("]");
    }
    Some(())
}

fn locals(d: &mut Dec<'_>) -> Option<()> {
    let _ = d.u8()?;
    let count = d.compressed()?;
    d.text("locals (");
    for i in 0..count.min(65536) {
        if i > 0 {
            d.text(", ");
        }
        d.ty(0)?;
    }
    d.text(")");
    Some(())
}

fn method_spec(d: &mut Dec<'_>) -> Option<()> {
    let _ = d.u8()?;
    let count = d.compressed()?;
    d.text("<");
    for i in 0..count.min(256) {
        if i > 0 {
            d.text(", ");
        }
        d.ty(0)?;
    }
    d.text(">");
    Some(())
}

// ---------------------------------------------------------------------------
// Constants and custom attributes

/// A constant blob of element type `ty`.
pub(super) fn constant_value(ty: u8, data: &[u8]) -> String {
    let int = |n: usize| -> Option<[u8; 8]> {
        let mut b = [0u8; 8];
        for (d, s) in b.iter_mut().zip(data.get(..n)?) {
            *d = *s;
        }
        Some(b)
    };
    let text = match ty {
        0x02 => data.first().map(|&b| (b != 0).to_string()),
        0x03 => int(2).map(|b| {
            let c = u16::from_le_bytes([b[0], b[1]]);
            char::from_u32(c.into()).map_or_else(|| format!("{c:#x}"), |c| format!("{c:?}"))
        }),
        0x04 => int(1).map(|b| i8::from_le_bytes([b[0]]).to_string()),
        0x05 => int(1).map(|b| b[0].to_string()),
        0x06 => int(2).map(|b| i16::from_le_bytes([b[0], b[1]]).to_string()),
        0x07 => int(2).map(|b| u16::from_le_bytes([b[0], b[1]]).to_string()),
        0x08 => int(4).map(|b| i32::from_le_bytes([b[0], b[1], b[2], b[3]]).to_string()),
        0x09 => int(4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]).to_string()),
        0x0a => int(8).map(|b| i64::from_le_bytes(b).to_string()),
        0x0b => int(8).map(|b| u64::from_le_bytes(b).to_string()),
        0x0c => int(4).map(|b| f32::from_le_bytes([b[0], b[1], b[2], b[3]]).to_string()),
        0x0d => int(8).map(|b| f64::from_le_bytes(b).to_string()),
        0x0e => Some(format!(
            "{:?}",
            crate::text::utf16(data, crate::fields::Endian::Little)
        )),
        0x12 => Some("null".to_owned()),
        _ => None,
    };
    text.unwrap_or_else(|| crate::text::hex_lower(data))
}

/// A `SerString`: 0xff (null) or a compressed length and UTF-8.
fn ser_string(d: &mut Dec<'_>) -> Option<String> {
    if d.peek() == Some(0xff) {
        d.pos = d.pos.saturating_add(1);
        return Some("null".to_owned());
    }
    let len = usize::try_from(d.compressed()?).ok()?;
    let bytes = d.data.get(d.pos..d.pos.checked_add(len)?)?;
    d.pos = d.pos.saturating_add(len);
    Some(format!("{:?}", String::from_utf8_lossy(bytes)))
}

/// One custom attribute argument of element type `ty` (simple types only).
fn ca_value(d: &mut Dec<'_>, ty: u8) -> Option<String> {
    let size = match ty {
        0x02 | 0x04 | 0x05 => 1,
        0x03 | 0x06 | 0x07 => 2,
        0x08 | 0x09 | 0x0c => 4,
        0x0a | 0x0b | 0x0d => 8,
        0x0e | 0x50 => {
            return ser_string(d).map(|s| {
                if ty == 0x50 {
                    format!("typeof({s})")
                } else {
                    s
                }
            });
        }
        _ => return None,
    };
    let bytes = d.data.get(d.pos..d.pos.checked_add(size)?)?;
    d.pos = d.pos.saturating_add(size);
    Some(constant_value(ty, bytes))
}

/// The parameter element types of a constructor signature, as far as they
/// are simple (primitives and strings).
fn ctor_params(sig: &[u8]) -> Option<Vec<u8>> {
    let mut d = Dec {
        data: sig,
        pos: 0,
        out: Vec::new(),
    };
    let conv = d.u8()?;
    if conv & 0x10 != 0 {
        d.compressed()?;
    }
    let count = d.compressed()?;
    let _ret = d.u8()?;
    let mut out = Vec::new();
    for _ in 0..count.min(256) {
        let t = d.u8()?;
        out.push(t);
        if !matches!(t, 0x02..=0x0e) {
            // A class or value type: its encoding is unknown here.
            break;
        }
    }
    Some(out)
}

/// A custom attribute value blob, decoded with the parameter types of its
/// constructor's signature (`ctor`, empty if unknown): "(args, Name = v)".
pub(super) fn custom_attribute(data: &[u8], ctor: &[u8]) -> Vec<Piece> {
    let mut d = Dec {
        data,
        pos: 0,
        out: Vec::new(),
    };
    if data.get(..2) != Some(&[1, 0]) {
        return vec![Piece::Text(format!("<{} bytes, no prolog>", data.len()))];
    }
    d.pos = 2;
    let mut args = Vec::new();
    let params = ctor_params(ctor).unwrap_or_default();
    let mut known = !ctor.is_empty();
    for &t in &params {
        match ca_value(&mut d, t) {
            Some(v) => args.push(v),
            None => {
                known = false;
                break;
            }
        }
    }
    if known {
        // Named arguments: FIELD (0x53) or PROPERTY (0x54), type, name, value.
        if let (Some(&lo), Some(&hi)) = (d.data.get(d.pos), d.data.get(d.pos.saturating_add(1))) {
            d.pos = d.pos.saturating_add(2);
            let named = u16::from_le_bytes([lo, hi]);
            for _ in 0..named {
                let Some(_kind) = d.u8() else { break };
                let Some(t) = d.u8() else { break };
                let Some(name) = ser_string(&mut d) else {
                    break;
                };
                match ca_value(&mut d, t) {
                    Some(v) => args.push(format!("{} = {v}", name.trim_matches('"'))),
                    None => {
                        args.push(format!("{} = …", name.trim_matches('"')));
                        break;
                    }
                }
            }
        }
    } else {
        args.push(format!("{} bytes", data.len().saturating_sub(2)));
    }
    vec![Piece::Text(format!("({})", args.join(", ")))]
}
