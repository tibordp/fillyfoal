//! gzip members (RFC 1952), one after another: the DEFLATE data of the
//! first member (whose header the dissector has already read), its trailer,
//! then any further members, header included, as `cat a.gz b.gz` or
//! `gzip -c a b` produce them. Decoding stops at the end of the input or at
//! bytes that do not start another member (trailing data, zero padding).
//!
//! Nothing records the total size up front (each trailer holds only its own
//! member's size, modulo 2^32), so the decoded length is known once the
//! last member has been decoded. Each member's CRC-32 and size are checked
//! as it ends; the first mismatch is reported as a warning.

use crate::codec::crc::crc32_update;
use crate::codec::inflate::{self, Inflate};
use crate::codec::pipeline::{Decode, Step};
use crate::error::{Diagnostic, Result};

/// The longest member header accepted: the fixed fields, an extra field,
/// and a file name and a comment of up to 64 KiB each.
const MAX_HEADER: usize = 10 + 2 + 65_535 + 2 * 65_536 + 2;

#[derive(Clone)]
enum Phase {
    /// Inside a member's DEFLATE data.
    Deflate,
    /// After a member's trailer: another member, or the end.
    Between,
    Done,
}

#[derive(Clone)]
pub struct Gzip {
    inflate: Inflate,
    phase: Phase,
    /// Input position of the current member's DEFLATE data (in `Deflate`),
    /// or of the next member (in `Between` and `Done`).
    base: usize,
    /// CRC-32 register and size (modulo 2^32) of the current member.
    crc: u32,
    size: u32,
    /// Members finished.
    members: u64,
    warning: Option<Diagnostic>,
}

impl Default for Gzip {
    fn default() -> Self {
        Gzip {
            inflate: Inflate::new(),
            phase: Phase::Deflate,
            base: 0,
            crc: !0,
            size: 0,
            members: 0,
            warning: None,
        }
    }
}

impl Gzip {
    /// A decoder whose input starts at a member's header (its magic)
    /// instead of after the first member's header: that member and those
    /// after it, decoded as a decoder that started at the start would once
    /// it got there, a container that records where members start (BGZF)
    /// can start one at any of them. `members` is how many members come
    /// before (it numbers them in warnings); a mismatch in those is not
    /// seen.
    pub fn at_member(members: u64) -> Self {
        Gzip {
            phase: Phase::Between,
            members,
            ..Gzip::default()
        }
    }
}

fn truncated(what: &str) -> Diagnostic {
    Diagnostic::malformed(format!("truncated gzip {what}"))
}

/// The length of the gzip member header at the start of `data` (starting
/// with its magic), or why there is none yet: `Codec::Gzip` decodes from
/// the end of the first member's header.
pub fn header_len(data: &[u8]) -> Result<usize> {
    let byte = |at: usize| {
        data.get(at)
            .copied()
            .ok_or_else(|| truncated("member header"))
    };
    if byte(2)? != 8 {
        return Err(Diagnostic::unsupported(
            "gzip compression method other than DEFLATE",
        ));
    }
    let flags = byte(3)?;
    let mut at = 10usize;
    if flags & 0x04 != 0 {
        let len = usize::from(byte(at)?) | usize::from(byte(at.saturating_add(1))?) << 8;
        at = at.saturating_add(2).saturating_add(len);
    }
    for flag in [0x08u8, 0x10] {
        if flags & flag != 0 {
            let rest = data.get(at..).unwrap_or_default();
            let window = rest.get(..65_536).unwrap_or(rest);
            match window.iter().position(|&b| b == 0) {
                Some(n) => at = at.saturating_add(n).saturating_add(1),
                None if rest.len() > 65_536 => {
                    return Err(Diagnostic::malformed(
                        "gzip member name or comment too long",
                    ));
                }
                None => return Err(truncated("member header")),
            }
        }
    }
    if flags & 0x02 != 0 {
        at = at.saturating_add(2);
    }
    if at > MAX_HEADER {
        return Err(Diagnostic::malformed("gzip member header too long"));
    }
    if data.len() < at {
        return Err(truncated("member header"));
    }
    Ok(at)
}

impl Decode for Gzip {
    fn step(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        loop {
            match self.phase {
                Phase::Done => return Ok(Step::Done),
                Phase::Deflate => {
                    let body = input.get(self.base..).unwrap_or_default();
                    let mark = out.len();
                    let result = self.inflate.step(body, out, step, limit)?;
                    let produced = out.get(mark..).unwrap_or_default();
                    self.crc = crc32_update(self.crc, produced);
                    // ISIZE is the size modulo 2^32.
                    #[allow(clippy::cast_possible_truncation)]
                    let n = produced.len() as u32;
                    self.size = self.size.wrapping_add(n);
                    if result == Step::More {
                        return Ok(Step::More);
                    }
                    let at = self.base.saturating_add(self.inflate.consumed());
                    let crc =
                        crate::bytes::u32_le(input, at).ok_or_else(|| truncated("trailer"))?;
                    let size = crate::bytes::u32_le(input, at.saturating_add(4))
                        .ok_or_else(|| truncated("trailer"))?;
                    self.members = self.members.saturating_add(1);
                    if self.warning.is_none() {
                        let which = self.members;
                        if crc != !self.crc {
                            self.warning = Some(Diagnostic::warning(format!(
                                "gzip member {which}: CRC-32 mismatch"
                            )));
                        } else if size != self.size {
                            self.warning = Some(Diagnostic::warning(format!(
                                "gzip member {which}: size mismatch"
                            )));
                        }
                    }
                    self.base = at.saturating_add(8);
                    self.phase = Phase::Between;
                    // A member boundary: hand back what this step produced.
                    if out.len() > mark {
                        return Ok(Step::More);
                    }
                }
                Phase::Between => {
                    let rest = input.get(self.base..).unwrap_or_default();
                    match rest {
                        [0x1f, 0x8b, ..] => {}
                        [] | [0x1f] if !eof => return Err(truncated("member header")),
                        // The end, or bytes that are not another member.
                        _ => {
                            self.phase = Phase::Done;
                            return Ok(Step::Done);
                        }
                    }
                    let len = header_len(rest)?;
                    self.base = self.base.saturating_add(len);
                    self.inflate = Inflate::new();
                    self.crc = !0;
                    self.size = 0;
                    self.phase = Phase::Deflate;
                }
            }
        }
    }

    fn consumed(&self) -> usize {
        match self.phase {
            Phase::Deflate => self.base.saturating_add(self.inflate.consumed()),
            Phase::Between | Phase::Done => self.base,
        }
    }

    fn warning(&self, _out: &[u8]) -> Option<Diagnostic> {
        self.warning.clone()
    }

    fn releasable_input(&self) -> usize {
        match self.phase {
            Phase::Deflate => match self.inflate.releasable_input() {
                0 => 0,
                n => self.base.saturating_add(n),
            },
            Phase::Between | Phase::Done => self.base,
        }
    }

    fn release_input(&mut self, n: usize) {
        match self.phase {
            Phase::Deflate if n >= self.base => {
                self.inflate.release_input(n.saturating_sub(self.base));
                self.base = 0;
            }
            _ => self.base = self.base.saturating_sub(n),
        }
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        match self.phase {
            Phase::Deflate => out_len.saturating_sub(inflate::WINDOW),
            // Between members the history resets: a checkpoint here needs
            // no window.
            Phase::Between | Phase::Done => out_len,
        }
    }

    fn heap_size(&self) -> Option<usize> {
        let warning = self.warning.as_ref().map_or(0, |w| w.message.capacity());
        Some(self.inflate.heap_size().saturating_add(warning))
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use crate::codec::pipeline::{Decoder, Status, Streaming};

    #[test]
    fn checkpoints_resume_inside_and_between_members() {
        let data: Vec<u8> = (0..300_000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        let mut stream = member(&data, Some("one"));
        stream.extend(member(&data[..1000], None));
        stream.extend(member(&data, None));
        let body = &stream[header_len(&stream).unwrap()..];
        let (checked, _) = crate::codec::pipeline::verify_checkpoints(
            || Box::new(Streaming(Gzip::default())),
            body,
            4096,
            7,
        )
        .unwrap();
        assert!(checked > 10, "{checked}");
    }

    /// A member with stored DEFLATE blocks.
    fn member(data: &[u8], name: Option<&str>) -> Vec<u8> {
        let mut out = vec![
            0x1f,
            0x8b,
            8,
            if name.is_some() { 0x08 } else { 0 },
            0,
            0,
            0,
            0,
            0,
            0xff,
        ];
        if let Some(name) = name {
            out.extend_from_slice(name.as_bytes());
            out.push(0);
        }
        let chunks: Vec<&[u8]> = data.chunks(65_535).collect();
        if chunks.is_empty() {
            out.extend_from_slice(&[1, 0, 0, 0xff, 0xff]);
        }
        for (i, chunk) in chunks.iter().enumerate() {
            out.push(u8::from(i + 1 == chunks.len()));
            out.extend_from_slice(&(chunk.len() as u16).to_le_bytes());
            out.extend_from_slice(&(!(chunk.len() as u16)).to_le_bytes());
            out.extend_from_slice(chunk);
        }
        out.extend_from_slice(&crate::codec::crc::crc32(data).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out
    }

    /// Skips the first member's header, as the dissector does.
    fn decode(file: &[u8], chunk: usize) -> (Vec<u8>, usize, Option<Diagnostic>) {
        let input = &file[header_len(file).unwrap()..];
        let mut d = Streaming(Gzip::default());
        let mut out = Vec::new();
        let mut fed = 0;
        loop {
            let eof = fed == input.len();
            match d
                .decode(&input[..fed], eof, &mut out, 4096, 1 << 30)
                .unwrap()
            {
                Status::Done => {
                    let warning = d.warning(&out);
                    return (out, d.consumed(), warning);
                }
                Status::More => {}
                Status::NeedInput => fed = (fed + chunk).min(input.len()),
            }
        }
    }

    #[test]
    fn concatenated_members_decode_as_one_stream() {
        let a: Vec<u8> = (0..100_000u32).map(|i| i as u8).collect();
        let b = b"second member".to_vec();
        let c: Vec<u8> = (0..70_000u32).map(|i| (i * 7) as u8).collect();
        let mut file = member(&a, Some("a.txt"));
        file.extend(member(&b, None));
        file.extend(member(&[], None));
        file.extend(member(&c, Some("c")));
        let first = header_len(&file).unwrap();
        for chunk in [1, 13, 4096, 1 << 20] {
            let (out, consumed, warning) = decode(&file, chunk);
            assert_eq!(
                out,
                [a.clone(), b.clone(), c.clone()].concat(),
                "chunk {chunk}"
            );
            assert_eq!(consumed, file.len() - first);
            assert!(warning.is_none());
        }
    }

    #[test]
    fn decoding_from_a_member_header() {
        let a: Vec<u8> = (0..100_000u32).map(|i| i as u8).collect();
        let b = b"second member".to_vec();
        let c: Vec<u8> = (0..70_000u32).map(|i| (i * 7) as u8).collect();
        let mut file = member(&a, Some("a.txt"));
        let second = file.len();
        file.extend(member(&b, None));
        let third = file.len();
        file.extend(member(&c, Some("c")));
        let n = file.len() - 4;
        file[n] ^= 1;
        for (at, before, want) in [(second, 1, [&b[..], &c].concat()), (third, 2, c.clone())] {
            let mut d = Streaming(Gzip::at_member(before));
            let out = crate::codec::pipeline::decode_all(&mut d, &file[at..], 1 << 30).unwrap();
            assert_eq!(out, want);
            assert_eq!(d.consumed(), file.len() - at);
            // Members are numbered as from the start.
            assert_eq!(
                d.warning(&out).unwrap().message,
                "gzip member 3: size mismatch"
            );
        }
    }

    #[test]
    fn trailing_data_ends_the_stream() {
        let mut file = member(b"hello", None);
        let len = file.len();
        file.extend_from_slice(&[0; 512]);
        let (out, consumed, _) = decode(&file, 7);
        assert_eq!(out, b"hello");
        assert_eq!(consumed, len - 10);
    }

    #[test]
    fn checksum_mismatches_are_warnings() {
        let mut file = member(b"hello", None);
        file.extend(member(b"world", None));
        let at = file.len() - 8;
        file[at] ^= 1;
        let (out, _, warning) = decode(&file, 1 << 20);
        assert_eq!(out, b"helloworld");
        assert_eq!(warning.unwrap().message, "gzip member 2: CRC-32 mismatch");
    }

    #[test]
    fn a_truncated_second_member_is_an_error() {
        let mut file = member(b"hello", None);
        file.extend_from_slice(&member(b"world", Some("w"))[..8]);
        let input = &file[10..];
        let mut d = Streaming(Gzip::default());
        let mut out = Vec::new();
        let result = loop {
            match d.decode(input, true, &mut out, 4096, 1 << 30) {
                Ok(Status::More) => {}
                other => break other,
            }
        };
        assert!(result.is_err(), "{result:?}");
        assert_eq!(out, b"hello");
    }
}
