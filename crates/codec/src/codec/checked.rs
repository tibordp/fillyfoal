//! A container's checksum of decoded data, verified as the data is
//! decoded: [`Codec::Checked`](super::Codec::Checked) wraps a codec's
//! decoder in [`Checked`], which runs the CRC over everything the decoder
//! produces and reports a mismatch as its warning once the stream ends.

use super::crc::{CRC16_ARC, CRC32, Crc};
use super::pipeline::{Decoder, Status};
use crate::error::{Diagnostic, Result};

/// The CRC a container records of the decoded data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DataCrc {
    /// CRC-32 (ZIP members).
    Crc32,
    /// CRC-32 without its final inversion (ACE members).
    Crc32NotInverted,
    /// CRC-16/ARC (LHA and ZOO members).
    Crc16Arc,
}

/// CRC-32 without the final inversion.
const CRC32_NOT_INVERTED: Crc = Crc::new(32, 0x04c1_1db7, 0xffff_ffff, true, 0);

impl DataCrc {
    /// The algorithm's name, as a check value shows it.
    pub fn name(self) -> &'static str {
        match self {
            DataCrc::Crc32 => "CRC-32",
            DataCrc::Crc32NotInverted => "CRC-32 (not inverted)",
            DataCrc::Crc16Arc => "CRC-16/ARC",
        }
    }

    fn crc(self) -> &'static Crc {
        match self {
            DataCrc::Crc32 => &CRC32,
            DataCrc::Crc32NotInverted => &CRC32_NOT_INVERTED,
            DataCrc::Crc16Arc => &CRC16_ARC,
        }
    }

    /// A running CRC of this kind.
    pub fn start(self) -> Running {
        Running {
            kind: self,
            reg: self.crc().init(),
        }
    }

    /// The mismatch diagnostic, in the house wording, when `computed`
    /// differs from `stored`.
    pub fn mismatch(self, stored: u64, computed: u64) -> Option<Diagnostic> {
        (stored != computed).then(|| {
            Diagnostic::warning(format!(
                "{} mismatch: stored {stored:#x}, computed {computed:#x}",
                self.name()
            ))
        })
    }
}

/// A CRC over data fed in pieces.
#[derive(Clone, Copy, Debug)]
pub struct Running {
    kind: DataCrc,
    reg: u64,
}

impl Running {
    pub fn update(&mut self, data: &[u8]) {
        self.reg = self.kind.crc().update(self.reg, data);
    }

    pub fn value(&self) -> u64 {
        self.kind.crc().finish(self.reg)
    }
}

/// A decoder (or, for stored data, a copy of the input) whose output's CRC
/// must equal `stored`. It never skips zero runs (it must see every byte),
/// and a decoder started mid-stream (a container's seed) would not know
/// the CRC of what came before, so it is not for seeded decoding.
pub struct Checked {
    /// `None`: the output is the input.
    inner: Option<Box<dyn Decoder>>,
    crc: Running,
    stored: u64,
    /// For a copy: input bytes consumed (relative to the input as it is).
    copied: usize,
}

impl Checked {
    pub fn new(inner: Option<Box<dyn Decoder>>, kind: DataCrc, stored: u64) -> Self {
        Checked {
            inner,
            crc: kind.start(),
            stored,
            copied: 0,
        }
    }
}

impl Decoder for Checked {
    fn decode(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Status> {
        let mark = out.len();
        let status = match &mut self.inner {
            Some(inner) => inner.decode(input, eof, out, step, limit)?,
            None => {
                let rest = input.get(self.copied..).unwrap_or_default();
                let room = limit.saturating_sub(out.len());
                if room == 0 && !rest.is_empty() {
                    return Err(Diagnostic::limit("output exceeds the limit"));
                }
                let n = rest.len().min(step.max(1)).min(room);
                out.extend_from_slice(rest.get(..n).unwrap_or_default());
                self.copied = self.copied.saturating_add(n);
                if self.copied < input.len() {
                    Status::More
                } else if eof {
                    Status::Done
                } else {
                    Status::NeedInput
                }
            }
        };
        self.crc.update(out.get(mark..).unwrap_or_default());
        Ok(status)
    }

    fn consumed(&self) -> usize {
        self.inner.as_ref().map_or(self.copied, |d| d.consumed())
    }

    fn warning(&self, out: &[u8]) -> Option<Diagnostic> {
        if let Some(w) = self.inner.as_ref().and_then(|d| d.warning(out)) {
            return Some(w);
        }
        self.crc.kind.mismatch(self.stored, self.crc.value())
    }

    fn releasable_input(&self) -> usize {
        self.inner
            .as_ref()
            .map_or(self.copied, |d| d.releasable_input())
    }

    fn release_input(&mut self, n: usize) {
        match &mut self.inner {
            Some(d) => d.release_input(n),
            None => self.copied = self.copied.saturating_sub(n),
        }
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        self.inner
            .as_ref()
            .map_or(out_len, |d| d.releasable_output(out_len))
    }

    fn release_output(&mut self, n: usize) {
        if let Some(d) = &mut self.inner {
            d.release_output(n);
        }
    }

    fn checkpoint(&self) -> Option<Box<dyn Decoder>> {
        let inner = match &self.inner {
            Some(d) => Some(d.checkpoint()?),
            None => None,
        };
        Some(Box::new(Checked {
            inner,
            crc: self.crc,
            stored: self.stored,
            copied: self.copied,
        }))
    }

    fn state_size(&self) -> usize {
        self.inner
            .as_ref()
            .map_or(0, |d| d.state_size())
            .saturating_add(std::mem::size_of::<Self>())
    }

    fn boundary(&self) -> Option<usize> {
        self.inner.as_ref().and_then(|d| d.boundary())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::Codec;
    use super::super::pipeline::decode_all;
    use super::*;

    fn deflated(data: &[u8]) -> Vec<u8> {
        // A stored DEFLATE block: BFINAL, BTYPE 00, LEN, NLEN, data.
        let len = u16::try_from(data.len()).unwrap();
        let mut v = vec![0x01];
        v.extend_from_slice(&len.to_le_bytes());
        v.extend_from_slice(&(!len).to_le_bytes());
        v.extend_from_slice(data);
        v
    }

    #[test]
    fn checks_the_decoded_crc() {
        let data = b"hello, checked world";
        let crc = super::super::crc32(data);
        for (codec, input) in [
            (Codec::Deflate, deflated(data)),
            (Codec::Stored, data.to_vec()),
        ] {
            let ok = codec.clone().checked(DataCrc::Crc32, crc.into());
            let mut d = ok.decoder().unwrap();
            let out = decode_all(d.as_mut(), &input, 1 << 20).unwrap();
            assert_eq!(out, data);
            assert!(d.warning(&out).is_none());
            let bad = codec.checked(DataCrc::Crc32, u64::from(crc ^ 1));
            let mut d = bad.decoder().unwrap();
            let out = decode_all(d.as_mut(), &input, 1 << 20).unwrap();
            let w = d.warning(&out).unwrap();
            assert!(w.message.starts_with("CRC-32 mismatch: stored"), "{w:?}");
        }
    }
}
