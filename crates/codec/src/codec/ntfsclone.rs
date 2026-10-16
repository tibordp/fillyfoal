//! The command stream of an ntfsclone special image (`ntfsclone
//! --save-image`, ntfs-3g), turned back into the volume it was saved from.
//!
//! After the image header (read by the container dissector), the stream
//! walks the volume's clusters from 0 up to and including cluster
//! `clusters` (the header's cluster count): the one past the last
//! cluster of the volume holds the backup boot sector, saved since image
//! version 10.1 (version 10.0 images end at cluster `clusters`). Each
//! command is one byte:
//!
//! - `0x00` (gap), then a signed little-endian 64-bit count: that many
//!   unused clusters, restored as zeros (ntfsclone seeks over them). A
//!   count of zero is rejected by ntfsclone, as is a gap past the last
//!   cluster; a negative count (a backward seek) appears only in metadata
//!   images saved with `--ignore-fs-check`, which ntfsclone cannot restore
//!   to a stream either.
//! - `0x01` (next), then the bytes of the next cluster: a whole cluster,
//!   except the cluster that reaches the end of the device (the backup
//!   boot sector's), of which only what the device holds is saved.
//!
//! Nothing follows the stream: no trailer or checksum.
//!
//! Every fact here was checked against what ntfs-3g 2022.10.3 writes and
//! against how its `ntfsclone --restore-image` reads (`restore_image` and
//! `copy_cluster` in `ntfsprogs/ntfsclone.c`, read for facts only; no code
//! was copied).
//!
//! The decoder's state is a handful of counters (no window, no history), so
//! it checkpoints for almost nothing; gaps are produced as bulk zero fills,
//! a bounded step at a time like every decoder.

use crate::codec::pipeline::{Decode, Step};
use crate::error::{DiagKind, Diagnostic, Result};

/// The gap command.
pub const CMD_GAP: u8 = 0;
/// The data command (the next cluster follows).
pub const CMD_NEXT: u8 = 1;
/// The largest cluster size decoded: NTFS clusters are at most 2 MiB.
pub const MAX_CLUSTER: u32 = 2 << 20;

/// What the decoder needs from the image header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Image {
    /// Bytes per cluster.
    pub cluster_size: u32,
    /// Bytes of the device the volume was saved from.
    pub device_size: u64,
    /// Clusters in the volume (the stream goes one cluster further, to the
    /// backup boot sector).
    pub clusters: u64,
}

impl Image {
    /// The volume offset of cluster `lcn`.
    pub fn offset(&self, lcn: u64) -> u64 {
        lcn.saturating_mul(u64::from(self.cluster_size))
    }

    /// Bytes a data command at cluster `lcn` carries: a whole cluster, or
    /// for the cluster that reaches the end of the device, what the device
    /// holds of it; `None` for a cluster past the end of the device (which
    /// ntfsclone refuses as corrupt).
    pub fn cluster_len(&self, lcn: u64) -> Option<u64> {
        let cs = u64::from(self.cluster_size);
        let start = self.offset(lcn);
        if start.saturating_add(cs) < self.device_size {
            return Some(cs);
        }
        self.device_size.checked_sub(start)
    }

    /// Bytes the stream restores: up to and including the backup boot
    /// sector's cluster (`backup`, image version 10.1 and later) or the
    /// volume's last cluster, and never past the device.
    pub fn volume_len(&self, backup: bool) -> u64 {
        let last = if backup {
            self.offset(self.clusters)
                .saturating_add(self.cluster_len(self.clusters).unwrap_or(0))
        } else {
            self.offset(self.clusters)
        };
        last.min(self.device_size)
    }
}

/// A shortage of input (see [`Decode::truncation_is_exact`]).
fn truncated(message: String) -> Diagnostic {
    Diagnostic::new(DiagKind::Truncated, message)
}

/// The resumable decoder; positions are relative to the buffers as they are
/// now (see "Releasing" in the pipeline docs).
#[derive(Clone, Debug)]
pub struct NtfsClone {
    image: Image,
    /// Input position (at a command, or inside a cluster being copied).
    at: usize,
    /// Input released before `at` (for positions in messages).
    released: u64,
    /// The next cluster a command describes.
    lcn: u64,
    /// Zero bytes of the current gap still to produce.
    zeros: u64,
    /// Bytes of the current data cluster still to copy.
    copy: u64,
    done: bool,
}

impl NtfsClone {
    pub fn new(image: Image) -> Self {
        NtfsClone {
            image,
            at: 0,
            released: 0,
            lcn: 0,
            zeros: 0,
            copy: 0,
            done: false,
        }
    }

    /// Stream offset of input position `at`.
    fn offset(&self, at: usize) -> u64 {
        self.released.saturating_add(crate::bytes::to_u64(at))
    }

    /// Reads the command at `self.at` and sets up what it produces, or
    /// says why it cannot. Returns `false` at the end of the stream.
    fn command(&mut self, input: &[u8], eof: bool) -> Result<bool> {
        let clusters = self.image.clusters;
        if self.lcn > clusters {
            return Ok(false);
        }
        let Some(&cmd) = input.get(self.at) else {
            if eof && self.lcn == clusters {
                // A version 10.0 image: no backup boot sector.
                return Ok(false);
            }
            return Err(truncated(format!(
                "ntfsclone image ends at cluster {} of {}",
                self.lcn,
                clusters.saturating_add(1)
            )));
        };
        match cmd {
            CMD_GAP => {
                let count = input
                    .get(self.at.saturating_add(1)..self.at.saturating_add(9))
                    .and_then(|b| <[u8; 8]>::try_from(b).ok())
                    .map(i64::from_le_bytes)
                    .ok_or_else(|| {
                        truncated(format!(
                            "ntfsclone image ends inside the gap command at stream offset {:#x}",
                            self.offset(self.at)
                        ))
                    })?;
                let at = self.offset(self.at);
                let count = match u64::try_from(count) {
                    Ok(0) => {
                        return Err(Diagnostic::malformed(format!(
                            "empty gap at stream offset {at:#x}"
                        )));
                    }
                    Ok(n) => n,
                    Err(_) => {
                        return Err(Diagnostic::unsupported(format!(
                            "backward gap of {count} clusters at stream offset {at:#x} \
                             (a metadata image saved with --ignore-fs-check)"
                        )));
                    }
                };
                let end = self.lcn.saturating_add(count);
                if end > clusters {
                    return Err(Diagnostic::malformed(format!(
                        "gap of {count} clusters from cluster {} at stream offset {at:#x} \
                         runs past the last cluster ({clusters})",
                        self.lcn
                    )));
                }
                self.zeros = self.image.offset(count);
                self.lcn = end;
                self.at = self.at.saturating_add(9);
            }
            CMD_NEXT => {
                let Some(len) = self.image.cluster_len(self.lcn) else {
                    return Err(Diagnostic::malformed(format!(
                        "cluster {} at stream offset {:#x} lies past the end of the device",
                        self.lcn,
                        self.offset(self.at)
                    )));
                };
                self.copy = len;
                self.lcn = self.lcn.saturating_add(1);
                self.at = self.at.saturating_add(1);
            }
            other => {
                return Err(Diagnostic::malformed(format!(
                    "unknown command {other:#04x} at stream offset {:#x}",
                    self.offset(self.at)
                )));
            }
        }
        Ok(true)
    }
}

impl Decode for NtfsClone {
    fn step(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        let cs = self.image.cluster_size;
        if cs == 0 || cs > MAX_CLUSTER {
            return Err(Diagnostic::unsupported(format!("cluster size {cs:#x}")));
        }
        let start = out.len();
        let goal = start.saturating_add(step.max(1));
        loop {
            if self.done {
                return Ok(Step::Done);
            }
            let room = goal.saturating_sub(out.len());
            if room == 0 {
                return Ok(Step::More);
            }
            let grow = |out: &mut Vec<u8>, n: usize| -> Result<()> {
                if out.len().saturating_add(n) > limit {
                    return Err(Diagnostic::limit("ntfsclone volume exceeds the limit"));
                }
                Ok(())
            };
            if self.zeros > 0 {
                let n = crate::bytes::to_usize(self.zeros).min(room);
                grow(out, n)?;
                out.resize(out.len().saturating_add(n), 0);
                self.zeros = self.zeros.saturating_sub(crate::bytes::to_u64(n));
                continue;
            }
            if self.copy > 0 {
                let avail = input.get(self.at..).unwrap_or_default();
                if avail.is_empty() {
                    if out.len() > start {
                        return Ok(Step::More);
                    }
                    return Err(truncated(format!(
                        "ntfsclone image ends inside cluster {}",
                        self.lcn.saturating_sub(1)
                    )));
                }
                let n = crate::bytes::to_usize(self.copy).min(room).min(avail.len());
                grow(out, n)?;
                out.extend_from_slice(avail.get(..n).unwrap_or_default());
                self.at = self.at.saturating_add(n);
                self.copy = self.copy.saturating_sub(crate::bytes::to_u64(n));
                continue;
            }
            match self.command(input, eof) {
                Ok(true) => {}
                Ok(false) => self.done = true,
                // Output so far stands; the shortage recurs on the next call.
                Err(e) if e.kind == DiagKind::Truncated && out.len() > start => {
                    return Ok(Step::More);
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn consumed(&self) -> usize {
        self.at
    }

    fn releasable_input(&self) -> usize {
        self.at
    }

    fn release_input(&mut self, n: usize) {
        let n = n.min(self.at);
        self.at = self.at.saturating_sub(n);
        self.released = self.released.saturating_add(crate::bytes::to_u64(n));
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        // No back-references: nothing decoded is read again.
        out_len
    }

    fn heap_size(&self) -> Option<usize> {
        Some(0)
    }

    fn truncation_is_exact(&self) -> bool {
        true
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
    use crate::codec::Codec;
    use crate::codec::pipeline::{Status, decode_all, verify_checkpoints};

    const CS: u32 = 512;

    fn gap(out: &mut Vec<u8>, n: i64) {
        out.push(CMD_GAP);
        out.extend_from_slice(&n.to_le_bytes());
    }

    fn data(out: &mut Vec<u8>, fill: u8, len: usize) {
        out.push(CMD_NEXT);
        out.extend(std::iter::repeat_n(fill, len));
    }

    /// Clusters 0-1 data, 2-9 empty, 10 data, then the backup boot sector's
    /// cluster 11, partial (the device ends 100 bytes into it).
    fn sample() -> (Image, Vec<u8>) {
        let image = Image {
            cluster_size: CS,
            device_size: 11 * 512 + 100,
            clusters: 11,
        };
        let mut s = Vec::new();
        data(&mut s, 0xa1, 512);
        data(&mut s, 0xa2, 512);
        gap(&mut s, 8);
        data(&mut s, 0xa3, 512);
        data(&mut s, 0xb0, 100);
        (image, s)
    }

    fn decode(image: Image, stream: &[u8]) -> Result<Vec<u8>> {
        decode_all(
            Codec::NtfsClone(image).decoder().unwrap().as_mut(),
            stream,
            1 << 30,
        )
    }

    #[test]
    fn restores_the_volume() {
        let (image, s) = sample();
        let out = decode(image, &s).unwrap();
        assert_eq!(out.len() as u64, image.volume_len(true));
        assert_eq!(out.len(), 11 * 512 + 100);
        assert!(out[..512].iter().all(|&b| b == 0xa1));
        assert!(out[512..1024].iter().all(|&b| b == 0xa2));
        assert!(out[1024..10 * 512].iter().all(|&b| b == 0));
        assert!(out[10 * 512..11 * 512].iter().all(|&b| b == 0xa3));
        assert!(out[11 * 512..].iter().all(|&b| b == 0xb0));
    }

    /// Small steps resume exactly, and checkpoints cost only the decoder.
    #[test]
    fn checkpoints_resume_exactly() {
        let (image, s) = sample();
        let (checked, largest) =
            verify_checkpoints(|| Codec::NtfsClone(image).decoder().unwrap(), &s, 100, 1).unwrap();
        assert!(checked > 20, "{checked}");
        assert!(largest < 256, "{largest}");
    }

    /// A version 10.0 image ends at the volume's last cluster.
    #[test]
    fn version_10_0_has_no_backup_cluster() {
        let (image, mut s) = sample();
        s.truncate(s.len() - 101);
        assert_eq!(
            decode(image, &s).unwrap().len() as u64,
            image.volume_len(false)
        );
    }

    /// What follows the stream is left unconsumed.
    #[test]
    fn stops_after_the_backup_cluster() {
        let (image, mut s) = sample();
        let len = s.len();
        s.extend_from_slice(b"trailing");
        let mut d = Codec::NtfsClone(image).decoder().unwrap();
        decode_all(d.as_mut(), &s, 1 << 30).unwrap();
        assert_eq!(d.consumed(), len);
    }

    #[test]
    fn damage_is_reported() {
        let (image, s) = sample();
        let kind = |s: &[u8]| decode(image, s).unwrap_err().kind;
        // Cut inside a cluster, inside a gap command, between commands.
        assert_eq!(kind(&s[..700]), DiagKind::Truncated);
        assert_eq!(kind(&s[..1030]), DiagKind::Truncated);
        assert_eq!(kind(&s[..1026]), DiagKind::Truncated);
        let mut bad = s.clone();
        bad[513] = 7;
        let e = decode(image, &bad).unwrap_err();
        assert_eq!(e.kind, DiagKind::Malformed);
        assert!(e.message.contains("0x07"), "{}", e.message);
        let mut zero = Vec::new();
        gap(&mut zero, 0);
        assert_eq!(kind(&zero), DiagKind::Malformed);
        let mut back = Vec::new();
        gap(&mut back, -3);
        assert_eq!(kind(&back), DiagKind::Unsupported);
        let mut over = Vec::new();
        gap(&mut over, 12);
        assert_eq!(kind(&over), DiagKind::Malformed);
        let past = Image {
            device_size: 512,
            ..image
        };
        let mut two = Vec::new();
        data(&mut two, 1, 512);
        data(&mut two, 2, 512);
        assert_eq!(decode(past, &two).unwrap_err().kind, DiagKind::Malformed);
        let huge = Image {
            cluster_size: MAX_CLUSTER * 2,
            ..image
        };
        assert_eq!(decode(huge, &s).unwrap_err().kind, DiagKind::Unsupported);
    }

    /// A gap of a billion clusters costs nine bytes; it is produced a step
    /// at a time.
    #[test]
    fn large_gaps_are_produced_in_bounded_steps() {
        let image = Image {
            cluster_size: 4096,
            device_size: 4096 << 30,
            clusters: (1 << 30) - 1,
        };
        let mut s = Vec::new();
        gap(&mut s, (1 << 30) - 1);
        let mut d = Codec::NtfsClone(image).decoder().unwrap();
        let mut out = Vec::new();
        for _ in 0..10 {
            out.clear();
            assert_eq!(
                d.decode(&s, true, &mut out, 4096, 1 << 30),
                Ok(Status::More)
            );
            assert!(out.len() < 2 * 4096 && out.iter().all(|&b| b == 0));
        }
        // An output limit is reported, not exceeded.
        let mut d = Codec::NtfsClone(image).decoder().unwrap();
        let mut out = Vec::new();
        let e = d.decode(&s, true, &mut out, 1 << 20, 1000).unwrap_err();
        assert_eq!(e.kind, DiagKind::Limit);
    }

    /// Input arriving a byte at a time decodes the same.
    #[test]
    fn decodes_incrementally() {
        let (image, s) = sample();
        let expected = decode(image, &s).unwrap();
        let mut d = Codec::NtfsClone(image).decoder().unwrap();
        let mut out = Vec::new();
        let mut fed = 0;
        loop {
            let eof = fed == s.len();
            match d.decode(&s[..fed], eof, &mut out, 64, 1 << 30).unwrap() {
                Status::Done => break,
                Status::More => {}
                Status::NeedInput => fed += 1,
            }
        }
        assert_eq!(out, expected);
    }
}
