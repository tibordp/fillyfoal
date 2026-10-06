//! Cyclic redundancy checks, table-driven, in the usual parameterised
//! ("Rocksoft") model: width, polynomial (normal form), initial register,
//! reflection, final XOR. Each named CRC is a `const` whose table is built
//! at compile time; the tests check the catalogue's check values (the CRC
//! of "123456789").

/// A CRC algorithm.
pub struct Crc {
    table: [u64; 256],
    width: u32,
    reflected: bool,
    init: u64,
    xorout: u64,
}

const fn mask(width: u32) -> u64 {
    if width >= 64 { u64::MAX } else { (1u64 << width).wrapping_sub(1) }
}

impl Crc {
    // Evaluated at compile time: an out-of-range index or an overflow is a
    // compile error.
    #[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
    pub const fn new(width: u32, poly: u64, init: u64, reflected: bool, xorout: u64) -> Self {
        let m = mask(width);
        // The polynomial bit-reversed within the width, for reflected CRCs.
        let mut rpoly = 0u64;
        let mut i = 0;
        while i < width {
            if poly & (1 << i) != 0 {
                rpoly |= 1 << (width - 1 - i);
            }
            i += 1;
        }
        let top = 1u64 << (width - 1);
        let mut table = [0u64; 256];
        let mut n = 0;
        while n < 256 {
            let mut c = if reflected { n as u64 } else { (n as u64) << (width - 8) };
            let mut k = 0;
            while k < 8 {
                c = if reflected {
                    if c & 1 != 0 { (c >> 1) ^ rpoly } else { c >> 1 }
                } else if c & top != 0 {
                    ((c << 1) ^ poly) & m
                } else {
                    (c << 1) & m
                };
                k += 1;
            }
            table[n] = c;
            n += 1;
        }
        Crc { table, width, reflected, init: init & m, xorout: xorout & m }
    }

    /// The initial register value.
    pub fn init(&self) -> u64 {
        self.init
    }

    /// Feeds one byte to a raw register (no initial value or final XOR).
    pub fn update_byte(&self, crc: u64, b: u8) -> u64 {
        if self.reflected {
            let i = usize::from(crc.to_le_bytes()[0] ^ b);
            self.table.get(i).copied().unwrap_or(0) ^ (crc >> 8)
        } else {
            let shift = self.width.saturating_sub(8);
            let i = usize::from((crc >> shift).to_le_bytes()[0] ^ b);
            (self.table.get(i).copied().unwrap_or(0) ^ crc.wrapping_shl(8)) & mask(self.width)
        }
    }

    /// Feeds bytes to a raw register (no initial value or final XOR).
    pub fn update(&self, crc: u64, data: &[u8]) -> u64 {
        data.iter().fold(crc, |c, &b| self.update_byte(c, b))
    }

    /// Finishes a register: the final XOR.
    pub fn finish(&self, crc: u64) -> u64 {
        crc ^ self.xorout
    }

    /// The CRC of `data`.
    pub fn checksum(&self, data: &[u8]) -> u64 {
        self.finish(self.update(self.init, data))
    }
}

/// CRC-32 (ISO-HDLC: zip, gzip, PNG, …).
pub const CRC32: Crc = Crc::new(32, 0x04c1_1db7, 0xffff_ffff, true, 0xffff_ffff);
/// CRC-32C (Castagnoli: ext4, Btrfs, XFS, iSCSI, Snappy, LevelDB, …).
pub const CRC32C: Crc = Crc::new(32, 0x1edc_6f41, 0xffff_ffff, true, 0xffff_ffff);
/// CRC-32/BZIP2 (unreflected), as bzip2 uses.
pub const CRC32_BZIP2: Crc = Crc::new(32, 0x04c1_1db7, 0xffff_ffff, false, 0xffff_ffff);
/// CRC-32/MPEG-2 (MPEG transport stream sections).
pub const CRC32_MPEG2: Crc = Crc::new(32, 0x04c1_1db7, 0xffff_ffff, false, 0);
/// The unreflected CRC-32 with a zero initial value, as Ogg pages use.
pub const CRC32_OGG: Crc = Crc::new(32, 0x04c1_1db7, 0, false, 0);
/// CRC-64/XZ (ECMA-182, reflected).
pub const CRC64_XZ: Crc = Crc::new(64, 0x42f0_e1eb_a9ea_3693, u64::MAX, true, u64::MAX);
/// CRC-24/OPENPGP (RFC 4880 armor checksums).
pub const CRC24_OPENPGP: Crc = Crc::new(24, 0x86_4cfb, 0xb7_04ce, false, 0);
/// CRC-24/LTE-A, a.k.a. CRC-24Q (RTCM 3, Qualcomm).
pub const CRC24Q: Crc = Crc::new(24, 0x86_4cfb, 0, false, 0);
/// CRC-16/ARC (LHA, ARC, FIT).
pub const CRC16_ARC: Crc = Crc::new(16, 0x8005, 0, true, 0);
/// CRC-16/MODBUS (ARC's polynomial with an all-ones start).
pub const CRC16_MODBUS: Crc = Crc::new(16, 0x8005, 0xffff, true, 0);
/// CRC-16/XMODEM.
pub const CRC16_XMODEM: Crc = Crc::new(16, 0x1021, 0, false, 0);
/// CRC-16/TELEDISK.
pub const CRC16_TELEDISK: Crc = Crc::new(16, 0xa097, 0, false, 0);
/// CRC-8/SMBUS (FLAC frame headers).
pub const CRC8: Crc = Crc::new(8, 0x07, 0, false, 0);

fn low32(v: u64) -> u32 {
    u32::try_from(v & 0xffff_ffff).unwrap_or(0)
}

fn low16(v: u64) -> u16 {
    u16::try_from(v & 0xffff).unwrap_or(0)
}

/// CRC-32 (ISO-HDLC).
pub fn crc32(data: &[u8]) -> u32 {
    low32(CRC32.checksum(data))
}

/// Raw CRC-32 register update, without initial or final inversion (for
/// formats that seed it themselves).
pub fn crc32_update(crc: u32, data: &[u8]) -> u32 {
    low32(CRC32.update(crc.into(), data))
}

/// CRC-32C (Castagnoli).
pub fn crc32c(data: &[u8]) -> u32 {
    low32(CRC32C.checksum(data))
}

/// Raw CRC-32C register update, without initial or final inversion.
pub fn crc32c_update(crc: u32, data: &[u8]) -> u32 {
    low32(CRC32C.update(crc.into(), data))
}

/// CRC-64/XZ.
pub fn crc64(data: &[u8]) -> u64 {
    CRC64_XZ.checksum(data)
}

/// CRC-24/OPENPGP.
pub fn crc24(data: &[u8]) -> u32 {
    low32(CRC24_OPENPGP.checksum(data))
}

/// CRC-24Q.
pub fn crc24q(data: &[u8]) -> u32 {
    low32(CRC24Q.checksum(data))
}

/// CRC-16/ARC.
pub fn crc16_arc(data: &[u8]) -> u16 {
    low16(CRC16_ARC.checksum(data))
}

/// CRC-16/MODBUS.
pub fn crc16_modbus(data: &[u8]) -> u16 {
    low16(CRC16_MODBUS.checksum(data))
}

/// CRC-16/XMODEM.
pub fn crc16_xmodem(data: &[u8]) -> u16 {
    low16(CRC16_XMODEM.checksum(data))
}

/// CRC-8/SMBUS.
pub fn crc8(data: &[u8]) -> u8 {
    CRC8.checksum(data).to_le_bytes()[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_check_values() {
        let c = b"123456789";
        assert_eq!(crc32(c), 0xcbf4_3926);
        assert_eq!(crc32c(c), 0xe306_9283);
        assert_eq!(CRC32_BZIP2.checksum(c), 0xfc89_1918);
        assert_eq!(CRC32_OGG.checksum(c), 0x89a1_897f);
        assert_eq!(CRC32_MPEG2.checksum(c), 0x0376_e6e7);
        assert_eq!(CRC16_TELEDISK.checksum(c), 0x0fb3);
        assert_eq!(crc64(c), 0x995d_c9bb_df19_39fa);
        assert_eq!(crc24(c), 0x21_cf02);
        assert_eq!(crc24q(c), 0xcd_e703);
        assert_eq!(crc16_arc(c), 0xbb3d);
        assert_eq!(crc16_modbus(c), 0x4b37);
        assert_eq!(crc16_xmodem(c), 0x31c3);
        assert_eq!(crc8(c), 0xf4);
    }

    #[test]
    fn raw_updates_compose() {
        let (a, b) = b"1234567890abcdef".split_at(7);
        assert_eq!(!crc32_update(crc32_update(!0, a), b), crc32(b"1234567890abcdef"));
        assert_eq!(!crc32c_update(crc32c_update(!0, a), b), crc32c(b"1234567890abcdef"));
    }
}
