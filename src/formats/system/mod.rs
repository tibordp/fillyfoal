//! System and platform artifacts: firmware tables, kernels and journals
//! (`artifacts`), Linux and boot tooling (`platform`), firmware and boot
//! images, embedded-device filesystems and console containers (`devices`),
//! Android OTA payloads, Intel HEX and S-records (`hexfile`), terminfo,
//! gettext catalogs (`mo`), Apple BOM stores, Windows compatibility
//! databases (`shim_sdb`), developer artifacts (`devtools`) and Git storage.

pub mod artifacts;
pub mod bom;
pub mod devices;
pub mod devtools;
pub mod firmware;
pub mod git;
pub mod hexfile;
pub mod mo;
pub mod ota;
pub mod platform;
pub mod shim_sdb;
pub mod terminfo;
