//! System and platform artifacts: firmware tables, kernels and journals
//! (`artifacts`), Linux and boot tooling (`platform`), firmware and boot
//! images, embedded-device filesystems and console containers (`devices`),
//! Android OTA payloads, Intel HEX and S-records (`hexfile`), terminfo,
//! gettext catalogs (`mo`), Apple BOM stores, Windows compatibility
//! databases (`shim_sdb`), .NET resources and BinaryFormatter streams
//! (`dotnet`), MSBuild binary logs (`binlog`), developer artifacts
//! (`devtools`, Delphi form streams in `delphi`),Git storage, OSTree objects and flatpak bundles
//! (`ostree`) and Outlook PST/OST mail stores (`pst`).

pub mod artifacts;
pub mod binlog;
pub mod bom;
pub mod delphi;
pub mod devices;
pub mod devtools;
pub mod dotnet;
pub mod firmware;
pub mod git;
pub mod hexfile;
pub mod kvstore;
pub mod mo;
pub mod ostree;
pub mod ota;
pub mod platform;
pub mod pst;
pub mod shim_sdb;
pub mod terminfo;
