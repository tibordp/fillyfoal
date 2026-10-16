//! System and platform artifacts: firmware tables, kernels and journals
//! (`artifacts`), Linux and boot tooling (`platform`), firmware and boot
//! images, embedded-device filesystems and console containers (`devices`),
//! Android OTA payloads, Intel HEX and S-records (`hexfile`), terminfo,
//! gettext catalogs (`mo`), Apple BOM stores, Windows compatibility
//! databases (`shim_sdb`), .NET resources and BinaryFormatter streams
//! (`dotnet`), MSBuild binary logs (`binlog`), developer artifacts
//! (`devtools`, Delphi form streams in `delphi`), Git storage
//! (commit-graphs in `commit_graph`), OSTree objects and flatpak bundles
//! (`ostree`), Outlook PST/OST mail stores (`pst`) and Linux tracing and
//! monitoring data (`tracecmd`, `sysstat`, `atop`, Common Trace Format in
//! `ctf`).

pub mod artifacts;
pub mod atop;
pub mod binlog;
pub mod bom;
pub mod commit_graph;
pub mod ctf;
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
pub mod sysstat;
pub mod terminfo;
pub mod tracecmd;
