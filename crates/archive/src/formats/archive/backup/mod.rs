//! Backup tools' storage formats: BorgBackup repository segments (`borg`),
//! Proxmox file archives (`pxar`), Proxmox VE VM archives (`vma`),
//! Proxmox Backup Server data blobs (`pbs`), index files (`pbs_index`)
//! and catalogs (`pbs_catalog`).

pub mod borg;
pub mod pbs;
pub mod pbs_catalog;
pub mod pbs_index;
pub mod pxar;
pub mod vma;
