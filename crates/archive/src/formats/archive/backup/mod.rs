//! Backup tools' storage formats: BorgBackup repository segments (`borg`),
//! Proxmox file archives (`pxar`), Proxmox VE VM archives (`vma`) and
//! Proxmox Backup Server data blobs (`pbs`).

pub mod borg;
pub mod pbs;
pub mod pxar;
pub mod vma;
