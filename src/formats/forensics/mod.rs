//! Forensic artifacts: Windows (`windows`, registry hives, event logs,
//! shell links, Prefetch, Recycle Bin, thumbnail caches, crash artifacts,
//! minidumps, Group Policy files, Address Book), macOS/iOS/Linux/Android
//! (`unix`, bookmarks, `.DS_Store`), browsers, logs, user-profile text
//! artifacts (`userdata`) and evidence containers and memory captures
//! (`evidence`).

pub mod bookmark;
pub mod browser;
pub mod dsstore;
pub mod evidence;
pub mod evt;
pub mod evtx;
pub mod lnk;
pub mod logs;
pub mod minidump;
pub mod prefetch;
pub mod recyclebin;
pub mod regf;
pub mod registry_pol;
pub mod thumbcache;
pub mod unix;
pub mod userdata;
pub mod wab;
pub mod windiag;
pub mod windows;
