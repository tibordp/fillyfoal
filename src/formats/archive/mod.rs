//! Archives and packages: ZIP and the formats built on it, tar, cpio, `ar`,
//! RAR, 7z, Cabinet, WIM, xar, RPM, StuffIt, LHA, ARJ, ACE and ZOO;
//! AppleSingle/AppleDouble, Chrome extensions (`crx`), WARC web archives,
//! application packages (`packaging`: AppImage, Solaris datastreams, Haiku
//! packages, Electron ASAR), less common archivers and installers (`minor`:
//! ALZip, EGG, KGB, InstallShield) and legacy archivers (`legacy`: HA, UHARC,
//! YZ1, GCA, PAQ8, Amiga XPK and LZX, PackIt).

pub mod ace;
pub mod applesingle;
pub mod ar;
pub mod arj;
pub mod cab;
pub mod cpio;
pub mod crx;
pub mod legacy;
pub mod lha;
pub mod minor;
pub mod packaging;
pub mod rar;
pub mod rpm;
pub mod sevenzip;
pub mod stuffit;
pub mod tar;
pub mod warc;
pub mod wim;
pub mod xar;
pub mod zip;
pub mod zoo;
