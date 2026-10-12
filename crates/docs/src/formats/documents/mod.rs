//! Documents and help files: legacy office formats, e-books (Palm, DjVu,
//! Microsoft Reader, Sony BBeB), word processors (`wordprocessing`), TeX DVI,
//! Windows Help, Compiled HTML Help and other help formats (`help`), SketchUp
//! models (`sketchup`), TempleOS DolDoc documents and HolyC source
//! (`doldoc`) and the TempleOS AutoComplete dictionary (`templeos_ac`).
//!
//! PDF lives in [`super::pdf`], OLE2 documents in [`super::cfb`], ZIP-based
//! documents in `super::archive::zip`, desktop publishing in
//! [`super::publishing`].

pub mod chm;
pub mod djvu;
pub mod doldoc;
pub mod dvi;
pub mod ebooks;
pub mod help;
pub mod lrf;
pub mod office_legacy;
pub mod onenote;
pub mod sketchup;
pub mod templeos_ac;
pub mod winhelp;
pub mod wordprocessing;
