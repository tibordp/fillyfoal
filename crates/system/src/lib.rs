//! fillyfoal's dissectors for operating system artifacts, forensic records, mobile platforms and machine learning models.
//!
//! The `fillyfoal` crate registers them; use that.

// Dissectors name the core by its paths in the single crate they grew up in
// (`crate::cx::Cx`, `crate::formats::Input`): the core's modules are
// imported at the root, and `formats` holds this crate's families beside the
// core's plumbing and the families of the crates this one builds on.
#[allow(unused_imports)]
use fillyfoal_core::*;

pub mod formats {
    pub use fillyfoal_core::formats::*;

    #[allow(unused_imports)]
    pub(crate) use fillyfoal_archive::formats::archive;
    #[allow(unused_imports)]
    pub(crate) use fillyfoal_archive::formats::compression;
    #[allow(unused_imports)]
    pub(crate) use fillyfoal_archive::formats::disk;
    #[allow(unused_imports)]
    pub(crate) use fillyfoal_data::formats::data;
    #[allow(unused_imports)]
    pub(crate) use fillyfoal_data::formats::sqlite;
    #[allow(unused_imports)]
    pub(crate) use fillyfoal_exec::formats::android;
    #[allow(unused_imports)]
    pub(crate) use fillyfoal_exec::formats::bytecode;
    #[allow(unused_imports)]
    pub(crate) use fillyfoal_exec::formats::executable;
    #[allow(unused_imports)]
    pub(crate) use fillyfoal_exec::formats::java;
    #[allow(unused_imports)]
    pub(crate) use fillyfoal_text::formats::text;

    pub mod forensics;
    pub mod ml;
    pub mod mobile;
    pub mod system;
}
