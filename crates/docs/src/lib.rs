//! fillyfoal's dissectors for office documents, PDF, e-books and desktop publishing.
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
    pub(crate) use fillyfoal_av::formats::audio;
    #[allow(unused_imports)]
    pub(crate) use fillyfoal_av::formats::iff;
    #[allow(unused_imports)]
    pub(crate) use fillyfoal_av::formats::isobmff;
    #[allow(unused_imports)]
    pub(crate) use fillyfoal_av::formats::mpeg;
    #[allow(unused_imports)]
    pub(crate) use fillyfoal_av::formats::tracker;
    #[allow(unused_imports)]
    pub(crate) use fillyfoal_av::formats::video;
    #[allow(unused_imports)]
    pub(crate) use fillyfoal_data::formats::data;
    #[allow(unused_imports)]
    pub(crate) use fillyfoal_data::formats::sqlite;
    #[allow(unused_imports)]
    pub(crate) use fillyfoal_image::formats::font;
    #[allow(unused_imports)]
    pub(crate) use fillyfoal_image::formats::image;
    #[allow(unused_imports)]
    pub(crate) use fillyfoal_security::formats::asn1;
    #[allow(unused_imports)]
    pub(crate) use fillyfoal_security::formats::pcap;
    #[allow(unused_imports)]
    pub(crate) use fillyfoal_security::formats::security;
    #[allow(unused_imports)]
    pub(crate) use fillyfoal_text::formats::text;

    pub mod cfb;
    pub mod documents;
    pub mod pdf;
    pub mod publishing;
}
