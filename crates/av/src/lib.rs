//! fillyfoal's dissectors for audio, video, their containers and tracker music.
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
    pub(crate) use fillyfoal_image::formats::font;
    #[allow(unused_imports)]
    pub(crate) use fillyfoal_image::formats::image;
    #[allow(unused_imports)]
    pub(crate) use fillyfoal_text::formats::text;

    pub mod audio;
    pub mod iff;
    pub mod isobmff;
    pub mod mpeg;
    pub mod tracker;
    pub mod video;
}
