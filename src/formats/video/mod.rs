//! Video containers and streams: Matroska/WebM, ASF, FLV, MXF, RealMedia,
//! IVF, Y4M, raw elementary streams (`annexb` for H.264/HEVC, `rawvideo`),
//! Bink and Smacker (`rad`), Flash movies (`swf`), game and multimedia video
//! (`gamevideo`, `movies`), smaller containers (`containers`: NSV,
//! NuppelVideo, RED, Deluxe Paint animations), NUT, and subtitles (`pgs`,
//! `subtitles`).
//!
//! ISO BMFF (MP4, MOV, HEIF) lives in [`super::isobmff`], MPEG program and
//! transport streams in [`super::mpeg`], AVI in [`super::iff`].

pub mod annexb;
pub mod asf;
pub mod containers;
pub mod flv;
pub mod gamevideo;
pub mod ivf;
pub mod matroska;
pub mod movies;
pub mod mxf;
pub mod nut;
pub mod pgs;
pub mod rad;
pub mod rawvideo;
pub mod realmedia;
pub mod subtitles;
pub mod swf;
pub mod y4m;
