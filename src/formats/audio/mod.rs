//! Audio streams, containers and tags: MPEG audio (`mpa`), AAC in ADTS, AC-3,
//! DTS, AMR, FLAC, Ogg (with Vorbis comments), Monkey's Audio and APE tags,
//! ID3, WavPack, Musepack, TTA and other lossless codecs, DSD, CAF, Wave64,
//! Sun `.au`, Creative VOC, Yamaha SMAF, MIDI, headered PCM (`simple_audio`,
//! `pcm_headers`), codec streams (`codecs`: RealAudio, Psion, EVS), sequenced
//! music (`sequenced`) and production files (`production`, `projects`).
//!
//! RIFF/IFF audio (WAVE, AIFF) lives in [`super::iff`], tracker modules in
//! [`super::tracker`].

pub mod ac3;
pub mod adts;
pub mod amr;
pub mod ape;
pub mod apetag;
pub mod au;
pub mod caf;
pub mod codecs;
pub mod dsd;
pub mod dts;
pub mod flac;
pub mod id3;
pub mod lossless;
pub mod midi;
pub mod mpa;
pub mod musepack;
pub mod ogg;
pub mod pcm_headers;
pub mod production;
pub mod projects;
pub mod sequenced;
pub mod simple_audio;
pub mod smaf;
pub mod tta;
pub mod voc;
pub mod vorbis;
pub mod w64;
pub mod wavpack;
