//! Scientific and lab data: bioinformatics ([`bio`]), instrument recordings
//! (`instruments`, `waveforms`), spectroscopy, microscopy and lab images
//! (`microscopy`, `lab_images`), FITS and DICOM (`imaging`), molecular
//! simulation, and statistics and science datasets (`datasets`).
//!
//! Geoscience lives in [`super::geo`].

pub mod bio;
pub mod datasets;
pub mod imaging;
pub mod instruments;
pub mod lab_images;
pub mod microscopy;
pub mod molecular;
pub mod spectroscopy;
pub mod waveforms;
