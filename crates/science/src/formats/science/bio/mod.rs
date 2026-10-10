//! Bioinformatics: binary formats (`binary`: BGZF, BAM, BCF, CRAM, indexes,
//! 2bit, BigWig, traces), text formats (`text`: sequences, alignments,
//! annotations, chemistry), sequencing data (`sequencing`: SFF, ZTR, SLOW5,
//! `.hic`) and text records (`records`: HMMER, EMBL, GTF, PSL, mzTab, AMBER).

pub mod binary;
pub mod records;
pub mod sequencing;
pub mod text;
