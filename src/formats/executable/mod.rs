//! Native executables, objects and debug data: ELF, Mach-O, PE (and MZ),
//! `a.out`, COFF objects, XCOFF, 16-bit NE, LE/LX, OMF, PEF, UEFI TE, CUDA
//! fat binaries and PDB program databases.

pub mod aout;
pub mod coff;
pub mod elf;
pub mod fatbin;
pub mod lx;
pub mod macho;
pub mod ne;
pub mod omf;
pub mod pdb;
pub mod pe;
pub mod pef;
pub mod te;
pub mod xcoff;
