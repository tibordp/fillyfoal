//! Native executables, objects and debug data: ELF, Mach-O, PE (and MZ),
//! `a.out`, COFF objects, XCOFF, 16-bit NE, LE/LX, OMF, Delphi compiled
//! units, PEF, UEFI TE, CUDA fat binaries and PDB program databases.

pub mod aout;
pub mod coff;
pub mod dcu;
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

use std::sync::Arc;

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::Result;
use crate::node::{Count, Node};

/// Expander that pushes pre-built nodes with an exact count: for groups
/// whose children were decoded together with their parent (NE and LX name
/// tables and resources, Mach-O command contents).
pub(crate) async fn push_nodes(cx: Cx, nodes: Arc<Vec<Node>>) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(nodes.len())));
    for node in nodes.iter() {
        cx.push(node.clone()).await;
    }
    Ok(())
}
