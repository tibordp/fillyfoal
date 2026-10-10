//! AutoCAD drawings: the native DWG format (`dwg`, with the section
//! contents in `dwg_data` and the bit codes in `bits`) and the drawing
//! exchange format DXF (`dxf`, ASCII and binary).

pub mod bits;
pub mod dwg;
mod dwg_data;
pub mod dxf;

/// Version strings (DWG magic, DXF `$ACADVER`) and the releases that
/// introduced them.
pub(crate) const VERSIONS: &[(&str, &str)] = &[
    ("AC1.40", "R1.40"),
    ("AC1.50", "R2.05"),
    ("AC2.10", "R2.10"),
    ("AC1001", "R2.21"),
    ("AC1002", "R2.5"),
    ("AC1003", "R2.6"),
    ("AC1004", "R9"),
    ("AC1006", "R10"),
    ("AC1009", "R11/R12"),
    ("AC1012", "R13"),
    ("AC1014", "R14"),
    ("AC1015", "AutoCAD 2000"),
    ("AC1018", "AutoCAD 2004"),
    ("AC1021", "AutoCAD 2007"),
    ("AC1024", "AutoCAD 2010"),
    ("AC1027", "AutoCAD 2013"),
    ("AC1032", "AutoCAD 2018"),
];

pub(crate) fn release(tag: &str) -> Option<&'static str> {
    VERSIONS.iter().find(|(v, _)| *v == tag).map(|(_, r)| *r)
}
