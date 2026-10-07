//! Engineering and 3D content: mechanical CAD (`cad`, `brep`), simulation
//! input and results (`simulation`), electronic design automation (`eda`,
//! `eda_text`), 3D models and meshes (`models`, `meshes`) and DCC scenes
//! (`dcc`: Maya, Cinema 4D, Houdini, Alembic), and machine-control programs
//! for 3D printers and CNC machines (`fabrication`: G-code, Prusa binary
//! G-code).

pub mod autocad;
pub mod brep;
pub mod cad;
pub mod dcc;
pub mod eda;
pub mod eda_text;
pub mod fabrication;
pub mod meshes;
pub mod models;
pub mod simulation;
