//! Game data: id Software, Valve and Epic engine files (`engines`), game and
//! console archives (`archives`, `packfiles`), engine packages (`packages`),
//! console assets (`consoles`, `nw4`), Blizzard and Bethesda assets, Minecraft
//! NBT, game audio and video middleware (`middleware`), 3D models (`models`)
//! and other engine data (`engine_data`).
//!
//! Retro consoles and computers live in [`super::retro`].

pub mod archives;
pub mod bethesda;
pub mod blizzard;
pub mod consoles;
pub mod engine_data;
pub mod engines;
pub mod middleware;
pub mod minecraft;
pub mod models;
pub mod nw4;
pub mod packages;
pub mod packfiles;
pub mod unity;
