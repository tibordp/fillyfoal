//! Mobile platform artifacts: Apple (NIB archives, Metal libraries, asset
//! catalogs, code signatures, Xcode and crash-report text files) and Android
//! (dynamic partitions, vendor boot images, bootloader bundles, ART
//! profiles, heap dumps, logs).

pub mod android;
pub mod android_text;
pub mod apple;
pub mod apple_text;
