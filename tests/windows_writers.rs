//! Details of the fixtures written by Windows-only tools (MSVC, signtool,
//! Inno Setup, OpenMPT) that their snapshots elide or that need a
//! modified copy: each test explores a fixture completely and checks the
//! decoded values against the reference tools' output recorded in
//! `tests/fixtures/external/SOURCES.md`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use std::path::Path;

fn external(path: &str) -> (String, Vec<u8>) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/external")
        .join(path);
    (common::fixture_name(&path), common::fixture_bytes(&path))
}

/// The whole explored tree of an external fixture, rendered.
fn tree(path: &str) -> String {
    let (name, data) = external(path);
    common::explore_full_as(&name, &data, None)
}

fn assert_has(tree: &str, needle: &str) {
    assert!(tree.contains(needle), "missing {needle:?} in\n{tree}");
}

#[test]
fn authenticode_digest_is_recomputed() {
    let t = tree("pe/fixture_hello_x64_signed.exe");
    assert_has(
        &t,
        "Computed digest: \"5E075BEF544C60D87F4EE42A850708C55D9F56865050FF2E71DE42C431102EC2\" — matches",
    );
    assert_has(&t, "Signer's messageDigest");
    assert_has(&t, "— matches SpcIndirectDataContent");
}

#[test]
fn authenticode_detects_a_changed_image() {
    let (name, mut data) = external("pe/fixture_hello_x64_signed.exe");
    // A byte of .text, covered by the signed digest.
    data[0x500] ^= 1;
    let t = common::explore_full_as(&name, &data, None);
    assert_has(&t, "— differs");
    assert_has(&t, "Authenticode digest mismatch");
}

#[test]
fn arm64x_fixups_name_the_header_fields_they_rewrite() {
    let t = tree("pe/fixture_lib_arm64x.dll");
    assert_has(&t, "PE32+ ARM64X DLL");
    assert_has(&t, "FileHeader.Machine: set 2 bytes to 0x8664");
    assert_has(&t, "AddressOfEntryPoint: set 4 bytes to 0x11050");
    assert_has(&t, "Export Table.VirtualAddress: set 4 bytes to 0x15580");
    assert_has(&t, "x64 Function Table — 3 functions");
    assert_has(&t, "Redirection Metadata — 6 redirections");
}

#[test]
fn arm64ec_image_is_named_and_its_arm64_table_decoded() {
    let t = tree("pe/fixture_hello_arm64ec.exe");
    assert_has(&t, "PE32+ ARM64EC EXE");
    assert_has(&t, "ARM64 Function Table — 300 functions");
    assert_has(&t, "Code Ranges to Entry Points — 1 range");
}

#[test]
fn fastlink_pdb_stand_ins_are_decoded() {
    let t = tree("pdb/fixture_hello_x64_fastlink.pdb.raw.zst");
    assert_has(&t, "/DEBUG:FASTLINK");
    assert_has(&t, "S_FASTLINK: \"FILE\" — type 0x1013");
    assert_has(&t, "S_FASTLINK: \"main\" — function");
    assert_has(&t, "S_FASTLINK: \"fillyfoal_banner\" — static data");
    assert_has(&t, "DEBUG_S_COFF_SYMBOL_RVA — 2 RVAs");
}

#[test]
fn type_server_object_names_the_compiler_pdb() {
    let t = tree("coff/fixture_hello_fastlink.obj");
    assert_has(
        &t,
        "LF_TYPESERVER2 — \"C:\\\\fillyfoal\\\\src\\\\fixture_hello_fastlink_cc.pdb\" {5fd1a816-2767-4628-ae8f-26592e1676d6}",
    );
    let t = tree("pdb/fixture_hello_fastlink_cc.pdb.raw.zst");
    assert_has(&t, "GUID {5fd1a816-2767-4628-ae8f-26592e1676d6}");
    assert_has(&t, "types only (compiler PDB)");
}
