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
        "Image digest: 5e075bef544c60d87f4ee42a850708c55d9f56865050ff2e71de42c431102ec2 (SHA-256, valid)",
    );
    assert_has(&t, "Signer's messageDigest");
    assert_has(&t, "Signer's messageDigest: ");
    assert!(!t.contains("mismatch"), "{t}");
}

#[test]
fn authenticode_detects_a_changed_image() {
    let (name, mut data) = external("pe/fixture_hello_x64_signed.exe");
    // A byte of .text, covered by the signed digest.
    data[0x500] ^= 1;
    let t = common::explore_full_as(&name, &data, None);
    assert_has(&t, "— the image was changed after signing");
    assert_has(&t, "SHA-256 mismatch");
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

/// The bytes of every node named `name` in the fully explored tree of an
/// external fixture, in tree order (derived sources included).
fn node_bytes(path: &str, name: &str) -> Vec<Vec<u8>> {
    let (file, data) = external(path);
    let mut host = common::Host::named(&file, data.clone(), fillyfoal::Limits::default());
    host.explore_all();
    let mut out = Vec::new();
    let mut stack = vec![host.root];
    let mut order = Vec::new();
    while let Some(id) = stack.pop() {
        order.push(id);
        let children = host.session.children(id).unwrap();
        stack.extend(children.ids.iter().rev().copied());
    }
    for id in order {
        let node = host.session.node(id).unwrap();
        if node.name != name {
            continue;
        }
        let span = node.span.unwrap();
        let bytes = match host.session.derived_data(span.source) {
            Some(d) => d[span.offset as usize..(span.offset + span.len) as usize].to_vec(),
            None => data[span.offset as usize..(span.offset + span.len) as usize].to_vec(),
        };
        out.push(bytes);
    }
    out
}

/// OpenMPT saved the same song with and without IT sample compression:
/// decompressing the IT 2.14 (`.it`) and IT 2.15 (`.mptm`) blocks gives
/// the uncompressed file's signed PCM exactly.
#[test]
fn it_compressed_samples_decode_to_the_uncompressed_pcm() {
    let plain = node_bytes("it/fillyfoal-uncompressed.it", "Sample data");
    assert_eq!(plain.iter().map(Vec::len).collect::<Vec<_>>(), [256, 512]);
    for path in [
        "it/fillyfoal-compressed.it",
        "it/fillyfoal-compat-compressed.it",
        "it/fillyfoal.mptm",
    ] {
        assert_eq!(node_bytes(path, "PCM"), plain, "{path}");
    }
}

/// Inno Setup 6.3 to 7.1 (the PE snapshots elide the installer data):
/// each version's header, settings and file entries parse, and the files'
/// hashes in the location entries match their decompressed content.
#[test]
fn inno_setup_layouts_from_6_3_to_7_1() {
    for (file, data_version, hash) in [
        ("6.3.3", "6.3.0", "SHA-1"),
        ("6.4.3", "6.4.3", "SHA-256"),
        ("6.5.4", "6.5.2", "SHA-256"),
        ("6.6.1", "6.6.1", "SHA-256"),
        ("6.7.3", "6.7.0", "SHA-256"),
        ("7.1.0", "7.0.0.3", "SHA-256"),
    ] {
        let t = tree(&format!("pe/inno-setup-{file}.exe"));
        assert_has(
            &t,
            &format!(
                "Inno Setup installer — Inno Setup {data_version} (Unicode), fillyfoal test 1.0.0, LZMA2, 3 files"
            ),
        );
        assert_has(&t, "PrivilegesRequired: lowest (0x3)");
        assert_has(&t, "DestName: \"{app}\\\\readme.txt\"");
        let checks = t.matches(&format!("({hash}, valid)")).count();
        assert!(checks >= 2, "{file}: {checks} {hash} checks\n{t}");
        for bad in [
            "CRC mismatch",
            "cannot parse",
            "not the size we expect",
            "fixed fields of an unexpected size",
        ] {
            assert!(!t.contains(bad), "{file}: {bad}\n{t}");
        }
        if file >= "6.5" {
            assert_has(&t, "EncryptionUse: none (0x0)");
            assert_has(&t, "KDFIterations: 220000");
        }
    }
    let t = tree("pe/inno-setup-7.1.0.exe");
    assert_has(&t, "CompiledCodeVersion: 0x7010000 — 7.1.0.0");
    assert_has(&t, "ArchitecturesAllowed: \"x86compatible\"");
    assert_has(&t, "Bitness: current process (0x4)");
}
