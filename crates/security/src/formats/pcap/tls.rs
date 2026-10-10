//! TLS (and SSL 3.0) records in one TCP segment: the record layer, alerts,
//! change-cipher-spec, and handshake messages in the clear — ClientHello and
//! ServerHello with their extensions (server name, ALPN, supported versions
//! and groups, key shares, signature algorithms, …) and cipher suites by
//! name, Certificate messages with each certificate dissected as X.509,
//! ServerKeyExchange, ClientKeyExchange, NewSessionTicket. Encrypted records
//! (application data, TLS 1.3 handshake after ServerHello) stay opaque.
//! Records that continue past the segment are marked; streams are not
//! reassembled.

use super::dec::{Dec, Ix};
use crate::error::Diagnostic;
use crate::formats::util::fmt::size;
use crate::value::{EnumTable, lookup};

const CONTENT_TYPES: EnumTable = &[
    (20, "ChangeCipherSpec"),
    (21, "Alert"),
    (22, "Handshake"),
    (23, "Application Data"),
    (24, "Heartbeat"),
    (25, "tls12_cid"),
    (26, "ACK"),
];

const VERSIONS: EnumTable = &[
    (0x0300, "SSL 3.0"),
    (0x0301, "TLS 1.0"),
    (0x0302, "TLS 1.1"),
    (0x0303, "TLS 1.2"),
    (0x0304, "TLS 1.3"),
    (0x7f1c, "TLS 1.3 draft 28"),
    (0xfeff, "DTLS 1.0"),
    (0xfefd, "DTLS 1.2"),
    (0xfefc, "DTLS 1.3"),
];

const HANDSHAKE_TYPES: EnumTable = &[
    (0, "HelloRequest"),
    (1, "ClientHello"),
    (2, "ServerHello"),
    (3, "HelloVerifyRequest"),
    (4, "NewSessionTicket"),
    (5, "EndOfEarlyData"),
    (6, "HelloRetryRequest"),
    (8, "EncryptedExtensions"),
    (11, "Certificate"),
    (12, "ServerKeyExchange"),
    (13, "CertificateRequest"),
    (14, "ServerHelloDone"),
    (15, "CertificateVerify"),
    (16, "ClientKeyExchange"),
    (20, "Finished"),
    (21, "CertificateURL"),
    (22, "CertificateStatus"),
    (24, "KeyUpdate"),
    (25, "CompressedCertificate"),
    (254, "MessageHash"),
];

const ALERT_LEVELS: EnumTable = &[(1, "warning"), (2, "fatal")];

const ALERTS: EnumTable = &[
    (0, "close_notify"),
    (10, "unexpected_message"),
    (20, "bad_record_mac"),
    (21, "decryption_failed"),
    (22, "record_overflow"),
    (30, "decompression_failure"),
    (40, "handshake_failure"),
    (41, "no_certificate"),
    (42, "bad_certificate"),
    (43, "unsupported_certificate"),
    (44, "certificate_revoked"),
    (45, "certificate_expired"),
    (46, "certificate_unknown"),
    (47, "illegal_parameter"),
    (48, "unknown_ca"),
    (49, "access_denied"),
    (50, "decode_error"),
    (51, "decrypt_error"),
    (60, "export_restriction"),
    (70, "protocol_version"),
    (71, "insufficient_security"),
    (80, "internal_error"),
    (86, "inappropriate_fallback"),
    (90, "user_canceled"),
    (100, "no_renegotiation"),
    (109, "missing_extension"),
    (110, "unsupported_extension"),
    (111, "certificate_unobtainable"),
    (112, "unrecognized_name"),
    (113, "bad_certificate_status_response"),
    (114, "bad_certificate_hash_value"),
    (115, "unknown_psk_identity"),
    (116, "certificate_required"),
    (120, "no_application_protocol"),
    (121, "ech_required"),
];

pub const CIPHER_SUITES: EnumTable = &[
    (0x0000, "TLS_NULL_WITH_NULL_NULL"),
    (0x0001, "TLS_RSA_WITH_NULL_MD5"),
    (0x0002, "TLS_RSA_WITH_NULL_SHA"),
    (0x0004, "TLS_RSA_WITH_RC4_128_MD5"),
    (0x0005, "TLS_RSA_WITH_RC4_128_SHA"),
    (0x000a, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
    (0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"),
    (0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"),
    (0x002f, "TLS_RSA_WITH_AES_128_CBC_SHA"),
    (0x0032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"),
    (0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"),
    (0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA"),
    (0x0038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"),
    (0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"),
    (0x003c, "TLS_RSA_WITH_AES_128_CBC_SHA256"),
    (0x003d, "TLS_RSA_WITH_AES_256_CBC_SHA256"),
    (0x0040, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"),
    (0x0041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"),
    (0x0045, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"),
    (0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"),
    (0x006a, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"),
    (0x006b, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"),
    (0x0084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"),
    (0x0088, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"),
    (0x008c, "TLS_PSK_WITH_AES_128_CBC_SHA"),
    (0x008d, "TLS_PSK_WITH_AES_256_CBC_SHA"),
    (0x0096, "TLS_RSA_WITH_SEED_CBC_SHA"),
    (0x009c, "TLS_RSA_WITH_AES_128_GCM_SHA256"),
    (0x009d, "TLS_RSA_WITH_AES_256_GCM_SHA384"),
    (0x009e, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"),
    (0x009f, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"),
    (0x00a2, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"),
    (0x00a3, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"),
    (0x00a8, "TLS_PSK_WITH_AES_128_GCM_SHA256"),
    (0x00a9, "TLS_PSK_WITH_AES_256_GCM_SHA384"),
    (0x00aa, "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256"),
    (0x00ab, "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384"),
    (0x00ff, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"),
    (0x1301, "TLS_AES_128_GCM_SHA256"),
    (0x1302, "TLS_AES_256_GCM_SHA384"),
    (0x1303, "TLS_CHACHA20_POLY1305_SHA256"),
    (0x1304, "TLS_AES_128_CCM_SHA256"),
    (0x1305, "TLS_AES_128_CCM_8_SHA256"),
    (0x5600, "TLS_FALLBACK_SCSV"),
    (0xc008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"),
    (0xc009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"),
    (0xc00a, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"),
    (0xc012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"),
    (0xc013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"),
    (0xc014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"),
    (0xc023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"),
    (0xc024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"),
    (0xc027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"),
    (0xc028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"),
    (0xc02b, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"),
    (0xc02c, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
    (0xc02f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
    (0xc030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
    (0xc035, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA"),
    (0xc036, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA"),
    (0xc09c, "TLS_RSA_WITH_AES_128_CCM"),
    (0xc09d, "TLS_RSA_WITH_AES_256_CCM"),
    (0xc09e, "TLS_DHE_RSA_WITH_AES_128_CCM"),
    (0xc09f, "TLS_DHE_RSA_WITH_AES_256_CCM"),
    (0xc0ac, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"),
    (0xc0ad, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM"),
    (0xc0ae, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"),
    (0xc0af, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8"),
    (0xcca8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
    (0xcca9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"),
    (0xccaa, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
    (0xccab, "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256"),
    (0xccac, "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256"),
    (0xccad, "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256"),
];

const EXTENSIONS: EnumTable = &[
    (0, "server_name"),
    (1, "max_fragment_length"),
    (2, "client_certificate_url"),
    (3, "trusted_ca_keys"),
    (4, "truncated_hmac"),
    (5, "status_request"),
    (6, "user_mapping"),
    (7, "client_authz"),
    (8, "server_authz"),
    (9, "cert_type"),
    (10, "supported_groups"),
    (11, "ec_point_formats"),
    (12, "srp"),
    (13, "signature_algorithms"),
    (14, "use_srtp"),
    (15, "heartbeat"),
    (16, "application_layer_protocol_negotiation"),
    (17, "status_request_v2"),
    (18, "signed_certificate_timestamp"),
    (19, "client_certificate_type"),
    (20, "server_certificate_type"),
    (21, "padding"),
    (22, "encrypt_then_mac"),
    (23, "extended_master_secret"),
    (24, "token_binding"),
    (25, "cached_info"),
    (27, "compress_certificate"),
    (28, "record_size_limit"),
    (34, "delegated_credential"),
    (35, "session_ticket"),
    (41, "pre_shared_key"),
    (42, "early_data"),
    (43, "supported_versions"),
    (44, "cookie"),
    (45, "psk_key_exchange_modes"),
    (47, "certificate_authorities"),
    (48, "oid_filters"),
    (49, "post_handshake_auth"),
    (50, "signature_algorithms_cert"),
    (51, "key_share"),
    (52, "transparency_info"),
    (57, "quic_transport_parameters"),
    (17513, "application_settings (old)"),
    (17613, "application_settings"),
    (65037, "encrypted_client_hello"),
    (65281, "renegotiation_info"),
];

const GROUPS: EnumTable = &[
    (0x0015, "secp224r1"),
    (0x0016, "secp256k1"),
    (0x0017, "secp256r1"),
    (0x0018, "secp384r1"),
    (0x0019, "secp521r1"),
    (0x001a, "brainpoolP256r1"),
    (0x001b, "brainpoolP384r1"),
    (0x001c, "brainpoolP512r1"),
    (0x001d, "x25519"),
    (0x001e, "x448"),
    (0x001f, "brainpoolP256r1tls13"),
    (0x0020, "brainpoolP384r1tls13"),
    (0x0021, "brainpoolP512r1tls13"),
    (0x0029, "curveSM2"),
    (0x0100, "ffdhe2048"),
    (0x0101, "ffdhe3072"),
    (0x0102, "ffdhe4096"),
    (0x0103, "ffdhe6144"),
    (0x0104, "ffdhe8192"),
    (0x0200, "MLKEM512"),
    (0x0201, "MLKEM768"),
    (0x0202, "MLKEM1024"),
    (0x11eb, "SecP256r1MLKEM768"),
    (0x11ec, "X25519MLKEM768"),
    (0x11ed, "SecP384r1MLKEM1024"),
    (0x6399, "X25519Kyber768Draft00"),
];

const SIGNATURE_SCHEMES: EnumTable = &[
    (0x0201, "rsa_pkcs1_sha1"),
    (0x0202, "dsa_sha1"),
    (0x0203, "ecdsa_sha1"),
    (0x0301, "rsa_pkcs1_sha224"),
    (0x0302, "dsa_sha224"),
    (0x0303, "ecdsa_sha224"),
    (0x0401, "rsa_pkcs1_sha256"),
    (0x0402, "dsa_sha256"),
    (0x0403, "ecdsa_secp256r1_sha256"),
    (0x0501, "rsa_pkcs1_sha384"),
    (0x0502, "dsa_sha384"),
    (0x0503, "ecdsa_secp384r1_sha384"),
    (0x0601, "rsa_pkcs1_sha512"),
    (0x0602, "dsa_sha512"),
    (0x0603, "ecdsa_secp521r1_sha512"),
    (0x0804, "rsa_pss_rsae_sha256"),
    (0x0805, "rsa_pss_rsae_sha384"),
    (0x0806, "rsa_pss_rsae_sha512"),
    (0x0807, "ed25519"),
    (0x0808, "ed448"),
    (0x0809, "rsa_pss_pss_sha256"),
    (0x080a, "rsa_pss_pss_sha384"),
    (0x080b, "rsa_pss_pss_sha512"),
    (0x081a, "ecdsa_brainpoolP256r1tls13_sha256"),
    (0x081b, "ecdsa_brainpoolP384r1tls13_sha384"),
    (0x081c, "ecdsa_brainpoolP512r1tls13_sha512"),
    (0x0904, "mldsa44"),
    (0x0905, "mldsa65"),
    (0x0906, "mldsa87"),
];

const POINT_FORMATS: EnumTable = &[
    (0, "uncompressed"),
    (1, "ansiX962_compressed_prime"),
    (2, "ansiX962_compressed_char2"),
];

const PSK_MODES: EnumTable = &[(0, "psk_ke"), (1, "psk_dhe_ke")];

const CERT_COMPRESSION: EnumTable = &[(1, "zlib"), (2, "brotli"), (3, "zstd")];

/// The ServerHello random of a HelloRetryRequest (SHA-256 of
/// "HelloRetryRequest").
const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

fn is_grease(v: u64) -> bool {
    v & 0x0f0f == 0x0a0a && (v >> 8) == (v & 0xff)
}

/// A 16-bit enumerated field, marked when it is a GREASE value.
fn enum16(b: &mut Dec, p: Ix, label: &'static str, at: usize, v: u64, table: EnumTable) {
    b.add(p, label, at, 2, |x| {
        let x = x.value(crate::formats::util::val::enumv(v, 16, table));
        if is_grease(v) {
            x.summary("GREASE (reserved to exercise extensibility)")
        } else {
            x
        }
    });
}

fn name16(table: EnumTable, v: u64) -> String {
    if is_grease(v) {
        format!("GREASE {v:#06x}")
    } else {
        lookup(table, v).map_or_else(|| format!("{v:#06x}"), str::to_owned)
    }
}

/// Whether the bytes at `off` start a TLS record.
pub fn looks_like(b: &Dec, off: usize) -> bool {
    let ct = b.u8(off).unwrap_or(0);
    let major = b.u8(off.saturating_add(1)).unwrap_or(0);
    let minor = b.u8(off.saturating_add(2)).unwrap_or(0xff);
    let len = b.be16(off.saturating_add(3)).unwrap_or(0xffff);
    (20..=24).contains(&ct) && major == 3 && minor <= 4 && len <= 0x4800 && len > 0
}

/// TLS records from `off`; returns the end of what was accounted for.
pub fn records(b: &mut Dec, p: Ix, off: usize, end: usize) -> usize {
    let mut at = off;
    let mut names: Vec<String> = Vec::new();
    let mut encrypted = false;
    let mut version_seen = 0u16;
    while end.saturating_sub(at) >= 5 && looks_like(b, at) {
        let ct = b.u8(at).unwrap_or(0);
        let ver = b.be16(at.saturating_add(1)).unwrap_or(0);
        let len = usize::from(b.be16(at.saturating_add(3)).unwrap_or(0));
        let body = at.saturating_add(5);
        let rend = body.saturating_add(len);
        let shown_end = rend.min(end);
        let ctname = lookup(CONTENT_TYPES, ct.into()).unwrap_or("record");
        let ix = b.group(
            p,
            format!("TLS record: {ctname}"),
            at,
            shown_end.saturating_sub(at),
        );
        b.enm(ix, "Content type", at, 1, CONTENT_TYPES);
        b.enm(ix, "Version", at.saturating_add(1), 2, VERSIONS);
        b.num(ix, "Length", at.saturating_add(3), 2);
        let partial = rend > end;
        if partial {
            b.diag(
                ix,
                Diagnostic::note(format!(
                    "{} of {} in this segment; the rest follows in later segments (TCP reassembly is not implemented)",
                    size(shown_end.saturating_sub(body) as u64),
                    size(len as u64)
                )),
            );
        }
        let mut what: Vec<String> = Vec::new();
        match ct {
            20 => {
                b.num(ix, "Message", body, 1);
                encrypted = true;
                what.push("Change Cipher Spec".to_owned());
            }
            21 if len == 2 && !encrypted => {
                let lvl = b.enm(ix, "Level", body, 1, ALERT_LEVELS).unwrap_or(0);
                let d = b
                    .enm(ix, "Description", body.saturating_add(1), 1, ALERTS)
                    .unwrap_or(0);
                what.push(format!(
                    "Alert ({}, {})",
                    lookup(ALERT_LEVELS, lvl).unwrap_or("?"),
                    lookup(ALERTS, d).unwrap_or("?")
                ));
            }
            21 => {
                b.data(ix, "Encrypted alert", body, shown_end);
                what.push("Encrypted Alert".to_owned());
            }
            22 if !encrypted => {
                let mut m = body;
                let mut count = 0u32;
                while shown_end.saturating_sub(m) >= 4 && count < 64 {
                    let ht = b.u8(m).unwrap_or(0);
                    if lookup(HANDSHAKE_TYPES, ht.into()).is_none() {
                        break;
                    }
                    let mlen = usize::try_from(b.be32(m).unwrap_or(0) & 0x00ff_ffff).unwrap_or(0);
                    let (name, next) = handshake(b, ix, m, mlen, shown_end, &mut version_seen);
                    what.push(name);
                    if next <= m {
                        break;
                    }
                    m = next;
                    count = count.saturating_add(1);
                }
                if m == body && count == 0 {
                    b.data(ix, "Encrypted handshake message", body, shown_end);
                    what.push("Encrypted Handshake Message".to_owned());
                } else if m < shown_end {
                    b.data(ix, "Rest", m, shown_end);
                }
            }
            22 => {
                b.data(ix, "Encrypted handshake message", body, shown_end);
                what.push("Encrypted Handshake Message".to_owned());
            }
            23 => {
                b.data(ix, "Encrypted application data", body, shown_end);
                what.push("Application Data".to_owned());
            }
            _ => {
                b.data(ix, "Data", body, shown_end);
                what.push(ctname.to_owned());
            }
        }
        let vname = lookup(VERSIONS, ver.into()).unwrap_or("unknown version");
        let line = what.join(", ");
        let shown = format!(
            "{line}, {len} bytes, record version {vname}{}",
            if partial { " (continues)" } else { "" }
        );
        b.summary(ix, || shown);
        names.extend(what);
        at = shown_end;
        if partial {
            break;
        }
    }
    if at == off {
        return off;
    }
    let mut dedup: Vec<String> = Vec::new();
    for n in names {
        if dedup.last() != Some(&n) {
            dedup.push(n);
        }
    }
    b.set_info("TLS", || format!("TLS {}", dedup.join(", ")));
    at
}

/// One handshake message at `m`; returns its display name and end.
fn handshake(
    b: &mut Dec,
    p: Ix,
    m: usize,
    mlen: usize,
    end: usize,
    version: &mut u16,
) -> (String, usize) {
    let ht = b.u8(m).unwrap_or(0);
    let body = m.saturating_add(4);
    let mend = body.saturating_add(mlen);
    let shown_end = mend.min(end);
    let mut hname = lookup(HANDSHAKE_TYPES, ht.into())
        .unwrap_or("Handshake")
        .to_owned();
    let ix = b.group(p, hname.clone(), m, shown_end.saturating_sub(m));
    b.enm(ix, "Handshake type", m, 1, HANDSHAKE_TYPES);
    b.num(ix, "Length", m.saturating_add(1), 3);
    if mend > end {
        b.diag(
            ix,
            Diagnostic::note("the message continues in a later record or segment"),
        );
    }
    let mut detail = String::new();
    match ht {
        1 => detail = hello(b, ix, body, shown_end, true, version, &mut hname),
        2 => detail = hello(b, ix, body, shown_end, false, version, &mut hname),
        4 if *version != 0x0304 && mlen >= 6 => {
            let life = b.num(ix, "Ticket lifetime hint (s)", body, 4).unwrap_or(0);
            let tl = usize::from(b.be16(body.saturating_add(4)).unwrap_or(0));
            b.num(ix, "Ticket length", body.saturating_add(4), 2);
            b.raw(
                ix,
                "Ticket",
                body.saturating_add(6),
                tl.min(shown_end.saturating_sub(body.saturating_add(6))),
            );
            detail = format!("lifetime {life} s, {} ticket", size(tl as u64));
        }
        11 => detail = certificates(b, ix, body, shown_end),
        12 => detail = server_key_exchange(b, ix, body, shown_end),
        16 => {
            let first = usize::from(b.u8(body).unwrap_or(0));
            if first.saturating_add(1) == mlen {
                b.num(ix, "Public key length", body, 1);
                b.raw(ix, "Public key", body.saturating_add(1), first);
                detail = "ECDHE public key".to_owned();
            } else {
                let n = usize::from(b.be16(body).unwrap_or(0));
                b.num(ix, "Length", body, 2);
                b.raw(
                    ix,
                    "Encrypted premaster secret or DH public value",
                    body.saturating_add(2),
                    n,
                );
            }
        }
        15 => {
            b.enm(ix, "Signature algorithm", body, 2, SIGNATURE_SCHEMES);
            let n = usize::from(b.be16(body.saturating_add(2)).unwrap_or(0));
            b.num(ix, "Signature length", body.saturating_add(2), 2);
            b.raw(ix, "Signature", body.saturating_add(4), n);
        }
        20 => {
            b.raw(ix, "Verify data", body, shown_end.saturating_sub(body));
        }
        24 => {
            b.enm(
                ix,
                "Request update",
                body,
                1,
                &[(0, "update_not_requested"), (1, "update_requested")],
            );
        }
        14 | 0 | 5 => {}
        _ => {
            b.data(ix, "Body", body, shown_end);
        }
    }
    b.update(ix, |n| n.renamed(hname.clone()));
    if !detail.is_empty() {
        let shown = detail.clone();
        b.summary(ix, || shown);
    }
    let name = if detail.is_empty() || !matches!(ht, 1 | 2) {
        hname
    } else {
        format!("{hname} {detail}")
    };
    (name, shown_end)
}

/// ClientHello or ServerHello; returns the short Info detail.
fn hello(
    b: &mut Dec,
    p: Ix,
    off: usize,
    end: usize,
    client: bool,
    version: &mut u16,
    hname: &mut String,
) -> String {
    let legacy = b.enm(p, "Legacy version", off, 2, VERSIONS).unwrap_or(0);
    let rnd = off.saturating_add(2);
    if !client && b.bytes(rnd, 32) == Some(&HRR_RANDOM[..]) {
        *hname = "HelloRetryRequest".to_owned();
        b.raw(p, "Random", rnd, 32);
        b.tail(|n| n.summary("HelloRetryRequest marker"));
    } else {
        b.raw(p, "Random", rnd, 32);
    }
    let mut at = rnd.saturating_add(32);
    let sl = usize::from(b.u8(at).unwrap_or(0));
    b.num(p, "Session ID length", at, 1);
    if sl > 0 {
        b.raw(p, "Session ID", at.saturating_add(1), sl);
    }
    at = at.saturating_add(1).saturating_add(sl);
    let mut suite_name = String::new();
    if client {
        let cl = usize::from(b.be16(at).unwrap_or(0));
        let g = b.group(p, "Cipher suites", at, cl.saturating_add(2));
        b.num(g, "Length", at, 2);
        let mut c = at.saturating_add(2);
        let cend = c.saturating_add(cl).min(end);
        let mut n = 0u32;
        while c.saturating_add(2) <= cend {
            let v = u64::from(b.be16(c).unwrap_or(0));
            enum16(b, g, "Cipher suite", c, v, CIPHER_SUITES);
            c = c.saturating_add(2);
            n = n.saturating_add(1);
        }
        b.summary(g, || crate::formats::util::fmt::plural(n, "suite"));
        at = at.saturating_add(2).saturating_add(cl);
        let ml = usize::from(b.u8(at).unwrap_or(0));
        let g = b.group(p, "Compression methods", at, ml.saturating_add(1));
        b.num(g, "Length", at, 1);
        for i in 0..ml {
            b.enm(
                g,
                "Method",
                at.saturating_add(1).saturating_add(i),
                1,
                &[(0, "null"), (1, "DEFLATE")],
            );
        }
        at = at.saturating_add(1).saturating_add(ml);
    } else {
        let v = u64::from(b.be16(at).unwrap_or(0));
        suite_name = name16(CIPHER_SUITES, v);
        b.enm(p, "Cipher suite", at, 2, CIPHER_SUITES);
        b.enm(
            p,
            "Compression method",
            at.saturating_add(2),
            1,
            &[(0, "null"), (1, "DEFLATE")],
        );
        at = at.saturating_add(3);
    }
    let mut info = Info::default();
    if at.saturating_add(2) <= end {
        let el = usize::from(b.be16(at).unwrap_or(0));
        let eend = at.saturating_add(2).saturating_add(el).min(end);
        let g = b.group(p, "Extensions", at, eend.saturating_sub(at));
        b.num(g, "Length", at, 2);
        let mut e = at.saturating_add(2);
        let mut n = 0u32;
        while eend.saturating_sub(e) >= 4 && n < 256 {
            let t = u64::from(b.be16(e).unwrap_or(0));
            let len = usize::from(b.be16(e.saturating_add(2)).unwrap_or(0));
            let xend = e.saturating_add(4).saturating_add(len).min(eend);
            let label = name16(EXTENSIONS, t);
            let x = b.group(g, label, e, xend.saturating_sub(e));
            b.add(x, "Type", e, 2, |n| {
                n.value(crate::formats::util::val::enumv(t, 16, EXTENSIONS))
            });
            b.num(x, "Length", e.saturating_add(2), 2);
            let s = extension(b, x, t, e.saturating_add(4), xend, client, &mut info);
            if !s.is_empty() {
                b.summary(x, || s);
            }
            e = xend;
            n = n.saturating_add(1);
        }
        b.summary(g, || crate::formats::util::fmt::plural(n, "extension"));
    }
    let negotiated = info.version.unwrap_or(u16::try_from(legacy).unwrap_or(0));
    if !client {
        *version = negotiated;
    }
    let mut parts = Vec::new();
    if let Some(sni) = &info.sni {
        parts.push(format!("SNI={sni}"));
    }
    if !info.alpn.is_empty() {
        parts.push(format!("ALPN={}", info.alpn.join(",")));
    }
    if !client {
        parts.push(
            lookup(VERSIONS, negotiated.into())
                .unwrap_or("unknown version")
                .to_owned(),
        );
        parts.push(suite_name);
    }
    parts.join(" ")
}

#[derive(Default)]
struct Info {
    sni: Option<String>,
    alpn: Vec<String>,
    version: Option<u16>,
}

/// Decodes one extension's body; returns its one-line rendering.
fn extension(
    b: &mut Dec,
    x: Ix,
    t: u64,
    off: usize,
    end: usize,
    client: bool,
    info: &mut Info,
) -> String {
    let list16 = |b: &mut Dec, at: usize, label: &'static str, table: EnumTable| -> Vec<String> {
        let mut names = Vec::new();
        let mut a = at;
        while a.saturating_add(2) <= end {
            let v = u64::from(b.be16(a).unwrap_or(0));
            names.push(name16(table, v));
            enum16(b, x, label, a, v, table);
            a = a.saturating_add(2);
        }
        names
    };
    match t {
        0 if client => {
            b.num(x, "Server name list length", off, 2);
            let mut a = off.saturating_add(2);
            let mut names = Vec::new();
            while end.saturating_sub(a) >= 3 {
                b.enm(x, "Name type", a, 1, &[(0, "host_name")]);
                let n = usize::from(b.be16(a.saturating_add(1)).unwrap_or(0));
                b.num(x, "Name length", a.saturating_add(1), 2);
                let s = String::from_utf8_lossy(
                    b.range(a.saturating_add(3), a.saturating_add(3).saturating_add(n)),
                )
                .into_owned();
                let shown = s.clone();
                b.text(x, "Server name", a.saturating_add(3), n, || shown);
                names.push(s);
                a = a.saturating_add(3).saturating_add(n);
            }
            info.sni = names.first().cloned();
            names.join(", ")
        }
        10 => {
            b.num(x, "Length", off, 2);
            list16(b, off.saturating_add(2), "Group", GROUPS).join(", ")
        }
        13 | 50 => {
            b.num(x, "Length", off, 2);
            list16(
                b,
                off.saturating_add(2),
                "Signature scheme",
                SIGNATURE_SCHEMES,
            )
            .join(", ")
        }
        11 => {
            let n = usize::from(b.u8(off).unwrap_or(0));
            b.num(x, "Length", off, 1);
            let mut names = Vec::new();
            for i in 0..n {
                let v = b
                    .enm(
                        x,
                        "Point format",
                        off.saturating_add(1).saturating_add(i),
                        1,
                        POINT_FORMATS,
                    )
                    .unwrap_or(0);
                names.push(lookup(POINT_FORMATS, v).unwrap_or("?").to_owned());
            }
            names.join(", ")
        }
        16 => {
            b.num(x, "ALPN extension length", off, 2);
            let mut a = off.saturating_add(2);
            let mut ids = Vec::new();
            while a < end {
                let n = usize::from(b.u8(a).unwrap_or(0));
                let s = String::from_utf8_lossy(
                    b.range(a.saturating_add(1), a.saturating_add(1).saturating_add(n)),
                )
                .into_owned();
                let shown = s.clone();
                b.text(x, "Protocol", a, n.saturating_add(1), || shown);
                ids.push(s);
                a = a.saturating_add(1).saturating_add(n);
            }
            info.alpn = ids.clone();
            ids.join(", ")
        }
        43 if client => {
            b.num(x, "Length", off, 1);
            list16(b, off.saturating_add(1), "Version", VERSIONS).join(", ")
        }
        43 => {
            let v = b.enm(x, "Selected version", off, 2, VERSIONS).unwrap_or(0);
            info.version = u16::try_from(v).ok();
            lookup(VERSIONS, v).unwrap_or("?").to_owned()
        }
        51 => {
            let mut a = off;
            if client {
                b.num(x, "Client key share length", off, 2);
                a = a.saturating_add(2);
            }
            let mut groups = Vec::new();
            while end.saturating_sub(a) >= 2 {
                let g = u64::from(b.be16(a).unwrap_or(0));
                let gname = name16(GROUPS, g);
                if end.saturating_sub(a) < 4 {
                    // HelloRetryRequest: the selected group only.
                    b.add(x, "Selected group", a, 2, |n| {
                        n.value(crate::formats::util::val::enumv(g, 16, GROUPS))
                    });
                    groups.push(gname);
                    break;
                }
                let kl = usize::from(b.be16(a.saturating_add(2)).unwrap_or(0));
                let e = b.group(x, "Key share entry", a, kl.saturating_add(4));
                enum16(b, e, "Group", a, g, GROUPS);
                b.num(e, "Key exchange length", a.saturating_add(2), 2);
                b.raw(e, "Key exchange", a.saturating_add(4), kl);
                let shown = format!("{gname}, {}", size(kl as u64));
                b.summary(e, || shown);
                groups.push(gname);
                a = a.saturating_add(4).saturating_add(kl);
            }
            groups.join(", ")
        }
        45 => {
            let n = usize::from(b.u8(off).unwrap_or(0));
            b.num(x, "Length", off, 1);
            let mut names = Vec::new();
            for i in 0..n {
                let v = b
                    .enm(
                        x,
                        "Mode",
                        off.saturating_add(1).saturating_add(i),
                        1,
                        PSK_MODES,
                    )
                    .unwrap_or(0);
                names.push(lookup(PSK_MODES, v).unwrap_or("?").to_owned());
            }
            names.join(", ")
        }
        27 => {
            b.num(x, "Length", off, 1);
            let mut names = Vec::new();
            let mut a = off.saturating_add(1);
            while a.saturating_add(2) <= end {
                let v = b.enm(x, "Algorithm", a, 2, CERT_COMPRESSION).unwrap_or(0);
                names.push(lookup(CERT_COMPRESSION, v).unwrap_or("?").to_owned());
                a = a.saturating_add(2);
            }
            names.join(", ")
        }
        28 if end.saturating_sub(off) == 2 => b
            .num(x, "Record size limit", off, 2)
            .unwrap_or(0)
            .to_string(),
        1 if end.saturating_sub(off) == 1 => {
            let v = b.num(x, "Maximum fragment length", off, 1).unwrap_or(0);
            match v {
                1..=4 => format!("{} bytes", 256u64 << v),
                _ => v.to_string(),
            }
        }
        65281 => {
            let n = usize::from(b.u8(off).unwrap_or(0));
            b.num(x, "Renegotiation info length", off, 1);
            if n > 0 {
                b.raw(x, "Renegotiated connection", off.saturating_add(1), n);
            }
            if n == 0 {
                "initial handshake".to_owned()
            } else {
                "renegotiation".to_owned()
            }
        }
        21 => {
            b.data(x, "Padding", off, end);
            size(end.saturating_sub(off) as u64)
        }
        5 if client && end.saturating_sub(off) >= 5 => {
            b.enm(x, "Certificate status type", off, 1, &[(1, "ocsp")]);
            let rl = usize::from(b.be16(off.saturating_add(1)).unwrap_or(0));
            b.num(x, "Responder ID list length", off.saturating_add(1), 2);
            b.raw(x, "Responder IDs", off.saturating_add(3), rl);
            let at = off.saturating_add(3).saturating_add(rl);
            b.num(x, "Request extensions length", at, 2);
            b.data(x, "Request extensions", at.saturating_add(2), end);
            "OCSP".to_owned()
        }
        41 if !client && end.saturating_sub(off) == 2 => {
            let v = b.num(x, "Selected identity", off, 2).unwrap_or(0);
            format!("identity {v}")
        }
        _ if off < end => {
            b.raw(x, "Data", off, end.saturating_sub(off));
            size(end.saturating_sub(off) as u64)
        }
        _ => String::new(),
    }
}

/// A Certificate message: TLS 1.2 (a list of certificates) or TLS 1.3 (a
/// request context, then entries with extensions).
fn certificates(b: &mut Dec, p: Ix, off: usize, end: usize) -> String {
    let len = end.saturating_sub(off);
    let mut at = off;
    let ctx = usize::from(b.u8(off).unwrap_or(0));
    let tls13 = b
        .uint(off.saturating_add(1).saturating_add(ctx), 3)
        .is_some_and(|l| {
            usize::try_from(l).unwrap_or(0) == len.saturating_sub(4).saturating_sub(ctx)
        });
    if tls13 {
        b.num(p, "Request context length", at, 1);
        if ctx > 0 {
            b.raw(p, "Request context", at.saturating_add(1), ctx);
        }
        at = at.saturating_add(1).saturating_add(ctx);
    }
    let total = usize::try_from(b.uint(at, 3).unwrap_or(0)).unwrap_or(0);
    b.num(p, "Certificates length", at, 3);
    at = at.saturating_add(3);
    let cend = at.saturating_add(total).min(end);
    let mut n = 0u32;
    while cend.saturating_sub(at) >= 3 && n < 64 {
        let cl = usize::try_from(b.uint(at, 3).unwrap_or(0)).unwrap_or(0);
        let start = at.saturating_add(3);
        let stop = start.saturating_add(cl);
        let g = b.group(
            p,
            format!("Certificate {n}"),
            at,
            stop.min(cend).saturating_sub(at),
        );
        b.num(g, "Length", at, 3);
        if stop <= cend && b.complete {
            let span = b.sp(start, cl);
            let node = crate::formats::embedded_as(
                "X.509 certificate",
                b.input.nested(span),
                &crate::formats::asn1::X509,
            );
            b.add(g, "X.509 certificate", start, cl, |_| node);
        } else {
            b.data(g, "Certificate (incomplete)", start, stop.min(cend));
        }
        at = stop;
        if tls13 && cend.saturating_sub(at) >= 2 {
            let el = usize::from(b.be16(at).unwrap_or(0));
            b.num(g, "Extensions length", at, 2);
            b.data(
                g,
                "Extensions",
                at.saturating_add(2),
                at.saturating_add(2).saturating_add(el).min(cend),
            );
            at = at.saturating_add(2).saturating_add(el);
        }
        let span = b.sp(
            start.saturating_sub(3),
            at.min(cend).saturating_sub(start.saturating_sub(3)),
        );
        b.update(g, |x| x.span(span));
        b.summary(g, || size(cl as u64));
        n = n.saturating_add(1);
    }
    crate::formats::util::fmt::plural(n, "certificate")
}

fn server_key_exchange(b: &mut Dec, p: Ix, off: usize, end: usize) -> String {
    if b.u8(off) != Some(3) {
        // DHE or RSA export parameters: not decoded.
        b.data(p, "Parameters", off, end);
        return String::new();
    }
    b.enm(
        p,
        "Curve type",
        off,
        1,
        &[
            (1, "explicit_prime"),
            (2, "explicit_char2"),
            (3, "named_curve"),
        ],
    );
    let g = b
        .enm(p, "Named curve", off.saturating_add(1), 2, GROUPS)
        .unwrap_or(0);
    let kl = usize::from(b.u8(off.saturating_add(3)).unwrap_or(0));
    b.num(p, "Public key length", off.saturating_add(3), 1);
    b.raw(p, "Public key", off.saturating_add(4), kl);
    let mut at = off.saturating_add(4).saturating_add(kl);
    if end.saturating_sub(at) >= 4 {
        b.enm(p, "Signature algorithm", at, 2, SIGNATURE_SCHEMES);
        let sl = usize::from(b.be16(at.saturating_add(2)).unwrap_or(0));
        b.num(p, "Signature length", at.saturating_add(2), 2);
        b.raw(p, "Signature", at.saturating_add(4), sl);
        at = at.saturating_add(4).saturating_add(sl);
    }
    b.data(p, "Rest", at, end);
    format!("ECDHE {}", lookup(GROUPS, g).unwrap_or("unknown curve"))
}
