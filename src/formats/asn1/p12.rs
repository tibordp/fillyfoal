//! PKCS#12 contents: the bags of a key store, decrypted with the password
//! (verified against the MAC), with certificates and keys embedded.

use super::der::{self, Tlv};
use super::pbe::{self, Failure, Password};
use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::{Input, embedded, embedded_as};
use crate::node::Node;
use crate::secret::{MAX_ATTEMPTS, SecretRequest};
use crate::span::{Origin, Span};

const DATA: &str = "1.2.840.113549.1.7.1";
const ENCRYPTED_DATA: &str = "1.2.840.113549.1.7.6";

/// A DER element: its header and where its content lies in `data`.
#[derive(Clone, Copy)]
struct El<'a> {
    tlv: Tlv,
    at: usize,
    content: &'a [u8],
}

/// The elements of `data` (relative offsets of their contents).
fn children(data: &[u8]) -> Vec<El<'_>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while let Some(rest) = data.get(pos..).filter(|r| !r.is_empty()) {
        let Some(tlv) = der::header(rest) else { break };
        let Some(len) = tlv.len.map(to_usize) else {
            break;
        };
        let at = pos.saturating_add(to_usize(tlv.header));
        let Some(content) = data.get(at..at.saturating_add(len)) else {
            break;
        };
        out.push(El { tlv, at, content });
        pos = at.saturating_add(len);
    }
    out
}

fn sub_el<'a>(parent: &El<'a>) -> Vec<El<'a>> {
    children(parent.content)
        .into_iter()
        .map(|e| El {
            at: parent.at.saturating_add(e.at),
            ..e
        })
        .collect()
}

fn oid(el: &El<'_>) -> Option<String> {
    (el.tlv.tag == 6).then(|| der::oid(el.content)).flatten()
}

/// A content type and its `[0]` content element.
fn content_info<'a>(el: &El<'a>) -> Option<(String, El<'a>)> {
    let parts = sub_el(el);
    let kind = oid(parts.first()?)?;
    let explicit = parts
        .get(1)
        .filter(|e| e.tlv.class == 2 && e.tlv.tag == 0)?;
    let inner = sub_el(explicit).into_iter().next()?;
    Some((kind, inner))
}

/// An encrypted part: algorithm content and ciphertext, with its offset.
struct Encrypted<'a> {
    alg: &'a [u8],
    data: &'a [u8],
    at: usize,
}

/// EncryptedData's EncryptedContentInfo.
fn encrypted_data<'a>(el: &El<'a>) -> Option<Encrypted<'a>> {
    let info = sub_el(el).into_iter().nth(1)?;
    let parts = sub_el(&info);
    let alg = parts.get(1)?;
    let body = parts.get(2)?;
    if body.tlv.class != 2 || body.tlv.constructed {
        return None; // constructed (BER) encryptedContent is not handled
    }
    Some(Encrypted {
        alg: alg.content,
        data: body.content,
        at: body.at,
    })
}

/// The password, if one works: free candidates first (checked with the MAC
/// or by a trial decryption), then the host.
async fn password(
    cx: &Cx,
    realm: Span,
    prompt: &str,
    check: &(dyn Fn(Password<'_>) -> bool + Sync),
) -> Option<(Vec<u8>, bool)> {
    for p in Password::FREE {
        if check(p) {
            return Some((Vec::new(), p.null));
        }
    }
    for attempt in 0..MAX_ATTEMPTS {
        let request = SecretRequest::password(realm, prompt, attempt);
        let secret = cx.secret(request).await?;
        let candidate = Password {
            text: secret.expose(),
            null: false,
        };
        if check(candidate) {
            return Some((secret.expose().to_vec(), false));
        }
    }
    None
}

/// The "Contents" node of a PKCS#12 file.
pub fn contents_node(input: Input) -> Node {
    Node::new("Contents")
        .desc("The bags of the key store: certificates and keys, decrypted with the password")
        .lazy(contents, input)
}

async fn contents(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let bytes = crate::codec::read_all(&cx, file).await?;
    let pfx = children(&bytes)
        .into_iter()
        .next()
        .ok_or_else(|| Diagnostic::malformed("not a PFX").at(file))?;
    let fields = sub_el(&pfx);
    let auth = fields
        .get(1)
        .ok_or_else(|| Diagnostic::malformed("PFX without authSafe").at(file))?;
    let (kind, octets) =
        content_info(auth).ok_or_else(|| Diagnostic::malformed("malformed authSafe").at(file))?;
    if kind != DATA {
        return Err(
            Diagnostic::unsupported("public-key integrity mode (signed authSafe)").at(file),
        );
    }
    let mac = fields.get(2).map(|m| m.content);
    let safes: Vec<El<'_>> = children(octets.content)
        .into_iter()
        .next()
        .map(|seq| {
            sub_el(&El {
                at: octets.at.saturating_add(seq.at),
                ..seq
            })
        })
        .unwrap_or_default();

    // The first encrypted thing, for checking passwords without a MAC.
    let probe: Option<(Vec<u8>, Vec<u8>)> = safes.iter().find_map(|ci| {
        let (kind, inner) = content_info(ci)?;
        (kind == ENCRYPTED_DATA)
            .then(|| encrypted_data(&inner))
            .flatten()
            .map(|e| (e.alg.to_vec(), e.data.to_vec()))
    });
    let check = |p: Password<'_>| match (mac, &probe) {
        (Some(mac), _) => pbe::verify_mac(mac, p, octets.content) == Some(true),
        (None, Some((alg, data))) => pbe::decrypt(alg, p, data).is_ok(),
        (None, None) => true,
    };
    let unlocked = password(&cx, file, "Password for the PKCS#12 key store", &check).await;
    let pw = unlocked
        .as_ref()
        .map(|(text, null)| Password { text, null: *null });
    if mac.is_some() && pw.is_some() {
        cx.annotate("MAC verified");
    }

    for ci in &safes {
        let Some((kind, inner)) = content_info(ci) else {
            continue;
        };
        if kind == DATA {
            let seq = children(inner.content).into_iter().next();
            if let Some(seq) = seq {
                let seq = El {
                    at: inner.at.saturating_add(seq.at),
                    ..seq
                };
                bags(&cx, input, file, &sub_el(&seq), pw).await?;
            }
        } else if kind == ENCRYPTED_DATA {
            let Some(enc) = encrypted_data(&inner) else {
                continue;
            };
            let span = file.sub(to_u64(enc.at), to_u64(enc.data.len()));
            let label = format!("Encrypted safe ({})", pbe::describe(enc.alg));
            let Some(p) = pw else {
                cx.emit(Node::new(label).span(span).diag(Diagnostic::unsupported(
                    "encrypted (no password, or a wrong one)",
                )));
                continue;
            };
            match pbe::decrypt(enc.alg, p, enc.data) {
                Ok(plain) => {
                    let decoded = cx.add_derived(
                        Origin {
                            parent: span,
                            transform: "pkcs12-decrypt",
                        },
                        plain,
                        span.len,
                        None,
                    )?;
                    let data = crate::codec::read_all(&cx, decoded.span).await?;
                    if let Some(seq) = children(&data).into_iter().next() {
                        bags(&cx, input, decoded.span, &sub_el(&seq), pw).await?;
                    }
                }
                Err(Failure::Unsupported(why)) => cx.emit(
                    Node::new(label)
                        .span(span)
                        .diag(Diagnostic::unsupported(why)),
                ),
                Err(Failure::Wrong) => cx.emit(
                    Node::new(label)
                        .span(span)
                        .diag(Diagnostic::malformed("decryption failed")),
                ),
            }
        } else {
            cx.emit(
                Node::new(format!("Content {kind}"))
                    .span(file.sub(to_u64(ci.at), to_u64(ci.content.len()))),
            );
        }
    }
    Ok(())
}

/// A bag's friendly name or local key ID, from its attributes.
fn bag_name(attributes: Option<&El<'_>>) -> Option<String> {
    let attributes = attributes?;
    let mut key_id = None;
    for attr in sub_el(attributes) {
        let parts = sub_el(&attr);
        let Some(kind) = parts.first().and_then(oid) else {
            continue;
        };
        let Some(value) = parts.get(1).and_then(|set| sub_el(set).into_iter().next()) else {
            continue;
        };
        match kind.as_str() {
            "1.2.840.113549.1.9.20" => {
                return Some(crate::text::utf16(
                    value.content,
                    crate::fields::Endian::Big,
                ));
            }
            "1.2.840.113549.1.9.21" => {
                key_id = Some(format!(
                    "key ID {}",
                    value
                        .content
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                ))
            }
            _ => {}
        }
    }
    key_id
}

/// Lists SafeBags (whose contents lie in `base`).
async fn bags(
    cx: &Cx,
    input: Input,
    base: Span,
    list: &[El<'_>],
    pw: Option<Password<'_>>,
) -> Result<()> {
    for bag in list {
        let parts = sub_el(bag);
        let Some(kind) = parts.first().and_then(oid) else {
            continue;
        };
        let Some(value) = parts.get(1).and_then(|v| sub_el(v).into_iter().next()) else {
            continue;
        };
        let name = bag_name(parts.get(2));
        let titled = |what: &str| match &name {
            Some(n) => format!("{what}: {n}"),
            None => what.to_owned(),
        };
        let whole = base.sub(
            to_u64(value.at.saturating_sub(to_usize(value.tlv.header))),
            to_u64(value.content.len()).saturating_add(value.tlv.header),
        );
        match kind.as_str() {
            "1.2.840.113549.1.12.10.1.3" => {
                // CertBag: certId, [0] { OCTET STRING cert }.
                let inner = sub_el(&value);
                let cert = inner.get(1).and_then(|e| sub_el(e).into_iter().next());
                match cert {
                    Some(cert) => {
                        cx.push(embedded_as(
                            titled("Certificate"),
                            input.nested(base.sub(to_u64(cert.at), to_u64(cert.content.len()))),
                            &super::X509,
                        ))
                        .await
                    }
                    None => cx.push(Node::new(titled("Certificate")).span(whole)).await,
                }
            }
            "1.2.840.113549.1.12.10.1.1" => {
                cx.push(embedded(titled("Private key"), input.nested(whole)))
                    .await
            }
            "1.2.840.113549.1.12.10.1.2" => {
                // EncryptedPrivateKeyInfo: AlgorithmIdentifier, OCTET STRING.
                let inner = sub_el(&value);
                let (Some(alg), Some(data)) = (inner.first(), inner.get(1)) else {
                    continue;
                };
                let span = base.sub(to_u64(data.at), to_u64(data.content.len()));
                let label = titled("Private key");
                let decrypted = pw.map(|p| pbe::decrypt(alg.content, p, data.content));
                match decrypted {
                    Some(Ok(plain)) => {
                        let decoded = cx.add_derived(
                            Origin {
                                parent: span,
                                transform: "pkcs8-decrypt",
                            },
                            plain,
                            span.len,
                            None,
                        )?;
                        cx.push(
                            embedded(label, input.nested(decoded.span))
                                .summary(format!("decrypted ({})", pbe::describe(alg.content))),
                        )
                        .await;
                    }
                    Some(Err(Failure::Unsupported(why))) => {
                        cx.push(
                            Node::new(label)
                                .span(span)
                                .diag(Diagnostic::unsupported(why)),
                        )
                        .await
                    }
                    Some(Err(Failure::Wrong)) => {
                        cx.push(
                            Node::new(label)
                                .span(span)
                                .diag(Diagnostic::malformed("decryption failed")),
                        )
                        .await
                    }
                    None => {
                        cx.push(Node::new(label).span(span).diag(Diagnostic::unsupported(
                            "encrypted (no password, or a wrong one)",
                        )))
                        .await
                    }
                }
            }
            "1.2.840.113549.1.12.10.1.6" => {
                let nested: Vec<El<'_>> = sub_el(&value);
                bags_boxed(cx, input, base, &nested, pw).await?;
            }
            other => {
                let what = match other {
                    "1.2.840.113549.1.12.10.1.4" => "CRL",
                    "1.2.840.113549.1.12.10.1.5" => "Secret",
                    _ => "Bag",
                };
                cx.push(Node::new(titled(what)).span(whole)).await;
            }
        }
    }
    Ok(())
}

/// `bags` for nested safe-contents bags (a boxed future breaks the
/// recursive type).
fn bags_boxed<'a>(
    cx: &'a Cx,
    input: Input,
    base: Span,
    list: &'a [El<'a>],
    pw: Option<Password<'a>>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
    Box::pin(bags(cx, input, base, list, pw))
}

/// The "Decrypted key" node of a standalone EncryptedPrivateKeyInfo.
pub fn decrypted_key_node(input: Input) -> Node {
    Node::new("Decrypted key").lazy(decrypted_key, input)
}

async fn decrypted_key(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let bytes = crate::codec::read_all(&cx, file).await?;
    let top = children(&bytes)
        .into_iter()
        .next()
        .ok_or_else(|| Diagnostic::malformed("not DER").at(file))?;
    let parts = sub_el(&top);
    let (Some(alg), Some(data)) = (parts.first(), parts.get(1)) else {
        return Err(Diagnostic::malformed("not an EncryptedPrivateKeyInfo").at(file));
    };
    let span = file.sub(to_u64(data.at), to_u64(data.content.len()));
    let check = |p: Password<'_>| pbe::decrypt(alg.content, p, data.content).is_ok();
    let Some((text, null)) = password(&cx, file, "Password for the private key", &check).await
    else {
        return Err(
            Diagnostic::unsupported("encrypted private key (no password, or a wrong one)").at(span),
        );
    };
    let plain = pbe::decrypt(alg.content, Password { text: &text, null }, data.content).map_err(
        |e| match e {
            Failure::Unsupported(why) => Diagnostic::unsupported(why).at(span),
            Failure::Wrong => Diagnostic::malformed("decryption failed").at(span),
        },
    )?;
    let decoded = cx.add_derived(
        Origin {
            parent: span,
            transform: "pkcs8-decrypt",
        },
        plain,
        span.len,
        None,
    )?;
    cx.annotate(format!("decrypted with {}", pbe::describe(alg.content)));
    crate::formats::dissect_or_data(cx, input.nested(decoded.span)).await
}
