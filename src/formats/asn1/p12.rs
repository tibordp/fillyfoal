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

/// The elements of a buffer, read one at a time (so taking the first few
/// of a long list costs nothing for the rest). Offsets are relative to
/// `base`.
struct Children<'a> {
    data: &'a [u8],
    pos: usize,
    base: usize,
}

impl<'a> Iterator for Children<'a> {
    type Item = El<'a>;

    fn next(&mut self) -> Option<El<'a>> {
        let el = self.element();
        if el.is_none() {
            self.pos = self.data.len();
        }
        el
    }
}

impl<'a> Children<'a> {
    fn element(&mut self) -> Option<El<'a>> {
        let rest = self.data.get(self.pos..).filter(|r| !r.is_empty())?;
        let tlv = der::header(rest)?;
        let len = tlv.len.map(to_usize)?;
        let at = self.pos.saturating_add(to_usize(tlv.header));
        let content = self.data.get(at..at.saturating_add(len))?;
        self.pos = at.saturating_add(len);
        Some(El {
            tlv,
            at: self.base.saturating_add(at),
            content,
        })
    }
}

/// The elements of `data` (relative offsets of their contents).
fn children(data: &[u8]) -> Children<'_> {
    Children {
        data,
        pos: 0,
        base: 0,
    }
}

fn sub_el<'a>(parent: &El<'a>) -> Children<'a> {
    Children {
        data: parent.content,
        pos: 0,
        base: parent.at,
    }
}

fn oid(el: &El<'_>) -> Option<String> {
    (el.tlv.tag == 6).then(|| der::oid(el.content)).flatten()
}

/// A content type and its `[0]` content element.
fn content_info<'a>(el: &El<'a>) -> Option<(String, El<'a>)> {
    let mut parts = sub_el(el);
    let kind = oid(&parts.next()?)?;
    let explicit = parts
        .next()
        .filter(|e| e.tlv.class == 2 && e.tlv.tag == 0)?;
    let inner = sub_el(&explicit).next()?;
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
    let info = sub_el(el).nth(1)?;
    let parts: Vec<El<'_>> = sub_el(&info).take(3).collect();
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

/// How a password candidate is checked (the key derivation is expensive,
/// so checks run in budgeted steps).
enum Check<'a> {
    /// Against the PKCS#12 MAC (MacData's content) over the authSafe bytes.
    Mac { mac: &'a [u8], data: &'a [u8] },
    /// By a trial decryption with this algorithm.
    Decrypt { alg: &'a [u8], data: &'a [u8] },
    /// Nothing to check against: anything goes.
    Nothing,
}

impl Check<'_> {
    async fn accepts(&self, cx: &Cx, p: Password<'_>) -> bool {
        match *self {
            Check::Mac { mac, data } => pbe::verify_mac(cx, mac, p, data).await == Some(true),
            Check::Decrypt { alg, data } => pbe::decrypt(cx, alg, p, data).await.is_ok(),
            Check::Nothing => true,
        }
    }
}

/// The password, if one works: free candidates first (checked with the MAC
/// or by a trial decryption), then the host.
async fn password(
    cx: &Cx,
    realm: Span,
    prompt: &str,
    check: &Check<'_>,
) -> Option<(Vec<u8>, bool)> {
    for p in Password::FREE {
        if check.accepts(cx, p).await {
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
        if check.accepts(cx, candidate).await {
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
        .next()
        .ok_or_else(|| Diagnostic::malformed("not a PFX").at(file))?;
    let fields: Vec<El<'_>> = sub_el(&pfx).take(3).collect();
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
    let safe_list = children(octets.content).next().map(|seq| El {
        at: octets.at.saturating_add(seq.at),
        ..seq
    });
    let safes = || safe_list.as_ref().map(sub_el).into_iter().flatten();

    // The first encrypted thing, for checking passwords without a MAC.
    let mut probe: Option<Encrypted<'_>> = None;
    if mac.is_none() {
        for ci in safes() {
            cx.checkpoint().await;
            if let Some((kind, inner)) = content_info(&ci)
                && kind == ENCRYPTED_DATA
                && let Some(e) = encrypted_data(&inner)
            {
                probe = Some(e);
                break;
            }
        }
    }
    let check = match (mac, &probe) {
        (Some(mac), _) => Check::Mac {
            mac,
            data: octets.content,
        },
        (None, Some(e)) => Check::Decrypt {
            alg: e.alg,
            data: e.data,
        },
        (None, None) => Check::Nothing,
    };
    let unlocked = password(&cx, file, "Password for the PKCS#12 key store", &check).await;
    let pw = unlocked
        .as_ref()
        .map(|(text, null)| Password { text, null: *null });
    if mac.is_some() && pw.is_some() {
        cx.annotate("MAC verified");
    }

    for ci in safes() {
        cx.checkpoint().await;
        let Some((kind, inner)) = content_info(&ci) else {
            continue;
        };
        if kind == DATA {
            let seq = children(inner.content).next();
            if let Some(seq) = seq {
                let seq = El {
                    at: inner.at.saturating_add(seq.at),
                    ..seq
                };
                bags(&cx, input, file, sub_el(&seq), pw).await?;
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
            match pbe::decrypt(&cx, enc.alg, p, enc.data).await {
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
                    if let Some(seq) = children(&data).next() {
                        bags(&cx, input, decoded.span, sub_el(&seq), pw).await?;
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
async fn bag_name(cx: &Cx, attributes: Option<&El<'_>>) -> Option<String> {
    let attributes = attributes?;
    let mut key_id = None;
    for (i, attr) in sub_el(attributes).enumerate() {
        if i % 64 == 63 {
            cx.checkpoint().await;
        }
        let mut parts = sub_el(&attr);
        let Some(kind) = parts.next().as_ref().and_then(oid) else {
            continue;
        };
        let Some(value) = parts.next().and_then(|set| sub_el(&set).next()) else {
            continue;
        };
        match kind.as_str() {
            "1.2.840.113549.1.9.20" => return Some(utf16_be_paced(cx, value.content).await),
            "1.2.840.113549.1.9.21" => {
                let mut hex = String::from("key ID ");
                for piece in value.content.chunks(TEXT_PIECE) {
                    for b in piece {
                        hex.push_str(&format!("{b:02x}"));
                    }
                    cx.checkpoint().await;
                }
                key_id = Some(hex);
            }
            _ => {}
        }
    }
    key_id
}

/// Bytes of an attribute decoded per unit of work.
const TEXT_PIECE: usize = 1024;

/// UTF-16BE text, decoded a piece at a time (never splitting a surrogate
/// pair, so the result is that of decoding it whole).
async fn utf16_be_paced(cx: &Cx, data: &[u8]) -> String {
    let mut out = String::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let mut end = data.len();
        if end.saturating_sub(pos) > TEXT_PIECE {
            end = pos.saturating_add(TEXT_PIECE);
            // Keep a high surrogate with its partner.
            if data
                .get(end.saturating_sub(2))
                .is_some_and(|&b| b & 0xfc == 0xd8)
            {
                end = end.saturating_sub(2);
            }
            cx.checkpoint().await;
        }
        out.push_str(&crate::text::utf16(
            data.get(pos..end).unwrap_or_default(),
            crate::fields::Endian::Big,
        ));
        pos = end;
    }
    out
}

/// Lists SafeBags (whose contents lie in `base`).
async fn bags(
    cx: &Cx,
    input: Input,
    base: Span,
    list: Children<'_>,
    pw: Option<Password<'_>>,
) -> Result<()> {
    for bag in list {
        cx.checkpoint().await;
        let parts: Vec<El<'_>> = sub_el(&bag).take(3).collect();
        let Some(kind) = parts.first().and_then(oid) else {
            continue;
        };
        let Some(value) = parts.get(1).and_then(|v| sub_el(v).next()) else {
            continue;
        };
        let name = bag_name(cx, parts.get(2)).await;
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
                let inner: Vec<El<'_>> = sub_el(&value).take(2).collect();
                let cert = inner.get(1).and_then(|e| sub_el(e).next());
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
                let inner: Vec<El<'_>> = sub_el(&value).take(2).collect();
                let (Some(alg), Some(data)) = (inner.first(), inner.get(1)) else {
                    continue;
                };
                let span = base.sub(to_u64(data.at), to_u64(data.content.len()));
                let label = titled("Private key");
                let decrypted = match pw {
                    Some(p) => Some(pbe::decrypt(cx, alg.content, p, data.content).await),
                    None => None,
                };
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
                let nested = sub_el(&value);
                bags_boxed(cx, input, base, nested, pw).await?;
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
    list: Children<'a>,
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
        .next()
        .ok_or_else(|| Diagnostic::malformed("not DER").at(file))?;
    let parts: Vec<El<'_>> = sub_el(&top).take(2).collect();
    let (Some(alg), Some(data)) = (parts.first(), parts.get(1)) else {
        return Err(Diagnostic::malformed("not an EncryptedPrivateKeyInfo").at(file));
    };
    let span = file.sub(to_u64(data.at), to_u64(data.content.len()));
    let check = Check::Decrypt {
        alg: alg.content,
        data: data.content,
    };
    let Some((text, null)) = password(&cx, file, "Password for the private key", &check).await
    else {
        return Err(
            Diagnostic::unsupported("encrypted private key (no password, or a wrong one)").at(span),
        );
    };
    let plain = pbe::decrypt(
        &cx,
        alg.content,
        Password { text: &text, null },
        data.content,
    )
    .await
    .map_err(|e| match e {
        Failure::Unsupported(why) => Diagnostic::unsupported(why).at(span),
        Failure::Wrong => Diagnostic::malformed("decryption failed").at(span),
    })?;
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
