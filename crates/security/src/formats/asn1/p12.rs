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
use std::borrow::Cow;

const DATA: &str = "1.2.840.113549.1.7.1";
const ENCRYPTED_DATA: &str = "1.2.840.113549.1.7.6";

/// A BER element: its header and where its content lies in `data` (for
/// the indefinite form, the content before the end-of-contents octets).
#[derive(Clone, Copy)]
struct El<'a> {
    tlv: Tlv,
    at: usize,
    content: &'a [u8],
}

/// The elements of a buffer, read one at a time (so taking the first few
/// of a long list costs nothing for the rest). Offsets are relative to
/// `base`. Indefinite lengths (NSS writes them throughout) are resolved by
/// walking to the matching end-of-contents.
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
        if tlv.id == 0 {
            return None; // end-of-contents
        }
        let header = to_usize(tlv.header);
        let (len, eoc) = match tlv.len {
            Some(len) => (to_usize(len), 0),
            None => (indefinite_len(rest.get(header..)?)?, 2),
        };
        let at = self.pos.saturating_add(header);
        let content = self.data.get(at..at.saturating_add(len))?;
        self.pos = at.saturating_add(len).saturating_add(eoc);
        Some(El {
            tlv,
            at: self.base.saturating_add(at),
            content,
        })
    }
}

/// Element headers walked to find where an indefinite-length content
/// ends. Real stores have a handful of nested indefinite levels; the cap
/// keeps a crafted one from making one step walk without bound.
const MAX_WALK: usize = 1 << 16;
/// Deepest nesting of indefinite lengths followed.
const MAX_INDEFINITE_DEPTH: u32 = 32;

/// Length of an indefinite-length content (starting at `data`), up to its
/// end-of-contents octets.
fn indefinite_len(data: &[u8]) -> Option<usize> {
    let mut pos = 0usize;
    let mut depth = 0u32;
    for _ in 0..MAX_WALK {
        let rest = data.get(pos..)?;
        if rest.starts_with(&[0, 0]) {
            if depth == 0 {
                return Some(pos);
            }
            depth = depth.saturating_sub(1);
            pos = pos.saturating_add(2);
            continue;
        }
        let tlv = der::header(rest)?;
        pos = pos.saturating_add(to_usize(tlv.header));
        match tlv.len {
            Some(len) => pos = pos.checked_add(to_usize(len))?,
            None => {
                depth = depth.saturating_add(1);
                if depth > MAX_INDEFINITE_DEPTH {
                    return None;
                }
            }
        }
    }
    None
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

/// The value of an OCTET STRING (or an implicitly tagged one): its bytes,
/// and the source and offset they lie at. A constructed (BER) string's
/// segments are joined into a derived source.
struct Octets<'a> {
    base: Span,
    data: Cow<'a, [u8]>,
    at: usize,
}

impl Octets<'_> {
    fn children(&self) -> Children<'_> {
        Children {
            data: &self.data,
            pos: 0,
            base: self.at,
        }
    }

    fn span(&self) -> Span {
        self.base.sub(to_u64(self.at), to_u64(self.data.len()))
    }
}

/// Deepest nesting of constructed string segments followed.
const MAX_SEGMENT_DEPTH: usize = 8;

/// `el`'s value as an OCTET STRING, `el` lying in `base`; `None` if a
/// constructed string holds anything but OCTET STRING segments.
async fn octets<'a>(cx: &Cx, base: Span, el: &El<'a>) -> Result<Option<Octets<'a>>> {
    if !el.tlv.constructed {
        return Ok(Some(Octets {
            base,
            data: Cow::Borrowed(el.content),
            at: el.at,
        }));
    }
    let mut joined = Vec::new();
    let mut stack = vec![sub_el(el)];
    let mut steps = 0u32;
    while let Some(top) = stack.last_mut() {
        let Some(seg) = top.next() else {
            stack.pop();
            continue;
        };
        steps = steps.wrapping_add(1);
        if steps.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        if !seg.tlv.is_universal(der::OCTET_STRING) {
            return Ok(None);
        }
        if seg.tlv.constructed {
            if stack.len() >= MAX_SEGMENT_DEPTH {
                return Ok(None);
            }
            stack.push(sub_el(&seg));
        } else {
            joined.extend_from_slice(seg.content);
        }
    }
    let span = base.sub(to_u64(el.at), to_u64(el.content.len()));
    let decoded = cx.add_derived(
        Origin {
            parent: span,
            transform: "ber-octets",
        },
        joined.clone(),
        span.len,
        None,
    )?;
    Ok(Some(Octets {
        base: decoded.span,
        data: Cow::Owned(joined),
        at: 0,
    }))
}

/// An encrypted part: algorithm content and the encryptedContent element.
struct Encrypted<'a> {
    alg: &'a [u8],
    body: El<'a>,
}

/// EncryptedData's EncryptedContentInfo.
fn encrypted_data<'a>(el: &El<'a>) -> Option<Encrypted<'a>> {
    let info = sub_el(el).nth(1)?;
    let parts: Vec<El<'_>> = sub_el(&info).take(3).collect();
    let alg = parts.get(1)?;
    let body = parts
        .get(2)
        .filter(|b| b.tlv.class == 2 && b.tlv.tag == 0)?;
    Some(Encrypted {
        alg: alg.content,
        body: *body,
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
    let (kind, octets_el) =
        content_info(auth).ok_or_else(|| Diagnostic::malformed("malformed authSafe").at(file))?;
    if kind != DATA {
        return Err(
            Diagnostic::unsupported("public-key integrity mode (signed authSafe)").at(file),
        );
    }
    // The MAC covers the authSafe's octets, joined if BER-segmented.
    let auth_octets = octets(&cx, file, &octets_el)
        .await?
        .ok_or_else(|| Diagnostic::malformed("malformed authSafe").at(file))?;
    let mac = fields.get(2).map(|m| m.content);
    let safe_list = auth_octets.children().next();
    let safes = || safe_list.as_ref().map(sub_el).into_iter().flatten();
    let auth_base = auth_octets.base;

    // The first encrypted thing, for checking passwords without a MAC.
    let mut probe: Option<(&[u8], Octets<'_>)> = None;
    if mac.is_none() {
        for ci in safes() {
            cx.checkpoint().await;
            if let Some((kind, inner)) = content_info(&ci)
                && kind == ENCRYPTED_DATA
                && let Some(e) = encrypted_data(&inner)
                && let Some(data) = octets(&cx, auth_base, &e.body).await?
            {
                probe = Some((e.alg, data));
                break;
            }
        }
    }
    let check = match (mac, &probe) {
        (Some(mac), _) => Check::Mac {
            mac,
            data: &auth_octets.data,
        },
        (None, Some((alg, data))) => Check::Decrypt {
            alg,
            data: &data.data,
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
            let Some(safe) = octets(&cx, auth_base, &inner).await? else {
                continue;
            };
            if let Some(seq) = safe.children().next() {
                bags(&cx, input, safe.base, sub_el(&seq), pw, 0).await?;
            }
        } else if kind == ENCRYPTED_DATA {
            let Some(enc) = encrypted_data(&inner) else {
                continue;
            };
            let Some(data) = octets(&cx, auth_base, &enc.body).await? else {
                continue;
            };
            let span = data.span();
            let label = format!("Encrypted safe ({})", pbe::describe(enc.alg));
            let Some(p) = pw else {
                cx.emit(Node::new(label).span(span).diag(Diagnostic::unsupported(
                    "encrypted (no password, or a wrong one)",
                )));
                continue;
            };
            match pbe::decrypt(&cx, enc.alg, p, &data.data).await {
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
                        bags(&cx, input, decoded.span, sub_el(&seq), pw, 0).await?;
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
                    .span(auth_base.sub(to_u64(ci.at), to_u64(ci.content.len()))),
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
                    hex.push_str(&crate::text::hex_lower(piece));
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

/// Deepest nesting of safeContentsBags followed. Real stores do not nest
/// them at all; the cap keeps a crafted chain from exhausting the stack.
const MAX_BAG_DEPTH: u32 = 8;

/// Lists SafeBags (whose contents lie in `base`), `depth` safeContentsBags
/// deep.
async fn bags(
    cx: &Cx,
    input: Input,
    base: Span,
    list: Children<'_>,
    pw: Option<Password<'_>>,
    depth: u32,
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
            to_u64(value.content.len())
                .saturating_add(value.tlv.header)
                .saturating_add(if value.tlv.len.is_none() { 2 } else { 0 }),
        );
        match kind.as_str() {
            "1.2.840.113549.1.12.10.1.3" => {
                // CertBag: certId, [0] { OCTET STRING cert }.
                let inner: Vec<El<'_>> = sub_el(&value).take(2).collect();
                let cert = match inner.get(1).and_then(|e| sub_el(e).next()) {
                    Some(el) => octets(cx, base, &el).await?,
                    None => None,
                };
                match cert {
                    Some(cert) => {
                        cx.push(embedded_as(
                            titled("Certificate"),
                            input.nested(cert.span()),
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
                let Some(data) = octets(cx, base, data).await? else {
                    continue;
                };
                let span = data.span();
                let label = titled("Private key");
                let decrypted = match pw {
                    Some(p) => Some(pbe::decrypt(cx, alg.content, p, &data.data).await),
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
                if depth >= MAX_BAG_DEPTH {
                    cx.push(Node::new(titled("Safe contents")).span(whole).diag(
                        Diagnostic::limit(format!(
                            "safe contents nested deeper than {MAX_BAG_DEPTH}"
                        )),
                    ))
                    .await;
                    continue;
                }
                let nested = sub_el(&value);
                bags_boxed(cx, input, base, nested, pw, depth.saturating_add(1)).await?;
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
    depth: u32,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
    Box::pin(bags(cx, input, base, list, pw, depth))
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
