//! URL pieces for display: percent-decoding, `data:` URLs, and
//! internationalised host names (Punycode, RFC 3492; IDNA `xn--` labels).
//!
//! These only make text readable; they never replace the raw value, which
//! callers keep and show alongside.

use crate::text::hex_digit as hex;

/// `%XX` escapes decoded to bytes; malformed escapes are kept as they are.
pub fn percent_decode_bytes(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    let mut i = 0usize;
    while let Some(&b) = text.get(i) {
        let escaped = (b == b'%')
            .then(|| {
                let h = hex(*text.get(i.saturating_add(1))?)?;
                let l = hex(*text.get(i.saturating_add(2))?)?;
                Some(h << 4 | l)
            })
            .flatten();
        match escaped {
            Some(v) => {
                out.push(v);
                i = i.saturating_add(3);
            }
            None => {
                out.push(b);
                i = i.saturating_add(1);
            }
        }
    }
    out
}

/// `%XX` escapes decoded, the result read as UTF-8 (lossily).
pub fn percent_decode(text: &str) -> String {
    String::from_utf8_lossy(&percent_decode_bytes(text.as_bytes())).into_owned()
}

// ---------------------------------------------------------------------------
// Punycode

const BASE: u32 = 36;
const TMIN: u32 = 1;
const TMAX: u32 = 26;
const SKEW: u32 = 38;
const DAMP: u32 = 700;
const INITIAL_BIAS: u32 = 72;
const INITIAL_N: u32 = 128;
/// Longest label decoded (DNS labels have at most 63 octets).
const MAX_LABEL: usize = 256;

fn adapt(delta: u32, points: u32, first: bool) -> u32 {
    let mut delta = if first { delta / DAMP } else { delta / 2 };
    delta = delta.saturating_add(delta.checked_div(points).unwrap_or(0));
    let mut k = 0u32;
    let limit = (BASE - TMIN) * TMAX / 2;
    while delta > limit {
        delta /= BASE - TMIN;
        k = k.saturating_add(BASE);
    }
    k.saturating_add(
        ((BASE - TMIN + 1).saturating_mul(delta))
            .checked_div(delta.saturating_add(SKEW))
            .unwrap_or(0),
    )
}

fn digit(b: u8) -> Option<u32> {
    match b {
        b'a'..=b'z' => Some(u32::from(b.wrapping_sub(b'a'))),
        b'A'..=b'Z' => Some(u32::from(b.wrapping_sub(b'A'))),
        b'0'..=b'9' => Some(u32::from(b.wrapping_sub(b'0')).wrapping_add(26)),
        _ => None,
    }
}

/// Decodes a Punycode string (without the `xn--` prefix), or `None` if it
/// is malformed.
pub fn punycode_decode(input: &str) -> Option<String> {
    if input.len() > MAX_LABEL || !input.is_ascii() {
        return None;
    }
    let (basic, extended) = match input.rfind('-') {
        Some(i) => (input.get(..i)?, input.get(i.checked_add(1)?..)?),
        None => ("", input),
    };
    let mut output: Vec<char> = basic.chars().collect();
    let mut n = INITIAL_N;
    let mut i = 0u32;
    let mut bias = INITIAL_BIAS;
    let mut bytes = extended.bytes();
    while bytes.len() > 0 {
        let old_i = i;
        let mut w = 1u32;
        let mut k = BASE;
        loop {
            let d = digit(bytes.next()?)?;
            i = i.checked_add(d.checked_mul(w)?)?;
            let t = if k <= bias {
                TMIN
            } else if k >= bias.saturating_add(TMAX) {
                TMAX
            } else {
                k.wrapping_sub(bias)
            };
            if d < t {
                break;
            }
            w = w.checked_mul(BASE.checked_sub(t)?)?;
            k = k.checked_add(BASE)?;
        }
        let len = u32::try_from(output.len()).ok()?.checked_add(1)?;
        bias = adapt(i.wrapping_sub(old_i), len, old_i == 0);
        n = n.checked_add(i.checked_div(len)?)?;
        i = i.checked_rem(len)?;
        let c = char::from_u32(n)?;
        if c.is_ascii() || output.len() >= MAX_LABEL {
            return None;
        }
        output.insert(usize::try_from(i).ok()?, c);
        i = i.checked_add(1)?;
    }
    Some(output.into_iter().collect())
}

/// One label in its Unicode form, if it is an `xn--` label that decodes.
fn label_to_unicode(label: &str) -> Option<String> {
    let prefix = label.get(..4)?;
    if !prefix.eq_ignore_ascii_case("xn--") {
        return None;
    }
    punycode_decode(label.get(4..)?)
}

/// A host name with its `xn--` labels in Unicode, or `None` if it has none
/// (or none that decode).
pub fn host_to_unicode(host: &str) -> Option<String> {
    let mut changed = false;
    let labels: Vec<String> = host
        .split('.')
        .map(|l| match label_to_unicode(l) {
            Some(u) => {
                changed = true;
                u
            }
            None => l.to_owned(),
        })
        .collect();
    changed.then(|| labels.join("."))
}

/// `text` (a URL, an e-mail address, a header, a certificate name) with the
/// `xn--` labels of the host names in it shown in Unicode, or `None` if
/// there are none.
pub fn hosts_to_unicode(text: &str) -> Option<String> {
    if !text.to_ascii_lowercase().contains("xn--") {
        return None;
    }
    let is_host = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '.';
    let mut out = String::with_capacity(text.len());
    let mut changed = false;
    let mut rest = text;
    while !rest.is_empty() {
        let start = rest.find(is_host).unwrap_or(rest.len());
        out.push_str(rest.get(..start).unwrap_or_default());
        rest = rest.get(start..).unwrap_or_default();
        let end = rest.find(|c: char| !is_host(c)).unwrap_or(rest.len());
        let run = rest.get(..end).unwrap_or_default();
        match host_to_unicode(run) {
            Some(u) => {
                changed = true;
                out.push_str(&u);
            }
            None => out.push_str(run),
        }
        rest = rest.get(end..).unwrap_or_default();
    }
    changed.then_some(out)
}

/// A URL for display: percent escapes decoded (when they spell UTF-8 text
/// without control characters) and `xn--` host labels in Unicode. `None`
/// if that changes nothing.
pub fn display_url(url: &str) -> Option<String> {
    let hosts = hosts_to_unicode(url);
    let base = hosts.as_deref().unwrap_or(url);
    let decoded = if base.contains('%') {
        std::str::from_utf8(&percent_decode_bytes(base.as_bytes()))
            .ok()
            .filter(|s| !s.chars().any(char::is_control))
            .map(str::to_owned)
    } else {
        None
    };
    decoded.or(hosts).filter(|d| d != url)
}

// ---------------------------------------------------------------------------
// data: URLs

/// A parsed `data:` URL (RFC 2397).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataUrl {
    /// The media type and parameters, without `;base64` (may be empty,
    /// meaning `text/plain;charset=US-ASCII`).
    pub media_type: String,
    pub base64: bool,
    /// Byte offset of the payload (after the comma) in the URL.
    pub payload: usize,
}

/// Parses a `data:` URL (the scheme matched case-insensitively).
pub fn data_url(url: &str) -> Option<DataUrl> {
    let scheme = url.get(..5)?;
    if !scheme.eq_ignore_ascii_case("data:") {
        return None;
    }
    let comma = url.find(',')?;
    let meta = url.get(5..comma)?.trim();
    let (media_type, base64) = match meta.len().checked_sub(7).and_then(|i| meta.get(i..)) {
        Some(tail) if tail.eq_ignore_ascii_case(";base64") => {
            (meta.get(..meta.len().saturating_sub(7))?, true)
        }
        _ => (meta, false),
    };
    Some(DataUrl {
        media_type: percent_decode(media_type),
        base64,
        payload: comma.checked_add(1)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 3492, section 7.1 (samples A, B, L, M, S) and Python's
    /// `codecs.decode(..., "punycode")`.
    #[test]
    fn punycode_vectors() {
        let cases: &[(&str, &str)] = &[
            (
                "egbpdaj6bu4bxfgehfvwxn",
                "\u{0644}\u{064A}\u{0647}\u{0645}\u{0627}\u{0628}\u{062A}\u{0643}\u{0644}\u{0645}\u{0648}\u{0634}\u{0639}\u{0631}\u{0628}\u{064A}\u{061F}",
            ),
            ("ihqwcrb4cv8a8dqg056pqjye", "他们为什么不说中文"),
            ("3B-ww4c5e180e575a65lsy2b", "3年B組金八先生"),
            (
                "-with-SUPER-MONKEYS-pc58ag80a8qai00g7n9n",
                "安室奈美恵-with-SUPER-MONKEYS",
            ),
            ("-> $1.00 <--", "-> $1.00 <-"),
            ("bcher-kva", "bücher"),
            ("mnchen-3ya", "münchen"),
        ];
        for (encoded, decoded) in cases {
            assert_eq!(
                punycode_decode(encoded).as_deref(),
                Some(*decoded),
                "{encoded}"
            );
        }
        assert_eq!(punycode_decode("99999999999999"), None);
        assert_eq!(punycode_decode("a-é"), None);
    }

    #[test]
    fn hosts_and_urls() {
        assert_eq!(
            host_to_unicode("www.XN--bcher-kva.example").as_deref(),
            Some("www.bücher.example")
        );
        assert_eq!(host_to_unicode("example.com"), None);
        assert_eq!(
            hosts_to_unicode("Jane <jane@xn--mnchen-3ya.de>").as_deref(),
            Some("Jane <jane@münchen.de>")
        );
        assert_eq!(
            display_url("https://xn--bcher-kva.example/a%20b%C3%A9?q=%E2%82%AC").as_deref(),
            Some("https://bücher.example/a bé?q=€")
        );
        assert_eq!(display_url("https://example.com/%ff"), None);
        assert_eq!(display_url("https://example.com/"), None);
        assert_eq!(percent_decode("100%25 %zz"), "100% %zz");
    }

    #[test]
    fn data_urls() {
        assert_eq!(
            data_url("data:image/png;base64,iVBOR"),
            Some(DataUrl {
                media_type: "image/png".to_owned(),
                base64: true,
                payload: 22
            })
        );
        assert_eq!(
            data_url("DATA:,Hello%2C%20World"),
            Some(DataUrl {
                media_type: String::new(),
                base64: false,
                payload: 6
            })
        );
        assert_eq!(data_url("https://x/,"), None);
    }
}
