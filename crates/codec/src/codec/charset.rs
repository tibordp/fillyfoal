//! Character sets: single-byte code pages decoded to text, and the lookup of
//! charset names (`charset=` in MIME, `encoding=` in XML, `<meta charset>`)
//! by the labels of the WHATWG Encoding Standard.
//!
//! The tables in [`tables`] are generated with Python's `codecs` module and
//! checked against it in the tests. Multi-byte East Asian encodings
//! (Shift_JIS, EUC-JP, GBK, Big5, EUC-KR, ...) are recognised by name
//! ([`Label::Unsupported`]) but not decoded.

mod tables;

macro_rules! charsets {
    ($($variant:ident => $name:literal, $table:ident, $transform:literal;)*) => {
        /// A single-byte character set whose bytes 0x00..=0x7F are ASCII.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum Charset {
            $($variant,)*
        }

        impl Charset {
            /// Every supported code page.
            pub const ALL: &'static [Charset] = &[$(Charset::$variant,)*];

            /// The usual name, e.g. `"ISO-8859-2"`.
            pub fn name(self) -> &'static str {
                match self {
                    $(Charset::$variant => $name,)*
                }
            }

            /// The transform name of sources transcoded from this charset
            /// into UTF-8 (see [`crate::span::Origin`]).
            pub fn transform(self) -> &'static str {
                match self {
                    $(Charset::$variant => $transform,)*
                }
            }

            /// The characters of bytes 0x80..=0xFF.
            pub fn high(self) -> &'static [u16; 128] {
                match self {
                    $(Charset::$variant => &tables::$table,)*
                }
            }
        }
    };
}

charsets! {
    Windows874 => "Windows-874", WINDOWS_874, "from Windows-874";
    Windows1250 => "Windows-1250", WINDOWS_1250, "from Windows-1250";
    Windows1251 => "Windows-1251", WINDOWS_1251, "from Windows-1251";
    Windows1252 => "Windows-1252", WINDOWS_1252, "from Windows-1252";
    Windows1253 => "Windows-1253", WINDOWS_1253, "from Windows-1253";
    Windows1254 => "Windows-1254", WINDOWS_1254, "from Windows-1254";
    Windows1255 => "Windows-1255", WINDOWS_1255, "from Windows-1255";
    Windows1256 => "Windows-1256", WINDOWS_1256, "from Windows-1256";
    Windows1257 => "Windows-1257", WINDOWS_1257, "from Windows-1257";
    Windows1258 => "Windows-1258", WINDOWS_1258, "from Windows-1258";
    Iso8859_1 => "ISO-8859-1", ISO_8859_1, "from ISO-8859-1";
    Iso8859_2 => "ISO-8859-2", ISO_8859_2, "from ISO-8859-2";
    Iso8859_3 => "ISO-8859-3", ISO_8859_3, "from ISO-8859-3";
    Iso8859_4 => "ISO-8859-4", ISO_8859_4, "from ISO-8859-4";
    Iso8859_5 => "ISO-8859-5", ISO_8859_5, "from ISO-8859-5";
    Iso8859_6 => "ISO-8859-6", ISO_8859_6, "from ISO-8859-6";
    Iso8859_7 => "ISO-8859-7", ISO_8859_7, "from ISO-8859-7";
    Iso8859_8 => "ISO-8859-8", ISO_8859_8, "from ISO-8859-8";
    Iso8859_9 => "ISO-8859-9", ISO_8859_9, "from ISO-8859-9";
    Iso8859_10 => "ISO-8859-10", ISO_8859_10, "from ISO-8859-10";
    Iso8859_11 => "ISO-8859-11", ISO_8859_11, "from ISO-8859-11";
    Iso8859_13 => "ISO-8859-13", ISO_8859_13, "from ISO-8859-13";
    Iso8859_14 => "ISO-8859-14", ISO_8859_14, "from ISO-8859-14";
    Iso8859_15 => "ISO-8859-15", ISO_8859_15, "from ISO-8859-15";
    Iso8859_16 => "ISO-8859-16", ISO_8859_16, "from ISO-8859-16";
    Koi8R => "KOI8-R", KOI8_R, "from KOI8-R";
    Koi8U => "KOI8-U", KOI8_U, "from KOI8-U";
    Cp437 => "CP437", CP437, "from CP437";
    Cp850 => "CP850", CP850, "from CP850";
    Cp866 => "CP866", CP866, "from CP866";
    MacRoman => "Mac Roman", MAC_ROMAN, "from Mac Roman";
}

impl Charset {
    /// The character of one byte.
    pub fn char(self, b: u8) -> char {
        if b < 0x80 {
            return char::from(b);
        }
        self.high()
            .get(usize::from(b & 0x7f))
            .and_then(|&u| char::from_u32(u32::from(u)))
            .unwrap_or(char::REPLACEMENT_CHARACTER)
    }

    pub fn decode(self, bytes: &[u8]) -> String {
        bytes.iter().map(|&b| self.char(b)).collect()
    }
}

/// What a charset label names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Label {
    Utf8,
    Utf16Le,
    Utf16Be,
    Single(Charset),
    /// A known encoding that is not decoded (multi-byte East Asian
    /// encodings, ISO-2022 variants), with its canonical name.
    Unsupported(&'static str),
}

impl Label {
    pub fn name(self) -> &'static str {
        match self {
            Label::Utf8 => "UTF-8",
            Label::Utf16Le => "UTF-16LE",
            Label::Utf16Be => "UTF-16BE",
            Label::Single(c) => c.name(),
            Label::Unsupported(name) => name,
        }
    }

    /// Decodes `bytes`, or `None` for an unsupported encoding. UTF-8 is
    /// decoded lossily.
    pub fn decode(self, bytes: &[u8]) -> Option<String> {
        Some(match self {
            Label::Utf8 => String::from_utf8_lossy(bytes).into_owned(),
            Label::Utf16Le => crate::text::utf16(bytes, crate::bytes::Endian::Little),
            Label::Utf16Be => crate::text::utf16(bytes, crate::bytes::Endian::Big),
            Label::Single(c) => c.decode(bytes),
            Label::Unsupported(_) => return None,
        })
    }
}

/// Labels by encoding: the WHATWG Encoding Standard's labels (which, like
/// browsers, read `iso-8859-1` and `us-ascii` as Windows-1252, `iso-8859-9`
/// as Windows-1254 and `iso-8859-11` as Windows-874), plus common names of
/// code pages the standard leaves out (DOS code pages 437 and 850).
const LABELS: &[(Label, &[&str])] = {
    use Charset::*;
    use Label::{Single as S, Unsupported as U};
    &[
        (
            Label::Utf8,
            &[
                "unicode-1-1-utf-8",
                "unicode11utf8",
                "unicode20utf8",
                "utf-8",
                "utf8",
                "x-unicode20utf8",
            ],
        ),
        (S(Cp866), &["866", "cp866", "csibm866", "ibm866"]),
        (
            S(Iso8859_2),
            &[
                "csisolatin2",
                "iso-8859-2",
                "iso-ir-101",
                "iso8859-2",
                "iso88592",
                "iso_8859-2",
                "iso_8859-2:1987",
                "l2",
                "latin2",
            ],
        ),
        (
            S(Iso8859_3),
            &[
                "csisolatin3",
                "iso-8859-3",
                "iso-ir-109",
                "iso8859-3",
                "iso88593",
                "iso_8859-3",
                "iso_8859-3:1988",
                "l3",
                "latin3",
            ],
        ),
        (
            S(Iso8859_4),
            &[
                "csisolatin4",
                "iso-8859-4",
                "iso-ir-110",
                "iso8859-4",
                "iso88594",
                "iso_8859-4",
                "iso_8859-4:1988",
                "l4",
                "latin4",
            ],
        ),
        (
            S(Iso8859_5),
            &[
                "csisolatincyrillic",
                "cyrillic",
                "iso-8859-5",
                "iso-ir-144",
                "iso8859-5",
                "iso88595",
                "iso_8859-5",
                "iso_8859-5:1988",
            ],
        ),
        (
            S(Iso8859_6),
            &[
                "arabic",
                "asmo-708",
                "csiso88596e",
                "csiso88596i",
                "csisolatinarabic",
                "ecma-114",
                "iso-8859-6",
                "iso-8859-6-e",
                "iso-8859-6-i",
                "iso-ir-127",
                "iso8859-6",
                "iso88596",
                "iso_8859-6",
                "iso_8859-6:1987",
            ],
        ),
        (
            S(Iso8859_7),
            &[
                "csisolatingreek",
                "ecma-118",
                "elot_928",
                "greek",
                "greek8",
                "iso-8859-7",
                "iso-ir-126",
                "iso8859-7",
                "iso88597",
                "iso_8859-7",
                "iso_8859-7:1987",
                "sun_eu_greek",
            ],
        ),
        (
            S(Iso8859_8),
            &[
                "csiso88598e",
                "csisolatinhebrew",
                "hebrew",
                "iso-8859-8",
                "iso-8859-8-e",
                "iso-ir-138",
                "iso8859-8",
                "iso88598",
                "iso_8859-8",
                "iso_8859-8:1988",
                "visual",
                "csiso88598i",
                "iso-8859-8-i",
                "logical",
            ],
        ),
        (
            S(Iso8859_10),
            &[
                "csisolatin6",
                "iso-8859-10",
                "iso-ir-157",
                "iso8859-10",
                "iso885910",
                "l6",
                "latin6",
            ],
        ),
        (S(Iso8859_13), &["iso-8859-13", "iso8859-13", "iso885913"]),
        (S(Iso8859_14), &["iso-8859-14", "iso8859-14", "iso885914"]),
        (
            S(Iso8859_15),
            &[
                "csisolatin9",
                "iso-8859-15",
                "iso8859-15",
                "iso885915",
                "iso_8859-15",
                "l9",
            ],
        ),
        (S(Iso8859_16), &["iso-8859-16"]),
        (S(Koi8R), &["cskoi8r", "koi", "koi8", "koi8-r", "koi8_r"]),
        (S(Koi8U), &["koi8-ru", "koi8-u"]),
        (
            S(MacRoman),
            &["csmacintosh", "mac", "macintosh", "x-mac-roman"],
        ),
        (
            S(Windows874),
            &[
                "dos-874",
                "iso-8859-11",
                "iso8859-11",
                "iso885911",
                "tis-620",
                "windows-874",
            ],
        ),
        (S(Windows1250), &["cp1250", "windows-1250", "x-cp1250"]),
        (S(Windows1251), &["cp1251", "windows-1251", "x-cp1251"]),
        (
            S(Windows1252),
            &[
                "ansi_x3.4-1968",
                "ascii",
                "cp1252",
                "cp819",
                "csisolatin1",
                "ibm819",
                "iso-8859-1",
                "iso-ir-100",
                "iso8859-1",
                "iso88591",
                "iso_8859-1",
                "iso_8859-1:1987",
                "l1",
                "latin1",
                "us-ascii",
                "windows-1252",
                "x-cp1252",
            ],
        ),
        (S(Windows1253), &["cp1253", "windows-1253", "x-cp1253"]),
        (
            S(Windows1254),
            &[
                "cp1254",
                "csisolatin5",
                "iso-8859-9",
                "iso-ir-148",
                "iso8859-9",
                "iso88599",
                "iso_8859-9",
                "iso_8859-9:1989",
                "l5",
                "latin5",
                "windows-1254",
                "x-cp1254",
            ],
        ),
        (S(Windows1255), &["cp1255", "windows-1255", "x-cp1255"]),
        (S(Windows1256), &["cp1256", "windows-1256", "x-cp1256"]),
        (S(Windows1257), &["cp1257", "windows-1257", "x-cp1257"]),
        (S(Windows1258), &["cp1258", "windows-1258", "x-cp1258"]),
        (Label::Utf16Be, &["unicodefffe", "utf-16be"]),
        (
            Label::Utf16Le,
            &[
                "csunicode",
                "iso-10646-ucs-2",
                "ucs-2",
                "unicode",
                "unicodefeff",
                "utf-16",
                "utf-16le",
            ],
        ),
        // Not in the WHATWG standard.
        (S(Cp437), &["437", "cp437", "ibm437", "cspc8codepage437"]),
        (S(Cp850), &["850", "cp850", "ibm850", "cspc850multilingual"]),
        (
            U("GBK"),
            &[
                "chinese",
                "csgb2312",
                "csiso58gb231280",
                "gb2312",
                "gb_2312",
                "gb_2312-80",
                "gbk",
                "iso-ir-58",
                "x-gbk",
            ],
        ),
        (U("gb18030"), &["gb18030"]),
        (
            U("Big5"),
            &["big5", "big5-hkscs", "cn-big5", "csbig5", "x-x-big5"],
        ),
        (U("EUC-JP"), &["cseucpkdfmtjapanese", "euc-jp", "x-euc-jp"]),
        (U("ISO-2022-JP"), &["csiso2022jp", "iso-2022-jp"]),
        (
            U("Shift_JIS"),
            &[
                "csshiftjis",
                "ms932",
                "ms_kanji",
                "shift-jis",
                "shift_jis",
                "sjis",
                "windows-31j",
                "x-sjis",
            ],
        ),
        (
            U("EUC-KR"),
            &[
                "cseuckr",
                "csksc56011987",
                "euc-kr",
                "iso-ir-149",
                "korean",
                "ks_c_5601-1987",
                "ks_c_5601-1989",
                "ksc5601",
                "ksc_5601",
                "windows-949",
            ],
        ),
        (
            U("replacement"),
            &[
                "csiso2022kr",
                "hz-gb-2312",
                "iso-2022-cn",
                "iso-2022-cn-ext",
                "iso-2022-kr",
                "replacement",
            ],
        ),
        (U("x-mac-cyrillic"), &["x-mac-cyrillic", "x-mac-ukrainian"]),
        (U("UTF-32"), &["utf-32", "utf-32le", "utf-32be", "ucs-4"]),
    ]
};

/// Extra spellings seen in the wild (Python and Emacs coding cookies, mail
/// software), checked after the standard labels.
const ALIASES: &[(&str, &str)] = &[
    ("latin-1", "latin1"),
    ("iso-latin-1", "latin1"),
    ("latin-2", "latin2"),
    ("iso-latin-2", "latin2"),
    ("latin-9", "l9"),
    ("latin9", "l9"),
    ("iso8859-16", "iso-8859-16"),
    ("iso885916", "iso-8859-16"),
    ("iso_8859-16", "iso-8859-16"),
    ("latin10", "iso-8859-16"),
    ("cp-1250", "cp1250"),
    ("cp-1251", "cp1251"),
    ("cp-1252", "cp1252"),
    ("mac-roman", "x-mac-roman"),
    ("macroman", "x-mac-roman"),
    ("mac_roman", "x-mac-roman"),
    ("koi8-u", "koi8-u"),
    ("koi8_u", "koi8-u"),
    ("ibm-437", "cp437"),
    ("ibm-850", "cp850"),
    ("ibm-866", "cp866"),
    ("utf_8", "utf8"),
    ("utf-8-unix", "utf8"),
    ("utf-8-dos", "utf8"),
    ("utf-8-sig", "utf8"),
];

/// The encoding a charset label names (ASCII case-insensitive, surrounding
/// whitespace and quotes ignored).
pub fn lookup(label: &str) -> Option<Label> {
    let wanted = label
        .trim_matches(|c: char| c.is_ascii_whitespace() || c == '"' || c == '\'')
        .to_ascii_lowercase();
    let find = |name: &str| {
        LABELS
            .iter()
            .find(|(_, names)| names.contains(&name))
            .map(|(l, _)| *l)
    };
    find(&wanted).or_else(|| {
        ALIASES
            .iter()
            .find(|(alias, _)| *alias == wanted)
            .and_then(|(_, label)| find(label))
    })
}

/// Decodes `bytes` in the charset `label` names, or `None` if it is unknown
/// or unsupported.
pub fn decode_label(label: &str, bytes: &[u8]) -> Option<String> {
    lookup(label)?.decode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_follow_whatwg() {
        assert_eq!(
            lookup(" ISO-8859-1 "),
            Some(Label::Single(Charset::Windows1252))
        );
        assert_eq!(lookup("latin2"), Some(Label::Single(Charset::Iso8859_2)));
        assert_eq!(
            lookup("iso-8859-9"),
            Some(Label::Single(Charset::Windows1254))
        );
        assert_eq!(lookup("tis-620"), Some(Label::Single(Charset::Windows874)));
        assert_eq!(lookup("KOI8-R"), Some(Label::Single(Charset::Koi8R)));
        assert_eq!(lookup("UTF8"), Some(Label::Utf8));
        assert_eq!(lookup("utf-16"), Some(Label::Utf16Le));
        assert_eq!(lookup("Shift_JIS"), Some(Label::Unsupported("Shift_JIS")));
        assert_eq!(lookup("latin-1"), Some(Label::Single(Charset::Windows1252)));
        assert_eq!(lookup("ibm437"), Some(Label::Single(Charset::Cp437)));
        assert_eq!(lookup("klingon"), None);
        // Every label is unique.
        let mut all: Vec<&str> = LABELS.iter().flat_map(|(_, n)| n.iter().copied()).collect();
        let n = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), n);
        for (alias, target) in ALIASES {
            assert!(lookup(alias).is_some(), "{alias} -> {target}");
        }
    }

    #[test]
    fn decodes_bytes() {
        assert_eq!(Charset::Iso8859_2.decode(b"\xb1\xe6\xea"), "ąćę");
        assert_eq!(Charset::Koi8R.decode(b"\xf0\xd2\xc9\xd7\xc5\xd4"), "Привет");
        assert_eq!(Charset::Windows1252.decode(b"\x80\x81"), "€\u{81}");
        assert_eq!(Charset::Iso8859_3.decode(b"\xa5"), "\u{fffd}");
    }
}
