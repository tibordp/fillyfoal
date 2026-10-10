//! Just enough of the X.509, PKCS#7/CMS, PKCS#10, PKCS#12, OCSP, time-stamp
//! and key modules to give elements their field names. Anything not
//! described here is shown generically by its tag.

use super::x509;
use crate::value::EnumTable;

/// Content decoders for primitives with a structure of their own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Special {
    /// An elliptic-curve point (SEC 1 encoding) in a BIT or OCTET STRING.
    EcPoint,
    /// A raw public key of a fixed-size algorithm (Ed25519, X25519, ...).
    RawKey,
    /// An IP address, or an address and mask in a name constraint.
    IpAddress,
    /// RFC 6962 SignedCertificateTimestampList (TLS encoding).
    SctList,
    /// A key identifier or hash, shown as colon-separated hex.
    KeyId,
    /// Content of some other format, detected and dissected.
    Embedded,
}

/// What the children of a constructed element are.
pub enum Schema {
    /// Unknown: children are named by their tags.
    Any,
    /// A SEQUENCE (or SET) with these fields, in order.
    Seq(&'static [Field]),
    /// Every child is `name` with the given schema.
    SeqOf(&'static str, &'static Schema),
    /// An X.500 Name: a sequence of relative distinguished names.
    Name,
    /// `ANY DEFINED BY`: chosen by the value of the object identifier
    /// before this field in the same SEQUENCE: `(OID, name, schema)`, where
    /// the name, if any, replaces the field's.
    DefinedBy(&'static [(&'static str, Option<&'static str>, &'static Schema)]),
    /// Like `DefinedBy`, by the algorithm of the AlgorithmIdentifier before
    /// this field (a key or signature by its algorithm).
    ByAlgorithm(&'static [(&'static str, Option<&'static str>, &'static Schema)]),
    /// A CHOICE: the alternative with this identifier octet, by name.
    Choice(&'static [(u8, &'static str, &'static Schema)]),
    /// A context-tagged primitive that is an IMPLICIT string of this
    /// universal type (its value is decoded as that type's).
    Implicit(u64),
    /// An OCTET or BIT STRING holding DER whose elements have this schema.
    Encap(&'static Schema),
    /// A BIT STRING of named bits (bit 0 first).
    Bits(&'static [&'static str]),
    /// An INTEGER or ENUMERATED with named values.
    Enum(EnumTable),
    /// A constructed element summarised from its content by a function.
    Summary(fn(&[u8]) -> Option<String>, &'static Schema),
    /// A primitive decoded by a special decoder.
    Special(Special),
}

/// What an `ANY DEFINED BY` or `CHOICE` is resolved against.
pub struct Context<'a> {
    /// The last OBJECT IDENTIFIER before this field.
    pub oid: Option<&'a str>,
    /// The algorithm of the last AlgorithmIdentifier before this field.
    pub algorithm: Option<&'a str>,
    /// This element's identifier octet.
    pub id: u8,
}

impl Schema {
    /// This schema with `ANY DEFINED BY` and `CHOICE` resolved, and the
    /// name that replaces the field's.
    pub fn resolve(&'static self, cx: &Context<'_>) -> (Option<&'static str>, &'static Schema) {
        let mut schema = self;
        let mut name = None;
        for _ in 0..4 {
            let (n, next) = match schema {
                Schema::DefinedBy(table) => pick(table, cx.oid),
                Schema::ByAlgorithm(table) => pick(table, cx.algorithm),
                Schema::Choice(table) => table
                    .iter()
                    .find(|(id, _, _)| *id == cx.id)
                    .map_or((None, &UNKNOWN), |(_, n, s)| (Some(*n), *s)),
                _ => return (name, schema),
            };
            name = n.or(name);
            schema = next;
        }
        (name, schema)
    }

    /// The schema of the children, past any summary wrapper.
    pub fn body(&'static self) -> &'static Schema {
        match self {
            Schema::Summary(_, inner) => inner,
            _ => self,
        }
    }

    /// The universal type of an IMPLICIT tagged primitive with this schema.
    pub fn implied_tag(&self) -> Option<u64> {
        Some(match self {
            Schema::Implicit(tag) => *tag,
            Schema::Bits(_) => super::der::BIT_STRING,
            Schema::Enum(_) => super::der::INTEGER,
            Schema::Special(Special::IpAddress | Special::KeyId) => super::der::OCTET_STRING,
            _ => return None,
        })
    }
}

type Table = [(&'static str, Option<&'static str>, &'static Schema)];

fn pick(table: &'static Table, oid: Option<&str>) -> (Option<&'static str>, &'static Schema) {
    table
        .iter()
        .find(|(o, _, _)| Some(*o) == oid)
        .map_or((None, &UNKNOWN), |(_, name, schema)| (*name, *schema))
}

/// One field of a [`Schema::Seq`].
pub struct Field {
    pub name: &'static str,
    /// Identifier octets this field may have; empty means any.
    pub ids: &'static [u8],
    pub optional: bool,
    pub schema: &'static Schema,
}

const fn req(name: &'static str, ids: &'static [u8], schema: &'static Schema) -> Field {
    Field {
        name,
        ids,
        optional: false,
        schema,
    }
}

const fn opt(name: &'static str, ids: &'static [u8], schema: &'static Schema) -> Field {
    Field {
        name,
        ids,
        optional: true,
        schema,
    }
}

const SEQ: &[u8] = &[0x30];
const SET: &[u8] = &[0x31];
const INT: &[u8] = &[0x02];
const BOOL: &[u8] = &[0x01];
const OID: &[u8] = &[0x06];
const OCTETS: &[u8] = &[0x04];
const BITS: &[u8] = &[0x03];
const ENUM: &[u8] = &[0x0a];
const TIME: &[u8] = &[0x17, 0x18];
const GTIME: &[u8] = &[0x18];
const ANY: &[u8] = &[];

pub static UNKNOWN: Schema = Schema::Any;

/// The children of an element whose schema is `schema`: the name and
/// schema of each, matched in order. Returns `None` for unnamed children.
pub struct Matcher {
    schema: &'static Schema,
    next: usize,
}

impl Matcher {
    pub fn new(schema: &'static Schema) -> Self {
        Matcher {
            schema: schema.body(),
            next: 0,
        }
    }

    pub fn child(&mut self, id: u8) -> (Option<&'static str>, &'static Schema) {
        match self.schema {
            Schema::SeqOf(name, schema) => (Some(name), schema),
            Schema::Name => (Some("RelativeDistinguishedName"), &RDN),
            Schema::Seq(fields) => {
                while let Some(field) = fields.get(self.next) {
                    self.next = self.next.saturating_add(1);
                    if field.ids.is_empty() || field.ids.contains(&id) {
                        return (Some(field.name), field.schema);
                    }
                    if !field.optional {
                        // Out of step with the schema: stop naming.
                        self.next = usize::MAX;
                        break;
                    }
                }
                (None, &UNKNOWN)
            }
            _ => (None, &UNKNOWN),
        }
    }
}

// --- Shared ---------------------------------------------------------------

pub static ALGORITHM: Schema = Schema::Summary(x509::algorithm, &ALGORITHM_BODY);
static ALGORITHM_BODY: Schema = Schema::Seq(&[
    req("algorithm", OID, &UNKNOWN),
    opt("parameters", ANY, &ALGORITHM_PARAMETERS),
]);

/// AlgorithmIdentifier parameters with structure of their own.
static ALGORITHM_PARAMETERS: Schema = Schema::DefinedBy(&[
    (
        "1.2.840.113549.1.1.10",
        Some("RSASSA-PSS-params"),
        &RSASSA_PSS_PARAMS,
    ),
    (
        "1.2.840.113549.1.1.7",
        Some("RSAES-OAEP-params"),
        &RSAES_OAEP_PARAMS,
    ),
    ("1.2.840.113549.1.1.8", Some("hashAlgorithm"), &ALGORITHM),
    ("1.2.840.10040.4.1", Some("Dss-Parms"), &DSS_PARMS),
    ("1.2.840.10046.2.1", Some("DomainParameters"), &DH_DOMAIN),
    ("1.2.840.113549.1.3.1", Some("DHParameter"), &DH_PARAMETER),
    ("1.2.840.10045.2.1", Some("namedCurve"), &UNKNOWN),
    ("1.2.840.113549.1.5.13", Some("PBES2-params"), &PBES2_PARAMS),
    (
        "1.2.840.113549.1.5.12",
        Some("PBKDF2-params"),
        &PBKDF2_PARAMS,
    ),
    (
        "1.2.840.113549.1.12.1.1",
        Some("pkcs-12PbeParams"),
        &PKCS12_PBE,
    ),
    (
        "1.2.840.113549.1.12.1.3",
        Some("pkcs-12PbeParams"),
        &PKCS12_PBE,
    ),
    (
        "1.2.840.113549.1.12.1.6",
        Some("pkcs-12PbeParams"),
        &PKCS12_PBE,
    ),
    ("1.3.6.1.4.1.42.2.19.1", Some("PBEParameter"), &PKCS12_PBE),
    (
        "1.3.133.16.840.63.0.2",
        Some("keyWrapAlgorithm"),
        &ALGORITHM,
    ),
    ("1.3.132.1.11.0", Some("keyWrapAlgorithm"), &ALGORITHM),
    ("1.3.132.1.11.1", Some("keyWrapAlgorithm"), &ALGORITHM),
    ("1.3.132.1.11.2", Some("keyWrapAlgorithm"), &ALGORITHM),
    ("1.3.132.1.11.3", Some("keyWrapAlgorithm"), &ALGORITHM),
    ("1.3.132.1.14.1", Some("keyWrapAlgorithm"), &ALGORITHM),
    (
        "1.2.840.113549.1.9.16.3.9",
        Some("keyEncryptionAlgorithm"),
        &ALGORITHM,
    ),
    ("2.16.840.1.101.3.4.1.2", Some("iv"), &UNKNOWN),
    ("2.16.840.1.101.3.4.1.22", Some("iv"), &UNKNOWN),
    ("2.16.840.1.101.3.4.1.42", Some("iv"), &UNKNOWN),
    ("1.2.840.113549.3.7", Some("iv"), &UNKNOWN),
    ("2.16.840.1.101.3.4.1.6", Some("GCMParameters"), &GCM_PARAMS),
    (
        "2.16.840.1.101.3.4.1.26",
        Some("GCMParameters"),
        &GCM_PARAMS,
    ),
    (
        "2.16.840.1.101.3.4.1.46",
        Some("GCMParameters"),
        &GCM_PARAMS,
    ),
]);

static EXPLICIT_HASH: Schema = Schema::Seq(&[req("AlgorithmIdentifier", SEQ, &ALGORITHM)]);
static EXPLICIT_MGF: Schema = Schema::Seq(&[req("AlgorithmIdentifier", SEQ, &ALGORITHM)]);
static EXPLICIT_INT: Schema = Schema::Seq(&[req("value", INT, &UNKNOWN)]);
static EXPLICIT_PSOURCE: Schema = Schema::Seq(&[req("AlgorithmIdentifier", SEQ, &ALGORITHM)]);

static RSASSA_PSS_PARAMS: Schema = Schema::Seq(&[
    opt("hashAlgorithm", &[0xa0], &EXPLICIT_HASH),
    opt("maskGenAlgorithm", &[0xa1], &EXPLICIT_MGF),
    opt("saltLength", &[0xa2], &EXPLICIT_INT),
    opt("trailerField", &[0xa3], &EXPLICIT_INT),
]);

static RSAES_OAEP_PARAMS: Schema = Schema::Seq(&[
    opt("hashAlgorithm", &[0xa0], &EXPLICIT_HASH),
    opt("maskGenAlgorithm", &[0xa1], &EXPLICIT_MGF),
    opt("pSourceAlgorithm", &[0xa2], &EXPLICIT_PSOURCE),
]);

static DSS_PARMS: Schema = Schema::Seq(&[
    req("p", INT, &UNKNOWN),
    req("q", INT, &UNKNOWN),
    req("g", INT, &UNKNOWN),
]);

/// X9.42 DomainParameters.
static DH_DOMAIN: Schema = Schema::Seq(&[
    req("p", INT, &UNKNOWN),
    req("g", INT, &UNKNOWN),
    req("q", INT, &UNKNOWN),
    opt("j", INT, &UNKNOWN),
    opt("validationParms", SEQ, &UNKNOWN),
]);

/// PKCS #3 DHParameter.
static DH_PARAMETER: Schema = Schema::Seq(&[
    req("prime", INT, &UNKNOWN),
    req("base", INT, &UNKNOWN),
    opt("privateValueLength", INT, &UNKNOWN),
]);

static PBES2_PARAMS: Schema = Schema::Seq(&[
    req("keyDerivationFunc", SEQ, &ALGORITHM),
    req("encryptionScheme", SEQ, &ALGORITHM),
]);

static PBKDF2_PARAMS: Schema = Schema::Seq(&[
    req("salt", OCTETS, &UNKNOWN),
    req("iterationCount", INT, &UNKNOWN),
    opt("keyLength", INT, &UNKNOWN),
    opt("prf", SEQ, &ALGORITHM),
]);

static PKCS12_PBE: Schema = Schema::Seq(&[
    req("salt", OCTETS, &UNKNOWN),
    req("iterations", INT, &UNKNOWN),
]);

static GCM_PARAMS: Schema = Schema::Seq(&[
    req("aes-nonce", OCTETS, &UNKNOWN),
    opt("aes-ICVlen", INT, &UNKNOWN),
]);

static RDN: Schema = Schema::SeqOf("AttributeTypeAndValue", &ATTRIBUTE_VALUE);
static ATTRIBUTE_VALUE: Schema =
    Schema::Seq(&[req("type", OID, &UNKNOWN), req("value", ANY, &UNKNOWN)]);
pub static NAME: Schema = Schema::Name;
static EXPLICIT_NAME: Schema = Schema::Seq(&[req("Name", SEQ, &NAME)]);

static ATTRIBUTE: Schema = Schema::Summary(x509::attribute, &ATTRIBUTE_BODY);
static ATTRIBUTE_BODY: Schema = Schema::Seq(&[
    req("attrType", OID, &UNKNOWN),
    req("attrValues", SET, &ATTRIBUTE_VALUES),
]);

/// The values of the attributes that have structure of their own.
static ATTRIBUTE_VALUES: Schema = Schema::DefinedBy(&[
    ("1.2.840.113549.1.9.6", None, &SIGNER_INFOS),
    ("1.2.840.113549.1.9.14", None, &EXTENSION_REQUEST),
    ("1.2.840.113549.1.9.15", None, &SMIME_CAPABILITIES_SET),
    ("1.2.840.113549.1.9.16.2.12", None, &SIGNING_CERTIFICATES),
    ("1.2.840.113549.1.9.16.2.47", None, &SIGNING_CERTIFICATES_V2),
    ("1.2.840.113549.1.9.16.2.14", None, &CONTENT_INFOS),
    ("1.2.840.113549.1.9.52", None, &ALGORITHM_PROTECTIONS),
    ("1.3.6.1.4.1.311.2.1.11", None, &SPC_STATEMENT_TYPES),
    ("1.3.6.1.4.1.311.2.1.12", None, &SPC_SP_OPUS_INFOS),
    ("1.3.6.1.4.1.311.2.4.1", None, &CONTENT_INFOS),
    ("1.3.6.1.4.1.311.3.3.1", None, &CONTENT_INFOS),
]);
static ATTRIBUTES: Schema = Schema::SeqOf("Attribute", &ATTRIBUTE);

static EXTENSION_REQUEST: Schema = Schema::SeqOf("Extensions", &EXTENSIONS);
static SMIME_CAPABILITIES_SET: Schema = Schema::SeqOf("SMIMECapabilities", &SMIME_CAPABILITIES);
static SMIME_CAPABILITIES: Schema = Schema::SeqOf("SMIMECapability", &ALGORITHM);
static ALGORITHM_PROTECTIONS: Schema =
    Schema::SeqOf("CMSAlgorithmProtection", &ALGORITHM_PROTECTION);
static ALGORITHM_PROTECTION: Schema = Schema::Seq(&[
    req("digestAlgorithm", SEQ, &ALGORITHM),
    opt("signatureAlgorithm", &[0xa1], &UNKNOWN),
    opt("macAlgorithm", &[0xa2], &UNKNOWN),
]);

/// ESS SigningCertificate (RFC 2634) and SigningCertificateV2 (RFC 5035).
static SIGNING_CERTIFICATES: Schema = Schema::SeqOf("SigningCertificate", &SIGNING_CERTIFICATE);
static SIGNING_CERTIFICATE: Schema = Schema::Seq(&[
    req("certs", SEQ, &ESS_CERT_IDS),
    opt("policies", SEQ, &CERTIFICATE_POLICIES),
]);
static ESS_CERT_IDS: Schema = Schema::SeqOf("ESSCertID", &ESS_CERT_ID);
static ESS_CERT_ID: Schema = Schema::Seq(&[
    req("certHash", OCTETS, &KEY_ID),
    opt("issuerSerial", SEQ, &ISSUER_SERIAL),
]);
static SIGNING_CERTIFICATES_V2: Schema =
    Schema::SeqOf("SigningCertificateV2", &SIGNING_CERTIFICATE_V2);
static SIGNING_CERTIFICATE_V2: Schema = Schema::Seq(&[
    req("certs", SEQ, &ESS_CERT_IDS_V2),
    opt("policies", SEQ, &CERTIFICATE_POLICIES),
]);
static ESS_CERT_IDS_V2: Schema = Schema::SeqOf("ESSCertIDv2", &ESS_CERT_ID_V2);
static ESS_CERT_ID_V2: Schema = Schema::Seq(&[
    opt("hashAlgorithm", SEQ, &ALGORITHM),
    req("certHash", OCTETS, &KEY_ID),
    opt("issuerSerial", SEQ, &ISSUER_SERIAL),
]);
static ISSUER_SERIAL: Schema = Schema::Seq(&[
    req("issuer", SEQ, &GENERAL_NAMES),
    req("serialNumber", INT, &UNKNOWN),
]);

// --- General names ---------------------------------------------------------

pub static GENERAL_NAMES: Schema = Schema::Summary(x509::general_names, &GENERAL_NAMES_BODY);
static GENERAL_NAMES_BODY: Schema = Schema::SeqOf("GeneralName", &GENERAL_NAME);

static GENERAL_NAME: Schema = Schema::Choice(&[
    (0xa0, "otherName", &OTHER_NAME),
    (0x81, "rfc822Name", &IA5_STRING),
    (0x82, "dNSName", &IA5_STRING),
    (0xa3, "x400Address", &UNKNOWN),
    (0xa4, "directoryName", &DIRECTORY_NAME),
    (0xa5, "ediPartyName", &EDI_PARTY_NAME),
    (0x86, "uniformResourceIdentifier", &IA5_STRING),
    (0x87, "iPAddress", &IP_ADDRESS),
    (0x88, "registeredID", &IMPLICIT_OID),
]);

static OTHER_NAME: Schema = Schema::Seq(&[
    req("type-id", OID, &UNKNOWN),
    req("value", &[0xa0], &UNKNOWN),
]);
static DIRECTORY_NAME: Schema = Schema::Summary(x509::explicit_name, &EXPLICIT_NAME);
static EDI_PARTY_NAME: Schema = Schema::Seq(&[
    opt("nameAssigner", &[0xa0], &UNKNOWN),
    req("partyName", &[0xa1], &UNKNOWN),
]);
static IP_ADDRESS: Schema = Schema::Special(Special::IpAddress);
static IMPLICIT_OID: Schema = Schema::Implicit(6);
static IMPLICIT_INT: Schema = Schema::Implicit(2);
static IMPLICIT_BOOL: Schema = Schema::Implicit(1);
static IMPLICIT_NULL: Schema = Schema::Implicit(5);
static IMPLICIT_GTIME: Schema = Schema::Implicit(24);
static KEY_ID: Schema = Schema::Special(Special::KeyId);

// --- Extensions (RFC 5280 and others) --------------------------------------

static EXTENSION: Schema = Schema::Summary(x509::extension, &EXTENSION_BODY);
static EXTENSION_BODY: Schema = Schema::Seq(&[
    req("extnID", OID, &UNKNOWN),
    opt("critical", BOOL, &UNKNOWN),
    req("extnValue", OCTETS, &EXTENSION_VALUES),
]);
static EXTENSIONS: Schema = Schema::SeqOf("Extension", &EXTENSION);
static EXPLICIT_EXTENSIONS: Schema = Schema::Seq(&[req("Extensions", SEQ, &EXTENSIONS)]);

macro_rules! encap {
    ($id:ident, $name:literal, $ids:expr, $schema:expr) => {
        static $id: Schema = Schema::Encap(&Schema::Seq(&[req($name, $ids, $schema)]));
    };
}

encap!(X_AKI, "AuthorityKeyIdentifier", SEQ, &AUTHORITY_KEY_ID);
encap!(X_SKI, "SubjectKeyIdentifier", OCTETS, &KEY_ID);
encap!(X_KEY_USAGE, "KeyUsage", BITS, &KEY_USAGE);
encap!(
    X_PKUP,
    "PrivateKeyUsagePeriod",
    SEQ,
    &PRIVATE_KEY_USAGE_PERIOD
);
encap!(
    X_POLICIES,
    "CertificatePolicies",
    SEQ,
    &CERTIFICATE_POLICIES
);
encap!(X_POLICY_MAPPINGS, "PolicyMappings", SEQ, &POLICY_MAPPINGS);
encap!(X_GENERAL_NAMES, "GeneralNames", SEQ, &GENERAL_NAMES);
encap!(
    X_DIRECTORY_ATTRIBUTES,
    "SubjectDirectoryAttributes",
    SEQ,
    &ATTRIBUTES_SEQ
);
encap!(
    X_BASIC_CONSTRAINTS,
    "BasicConstraints",
    SEQ,
    &BASIC_CONSTRAINTS
);
encap!(
    X_NAME_CONSTRAINTS,
    "NameConstraints",
    SEQ,
    &NAME_CONSTRAINTS
);
encap!(
    X_POLICY_CONSTRAINTS,
    "PolicyConstraints",
    SEQ,
    &POLICY_CONSTRAINTS
);
encap!(X_EKU, "ExtKeyUsageSyntax", SEQ, &EXT_KEY_USAGE);
encap!(
    X_CRL_DP,
    "CRLDistributionPoints",
    SEQ,
    &CRL_DISTRIBUTION_POINTS
);
encap!(X_SKIP_CERTS, "SkipCerts", INT, &UNKNOWN);
encap!(
    X_INFO_ACCESS,
    "AuthorityInfoAccessSyntax",
    SEQ,
    &INFO_ACCESS
);
encap!(X_TLS_FEATURE, "Features", SEQ, &TLS_FEATURES);
encap!(
    X_SCT_LIST,
    "SignedCertificateTimestampList",
    OCTETS,
    &SCT_LIST
);
encap!(X_POISON, "poison", &[0x05], &UNKNOWN);
encap!(X_CRL_NUMBER, "CRLNumber", INT, &UNKNOWN);
encap!(X_CRL_REASON, "CRLReason", ENUM, &CRL_REASON);
encap!(X_INVALIDITY, "InvalidityDate", GTIME, &UNKNOWN);
encap!(X_HOLD, "HoldInstructionCode", OID, &UNKNOWN);
encap!(
    X_IDP,
    "IssuingDistributionPoint",
    SEQ,
    &ISSUING_DISTRIBUTION_POINT
);
encap!(X_MS_TEMPLATE, "CertificateTemplate", SEQ, &MS_TEMPLATE);
encap!(
    X_MS_TEMPLATE_NAME,
    "CertificateTemplateName",
    &[0x1e],
    &UNKNOWN
);
encap!(X_MS_CA_VERSION, "CAVersion", INT, &UNKNOWN);
encap!(X_MS_PREVIOUS_HASH, "PreviousCACertHash", OCTETS, &KEY_ID);
encap!(X_NS_CERT_TYPE, "NetscapeCertType", BITS, &NS_CERT_TYPE);
encap!(X_IA5, "comment", &[0x16], &UNKNOWN);
encap!(X_OCSP_NONCE, "Nonce", OCTETS, &UNKNOWN);
encap!(X_OCSP_NOCHECK, "NULL", &[0x05], &UNKNOWN);
encap!(X_CRL_ID, "CrlID", SEQ, &OCSP_CRL_ID);
encap!(X_ARCHIVE_CUTOFF, "ArchiveCutoff", GTIME, &UNKNOWN);
encap!(
    X_ACCEPTABLE,
    "AcceptableResponses",
    SEQ,
    &ACCEPTABLE_RESPONSES
);
encap!(X_QC_STATEMENTS, "QCStatements", SEQ, &QC_STATEMENTS);

static EXTENSION_VALUES: Schema = Schema::DefinedBy(&[
    ("2.5.29.9", None, &X_DIRECTORY_ATTRIBUTES),
    ("2.5.29.14", None, &X_SKI),
    ("2.5.29.15", None, &X_KEY_USAGE),
    ("2.5.29.16", None, &X_PKUP),
    ("2.5.29.17", None, &X_GENERAL_NAMES),
    ("2.5.29.18", None, &X_GENERAL_NAMES),
    ("2.5.29.19", None, &X_BASIC_CONSTRAINTS),
    ("2.5.29.20", None, &X_CRL_NUMBER),
    ("2.5.29.21", None, &X_CRL_REASON),
    ("2.5.29.23", None, &X_HOLD),
    ("2.5.29.24", None, &X_INVALIDITY),
    ("2.5.29.27", None, &X_CRL_NUMBER),
    ("2.5.29.28", None, &X_IDP),
    ("2.5.29.29", None, &X_GENERAL_NAMES),
    ("2.5.29.30", None, &X_NAME_CONSTRAINTS),
    ("2.5.29.31", None, &X_CRL_DP),
    ("2.5.29.32", None, &X_POLICIES),
    ("2.5.29.33", None, &X_POLICY_MAPPINGS),
    ("2.5.29.35", None, &X_AKI),
    ("2.5.29.36", None, &X_POLICY_CONSTRAINTS),
    ("2.5.29.37", None, &X_EKU),
    ("2.5.29.46", None, &X_CRL_DP),
    ("2.5.29.54", None, &X_SKIP_CERTS),
    ("1.3.6.1.5.5.7.1.1", None, &X_INFO_ACCESS),
    ("1.3.6.1.5.5.7.1.3", None, &X_QC_STATEMENTS),
    ("1.3.6.1.5.5.7.1.11", None, &X_INFO_ACCESS),
    ("1.3.6.1.5.5.7.1.24", None, &X_TLS_FEATURE),
    ("1.3.6.1.4.1.11129.2.4.2", None, &X_SCT_LIST),
    ("1.3.6.1.4.1.11129.2.4.3", None, &X_POISON),
    ("1.3.6.1.4.1.11129.2.4.5", None, &X_SCT_LIST),
    ("1.3.6.1.4.1.311.20.2", None, &X_MS_TEMPLATE_NAME),
    ("1.3.6.1.4.1.311.21.1", None, &X_MS_CA_VERSION),
    ("1.3.6.1.4.1.311.21.2", None, &X_MS_PREVIOUS_HASH),
    ("1.3.6.1.4.1.311.21.7", None, &X_MS_TEMPLATE),
    ("1.3.6.1.4.1.311.21.10", None, &X_POLICIES),
    ("2.16.840.1.113730.1.1", None, &X_NS_CERT_TYPE),
    ("2.16.840.1.113730.1.13", None, &X_IA5),
    ("1.3.6.1.5.5.7.48.1.2", None, &X_OCSP_NONCE),
    ("1.3.6.1.5.5.7.48.1.3", None, &X_CRL_ID),
    ("1.3.6.1.5.5.7.48.1.4", None, &X_ACCEPTABLE),
    ("1.3.6.1.5.5.7.48.1.5", None, &X_OCSP_NOCHECK),
    ("1.3.6.1.5.5.7.48.1.6", None, &X_ARCHIVE_CUTOFF),
]);

static AUTHORITY_KEY_ID: Schema = Schema::Seq(&[
    opt("keyIdentifier", &[0x80], &KEY_ID),
    opt("authorityCertIssuer", &[0xa1], &GENERAL_NAMES),
    opt("authorityCertSerialNumber", &[0x82], &IMPLICIT_INT),
]);

pub const KEY_USAGE_BITS: &[&str] = &[
    "digitalSignature",
    "nonRepudiation",
    "keyEncipherment",
    "dataEncipherment",
    "keyAgreement",
    "keyCertSign",
    "cRLSign",
    "encipherOnly",
    "decipherOnly",
];
static KEY_USAGE: Schema = Schema::Bits(KEY_USAGE_BITS);

pub const NS_CERT_TYPE_BITS: &[&str] = &[
    "sslClient",
    "sslServer",
    "smime",
    "objectSigning",
    "reserved",
    "sslCA",
    "smimeCA",
    "objectSigningCA",
];
static NS_CERT_TYPE: Schema = Schema::Bits(NS_CERT_TYPE_BITS);

pub const REASON_FLAGS_BITS: &[&str] = &[
    "unused",
    "keyCompromise",
    "cACompromise",
    "affiliationChanged",
    "superseded",
    "cessationOfOperation",
    "certificateHold",
    "privilegeWithdrawn",
    "aACompromise",
];
static REASON_FLAGS: Schema = Schema::Bits(REASON_FLAGS_BITS);

pub const CRL_REASONS: EnumTable = &[
    (0, "unspecified"),
    (1, "keyCompromise"),
    (2, "cACompromise"),
    (3, "affiliationChanged"),
    (4, "superseded"),
    (5, "cessationOfOperation"),
    (6, "certificateHold"),
    (8, "removeFromCRL"),
    (9, "privilegeWithdrawn"),
    (10, "aACompromise"),
];
static CRL_REASON: Schema = Schema::Enum(CRL_REASONS);

static PRIVATE_KEY_USAGE_PERIOD: Schema = Schema::Seq(&[
    opt("notBefore", &[0x80], &IMPLICIT_GTIME),
    opt("notAfter", &[0x81], &IMPLICIT_GTIME),
]);

static CERTIFICATE_POLICIES: Schema = Schema::SeqOf("PolicyInformation", &POLICY_INFORMATION);
static POLICY_INFORMATION: Schema = Schema::Seq(&[
    req("policyIdentifier", OID, &UNKNOWN),
    opt("policyQualifiers", SEQ, &POLICY_QUALIFIERS),
]);
static POLICY_QUALIFIERS: Schema = Schema::SeqOf("PolicyQualifierInfo", &POLICY_QUALIFIER);
static POLICY_QUALIFIER: Schema = Schema::Seq(&[
    req("policyQualifierId", OID, &UNKNOWN),
    req("qualifier", ANY, &QUALIFIERS),
]);
static QUALIFIERS: Schema = Schema::DefinedBy(&[
    ("1.3.6.1.5.5.7.2.1", Some("cPSuri"), &UNKNOWN),
    ("1.3.6.1.5.5.7.2.2", Some("userNotice"), &USER_NOTICE),
]);
static USER_NOTICE: Schema = Schema::Seq(&[
    opt("noticeRef", SEQ, &NOTICE_REFERENCE),
    opt("explicitText", ANY, &UNKNOWN),
]);
static NOTICE_REFERENCE: Schema = Schema::Seq(&[
    req("organization", ANY, &UNKNOWN),
    req("noticeNumbers", SEQ, &NOTICE_NUMBERS),
]);
static NOTICE_NUMBERS: Schema = Schema::SeqOf("noticeNumber", &UNKNOWN);

static POLICY_MAPPINGS: Schema = Schema::SeqOf("PolicyMapping", &POLICY_MAPPING);
static POLICY_MAPPING: Schema = Schema::Seq(&[
    req("issuerDomainPolicy", OID, &UNKNOWN),
    req("subjectDomainPolicy", OID, &UNKNOWN),
]);

static ATTRIBUTES_SEQ: Schema = Schema::SeqOf("Attribute", &ATTRIBUTE);

static BASIC_CONSTRAINTS: Schema = Schema::Seq(&[
    opt("cA", BOOL, &UNKNOWN),
    opt("pathLenConstraint", INT, &UNKNOWN),
]);

static NAME_CONSTRAINTS: Schema = Schema::Seq(&[
    opt("permittedSubtrees", &[0xa0], &GENERAL_SUBTREES),
    opt("excludedSubtrees", &[0xa1], &GENERAL_SUBTREES),
]);
static GENERAL_SUBTREES: Schema = Schema::SeqOf("GeneralSubtree", &GENERAL_SUBTREE);
static GENERAL_SUBTREE: Schema = Schema::Summary(x509::general_subtree, &GENERAL_SUBTREE_BODY);
static GENERAL_SUBTREE_BODY: Schema = Schema::Seq(&[
    req("base", ANY, &GENERAL_NAME),
    opt("minimum", &[0x80], &IMPLICIT_INT),
    opt("maximum", &[0x81], &IMPLICIT_INT),
]);

static POLICY_CONSTRAINTS: Schema = Schema::Seq(&[
    opt("requireExplicitPolicy", &[0x80], &IMPLICIT_INT),
    opt("inhibitPolicyMapping", &[0x81], &IMPLICIT_INT),
]);

static EXT_KEY_USAGE: Schema = Schema::SeqOf("KeyPurposeId", &UNKNOWN);

static CRL_DISTRIBUTION_POINTS: Schema = Schema::SeqOf("DistributionPoint", &DISTRIBUTION_POINT);
static DISTRIBUTION_POINT: Schema = Schema::Seq(&[
    opt("distributionPoint", &[0xa0], &DISTRIBUTION_POINT_NAME),
    opt("reasons", &[0x81], &REASON_FLAGS),
    opt("cRLIssuer", &[0xa2], &GENERAL_NAMES),
]);
/// DistributionPointName, a CHOICE (as the content of its `[0]`).
static DISTRIBUTION_POINT_NAME: Schema = Schema::Seq(&[
    opt("fullName", &[0xa0], &GENERAL_NAMES),
    opt("nameRelativeToCRLIssuer", &[0xa1], &RDN),
]);

static ISSUING_DISTRIBUTION_POINT: Schema = Schema::Seq(&[
    opt("distributionPoint", &[0xa0], &DISTRIBUTION_POINT_NAME),
    opt("onlyContainsUserCerts", &[0x81], &IMPLICIT_BOOL),
    opt("onlyContainsCACerts", &[0x82], &IMPLICIT_BOOL),
    opt("onlySomeReasons", &[0x83], &REASON_FLAGS),
    opt("indirectCRL", &[0x84], &IMPLICIT_BOOL),
    opt("onlyContainsAttributeCerts", &[0x85], &IMPLICIT_BOOL),
]);

static INFO_ACCESS: Schema = Schema::SeqOf("AccessDescription", &ACCESS_DESCRIPTION);
static ACCESS_DESCRIPTION: Schema = Schema::Seq(&[
    req("accessMethod", OID, &UNKNOWN),
    req("accessLocation", ANY, &GENERAL_NAME),
]);

pub const TLS_EXTENSIONS: EnumTable = &[
    (0, "server_name"),
    (5, "status_request"),
    (17, "status_request_v2"),
];
static TLS_FEATURES: Schema = Schema::SeqOf("Feature", &TLS_FEATURE);
static TLS_FEATURE: Schema = Schema::Enum(TLS_EXTENSIONS);

static SCT_LIST: Schema = Schema::Special(Special::SctList);

/// Microsoft CertificateTemplate (szOID_CERTIFICATE_TEMPLATE).
static MS_TEMPLATE: Schema = Schema::Seq(&[
    req("templateID", OID, &UNKNOWN),
    req("templateMajorVersion", INT, &UNKNOWN),
    opt("templateMinorVersion", INT, &UNKNOWN),
]);

static QC_STATEMENTS: Schema = Schema::SeqOf("QCStatement", &QC_STATEMENT);
static QC_STATEMENT: Schema = Schema::Seq(&[
    req("statementId", OID, &UNKNOWN),
    opt("statementInfo", ANY, &UNKNOWN),
]);

static SPKI: Schema = Schema::Summary(x509::public_key_info, &SPKI_BODY);
static SPKI_BODY: Schema = Schema::Seq(&[
    req("algorithm", SEQ, &ALGORITHM),
    req("subjectPublicKey", BITS, &PUBLIC_KEYS),
]);

const RSA: &str = "1.2.840.113549.1.1.1";
const RSA_PSS: &str = "1.2.840.113549.1.1.10";
const EC: &str = "1.2.840.10045.2.1";
const DSA: &str = "1.2.840.10040.4.1";
const DH: &str = "1.2.840.10046.2.1";

/// Public keys (the content of subjectPublicKey) by algorithm.
static PUBLIC_KEYS: Schema = Schema::ByAlgorithm(&[
    (RSA, None, &ENCAP_RSA_PUBLIC_KEY),
    (RSA_PSS, None, &ENCAP_RSA_PUBLIC_KEY),
    ("1.2.840.113549.1.1.7", None, &ENCAP_RSA_PUBLIC_KEY),
    (EC, None, &EC_POINT),
    (DSA, None, &ENCAP_PUBLIC_INT),
    (DH, None, &ENCAP_PUBLIC_INT),
    ("1.2.840.113549.1.3.1", None, &ENCAP_PUBLIC_INT),
    ("1.3.101.110", None, &RAW_KEY),
    ("1.3.101.111", None, &RAW_KEY),
    ("1.3.101.112", None, &RAW_KEY),
    ("1.3.101.113", None, &RAW_KEY),
]);
static EC_POINT: Schema = Schema::Special(Special::EcPoint);
static RAW_KEY: Schema = Schema::Special(Special::RawKey);
static ENCAP_RSA_PUBLIC_KEY: Schema = Schema::Encap(&TOP_RSA_PUBLIC_KEY);
static ENCAP_PUBLIC_INT: Schema = Schema::Encap(&Schema::Seq(&[req("publicKey", INT, &UNKNOWN)]));

pub static RSA_PUBLIC_KEY: Schema = Schema::Summary(x509::rsa_public_key, &RSA_PUBLIC_KEY_BODY);
static RSA_PUBLIC_KEY_BODY: Schema = Schema::Seq(&[
    req("modulus", INT, &UNKNOWN),
    req("publicExponent", INT, &UNKNOWN),
]);

/// Signature values by algorithm: (EC)DSA signatures are DER.
static SIGNATURE_VALUES: Schema = Schema::ByAlgorithm(&[
    ("1.2.840.10045.4.1", None, &ENCAP_DSA_SIG),
    ("1.2.840.10045.4.3.1", None, &ENCAP_DSA_SIG),
    ("1.2.840.10045.4.3.2", None, &ENCAP_DSA_SIG),
    ("1.2.840.10045.4.3.3", None, &ENCAP_DSA_SIG),
    ("1.2.840.10045.4.3.4", None, &ENCAP_DSA_SIG),
    ("1.2.840.10040.4.3", None, &ENCAP_DSA_SIG),
    ("2.16.840.1.101.3.4.3.1", None, &ENCAP_DSA_SIG),
    ("2.16.840.1.101.3.4.3.2", None, &ENCAP_DSA_SIG),
    (EC, None, &ENCAP_DSA_SIG),
]);
static ENCAP_DSA_SIG: Schema = Schema::Encap(&Schema::Seq(&[req("Dss-Sig-Value", SEQ, &DSA_SIG)]));
static DSA_SIG: Schema = Schema::Seq(&[req("r", INT, &UNKNOWN), req("s", INT, &UNKNOWN)]);

// --- X.509 certificates (RFC 5280) -----------------------------------------

pub static CERTIFICATE: Schema = Schema::Summary(super::summary::certificate, &CERTIFICATE_BODY);
static CERTIFICATE_BODY: Schema = Schema::Seq(&[
    req("tbsCertificate", SEQ, &TBS_CERTIFICATE),
    req("signatureAlgorithm", SEQ, &ALGORITHM),
    req("signatureValue", BITS, &SIGNATURE_VALUES),
]);

static TBS_CERTIFICATE: Schema = Schema::Seq(&[
    opt("version", &[0xa0], &EXPLICIT_VERSION),
    req("serialNumber", INT, &UNKNOWN),
    req("signature", SEQ, &ALGORITHM),
    req("issuer", SEQ, &NAME),
    req("validity", SEQ, &VALIDITY),
    req("subject", SEQ, &NAME),
    req("subjectPublicKeyInfo", SEQ, &SPKI),
    opt("issuerUniqueID", &[0x81, 0xa1], &UNKNOWN),
    opt("subjectUniqueID", &[0x82, 0xa2], &UNKNOWN),
    opt("extensions", &[0xa3], &EXPLICIT_EXTENSIONS),
]);

static EXPLICIT_VERSION: Schema = Schema::Seq(&[req("Version", INT, &VERSION)]);
static VERSION: Schema = Schema::Enum(&[(0, "v1"), (1, "v2"), (2, "v3")]);

static VALIDITY: Schema = Schema::Summary(x509::validity, &VALIDITY_BODY);
static VALIDITY_BODY: Schema = Schema::Seq(&[
    req("notBefore", TIME, &UNKNOWN),
    req("notAfter", TIME, &UNKNOWN),
]);

// --- CRLs ------------------------------------------------------------------

pub static CERTIFICATE_LIST: Schema = Schema::Seq(&[
    req("tbsCertList", SEQ, &TBS_CERT_LIST),
    req("signatureAlgorithm", SEQ, &ALGORITHM),
    req("signatureValue", BITS, &SIGNATURE_VALUES),
]);

static TBS_CERT_LIST: Schema = Schema::Seq(&[
    opt("version", INT, &VERSION),
    req("signature", SEQ, &ALGORITHM),
    req("issuer", SEQ, &NAME),
    req("thisUpdate", TIME, &UNKNOWN),
    opt("nextUpdate", TIME, &UNKNOWN),
    opt("revokedCertificates", SEQ, &REVOKED_LIST),
    opt("crlExtensions", &[0xa0], &EXPLICIT_EXTENSIONS),
]);

static REVOKED_LIST: Schema = Schema::SeqOf("revokedCertificate", &REVOKED);
static REVOKED: Schema = Schema::Summary(x509::revoked, &REVOKED_BODY);
static REVOKED_BODY: Schema = Schema::Seq(&[
    req("userCertificate", INT, &UNKNOWN),
    req("revocationDate", TIME, &UNKNOWN),
    opt("crlEntryExtensions", SEQ, &EXTENSIONS),
]);

// --- PKCS#10 certification requests ----------------------------------------

pub static CERTIFICATION_REQUEST: Schema = Schema::Seq(&[
    req("certificationRequestInfo", SEQ, &REQUEST_INFO),
    req("signatureAlgorithm", SEQ, &ALGORITHM),
    req("signature", BITS, &SIGNATURE_VALUES),
]);

static REQUEST_INFO: Schema = Schema::Seq(&[
    req("version", INT, &UNKNOWN),
    req("subject", SEQ, &NAME),
    req("subjectPKInfo", SEQ, &SPKI),
    opt("attributes", &[0xa0], &ATTRIBUTES),
]);

// --- PKCS#7 / CMS (RFC 5652) -----------------------------------------------

pub static CONTENT_INFO: Schema = Schema::Seq(&[
    req("contentType", OID, &UNKNOWN),
    opt("content", &[0xa0], &CONTENTS),
]);

/// The `[0] EXPLICIT` content of a ContentInfo, by content type.
static CONTENTS: Schema = Schema::DefinedBy(&[
    ("1.2.840.113549.1.7.1", None, &EXPLICIT_DATA),
    ("1.2.840.113549.1.7.2", None, &EXPLICIT_SIGNED_DATA),
    ("1.2.840.113549.1.7.3", None, &EXPLICIT_ENVELOPED_DATA),
    ("1.2.840.113549.1.7.5", None, &EXPLICIT_DIGESTED_DATA),
    ("1.2.840.113549.1.7.6", None, &EXPLICIT_ENCRYPTED_DATA),
    (
        "1.2.840.113549.1.9.16.1.2",
        None,
        &EXPLICIT_AUTHENTICATED_DATA,
    ),
    ("1.2.840.113549.1.9.16.1.9", None, &EXPLICIT_COMPRESSED_DATA),
    (
        "1.2.840.113549.1.9.16.1.23",
        None,
        &EXPLICIT_AUTH_ENVELOPED_DATA,
    ),
]);

static EXPLICIT_DATA: Schema = Schema::Seq(&[req("Data", &[0x04, 0x24], &EMBEDDED)]);
static EXPLICIT_SIGNED_DATA: Schema = Schema::Seq(&[req("SignedData", SEQ, &SIGNED_DATA)]);
static EXPLICIT_ENVELOPED_DATA: Schema = Schema::Seq(&[req("EnvelopedData", SEQ, &ENVELOPED_DATA)]);
static EXPLICIT_DIGESTED_DATA: Schema = Schema::Seq(&[req("DigestedData", SEQ, &DIGESTED_DATA)]);
static EXPLICIT_ENCRYPTED_DATA: Schema = Schema::Seq(&[req("EncryptedData", SEQ, &ENCRYPTED_DATA)]);
static EXPLICIT_AUTHENTICATED_DATA: Schema =
    Schema::Seq(&[req("AuthenticatedData", SEQ, &AUTHENTICATED_DATA)]);
static EXPLICIT_COMPRESSED_DATA: Schema =
    Schema::Seq(&[req("CompressedData", SEQ, &COMPRESSED_DATA)]);
static EXPLICIT_AUTH_ENVELOPED_DATA: Schema =
    Schema::Seq(&[req("AuthEnvelopedData", SEQ, &AUTH_ENVELOPED_DATA)]);

static EMBEDDED: Schema = Schema::Special(Special::Embedded);

static SIGNED_DATA: Schema = Schema::Seq(&[
    req("version", INT, &UNKNOWN),
    req("digestAlgorithms", SET, &DIGEST_ALGORITHMS),
    req("encapContentInfo", SEQ, &ENCAP_CONTENT_INFO),
    opt("certificates", &[0xa0], &CERTIFICATE_SET),
    opt("crls", &[0xa1], &CRL_SET),
    req("signerInfos", SET, &SIGNER_INFOS),
]);

static DIGEST_ALGORITHMS: Schema = Schema::SeqOf("DigestAlgorithmIdentifier", &ALGORITHM);
static CERTIFICATE_SET: Schema = Schema::SeqOf("Certificate", &CERTIFICATE);
static CRL_SET: Schema = Schema::SeqOf("CertificateList", &CERTIFICATE_LIST);
static SIGNER_INFOS: Schema = Schema::SeqOf("SignerInfo", &SIGNER_INFO);

static ENCAP_CONTENT_INFO: Schema = Schema::Seq(&[
    req("eContentType", OID, &UNKNOWN),
    opt("eContent", &[0xa0], &ECONTENT),
]);

/// `[0] EXPLICIT` content by content type. CMS wraps it in an OCTET
/// STRING; PKCS #7 v1.5 (Authenticode, CTLs) has the structure directly.
static ECONTENT: Schema = Schema::DefinedBy(&[
    ("1.3.6.1.4.1.311.2.1.4", None, &EXPLICIT_SPC_INDIRECT_DATA),
    ("1.3.6.1.4.1.311.10.1", None, &EXPLICIT_CTL),
    ("1.2.840.113549.1.9.16.1.4", None, &EXPLICIT_TST_INFO),
    ("1.2.840.113549.1.7.1", None, &EXPLICIT_DATA),
]);

static EXPLICIT_TST_INFO: Schema = Schema::Seq(&[req("eContent", OCTETS, &ENCAP_TST_INFO)]);
static ENCAP_TST_INFO: Schema = Schema::Encap(&TOP_TST_INFO);

static CONTENT_INFOS: Schema = Schema::SeqOf("ContentInfo", &CONTENT_INFO);

static SIGNER_INFO: Schema = Schema::Summary(x509::signer_info, &SIGNER_INFO_BODY);
static SIGNER_INFO_BODY: Schema = Schema::Seq(&[
    req("version", INT, &UNKNOWN),
    req("sid", ANY, &SIGNER_IDENTIFIER),
    req("digestAlgorithm", SEQ, &ALGORITHM),
    opt("signedAttrs", &[0xa0], &ATTRIBUTES),
    req("signatureAlgorithm", SEQ, &ALGORITHM),
    req("signature", OCTETS, &SIGNATURE_VALUES),
    opt("unsignedAttrs", &[0xa1], &ATTRIBUTES),
]);

static SIGNER_IDENTIFIER: Schema = Schema::Choice(&[
    (0x30, "issuerAndSerialNumber", &ISSUER_AND_SERIAL),
    (0x80, "subjectKeyIdentifier", &KEY_ID),
]);

static ISSUER_AND_SERIAL: Schema = Schema::Seq(&[
    req("issuer", SEQ, &NAME),
    req("serialNumber", INT, &UNKNOWN),
]);

static ENVELOPED_DATA: Schema = Schema::Seq(&[
    req("version", INT, &UNKNOWN),
    opt("originatorInfo", &[0xa0], &ORIGINATOR_INFO),
    req("recipientInfos", SET, &RECIPIENT_INFOS),
    req("encryptedContentInfo", SEQ, &ENCRYPTED_CONTENT_INFO),
    opt("unprotectedAttrs", &[0xa1], &ATTRIBUTES),
]);

static ORIGINATOR_INFO: Schema = Schema::Seq(&[
    opt("certs", &[0xa0], &CERTIFICATE_SET),
    opt("crls", &[0xa1], &CRL_SET),
]);

static RECIPIENT_INFOS: Schema = Schema::SeqOf("RecipientInfo", &RECIPIENT_INFO);
static RECIPIENT_INFO: Schema = Schema::Choice(&[
    (0x30, "KeyTransRecipientInfo", &KEY_TRANS_RECIPIENT),
    (0xa1, "KeyAgreeRecipientInfo", &KEY_AGREE_RECIPIENT),
    (0xa2, "KEKRecipientInfo", &KEK_RECIPIENT),
    (0xa3, "PasswordRecipientInfo", &PASSWORD_RECIPIENT),
    (0xa4, "OtherRecipientInfo", &UNKNOWN),
]);

static KEY_TRANS_RECIPIENT: Schema = Schema::Seq(&[
    req("version", INT, &UNKNOWN),
    req("rid", ANY, &SIGNER_IDENTIFIER),
    req("keyEncryptionAlgorithm", SEQ, &ALGORITHM),
    req("encryptedKey", OCTETS, &UNKNOWN),
]);

static KEY_AGREE_RECIPIENT: Schema = Schema::Seq(&[
    req("version", INT, &UNKNOWN),
    req("originator", &[0xa0], &ORIGINATOR_IDENTIFIER),
    opt("ukm", &[0xa1], &UNKNOWN),
    req("keyEncryptionAlgorithm", SEQ, &ALGORITHM),
    req("recipientEncryptedKeys", SEQ, &RECIPIENT_ENCRYPTED_KEYS),
]);
/// OriginatorIdentifierOrKey, a CHOICE (as the content of its `[0]`).
static ORIGINATOR_IDENTIFIER: Schema = Schema::Seq(&[
    opt("issuerAndSerialNumber", SEQ, &ISSUER_AND_SERIAL),
    opt("subjectKeyIdentifier", &[0x80], &KEY_ID),
    opt("originatorKey", &[0xa1], &ORIGINATOR_KEY),
]);
static ORIGINATOR_KEY: Schema = Schema::Seq(&[
    req("algorithm", SEQ, &ALGORITHM),
    req("publicKey", BITS, &PUBLIC_KEYS),
]);
static RECIPIENT_ENCRYPTED_KEYS: Schema =
    Schema::SeqOf("RecipientEncryptedKey", &RECIPIENT_ENCRYPTED_KEY);
static RECIPIENT_ENCRYPTED_KEY: Schema = Schema::Seq(&[
    req("rid", ANY, &KEY_AGREE_RECIPIENT_ID),
    req("encryptedKey", OCTETS, &UNKNOWN),
]);
static KEY_AGREE_RECIPIENT_ID: Schema = Schema::Choice(&[
    (0x30, "issuerAndSerialNumber", &ISSUER_AND_SERIAL),
    (0xa0, "rKeyId", &RECIPIENT_KEY_ID),
]);
static RECIPIENT_KEY_ID: Schema = Schema::Seq(&[
    req("subjectKeyIdentifier", OCTETS, &KEY_ID),
    opt("date", GTIME, &UNKNOWN),
    opt("other", SEQ, &UNKNOWN),
]);

static KEK_RECIPIENT: Schema = Schema::Seq(&[
    req("version", INT, &UNKNOWN),
    req("kekid", SEQ, &KEK_IDENTIFIER),
    req("keyEncryptionAlgorithm", SEQ, &ALGORITHM),
    req("encryptedKey", OCTETS, &UNKNOWN),
]);
static KEK_IDENTIFIER: Schema = Schema::Seq(&[
    req("keyIdentifier", OCTETS, &KEY_ID),
    opt("date", GTIME, &UNKNOWN),
    opt("other", SEQ, &UNKNOWN),
]);

static PASSWORD_RECIPIENT: Schema = Schema::Seq(&[
    req("version", INT, &UNKNOWN),
    opt("keyDerivationAlgorithm", &[0xa0], &ALGORITHM),
    req("keyEncryptionAlgorithm", SEQ, &ALGORITHM),
    req("encryptedKey", OCTETS, &UNKNOWN),
]);

static ENCRYPTED_CONTENT_INFO: Schema = Schema::Seq(&[
    req("contentType", OID, &UNKNOWN),
    req("contentEncryptionAlgorithm", SEQ, &ALGORITHM),
    opt("encryptedContent", &[0x80, 0xa0], &UNKNOWN),
]);

static ENCRYPTED_DATA: Schema = Schema::Seq(&[
    req("version", INT, &UNKNOWN),
    req("encryptedContentInfo", SEQ, &ENCRYPTED_CONTENT_INFO),
    opt("unprotectedAttrs", &[0xa1], &ATTRIBUTES),
]);

static DIGESTED_DATA: Schema = Schema::Seq(&[
    req("version", INT, &UNKNOWN),
    req("digestAlgorithm", SEQ, &ALGORITHM),
    req("encapContentInfo", SEQ, &ENCAP_CONTENT_INFO),
    req("digest", OCTETS, &KEY_ID),
]);

static AUTHENTICATED_DATA: Schema = Schema::Seq(&[
    req("version", INT, &UNKNOWN),
    opt("originatorInfo", &[0xa0], &ORIGINATOR_INFO),
    req("recipientInfos", SET, &RECIPIENT_INFOS),
    req("macAlgorithm", SEQ, &ALGORITHM),
    opt("digestAlgorithm", &[0xa1], &ALGORITHM),
    req("encapContentInfo", SEQ, &ENCAP_CONTENT_INFO),
    opt("authAttrs", &[0xa2], &ATTRIBUTES),
    req("mac", OCTETS, &KEY_ID),
    opt("unauthAttrs", &[0xa3], &ATTRIBUTES),
]);

static AUTH_ENVELOPED_DATA: Schema = Schema::Seq(&[
    req("version", INT, &UNKNOWN),
    opt("originatorInfo", &[0xa0], &ORIGINATOR_INFO),
    req("recipientInfos", SET, &RECIPIENT_INFOS),
    req("authEncryptedContentInfo", SEQ, &ENCRYPTED_CONTENT_INFO),
    opt("authAttrs", &[0xa1], &ATTRIBUTES),
    req("mac", OCTETS, &KEY_ID),
    opt("unauthAttrs", &[0xa2], &ATTRIBUTES),
]);

static COMPRESSED_DATA: Schema = Schema::Seq(&[
    req("version", INT, &UNKNOWN),
    req("compressionAlgorithm", SEQ, &ALGORITHM),
    req("encapContentInfo", SEQ, &ENCAP_CONTENT_INFO),
]);

// --- Microsoft Authenticode ------------------------------------------------
// ("Windows Authenticode Portable Executable Signature Format")

static EXPLICIT_SPC_INDIRECT_DATA: Schema = Schema::Seq(&[req(
    "SpcIndirectDataContent",
    SEQ,
    &SPC_INDIRECT_DATA_CONTENT,
)]);

static SPC_INDIRECT_DATA_CONTENT: Schema = Schema::Seq(&[
    req("data", SEQ, &SPC_ATTRIBUTE_TYPE_AND_OPTIONAL_VALUE),
    req("messageDigest", SEQ, &DIGEST_INFO),
]);

static SPC_ATTRIBUTE_TYPE_AND_OPTIONAL_VALUE: Schema = Schema::Seq(&[
    req("type", OID, &UNKNOWN),
    opt("value", ANY, &SPC_ATTRIBUTE_VALUE),
]);

static SPC_ATTRIBUTE_VALUE: Schema = Schema::DefinedBy(&[
    (
        "1.3.6.1.4.1.311.2.1.15",
        Some("SpcPeImageData"),
        &SPC_PE_IMAGE_DATA,
    ),
    ("1.3.6.1.4.1.311.2.1.30", Some("SpcSipInfo"), &SPC_SIP_INFO),
]);

static SPC_PE_IMAGE_DATA: Schema = Schema::Seq(&[
    opt("flags", BITS, &UNKNOWN),
    opt("file", &[0xa0], &SPC_LINK),
]);

/// SpcLink, a CHOICE: one of these.
static SPC_LINK: Schema = Schema::Seq(&[
    opt("url", &[0x80], &IA5_STRING),
    opt("moniker", &[0xa1], &SPC_SERIALIZED_OBJECT),
    opt("file", &[0xa2], &SPC_STRING),
]);

static SPC_SERIALIZED_OBJECT: Schema = Schema::Seq(&[
    req("classId", OCTETS, &UNKNOWN),
    req("serializedData", OCTETS, &UNKNOWN),
]);

/// SpcString, a CHOICE: one of these.
static SPC_STRING: Schema = Schema::Seq(&[
    opt("unicode", &[0x80], &BMP_STRING),
    opt("ascii", &[0x81], &IA5_STRING),
]);

static BMP_STRING: Schema = Schema::Implicit(30);
static IA5_STRING: Schema = Schema::Implicit(22);

/// Scripts, installers and other files signed through a subject interface
/// package.
static SPC_SIP_INFO: Schema = Schema::Seq(&[
    req("version", INT, &UNKNOWN),
    req("sipGuid", OCTETS, &UNKNOWN),
    req("reserved1", INT, &UNKNOWN),
    req("reserved2", INT, &UNKNOWN),
    req("reserved3", INT, &UNKNOWN),
    req("reserved4", INT, &UNKNOWN),
    req("reserved5", INT, &UNKNOWN),
]);

static SPC_SP_OPUS_INFOS: Schema = Schema::SeqOf("SpcSpOpusInfo", &SPC_SP_OPUS_INFO);
static SPC_SP_OPUS_INFO: Schema = Schema::Seq(&[
    opt("programName", &[0xa0], &SPC_STRING),
    opt("moreInfo", &[0xa1], &SPC_LINK),
]);

static SPC_STATEMENT_TYPES: Schema = Schema::SeqOf("SpcStatementType", &SPC_STATEMENT_TYPE);
static SPC_STATEMENT_TYPE: Schema = Schema::SeqOf("purpose", &UNKNOWN);

// --- Microsoft certificate trust lists (catalogs) ---------------------------

static EXPLICIT_CTL: Schema = Schema::Seq(&[req("CertificateTrustList", SEQ, &CTL)]);

static CTL: Schema = Schema::Seq(&[
    opt("version", INT, &UNKNOWN),
    req("subjectUsage", SEQ, &EXT_KEY_USAGE),
    opt("listIdentifier", OCTETS, &UNKNOWN),
    opt("sequenceNumber", INT, &UNKNOWN),
    req("ctlThisUpdate", TIME, &UNKNOWN),
    opt("ctlNextUpdate", TIME, &UNKNOWN),
    req("subjectAlgorithm", SEQ, &ALGORITHM),
    opt("trustedSubjects", SEQ, &TRUSTED_SUBJECTS),
    opt("ctlExtensions", &[0xa0], &EXPLICIT_EXTENSIONS),
]);
static TRUSTED_SUBJECTS: Schema = Schema::SeqOf("TrustedSubject", &TRUSTED_SUBJECT);
static TRUSTED_SUBJECT: Schema = Schema::Seq(&[
    req("subjectIdentifier", OCTETS, &KEY_ID),
    opt("subjectAttributes", SET, &ATTRIBUTES),
]);

// --- PKCS#12 (RFC 7292) ----------------------------------------------------

pub static PFX: Schema = Schema::Seq(&[
    req("version", INT, &UNKNOWN),
    req("authSafe", SEQ, &AUTH_SAFE),
    opt("macData", SEQ, &MAC_DATA),
]);

static AUTH_SAFE: Schema = Schema::Seq(&[
    req("contentType", OID, &UNKNOWN),
    opt("content", &[0xa0], &AUTH_SAFE_CONTENT),
]);

/// The authenticated safe: (for password integrity) data holding a
/// sequence of ContentInfos, each plain or encrypted SafeContents.
static AUTH_SAFE_CONTENT: Schema = Schema::DefinedBy(&[(
    "1.2.840.113549.1.7.1",
    None,
    &Schema::Seq(&[req(
        "AuthenticatedSafe",
        OCTETS,
        &Schema::Encap(&Schema::Seq(&[req(
            "AuthenticatedSafe",
            SEQ,
            &Schema::SeqOf("ContentInfo", &P12_CONTENT_INFO),
        )])),
    )]),
)]);
static P12_CONTENT_INFO: Schema = Schema::Seq(&[
    req("contentType", OID, &UNKNOWN),
    opt("content", &[0xa0], &P12_CONTENTS),
]);
static P12_CONTENTS: Schema = Schema::DefinedBy(&[
    (
        "1.2.840.113549.1.7.1",
        None,
        &Schema::Seq(&[req(
            "SafeContents",
            OCTETS,
            &Schema::Encap(&Schema::Seq(&[req("SafeContents", SEQ, &SAFE_CONTENTS)])),
        )]),
    ),
    ("1.2.840.113549.1.7.6", None, &EXPLICIT_ENCRYPTED_DATA),
]);
static SAFE_CONTENTS: Schema = Schema::SeqOf("SafeBag", &SAFE_BAG);
static SAFE_BAG: Schema = Schema::Seq(&[
    req("bagId", OID, &UNKNOWN),
    req("bagValue", &[0xa0], &BAG_VALUES),
    opt("bagAttributes", SET, &ATTRIBUTES),
]);
static BAG_VALUES: Schema = Schema::DefinedBy(&[
    (
        "1.2.840.113549.1.12.10.1.1",
        None,
        &Schema::Seq(&[req("PrivateKeyInfo", SEQ, &PRIVATE_KEY_INFO)]),
    ),
    (
        "1.2.840.113549.1.12.10.1.2",
        None,
        &Schema::Seq(&[req(
            "EncryptedPrivateKeyInfo",
            SEQ,
            &ENCRYPTED_PRIVATE_KEY_INFO,
        )]),
    ),
    (
        "1.2.840.113549.1.12.10.1.3",
        None,
        &Schema::Seq(&[req("CertBag", SEQ, &CERT_BAG)]),
    ),
    (
        "1.2.840.113549.1.12.10.1.4",
        None,
        &Schema::Seq(&[req("CRLBag", SEQ, &CRL_BAG)]),
    ),
    (
        "1.2.840.113549.1.12.10.1.5",
        None,
        &Schema::Seq(&[req("SecretBag", SEQ, &SECRET_BAG)]),
    ),
    (
        "1.2.840.113549.1.12.10.1.6",
        None,
        &Schema::Seq(&[req("SafeContents", SEQ, &SAFE_CONTENTS)]),
    ),
]);
static CERT_BAG: Schema = Schema::Seq(&[
    req("certId", OID, &UNKNOWN),
    req("certValue", &[0xa0], &CERT_VALUES),
]);
static CERT_VALUES: Schema = Schema::DefinedBy(&[(
    "1.2.840.113549.1.9.22.1",
    None,
    &Schema::Seq(&[req(
        "x509Certificate",
        OCTETS,
        &Schema::Encap(&TOP_CERTIFICATE),
    )]),
)]);
static CRL_BAG: Schema = Schema::Seq(&[
    req("crlId", OID, &UNKNOWN),
    req("crlValue", &[0xa0], &CRL_VALUES),
]);
static CRL_VALUES: Schema = Schema::DefinedBy(&[(
    "1.2.840.113549.1.9.23.1",
    None,
    &Schema::Seq(&[req("x509CRL", OCTETS, &Schema::Encap(&TOP_CRL))]),
)]);
/// SecretBag: a type, and the value (Java stores a shrouded key bag).
static SECRET_BAG: Schema = Schema::Seq(&[
    req("secretTypeId", OID, &UNKNOWN),
    req("secretValue", &[0xa0], &SECRET_VALUES),
]);
static SECRET_VALUES: Schema = Schema::DefinedBy(&[(
    "1.2.840.113549.1.12.10.1.2",
    None,
    &Schema::Seq(&[req(
        "secretValue",
        OCTETS,
        &Schema::Encap(&TOP_ENCRYPTED_PRIVATE_KEY_INFO),
    )]),
)]);

static MAC_DATA: Schema = Schema::Seq(&[
    req("mac", SEQ, &DIGEST_INFO),
    req("macSalt", OCTETS, &UNKNOWN),
    opt("iterations", INT, &UNKNOWN),
]);

static DIGEST_INFO: Schema = Schema::Seq(&[
    req("digestAlgorithm", SEQ, &ALGORITHM),
    req("digest", OCTETS, &KEY_ID),
]);

// --- Keys (PKCS#1, PKCS#8, SEC 1, PKCS#3, DSA) ------------------------------

pub static RSA_PRIVATE_KEY: Schema = Schema::Seq(&[
    req("version", INT, &UNKNOWN),
    req("modulus", INT, &UNKNOWN),
    req("publicExponent", INT, &UNKNOWN),
    req("privateExponent", INT, &UNKNOWN),
    req("prime1", INT, &UNKNOWN),
    req("prime2", INT, &UNKNOWN),
    req("exponent1", INT, &UNKNOWN),
    req("exponent2", INT, &UNKNOWN),
    req("coefficient", INT, &UNKNOWN),
    opt("otherPrimeInfos", SEQ, &UNKNOWN),
]);

pub static EC_PRIVATE_KEY: Schema = Schema::Seq(&[
    req("version", INT, &UNKNOWN),
    req("privateKey", OCTETS, &UNKNOWN),
    opt("parameters", &[0xa0], &EXPLICIT_CURVE),
    opt("publicKey", &[0xa1], &EXPLICIT_EC_POINT),
]);
static EXPLICIT_CURVE: Schema = Schema::Seq(&[req("namedCurve", ANY, &UNKNOWN)]);
static EXPLICIT_EC_POINT: Schema = Schema::Seq(&[req("publicKey", BITS, &EC_POINT)]);

pub static PRIVATE_KEY_INFO: Schema = Schema::Seq(&[
    req("version", INT, &UNKNOWN),
    req("privateKeyAlgorithm", SEQ, &ALGORITHM),
    req("privateKey", OCTETS, &PRIVATE_KEYS),
    opt("attributes", &[0xa0], &ATTRIBUTES),
    opt("publicKey", &[0x81], &UNKNOWN),
]);
static PRIVATE_KEYS: Schema = Schema::ByAlgorithm(&[
    (RSA, None, &ENCAP_RSA_PRIVATE_KEY),
    (RSA_PSS, None, &ENCAP_RSA_PRIVATE_KEY),
    (EC, None, &ENCAP_EC_PRIVATE_KEY),
    (DSA, None, &ENCAP_PRIVATE_INT),
    (DH, None, &ENCAP_PRIVATE_INT),
    ("1.2.840.113549.1.3.1", None, &ENCAP_PRIVATE_INT),
    ("1.3.101.110", None, &ENCAP_CURVE_PRIVATE_KEY),
    ("1.3.101.111", None, &ENCAP_CURVE_PRIVATE_KEY),
    ("1.3.101.112", None, &ENCAP_CURVE_PRIVATE_KEY),
    ("1.3.101.113", None, &ENCAP_CURVE_PRIVATE_KEY),
]);
static ENCAP_RSA_PRIVATE_KEY: Schema =
    Schema::Encap(&Schema::Seq(&[req("RSAPrivateKey", SEQ, &RSA_PRIVATE_KEY)]));
static ENCAP_EC_PRIVATE_KEY: Schema =
    Schema::Encap(&Schema::Seq(&[req("ECPrivateKey", SEQ, &EC_PRIVATE_KEY)]));
static ENCAP_PRIVATE_INT: Schema = Schema::Encap(&Schema::Seq(&[req("privateKey", INT, &UNKNOWN)]));
static ENCAP_CURVE_PRIVATE_KEY: Schema =
    Schema::Encap(&Schema::Seq(&[req("CurvePrivateKey", OCTETS, &UNKNOWN)]));

pub static DSA_PRIVATE_KEY: Schema = Schema::Seq(&[
    req("version", INT, &UNKNOWN),
    req("p", INT, &UNKNOWN),
    req("q", INT, &UNKNOWN),
    req("g", INT, &UNKNOWN),
    req("y", INT, &UNKNOWN),
    req("x", INT, &UNKNOWN),
]);

// --- OCSP (RFC 6960) -------------------------------------------------------

pub static OCSP_REQUEST: Schema = Schema::Seq(&[
    req("tbsRequest", SEQ, &TBS_REQUEST),
    opt("optionalSignature", &[0xa0], &EXPLICIT_OCSP_SIGNATURE),
]);
static TBS_REQUEST: Schema = Schema::Seq(&[
    opt("version", &[0xa0], &EXPLICIT_VERSION),
    opt("requestorName", &[0xa1], &EXPLICIT_GENERAL_NAME),
    req("requestList", SEQ, &REQUEST_LIST),
    opt("requestExtensions", &[0xa2], &EXPLICIT_EXTENSIONS),
]);
static EXPLICIT_GENERAL_NAME: Schema = Schema::Seq(&[req("GeneralName", ANY, &GENERAL_NAME)]);
static REQUEST_LIST: Schema = Schema::SeqOf("Request", &OCSP_SINGLE_REQUEST);
static OCSP_SINGLE_REQUEST: Schema = Schema::Seq(&[
    req("reqCert", SEQ, &CERT_ID),
    opt("singleRequestExtensions", &[0xa0], &EXPLICIT_EXTENSIONS),
]);
static CERT_ID: Schema = Schema::Summary(x509::cert_id, &CERT_ID_BODY);
static CERT_ID_BODY: Schema = Schema::Seq(&[
    req("hashAlgorithm", SEQ, &ALGORITHM),
    req("issuerNameHash", OCTETS, &KEY_ID),
    req("issuerKeyHash", OCTETS, &KEY_ID),
    req("serialNumber", INT, &UNKNOWN),
]);
static EXPLICIT_OCSP_SIGNATURE: Schema = Schema::Seq(&[req("Signature", SEQ, &OCSP_SIGNATURE)]);
static OCSP_SIGNATURE: Schema = Schema::Seq(&[
    req("signatureAlgorithm", SEQ, &ALGORITHM),
    req("signature", BITS, &SIGNATURE_VALUES),
    opt("certs", &[0xa0], &EXPLICIT_CERTIFICATES),
]);
static EXPLICIT_CERTIFICATES: Schema = Schema::Seq(&[req("Certificates", SEQ, &CERTIFICATE_SET)]);

pub const OCSP_STATUS: EnumTable = &[
    (0, "successful"),
    (1, "malformedRequest"),
    (2, "internalError"),
    (3, "tryLater"),
    (5, "sigRequired"),
    (6, "unauthorized"),
];

pub static OCSP_RESPONSE: Schema = Schema::Seq(&[
    req("responseStatus", ENUM, &Schema::Enum(OCSP_STATUS)),
    opt("responseBytes", &[0xa0], &EXPLICIT_RESPONSE_BYTES),
]);
static EXPLICIT_RESPONSE_BYTES: Schema = Schema::Seq(&[req("ResponseBytes", SEQ, &RESPONSE_BYTES)]);
static RESPONSE_BYTES: Schema = Schema::Seq(&[
    req("responseType", OID, &UNKNOWN),
    req("response", OCTETS, &RESPONSE_TYPES),
]);
static RESPONSE_TYPES: Schema = Schema::DefinedBy(&[(
    "1.3.6.1.5.5.7.48.1.1",
    None,
    &Schema::Encap(&Schema::Seq(&[req(
        "BasicOCSPResponse",
        SEQ,
        &BASIC_OCSP_RESPONSE,
    )])),
)]);
static BASIC_OCSP_RESPONSE: Schema = Schema::Seq(&[
    req("tbsResponseData", SEQ, &RESPONSE_DATA),
    req("signatureAlgorithm", SEQ, &ALGORITHM),
    req("signature", BITS, &SIGNATURE_VALUES),
    opt("certs", &[0xa0], &EXPLICIT_CERTIFICATES),
]);
static RESPONSE_DATA: Schema = Schema::Seq(&[
    opt("version", &[0xa0], &EXPLICIT_VERSION),
    req("responderID", &[0xa1, 0xa2], &RESPONDER_ID),
    req("producedAt", GTIME, &UNKNOWN),
    req("responses", SEQ, &SINGLE_RESPONSES),
    opt("responseExtensions", &[0xa1], &EXPLICIT_EXTENSIONS),
]);
static RESPONDER_ID: Schema = Schema::Choice(&[
    (0xa1, "byName", &EXPLICIT_NAME),
    (0xa2, "byKey", &EXPLICIT_KEY_HASH),
]);
static EXPLICIT_KEY_HASH: Schema = Schema::Seq(&[req("KeyHash", OCTETS, &KEY_ID)]);
static SINGLE_RESPONSES: Schema = Schema::SeqOf("SingleResponse", &SINGLE_RESPONSE);
static SINGLE_RESPONSE: Schema = Schema::Summary(x509::single_response, &SINGLE_RESPONSE_BODY);
static SINGLE_RESPONSE_BODY: Schema = Schema::Seq(&[
    req("certID", SEQ, &CERT_ID),
    req("certStatus", ANY, &CERT_STATUS),
    req("thisUpdate", GTIME, &UNKNOWN),
    opt("nextUpdate", &[0xa0], &EXPLICIT_GTIME),
    opt("singleExtensions", &[0xa1], &EXPLICIT_EXTENSIONS),
]);
static CERT_STATUS: Schema = Schema::Choice(&[
    (0x80, "good", &IMPLICIT_NULL),
    (0xa1, "revoked", &REVOKED_INFO),
    (0x82, "unknown", &IMPLICIT_NULL),
]);
static REVOKED_INFO: Schema = Schema::Seq(&[
    req("revocationTime", GTIME, &UNKNOWN),
    opt("revocationReason", &[0xa0], &EXPLICIT_REASON),
]);
static EXPLICIT_REASON: Schema = Schema::Seq(&[req("CRLReason", ENUM, &CRL_REASON)]);
static EXPLICIT_GTIME: Schema = Schema::Seq(&[req("GeneralizedTime", GTIME, &UNKNOWN)]);
static OCSP_CRL_ID: Schema = Schema::Seq(&[
    opt("crlUrl", &[0xa0], &UNKNOWN),
    opt("crlNum", &[0xa1], &UNKNOWN),
    opt("crlTime", &[0xa2], &UNKNOWN),
]);
static ACCEPTABLE_RESPONSES: Schema = Schema::SeqOf("responseType", &UNKNOWN);

// --- Time-stamp protocol (RFC 3161) ----------------------------------------

pub static TIME_STAMP_REQ: Schema = Schema::Seq(&[
    req("version", INT, &UNKNOWN),
    req("messageImprint", SEQ, &MESSAGE_IMPRINT),
    opt("reqPolicy", OID, &UNKNOWN),
    opt("nonce", INT, &UNKNOWN),
    opt("certReq", BOOL, &UNKNOWN),
    opt("extensions", &[0xa0], &EXTENSIONS),
]);
static MESSAGE_IMPRINT: Schema = Schema::Seq(&[
    req("hashAlgorithm", SEQ, &ALGORITHM),
    req("hashedMessage", OCTETS, &KEY_ID),
]);

pub const PKI_STATUS: EnumTable = &[
    (0, "granted"),
    (1, "grantedWithMods"),
    (2, "rejection"),
    (3, "waiting"),
    (4, "revocationWarning"),
    (5, "revocationNotification"),
];
pub const PKI_FAILURE_BITS: &[&str] = &[
    "badAlg",
    "",
    "badRequest",
    "",
    "",
    "badDataFormat",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "timeNotAvailable",
    "unacceptedPolicy",
    "unacceptedExtension",
    "addInfoNotAvailable",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "systemFailure",
];

pub static TIME_STAMP_RESP: Schema = Schema::Seq(&[
    req("status", SEQ, &PKI_STATUS_INFO),
    opt("timeStampToken", SEQ, &CONTENT_INFO),
]);
static PKI_STATUS_INFO: Schema = Schema::Seq(&[
    req("status", INT, &Schema::Enum(PKI_STATUS)),
    opt("statusString", SEQ, &PKI_FREE_TEXT),
    opt("failInfo", BITS, &Schema::Bits(PKI_FAILURE_BITS)),
]);
static PKI_FREE_TEXT: Schema = Schema::SeqOf("UTF8String", &UNKNOWN);

pub static TST_INFO: Schema = Schema::Seq(&[
    req("version", INT, &UNKNOWN),
    req("policy", OID, &UNKNOWN),
    req("messageImprint", SEQ, &MESSAGE_IMPRINT),
    req("serialNumber", INT, &UNKNOWN),
    req("genTime", GTIME, &UNKNOWN),
    opt("accuracy", SEQ, &ACCURACY),
    opt("ordering", BOOL, &UNKNOWN),
    opt("nonce", INT, &UNKNOWN),
    opt("tsa", &[0xa0], &EXPLICIT_GENERAL_NAME),
    opt("extensions", &[0xa1], &EXTENSIONS),
]);
static ACCURACY: Schema = Schema::Seq(&[
    opt("seconds", INT, &UNKNOWN),
    opt("millis", &[0x80], &IMPLICIT_INT),
    opt("micros", &[0x81], &IMPLICIT_INT),
]);

// --- Top levels ------------------------------------------------------------

pub static TOP_CERTIFICATE: Schema = Schema::Seq(&[req("Certificate", SEQ, &CERTIFICATE)]);
pub static TOP_CRL: Schema = Schema::Seq(&[req("CertificateList", SEQ, &CERTIFICATE_LIST)]);
pub static TOP_CSR: Schema =
    Schema::Seq(&[req("CertificationRequest", SEQ, &CERTIFICATION_REQUEST)]);
pub static TOP_PKCS7: Schema = Schema::Seq(&[req("ContentInfo", SEQ, &CONTENT_INFO)]);
pub static TOP_PKCS12: Schema = Schema::Seq(&[req("PFX", SEQ, &PFX)]);
pub static TOP_RSA_PUBLIC_KEY: Schema = Schema::Seq(&[req("RSAPublicKey", SEQ, &RSA_PUBLIC_KEY)]);
pub static TOP_RSA_PRIVATE_KEY: Schema =
    Schema::Seq(&[req("RSAPrivateKey", SEQ, &RSA_PRIVATE_KEY)]);
pub static TOP_EC_PRIVATE_KEY: Schema = Schema::Seq(&[req("ECPrivateKey", SEQ, &EC_PRIVATE_KEY)]);
pub static TOP_PRIVATE_KEY_INFO: Schema =
    Schema::Seq(&[req("PrivateKeyInfo", SEQ, &PRIVATE_KEY_INFO)]);
pub static TOP_DSA_PRIVATE_KEY: Schema =
    Schema::Seq(&[req("DSAPrivateKey", SEQ, &DSA_PRIVATE_KEY)]);
pub static TOP_SPKI: Schema = Schema::Seq(&[req("SubjectPublicKeyInfo", SEQ, &SPKI)]);
pub static TOP_DH_PARAMETER: Schema = Schema::Seq(&[req("DHParameter", SEQ, &DH_PARAMETER)]);
pub static TOP_DSA_PARAMETERS: Schema = Schema::Seq(&[req("Dss-Parms", SEQ, &DSS_PARMS)]);
pub static TOP_OCSP_REQUEST: Schema = Schema::Seq(&[req("OCSPRequest", SEQ, &OCSP_REQUEST)]);
pub static TOP_OCSP_RESPONSE: Schema = Schema::Seq(&[req("OCSPResponse", SEQ, &OCSP_RESPONSE)]);
pub static TOP_TIME_STAMP_REQ: Schema = Schema::Seq(&[req("TimeStampReq", SEQ, &TIME_STAMP_REQ)]);
pub static TOP_TIME_STAMP_RESP: Schema =
    Schema::Seq(&[req("TimeStampResp", SEQ, &TIME_STAMP_RESP)]);
pub static TOP_TST_INFO: Schema = Schema::Seq(&[req("TSTInfo", SEQ, &TST_INFO)]);

// --- Kerberos (RFC 4120) ---------------------------------------------------

pub const KRB_ETYPES: EnumTable = &[
    (1, "des-cbc-crc"),
    (3, "des-cbc-md5"),
    (16, "des3-cbc-sha1"),
    (17, "aes128-cts-hmac-sha1-96"),
    (18, "aes256-cts-hmac-sha1-96"),
    (19, "aes128-cts-hmac-sha256-128"),
    (20, "aes256-cts-hmac-sha384-192"),
    (23, "rc4-hmac"),
    (24, "rc4-hmac-exp"),
    (25, "camellia128-cts-cmac"),
    (26, "camellia256-cts-cmac"),
];

pub const KRB_NAME_TYPES: EnumTable = &[
    (0, "NT-UNKNOWN"),
    (1, "NT-PRINCIPAL"),
    (2, "NT-SRV-INST"),
    (3, "NT-SRV-HST"),
    (4, "NT-SRV-XHST"),
    (5, "NT-UID"),
    (10, "NT-ENTERPRISE"),
    (11, "NT-WELLKNOWN"),
];

pub static TOP_KRB5_TICKET: Schema = Schema::Seq(&[req("Ticket", &[0x61], &KRB_TICKET_APP)]);
static KRB_TICKET_APP: Schema = Schema::Seq(&[req("fields", SEQ, &KRB_TICKET)]);
static KRB_TICKET: Schema = Schema::Seq(&[
    req("tkt-vno", &[0xa0], &K_INT),
    req("realm", &[0xa1], &K_STRING),
    req("sname", &[0xa2], &K_PRINCIPAL),
    req("enc-part", &[0xa3], &K_ENCRYPTED),
]);
static K_INT: Schema = Schema::Seq(&[req("value", INT, &UNKNOWN)]);
static K_STRING: Schema = Schema::Seq(&[req("KerberosString", ANY, &UNKNOWN)]);
static K_PRINCIPAL: Schema = Schema::Seq(&[req("PrincipalName", SEQ, &KRB_PRINCIPAL)]);
static KRB_PRINCIPAL: Schema = Schema::Summary(x509::krb_principal, &KRB_PRINCIPAL_BODY);
static KRB_PRINCIPAL_BODY: Schema = Schema::Seq(&[
    req("name-type", &[0xa0], &K_NAME_TYPE),
    req("name-string", &[0xa1], &K_NAME_STRINGS),
]);
static K_NAME_TYPE: Schema = Schema::Seq(&[req("Int32", INT, &KRB_NAME_TYPE)]);
static KRB_NAME_TYPE: Schema = Schema::Enum(KRB_NAME_TYPES);
static K_NAME_STRINGS: Schema = Schema::Seq(&[req("names", SEQ, &KRB_NAME_STRINGS)]);
static KRB_NAME_STRINGS: Schema = Schema::SeqOf("KerberosString", &UNKNOWN);
static K_ENCRYPTED: Schema = Schema::Seq(&[req("EncryptedData", SEQ, &KRB_ENCRYPTED)]);
static KRB_ENCRYPTED: Schema = Schema::Seq(&[
    req("etype", &[0xa0], &K_ETYPE),
    opt("kvno", &[0xa1], &K_INT),
    req("cipher", &[0xa2], &K_CIPHER),
]);
static K_ETYPE: Schema = Schema::Seq(&[req("Int32", INT, &KRB_ETYPE)]);
static KRB_ETYPE: Schema = Schema::Enum(KRB_ETYPES);
static K_CIPHER: Schema = Schema::Seq(&[req("OCTET STRING", OCTETS, &UNKNOWN)]);

// --- Encrypted private keys (PKCS#8) ----------------------------------------

pub static TOP_ENCRYPTED_PRIVATE_KEY_INFO: Schema = Schema::Seq(&[req(
    "EncryptedPrivateKeyInfo",
    SEQ,
    &ENCRYPTED_PRIVATE_KEY_INFO,
)]);
static ENCRYPTED_PRIVATE_KEY_INFO: Schema = Schema::Seq(&[
    req("encryptionAlgorithm", SEQ, &ALGORITHM),
    req("encryptedData", OCTETS, &UNKNOWN),
]);
