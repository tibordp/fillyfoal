//! Just enough of the X.509, PKCS#7/CMS, PKCS#10 and PKCS#12 ASN.1 modules
//! to give elements their field names. Anything not described here is shown
//! generically by its tag.

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
const OID: &[u8] = &[0x06];
const OCTETS: &[u8] = &[0x04];
const BITS: &[u8] = &[0x03];
const TIME: &[u8] = &[0x17, 0x18];
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
        Matcher { schema, next: 0 }
    }

    pub fn child(&mut self, id: u8) -> (Option<&'static str>, &'static Schema) {
        match self.schema {
            Schema::Any => (None, &UNKNOWN),
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
        }
    }
}

// --- Shared ---------------------------------------------------------------

pub static ALGORITHM: Schema = Schema::Seq(&[
    req("algorithm", OID, &UNKNOWN),
    opt("parameters", ANY, &UNKNOWN),
]);

static RDN: Schema = Schema::SeqOf("AttributeTypeAndValue", &ATTRIBUTE_VALUE);
static ATTRIBUTE_VALUE: Schema =
    Schema::Seq(&[req("type", OID, &UNKNOWN), req("value", ANY, &UNKNOWN)]);
pub static NAME: Schema = Schema::Name;

static ATTRIBUTE: Schema = Schema::Seq(&[
    req("attrType", OID, &UNKNOWN),
    req("attrValues", SET, &UNKNOWN),
]);
static ATTRIBUTES: Schema = Schema::SeqOf("Attribute", &ATTRIBUTE);

static EXTENSION: Schema = Schema::Seq(&[
    req("extnID", OID, &UNKNOWN),
    opt("critical", &[0x01], &UNKNOWN),
    req("extnValue", OCTETS, &UNKNOWN),
]);
static EXTENSIONS: Schema = Schema::SeqOf("Extension", &EXTENSION);
static EXPLICIT_EXTENSIONS: Schema = Schema::Seq(&[req("Extensions", SEQ, &EXTENSIONS)]);

static SPKI: Schema = Schema::Seq(&[
    req("algorithm", SEQ, &ALGORITHM),
    req("subjectPublicKey", BITS, &UNKNOWN),
]);

// --- X.509 certificates (RFC 5280) -----------------------------------------

pub static CERTIFICATE: Schema = Schema::Seq(&[
    req("tbsCertificate", SEQ, &TBS_CERTIFICATE),
    req("signatureAlgorithm", SEQ, &ALGORITHM),
    req("signatureValue", BITS, &UNKNOWN),
]);

static TBS_CERTIFICATE: Schema = Schema::Seq(&[
    opt("version", &[0xa0], &UNKNOWN),
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

static VALIDITY: Schema = Schema::Seq(&[
    req("notBefore", TIME, &UNKNOWN),
    req("notAfter", TIME, &UNKNOWN),
]);

// --- CRLs ------------------------------------------------------------------

pub static CERTIFICATE_LIST: Schema = Schema::Seq(&[
    req("tbsCertList", SEQ, &TBS_CERT_LIST),
    req("signatureAlgorithm", SEQ, &ALGORITHM),
    req("signatureValue", BITS, &UNKNOWN),
]);

static TBS_CERT_LIST: Schema = Schema::Seq(&[
    opt("version", INT, &UNKNOWN),
    req("signature", SEQ, &ALGORITHM),
    req("issuer", SEQ, &NAME),
    req("thisUpdate", TIME, &UNKNOWN),
    opt("nextUpdate", TIME, &UNKNOWN),
    opt("revokedCertificates", SEQ, &REVOKED_LIST),
    opt("crlExtensions", &[0xa0], &EXPLICIT_EXTENSIONS),
]);

static REVOKED_LIST: Schema = Schema::SeqOf("revokedCertificate", &REVOKED);
static REVOKED: Schema = Schema::Seq(&[
    req("userCertificate", INT, &UNKNOWN),
    req("revocationDate", TIME, &UNKNOWN),
    opt("crlEntryExtensions", SEQ, &EXTENSIONS),
]);

// --- PKCS#10 certification requests ----------------------------------------

pub static CERTIFICATION_REQUEST: Schema = Schema::Seq(&[
    req("certificationRequestInfo", SEQ, &REQUEST_INFO),
    req("signatureAlgorithm", SEQ, &ALGORITHM),
    req("signature", BITS, &UNKNOWN),
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
    opt("content", &[0xa0], &EXPLICIT_CONTENT),
]);

/// `[0] EXPLICIT` content of a ContentInfo, assumed to be SignedData when it
/// is a SEQUENCE starting with a version number (the common case).
static EXPLICIT_CONTENT: Schema = Schema::Seq(&[req("SignedData", SEQ, &SIGNED_DATA)]);

static SIGNED_DATA: Schema = Schema::Seq(&[
    req("version", INT, &UNKNOWN),
    req("digestAlgorithms", SET, &DIGEST_ALGORITHMS),
    req("encapContentInfo", SEQ, &ENCAP_CONTENT_INFO),
    opt("certificates", &[0xa0], &CERTIFICATE_SET),
    opt("crls", &[0xa1], &UNKNOWN),
    req("signerInfos", SET, &SIGNER_INFOS),
]);

static DIGEST_ALGORITHMS: Schema = Schema::SeqOf("DigestAlgorithmIdentifier", &ALGORITHM);
static CERTIFICATE_SET: Schema = Schema::SeqOf("Certificate", &CERTIFICATE);
static SIGNER_INFOS: Schema = Schema::SeqOf("SignerInfo", &SIGNER_INFO);

static ENCAP_CONTENT_INFO: Schema = Schema::Seq(&[
    req("eContentType", OID, &UNKNOWN),
    opt("eContent", &[0xa0], &UNKNOWN),
]);

static SIGNER_INFO: Schema = Schema::Seq(&[
    req("version", INT, &UNKNOWN),
    req("sid", ANY, &ISSUER_AND_SERIAL),
    req("digestAlgorithm", SEQ, &ALGORITHM),
    opt("signedAttrs", &[0xa0], &ATTRIBUTES),
    req("signatureAlgorithm", SEQ, &ALGORITHM),
    req("signature", OCTETS, &UNKNOWN),
    opt("unsignedAttrs", &[0xa1], &ATTRIBUTES),
]);

static ISSUER_AND_SERIAL: Schema = Schema::Seq(&[
    req("issuer", SEQ, &NAME),
    req("serialNumber", INT, &UNKNOWN),
]);

// --- PKCS#12 (RFC 7292) ----------------------------------------------------

pub static PFX: Schema = Schema::Seq(&[
    req("version", INT, &UNKNOWN),
    req("authSafe", SEQ, &AUTH_SAFE),
    opt("macData", SEQ, &MAC_DATA),
]);

static AUTH_SAFE: Schema = Schema::Seq(&[
    req("contentType", OID, &UNKNOWN),
    opt("content", &[0xa0], &UNKNOWN),
]);

static MAC_DATA: Schema = Schema::Seq(&[
    req("mac", SEQ, &DIGEST_INFO),
    req("macSalt", OCTETS, &UNKNOWN),
    opt("iterations", INT, &UNKNOWN),
]);

static DIGEST_INFO: Schema = Schema::Seq(&[
    req("digestAlgorithm", SEQ, &ALGORITHM),
    req("digest", OCTETS, &UNKNOWN),
]);

// --- Top levels ------------------------------------------------------------

pub static TOP_CERTIFICATE: Schema = Schema::Seq(&[req("Certificate", SEQ, &CERTIFICATE)]);
pub static TOP_CRL: Schema = Schema::Seq(&[req("CertificateList", SEQ, &CERTIFICATE_LIST)]);
pub static TOP_CSR: Schema =
    Schema::Seq(&[req("CertificationRequest", SEQ, &CERTIFICATION_REQUEST)]);
pub static TOP_PKCS7: Schema = Schema::Seq(&[req("ContentInfo", SEQ, &CONTENT_INFO)]);
pub static TOP_PKCS12: Schema = Schema::Seq(&[req("PFX", SEQ, &PFX)]);
