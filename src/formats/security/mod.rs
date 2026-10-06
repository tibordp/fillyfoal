//! Keys, credentials and encrypted files: PEM, OpenPGP, credential stores and
//! key files (`credentials`), desktop keyrings, Kerberos keytabs and caches,
//! PuTTY keys, age, and other encrypted and signed files (`encryption`).
//!
//! DER/PKCS structures live in [`super::asn1`].

pub mod age;
pub mod credentials;
pub mod encryption;
pub mod kerberos;
pub mod keyrings;
pub mod pem;
pub mod pgp;
pub mod putty;
