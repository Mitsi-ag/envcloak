//! TLS configuration and the release vs. `testing` root-verifier seam for
//! `envcloak-poll` (`SPEC §8`, `§11`, `D4-04`, `D4-20`, `D4-27`, task
//! `M4-06a`, gate `11` and `s3`).
//!
//! Release builds (`#[cfg(not(feature = "testing"))]`) verify server
//! certificates exclusively through [`rustls_platform_verifier`] (`ReleaseRoots`).
// When built with `#[cfg(feature = "testing")]`, `TestRoots` allows a test to
// supply a single run-time root CA (`TestCa`) for the local HTTPS recording
// fixture server (`D4-20`) while still rejecting any certificate issued by a
// foreign CA or lacking a matching Subject Alternative Name.

use std::fmt;
use std::sync::Arc;

use rustls::ClientConfig;
use rustls_platform_verifier::BuilderVerifierExt as _;

#[cfg(feature = "testing")]
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// Marker string compiled into binaries and libraries only when
/// `envcloak-poll/testing` is enabled.
///
/// The release-feature test checks that the test build contains this marker as
/// a positive control and that a release build (`cargo build --release`)
/// contains neither `TestRoots` nor this marker.
#[cfg(feature = "testing")]
pub const TEST_ROOTS_SENTINEL: &[u8] = b"ENVCLOAK_POLL_TEST_CA_VERIFIER_SEAM_V1";

/// Selects the platform certificate verifier (`rustls-platform-verifier`), the
/// only root verifier compiled into release builds (`SPEC §11`, `D4-04`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReleaseRoots;

impl ReleaseRoots {
    /// Builds a [`ClientConfig`] verified against the platform's root store.
    ///
    /// # Errors
    /// Returns [`TlsConfigError`] if the platform verifier cannot be
    /// initialized.
    #[inline(never)]
    pub fn tls_config(self) -> Result<ClientConfig, TlsConfigError> {
        tls_config(self)
    }
}

/// Selects a single run-time test CA (`TestCa`) for `testing` builds (`D4-20`).
///
/// Absent from release builds (`#[cfg(feature = "testing")]`).
#[cfg(feature = "testing")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestRoots {
    ca: TestCa,
}

#[cfg(feature = "testing")]
impl TestRoots {
    /// Wraps a run-time [`TestCa`] as the sole root trust anchor for a test
    /// poller client.
    #[inline(never)]
    #[must_use]
    pub fn new(ca: TestCa) -> Self {
        std::hint::black_box(TEST_ROOTS_SENTINEL);
        Self { ca }
    }

    /// Returns the underlying [`TestCa`].
    #[must_use]
    pub const fn ca(&self) -> &TestCa {
        &self.ca
    }
}

/// Root certificate verifier selection for [`tls_config`] and
/// [`ureq_tls_config`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootVerifier {
    /// Platform certificate verification via `rustls-platform-verifier`.
    Release(ReleaseRoots),
    /// Run-time test CA verification (`testing` feature only).
    #[cfg(feature = "testing")]
    Test(TestRoots),
}

impl From<ReleaseRoots> for RootVerifier {
    fn from(r: ReleaseRoots) -> Self {
        Self::Release(r)
    }
}

#[cfg(feature = "testing")]
impl From<TestRoots> for RootVerifier {
    fn from(t: TestRoots) -> Self {
        Self::Test(t)
    }
}

/// Error returned when constructing a TLS configuration fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsConfigError {
    /// The platform verifier or TLS protocol builder reported an error.
    Rustls(String),
}

impl fmt::Display for TlsConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rustls(msg) => write!(f, "TLS configuration failed: {msg}"),
        }
    }
}

impl std::error::Error for TlsConfigError {}

/// Builds a [`rustls::ClientConfig`] using `ring` and the chosen root verifier.
///
/// # Errors
/// Returns [`TlsConfigError`] if the platform verifier or root store cannot be
/// initialized.
pub fn tls_config(roots: impl Into<RootVerifier>) -> Result<ClientConfig, TlsConfigError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| TlsConfigError::Rustls(e.to_string()))?;

    match roots.into() {
        RootVerifier::Release(ReleaseRoots) => {
            let cfg = builder
                .with_platform_verifier()
                .map_err(|e| TlsConfigError::Rustls(e.to_string()))?
                .with_no_client_auth();
            Ok(cfg)
        }
        #[cfg(feature = "testing")]
        RootVerifier::Test(test_roots) => {
            let mut store = rustls::RootCertStore::empty();
            store
                .add(test_roots.ca().root_cert_der())
                .map_err(|e| TlsConfigError::Rustls(e.to_string()))?;
            Ok(builder.with_root_certificates(store).with_no_client_auth())
        }
    }
}

/// Builds a [`ureq::tls::TlsConfig`] using `ring` and the chosen root verifier.
#[must_use]
pub fn ureq_tls_config(roots: impl Into<RootVerifier>) -> ureq::tls::TlsConfig {
    let crypto = Arc::new(rustls::crypto::ring::default_provider());
    let root_certs = match roots.into() {
        RootVerifier::Release(ReleaseRoots) => ureq::tls::RootCerts::PlatformVerifier,
        #[cfg(feature = "testing")]
        RootVerifier::Test(test_roots) => {
            let der: CertificateDer<'static> = test_roots.ca().root_cert_der();
            let cert: ureq::tls::Certificate<'static> =
                ureq::tls::Certificate::from_der(der.as_ref()).to_owned();
            ureq::tls::RootCerts::Specific(Arc::new(vec![cert]))
        }
    };
    ureq::tls::TlsConfig::builder()
        .provider(ureq::tls::TlsProvider::Rustls)
        .root_certs(root_certs)
        .disable_verification(false)
        .unversioned_rustls_crypto_provider(crypto)
        .build()
}

/// Run-time X.509 v3 P-256 ECDSA Root CA for `testing` builds (`D4-20`).
#[cfg(feature = "testing")]
#[derive(Clone, PartialEq, Eq)]
pub struct TestCa {
    common_name: String,
    ca_sk: [u8; 32],
    ca_pub_sec1: [u8; 65],
    root_cert_der: Vec<u8>,
}

#[cfg(feature = "testing")]
impl fmt::Debug for TestCa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestCa")
            .field("common_name", &self.common_name)
            .field("root_cert_der_len", &self.root_cert_der.len())
            .finish_non_exhaustive()
    }
}

/// Leaf server certificate and PKCS#8 private key issued by a [`TestCa`].
#[cfg(feature = "testing")]
#[derive(Clone, PartialEq, Eq)]
pub struct CertifiedServerKey {
    cert_der: Vec<u8>,
    pkcs8_der: Vec<u8>,
}

#[cfg(feature = "testing")]
impl fmt::Debug for CertifiedServerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertifiedServerKey")
            .field("cert_der_len", &self.cert_der.len())
            .field("pkcs8_der_len", &self.pkcs8_der.len())
            .finish()
    }
}

#[cfg(feature = "testing")]
impl CertifiedServerKey {
    /// Returns the DER-encoded leaf server certificate.
    #[must_use]
    pub fn cert_der(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.cert_der.clone())
    }

    /// Returns the DER-encoded PKCS#8 v1 private key.
    #[must_use]
    pub fn private_key_der(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.pkcs8_der.clone()))
    }
}

#[cfg(feature = "testing")]
impl TestCa {
    /// Generates a fresh run-time [`TestCa`] from OS randomness.
    ///
    /// # Panics
    /// Panics if OS randomness (`getrandom`) is unavailable.
    #[must_use]
    pub fn generate(common_name: &str) -> Self {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("OS CSPRNG available for test CA");
        Self::from_seed(seed, common_name)
    }

    /// Deterministically constructs a [`TestCa`] from `seed` and `common_name`.
    #[must_use]
    pub fn from_seed(seed: [u8; 32], common_name: &str) -> Self {
        let (ca_sk, ca_pub_sec1) = envcloak_core::crypto::derive_p256_keypair(&seed);
        let serial = derive_serial(&seed, b"ca-serial");
        let root_cert_der = x509::build_ca_cert_der(common_name, &serial, &ca_sk, &ca_pub_sec1);
        Self {
            common_name: common_name.to_owned(),
            ca_sk,
            ca_pub_sec1,
            root_cert_der,
        }
    }

    /// Returns the DER-encoded Root CA certificate.
    #[must_use]
    pub fn root_cert_der(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.root_cert_der.clone())
    }

    /// Issues a leaf server certificate and PKCS#8 private key signed by this
    /// Root CA covering `dns_names` and `ipv4_addrs` in `subjectAltName`.
    #[must_use]
    pub fn issue_server_cert(
        &self,
        leaf_seed: [u8; 32],
        dns_names: &[&str],
        ipv4_addrs: &[[u8; 4]],
    ) -> CertifiedServerKey {
        let (leaf_sk, leaf_pub_sec1) = envcloak_core::crypto::derive_p256_keypair(&leaf_seed);
        let serial = derive_serial(&leaf_seed, b"leaf-serial");
        let leaf_cn = dns_names.first().copied().unwrap_or("localhost");
        let cert_der = x509::build_server_leaf_cert_der(
            &self.common_name,
            leaf_cn,
            &serial,
            &leaf_pub_sec1,
            dns_names,
            ipv4_addrs,
            &self.ca_sk,
        );
        let pkcs8_der = x509::build_p256_pkcs8_v1_der(&leaf_sk, &leaf_pub_sec1);
        CertifiedServerKey {
            cert_der,
            pkcs8_der,
        }
    }

    /// Builds a [`rustls::ServerConfig`] for a local TLS fixture server using a
    /// leaf certificate issued by this [`TestCa`].
    ///
    /// # Errors
    /// Returns [`TlsConfigError`] if `rustls` rejects the generated certificate
    /// or key.
    pub fn server_config(
        &self,
        leaf_seed: [u8; 32],
        dns_names: &[&str],
        ipv4_addrs: &[[u8; 4]],
    ) -> Result<rustls::ServerConfig, TlsConfigError> {
        let leaf = self.issue_server_cert(leaf_seed, dns_names, ipv4_addrs);
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| TlsConfigError::Rustls(e.to_string()))?
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.cert_der(), self.root_cert_der()],
                leaf.private_key_der(),
            )
            .map_err(|e| TlsConfigError::Rustls(e.to_string()))
    }
}

#[cfg(feature = "testing")]
fn derive_serial(seed: &[u8; 32], label: &[u8]) -> [u8; 16] {
    let mut input = Vec::with_capacity(seed.len() + label.len());
    input.extend_from_slice(seed);
    input.extend_from_slice(label);
    let digest =
        envcloak_core::crypto::secret_sha256(&envcloak_core::SecretBytes::copy_from(&input));
    let mut serial = [0u8; 16];
    serial.copy_from_slice(&digest[..16]);
    // Ensure positive non-zero ASN.1 INTEGER without leading 0x00 padding need.
    serial[0] = (serial[0] & 0x7f) | 0x01;
    serial
}

#[cfg(feature = "testing")]
mod x509 {
    use envcloak_core::crypto::{secret_sha256, sign_p256_prehash};

    // OIDs in raw DER content bytes:
    // 1.2.840.10045.2.1 (id-ecPublicKey)
    const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    // 1.2.840.10045.3.1.7 (prime256v1 / secp256r1)
    const OID_PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    // 1.2.840.10045.4.3.2 (ecdsa-with-SHA256)
    const OID_ECDSA_WITH_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    // 2.5.4.3 (commonName)
    const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
    // 2.5.29.15 (keyUsage)
    const OID_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
    // 2.5.29.17 (subjectAltName)
    const OID_SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
    // 2.5.29.19 (basicConstraints)
    const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
    // 2.5.29.37 (extKeyUsage)
    const OID_EXT_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
    // 1.3.6.1.5.5.7.3.1 (id-kp-serverAuth)
    const OID_SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];

    pub(super) fn build_p256_pkcs8_v1_der(sk: &[u8; 32], pub_sec1: &[u8; 65]) -> Vec<u8> {
        let ec_private_key = der_seq(&[
            &der_int_small(1),
            &der_octet_string(sk),
            &der_explicit(1, &der_bit_string(pub_sec1, 0)),
        ]);
        let alg_id = der_seq(&[&der_oid(OID_EC_PUBLIC_KEY), &der_oid(OID_PRIME256V1)]);
        der_seq(&[
            &der_int_small(0),
            &alg_id,
            &der_octet_string(&ec_private_key),
        ])
    }

    pub(super) fn build_ca_cert_der(
        common_name: &str,
        serial: &[u8; 16],
        ca_sk: &[u8; 32],
        ca_pub_sec1: &[u8; 65],
    ) -> Vec<u8> {
        let basic_constraints =
            der_extension(OID_BASIC_CONSTRAINTS, true, &der_seq(&[&der_bool(true)]));
        // keyCertSign (bit 5) | cRLSign (bit 6) -> 0x06 with 1 unused bit
        let key_usage = der_extension(OID_KEY_USAGE, true, &der_bit_string(&[0x06], 1));
        let extensions = der_explicit(3, &der_seq(&[&basic_constraints, &key_usage]));

        let tbs = build_tbs_cert(serial, common_name, common_name, ca_pub_sec1, &extensions);
        sign_tbs_cert(&tbs, ca_sk)
    }

    pub(super) fn build_server_leaf_cert_der(
        issuer_cn: &str,
        subject_cn: &str,
        serial: &[u8; 16],
        leaf_pub_sec1: &[u8; 65],
        dns_names: &[&str],
        ipv4_addrs: &[[u8; 4]],
        ca_sk: &[u8; 32],
    ) -> Vec<u8> {
        let basic_constraints = der_extension(OID_BASIC_CONSTRAINTS, true, &der_seq(&[]));
        // digitalSignature (bit 0) -> 0x80 with 7 unused bits
        let key_usage = der_extension(OID_KEY_USAGE, true, &der_bit_string(&[0x80], 7));
        let ext_key_usage = der_extension(
            OID_EXT_KEY_USAGE,
            false,
            &der_seq(&[&der_oid(OID_SERVER_AUTH)]),
        );

        let mut san_entries: Vec<Vec<u8>> = Vec::new();
        for name in dns_names {
            // dNSName [2] IMPLICIT IA5String
            san_entries.push(der_tlv(0x82, name.as_bytes()));
        }
        for ip in ipv4_addrs {
            // iPAddress [7] IMPLICIT OCTET STRING
            san_entries.push(der_tlv(0x87, ip));
        }
        let san_refs: Vec<&[u8]> = san_entries.iter().map(Vec::as_slice).collect();
        let san_ext = der_extension(OID_SUBJECT_ALT_NAME, false, &der_seq(&san_refs));

        let extensions = der_explicit(
            3,
            &der_seq(&[&basic_constraints, &key_usage, &ext_key_usage, &san_ext]),
        );
        let tbs = build_tbs_cert(serial, issuer_cn, subject_cn, leaf_pub_sec1, &extensions);
        sign_tbs_cert(&tbs, ca_sk)
    }

    fn build_tbs_cert(
        serial: &[u8; 16],
        issuer_cn: &str,
        subject_cn: &str,
        pub_sec1: &[u8; 65],
        extensions: &[u8],
    ) -> Vec<u8> {
        let version = der_explicit(0, &der_int_small(2));
        let serial_int = der_int_positive_bytes(serial);
        let sig_alg = der_seq(&[&der_oid(OID_ECDSA_WITH_SHA256)]);
        let issuer = der_name_cn(issuer_cn);
        let validity = der_seq(&[
            &der_utc_time(b"250101000000Z"),
            &der_utc_time(b"350101000000Z"),
        ]);
        let subject = der_name_cn(subject_cn);
        let spki_alg = der_seq(&[&der_oid(OID_EC_PUBLIC_KEY), &der_oid(OID_PRIME256V1)]);
        let spki = der_seq(&[&spki_alg, &der_bit_string(pub_sec1, 0)]);

        der_seq(&[
            &version,
            &serial_int,
            &sig_alg,
            &issuer,
            &validity,
            &subject,
            &spki,
            extensions,
        ])
    }

    fn sign_tbs_cert(tbs: &[u8], signing_sk: &[u8; 32]) -> Vec<u8> {
        let digest = secret_sha256(&envcloak_core::SecretBytes::copy_from(tbs));
        let sig_raw =
            sign_p256_prehash(signing_sk, &digest).expect("valid P-256 test CA signing key");
        let r = der_int_positive_bytes(&sig_raw[..32]);
        let s = der_int_positive_bytes(&sig_raw[32..64]);
        let sig_der = der_seq(&[&r, &s]);
        let sig_alg = der_seq(&[&der_oid(OID_ECDSA_WITH_SHA256)]);
        der_seq(&[tbs, &sig_alg, &der_bit_string(&sig_der, 0)])
    }

    fn der_name_cn(cn: &str) -> Vec<u8> {
        let atv = der_seq(&[&der_oid(OID_COMMON_NAME), &der_utf8_string(cn)]);
        let rdn = der_set(&[&atv]);
        der_seq(&[&rdn])
    }

    fn der_extension(oid: &[u8], critical: bool, value_der: &[u8]) -> Vec<u8> {
        let oid_tlv = der_oid(oid);
        let val_octets = der_octet_string(value_der);
        if critical {
            let crit = der_bool(true);
            der_seq(&[&oid_tlv, &crit, &val_octets])
        } else {
            der_seq(&[&oid_tlv, &val_octets])
        }
    }

    fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + content.len());
        out.push(tag);
        let len = content.len();
        if len < 0x80 {
            out.push(len as u8);
        } else if len <= 0xff {
            out.push(0x81);
            out.push(len as u8);
        } else {
            out.push(0x82);
            out.push((len >> 8) as u8);
            out.push((len & 0xff) as u8);
        }
        out.extend_from_slice(content);
        out
    }

    fn der_seq(parts: &[&[u8]]) -> Vec<u8> {
        let mut body = Vec::new();
        for p in parts {
            body.extend_from_slice(p);
        }
        der_tlv(0x30, &body)
    }

    fn der_set(parts: &[&[u8]]) -> Vec<u8> {
        let mut body = Vec::new();
        for p in parts {
            body.extend_from_slice(p);
        }
        der_tlv(0x31, &body)
    }

    fn der_explicit(tag_num: u8, inner: &[u8]) -> Vec<u8> {
        der_tlv(0xa0 | (tag_num & 0x1f), inner)
    }

    fn der_oid(oid_bytes: &[u8]) -> Vec<u8> {
        der_tlv(0x06, oid_bytes)
    }

    fn der_bool(val: bool) -> Vec<u8> {
        der_tlv(0x01, &[if val { 0xff } else { 0x00 }])
    }

    fn der_int_small(val: u8) -> Vec<u8> {
        der_tlv(0x02, &[val])
    }

    fn der_int_positive_bytes(raw: &[u8]) -> Vec<u8> {
        let trimmed = match raw.iter().position(|&b| b != 0) {
            Some(idx) => &raw[idx..],
            None => &[0u8],
        };
        let mut body = Vec::with_capacity(trimmed.len() + 1);
        if trimmed[0] & 0x80 != 0 {
            body.push(0x00);
        }
        body.extend_from_slice(trimmed);
        der_tlv(0x02, &body)
    }

    fn der_octet_string(bytes: &[u8]) -> Vec<u8> {
        der_tlv(0x04, bytes)
    }

    fn der_bit_string(bytes: &[u8], unused_bits: u8) -> Vec<u8> {
        let mut body = Vec::with_capacity(1 + bytes.len());
        body.push(unused_bits);
        body.extend_from_slice(bytes);
        der_tlv(0x03, &body)
    }

    fn der_utf8_string(s: &str) -> Vec<u8> {
        der_tlv(0x0c, s.as_bytes())
    }

    fn der_utc_time(ascii: &[u8]) -> Vec<u8> {
        der_tlv(0x17, ascii)
    }
}
