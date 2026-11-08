// SPDX-License-Identifier: MIT OR Apache-2.0
//! Client side: fingerprint pinning instead of a CA chain.
//!
//! # What this module deliberately does NOT do
//!
//! [`pinned_client_config`] builds a `ClientConfig` that does **not** build any
//! CA chain and does **not** check the hostname against the SAN. It accepts
//! exactly one certificate: the one whose SHA-256 over the DER matches the
//! pinned value.
//!
//! That is not a shortcut — it is the right model for an internal setup
//! without a CA, and it is identical to SSH host-key pinning: the identity is
//! *exactly this key*. A CA
//! chain would have required a CA we do not have, and a name check would have
//! been meaningless when the peer is designated by fingerprint anyway.
//!
//! # What it still does — and what makes it safe
//!
//! The handshake signature is **verified in full** against the provider, for
//! both TLS 1.2 and TLS 1.3. Without that the pinning would be worthless:
//! anyone could replay a copied certificate they do not hold the private key
//! for. The comparison of the fingerprint itself is constant-time.
//!
//! # Consequence for the consumer
//!
//! Since the hostname is not checked, it does not matter which `ServerName`
//! you give `TlsConnector::connect` — but rustls requires that you give *one*.
//! Use the service name (e.g. `"gateway"`), so the SNI in the handshake is
//! something that makes sense in a packet capture.
//!
//! **If the server changes certificate, the pinned value must be updated.**
//! That is the price of pinning, and it is intentional: a silent swap should
//! stop the traffic, not pass.
//!
//! # Dates *(0.11.0)*
//!
//! After the identity, the certificate's dates are checked against the
//! handshake's time: one that is expired or not yet valid is refused with
//! rustls' own error, which carries the dates. An unknown certificate is
//! "untrusted" whatever its dates. [`Expiry::Ignore`] turns the date check off,
//! as an explicit choice in the `_with` forms; the short forms always check.
//! [`classify`] tells the consumer which of these refused a connection — the
//! same check runs in [`crate::generations::Trust`].

use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, Error, SignatureScheme};

use crate::error::TlsError;
use crate::fingerprint::parse_fingerprint;
use krypto::{ct_eq, sha256};

/// `ClientConfig` that only accepts the server with this SHA-256 fingerprint.
///
/// `fingerprint_sha256` is the value [`crate::TlsMaterial::fingerprint_sha256`]
/// gives. The format is tolerant (colons, uppercase and a `sha256:` prefix are
/// fine), but the length is not — a typo yields an error, never a config that
/// accepts more than it should.
///
/// No ALPN is set. If you need that, use
/// [`pinned_client_config_with_alpn`].
pub fn pinned_client_config(fingerprint_sha256: &str) -> Result<Arc<ClientConfig>, TlsError> {
    pinned_client_config_with_alpn(fingerprint_sha256, &[])
}

/// Like [`pinned_client_config`], but with an ALPN list.
pub fn pinned_client_config_with_alpn(
    fingerprint_sha256: &str,
    alpn: &[Vec<u8>],
) -> Result<Arc<ClientConfig>, TlsError> {
    pinned_client_config_with(
        fingerprint_sha256,
        alpn,
        &crate::transport::TransportPolicy::default(),
        Expiry::Enforce,
    )
}

/// Like [`pinned_client_config_with_alpn`], with an explicit
/// [`TransportPolicy`](crate::transport::TransportPolicy) (0.8.3) and an
/// explicit [`Expiry`] (0.11.0). Without a policy, the client offers the
/// default: **AES-256-GCM only**; the short forms use [`Expiry::Enforce`].
pub fn pinned_client_config_with(
    fingerprint_sha256: &str,
    alpn: &[Vec<u8>],
    transport: &crate::transport::TransportPolicy,
    expiry: Expiry,
) -> Result<Arc<ClientConfig>, TlsError> {
    let expected = parse_fingerprint(fingerprint_sha256)?;
    let provider = transport.provider();
    let verifier = PinnedServerCertVerifier {
        expected,
        provider: provider.clone(),
        expiry,
    };

    build(provider, Arc::new(verifier), alpn)
}

/// A `ClientConfig` that accepts **any** server certificate — for enrollment
/// only *(0.11.0)*.
///
/// Before a peer is approved there is nothing to pin, and its certificate has
/// to be fetched so the operator can see its fingerprint. This config does
/// that. It accepts whatever certificate the server shows, whatever its dates,
/// but still verifies the handshake signature in full: the server must hold
/// the key for the certificate it shows, so a copied certificate does not get
/// through. Read the certificate from the connection once the handshake is
/// done (`peer_certificates()`, or `Stream.peer_fingerprint()` in Python).
///
/// **For looking, never for transferring** — the enrollment rule in
/// `docs/API.md`: no secrets, no changes and no data over a connection made
/// with this config. The operator compares the fingerprint out of band and
/// approves it; from then on the peer is pinned.
pub fn unverified_client_config() -> Result<Arc<ClientConfig>, TlsError> {
    unverified_client_config_with(&[], &crate::transport::TransportPolicy::default())
}

/// Like [`unverified_client_config`], with ALPN and an explicit
/// [`TransportPolicy`](crate::transport::TransportPolicy), for a peer that
/// does not use the default cipher *(0.11.0)*.
pub fn unverified_client_config_with(
    alpn: &[Vec<u8>],
    transport: &crate::transport::TransportPolicy,
) -> Result<Arc<ClientConfig>, TlsError> {
    let provider = transport.provider();
    let verifier = UnverifiedServerCertVerifier {
        provider: provider.clone(),
    };
    build(provider, Arc::new(verifier), alpn)
}

/// A client config over `verifier`: TLS 1.3 and 1.2, no client
/// authentication, no resumption.
fn build(
    provider: Arc<CryptoProvider>,
    verifier: Arc<dyn ServerCertVerifier>,
    alpn: &[Vec<u8>],
) -> Result<Arc<ClientConfig>, TlsError> {
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| TlsError::Rustls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.to_vec();
    cfg.resumption = no_resumption();
    Ok(Arc::new(cfg))
}

/// **Session resumption is turned off on the client side — deliberately.**
///
/// Discovered 2026-08-10, during the work on rolling pinning: if the client
/// resumes an earlier session (TLS 1.3 PSK), the server does **not** send the
/// certificate again, and then our verifier does not run either. The pinning
/// then becomes a check performed on the *first* connection and thereafter
/// implied on all later ones — until the ticket expires.
///
/// That is not a hole in itself (whoever resumes must prove they hold the
/// secret from an already authenticated session), but it breaks two things we
/// depend on:
///
/// 1. **The rotation must bite immediately.** With resumption, a client that
///    has not yet seen the new identity could keep connecting on the old one —
///    directly contrary to the fact that the key's lifetime *is* the security
///    mechanism.
/// 2. **"Pinned" must mean checked at every handshake**, without exception. An
///    invariant with an exception is not an invariant, it is a footnote.
///
/// The price is one extra round trip on an internal network with very few new
/// connections — and our clients keep their connections open anyway. The
/// server side ([`crate::TlsMaterial::server_config`]) we leave alone: there,
/// resumption is useful for the browsers, and there is no pinning there to
/// undermine.
pub(crate) fn no_resumption() -> rustls::client::Resumption {
    rustls::client::Resumption::disabled()
}

/// The verifier behind [`unverified_client_config`] *(0.11.0)*: any
/// certificate, but the handshake signature must hold.
#[derive(Debug)]
struct UnverifiedServerCertVerifier {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for UnverifiedServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // Looking, not trusting: the certificate is what we came to read.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // The one check that stays: the server holds the key for the
        // certificate it shows, so what the operator sees is that server's.
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Whether a client refuses a certificate outside its validity window
/// *(0.11.0)*.
///
/// The short forms ([`pinned_client_config`], `Trust::client_config`) always
/// use [`Expiry::Enforce`]. [`Expiry::Ignore`] exists for a consumer that must
/// keep talking to a peer whose certificate has run out — an explicit choice,
/// never a default. The identity is checked either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Expiry {
    /// Refuse a certificate that is expired or not yet valid.
    #[default]
    Enforce,
    /// Accept it anyway.
    Ignore,
}

/// The date check both client verifiers run after the identity check
/// *(0.11.0)*. The errors are rustls' own, with the dates, as its standard
/// verifier gives them.
pub(crate) fn check_validity(
    cert: &CertificateDer<'_>,
    now: UnixTime,
    expiry: Expiry,
) -> Result<(), Error> {
    if expiry == Expiry::Ignore {
        return Ok(());
    }
    let (not_before, not_after) = crate::material::validity(cert.as_ref())
        .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
    let t = now.as_secs();
    let at = |s: i64| UnixTime::since_unix_epoch(Duration::from_secs(s.max(0) as u64));
    if (t as i64) < not_before {
        return Err(CertificateError::NotValidYetContext {
            time: now,
            not_before: at(not_before),
        }
        .into());
    }
    if (t as i64) > not_after {
        return Err(CertificateError::ExpiredContext {
            time: now,
            not_after: at(not_after),
        }
        .into());
    }
    Ok(())
}

/// Why a client refused the server's certificate, in nettls' terms
/// *(0.11.0)*. Times are Unix seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// The certificate is not one we trust: an unknown fingerprint, or one
    /// `Trust` does not accept.
    Untrusted,
    /// The certificate is trusted, but expired.
    Expired {
        /// The time of the handshake.
        now: i64,
        /// The certificate's `notAfter`.
        not_after: i64,
    },
    /// The certificate is trusted, but not valid yet.
    NotYetValid {
        /// The time of the handshake.
        now: i64,
        /// The certificate's `notBefore`.
        not_before: i64,
    },
    /// Anything else: not a certificate refusal by nettls' verifiers.
    Other,
}

/// Tells why a connection with a nettls client config failed *(0.11.0)*.
///
/// Give it the error the connection returned: a `rustls::Error`, the
/// `io::Error` tokio-rustls returns, or any error with one of them in its
/// `source()` chain. "Untrusted" and "expired" are different situations — the
/// first may be an attack, the second is a certificate someone forgot to
/// renew — and this is how a consumer tells them apart.
pub fn classify(err: &(dyn std::error::Error + 'static)) -> Rejection {
    let mut cur = Some(err);
    while let Some(e) = cur {
        if let Some(r) = e.downcast_ref::<Error>() {
            return from_rustls(r);
        }
        // `io::Error` does not list the error it wraps in `source()`.
        if let Some(r) = e
            .downcast_ref::<std::io::Error>()
            .and_then(|io| io.get_ref())
            .and_then(|inner| inner.downcast_ref::<Error>())
        {
            return from_rustls(r);
        }
        cur = e.source();
    }
    Rejection::Other
}

fn from_rustls(e: &Error) -> Rejection {
    let secs = |t: &UnixTime| t.as_secs() as i64;
    match e {
        Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure) => {
            Rejection::Untrusted
        }
        Error::InvalidCertificate(CertificateError::ExpiredContext { time, not_after }) => {
            Rejection::Expired {
                now: secs(time),
                not_after: secs(not_after),
            }
        }
        Error::InvalidCertificate(CertificateError::NotValidYetContext { time, not_before }) => {
            Rejection::NotYetValid {
                now: secs(time),
                not_before: secs(not_before),
            }
        }
        _ => Rejection::Other,
    }
}

/// The verifier behind [`pinned_client_config`].
struct PinnedServerCertVerifier {
    expected: [u8; 32],
    provider: Arc<CryptoProvider>,
    expiry: Expiry,
}

impl std::fmt::Debug for PinnedServerCertVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinnedServerCertVerifier")
            .field("expected", &krypto::hex::encode(&self.expected))
            .finish()
    }
}

impl ServerCertVerifier for PinnedServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // Intermediate certificates are ignored: we pin the leaf, there is no
        // chain to build, and a chain we do not trust must not be able to
        // influence anything.
        let actual = sha256(end_entity.as_ref());
        if ct_eq(&actual, &self.expected) {
            // Identity first, dates second: an unknown certificate is
            // "untrusted", whatever its dates (0.11.0).
            check_validity(end_entity, now, self.expiry)?;
            Ok(ServerCertVerified::assertion())
        } else {
            // The error does not contain the fingerprints. The client already
            // knows what it expected, and what it got belongs in a log call at
            // the consumer, not in a TLS alert that goes out on the wire.
            Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // This is not a formality: without signature verification, anyone
        // could replay a copied certificate without holding the private key,
        // and the pinning would be worthless.
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
