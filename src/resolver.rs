// SPDX-License-Identifier: MIT OR Apache-2.0
//! Server side: swap the certificate **without a restart**.
//!
//! Without this, the rotation is not invisible. A service that has to be
//! restarted to take a new certificate into use breaks every open connection
//! every 7 days — and then we have traded a security problem for an
//! operations problem (SPEC-nettls §6.10).
//!
//! The mechanism is rustls' own [`ResolvesServerCert`]: the `ServerConfig` is
//! built **once** with a resolver, and the resolver looks up the current
//! [`CertifiedKey`] for every new handshake. [`RotatingResolver::swap`]
//! replaces that lookup.
//!
//! The consequence is exactly the one we want:
//!
//! - **Open connections are not broken.** They have already completed their
//!   handshake; their key material is fully negotiated and lives in the
//!   connection, not in the resolver.
//! - **New handshakes get the new certificate** — immediately, without touching
//!   the listener, the `ServerConfig`, or the process.
//!
//! The counterpart on the client side is [`Trust`](crate::generations::Trust),
//! which in the same way reads live state at every handshake.
//!
//! ```no_run
//! # fn main() -> Result<(), nettls::TlsError> {
//! # let params = nettls::SelfSignedParams::default();
//! let material = nettls::TlsMaterial::load(&nettls::CertSource::auto("/tls", params.clone()))?;
//! let resolver = nettls::RotatingResolver::new(&material)?;
//! let config = resolver.server_config()?;   // bind once, keep forever
//!
//! // … later, when the §6 rotation reaches its switch point:
//! let next = nettls::TlsMaterial::load(&nettls::CertSource::self_signed(params))?;
//! resolver.swap(&next)?;                            // new handshakes get the new cert
//! # let _ = config; Ok(()) }
//! ```

use std::sync::{Arc, RwLock};

use rustls::ServerConfig;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::error::TlsError;
use crate::material::TlsMaterial;

#[derive(Debug)]
struct Current {
    key: Arc<CertifiedKey>,
    fingerprint: String,
}

/// A `ResolvesServerCert` with swappable material.
///
/// [`Clone`] shares state: all clones — and any `ServerConfig` built from
/// them — see the same certificate, and a [`RotatingResolver::swap`] applies to
/// all of them. That is the point; a clone living its own life would mean half
/// the service kept going on the old certificate.
#[derive(Debug, Clone)]
pub struct RotatingResolver {
    current: Arc<RwLock<Current>>,
}

impl RotatingResolver {
    /// Starts with this material.
    pub fn new(material: &TlsMaterial) -> Result<Self, TlsError> {
        Ok(Self {
            current: Arc::new(RwLock::new(Current {
                key: material.certified_key()?,
                fingerprint: material.fingerprint_sha256(),
            })),
        })
    }

    /// Swaps the certificate for **new** handshakes. Open connections are left
    /// alone.
    ///
    /// The material is validated (key against certificate, key type against the
    /// provider) **before** the swap happens — if that fails, the service is
    /// left with the old, working certificate. A rejected certificate must
    /// never be able to replace one that works.
    ///
    /// The consumer should log the swap (`tls_rotated`, with the old and the
    /// new fingerprint — the return value here is precisely the old one).
    /// "Invisible to humans" means *no interruption*, not *no trace* (§6,
    /// point 3).
    pub fn swap(&self, material: &TlsMaterial) -> Result<String, TlsError> {
        let fresh = Current {
            key: material.certified_key()?,
            fingerprint: material.fingerprint_sha256(),
        };
        let mut cur = self
            .current
            .write()
            .map_err(|_| TlsError::poisoned("the RotatingResolver lock"))?;
        let old = std::mem::replace(&mut *cur, fresh);
        Ok(old.fingerprint)
    }

    /// The fingerprint being served right now — the one clients should have in
    /// their chain. A poisoned lock is [`TlsError::LockPoisoned`] *(0.12.0)*.
    pub fn fingerprint_sha256(&self) -> Result<String, TlsError> {
        self.current
            .read()
            .map(|c| c.fingerprint.clone())
            .map_err(|_| TlsError::poisoned("the RotatingResolver lock"))
    }

    /// `ServerConfig` with this resolver, TLS 1.3 + 1.2, ALPN `h2, http/1.1`
    /// and the default transport policy (**AES-256-GCM only**, see
    /// [`TransportPolicy`](crate::transport::TransportPolicy)). Build it
    /// **once**; it follows the rotations by itself.
    pub fn server_config(&self) -> Result<Arc<ServerConfig>, TlsError> {
        self.server_config_with_alpn(&[b"h2".to_vec(), b"http/1.1".to_vec()])
    }

    /// Like [`RotatingResolver::server_config`], but with a custom ALPN list,
    /// checked as [`RotatingResolver::server_config_with`] checks it.
    pub fn server_config_with_alpn(&self, alpn: &[Vec<u8>]) -> Result<Arc<ServerConfig>, TlsError> {
        self.server_config_with(alpn, &crate::transport::TransportPolicy::default())
    }

    /// Like [`RotatingResolver::server_config_with_alpn`], with an explicit
    /// [`TransportPolicy`](crate::transport::TransportPolicy) (0.8.3).
    ///
    /// The ALPN list holds at most 16 entries of 1 to 255 bytes each; any
    /// other list is [`TlsError::Params`] *(0.12.0)*.
    pub fn server_config_with(
        &self,
        alpn: &[Vec<u8>],
        transport: &crate::transport::TransportPolicy,
    ) -> Result<Arc<ServerConfig>, TlsError> {
        crate::transport::check_alpn(alpn)?;
        let mut cfg = ServerConfig::builder_with_provider(transport.provider())
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|e| TlsError::Rustls(e.to_string()))?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(self.clone()));
        cfg.alpn_protocols = alpn.to_vec();
        // The consumer's order decides, not the peer's (SPEC-nettls §6.0b,
        // rule 3). rustls' default is to honour the CLIENT's preference.
        cfg.ignore_client_order = true;
        Ok(Arc::new(cfg))
    }
}

impl ResolvesServerCert for RotatingResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // SNI is deliberately ignored: our identity is the fingerprint, not
        // the name (same model as the pinning on the client side). One
        // service, one certificate.
        self.current.read().ok().map(|c| c.key.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CertSource, SelfSignedParams};

    /// A thread that panics while holding the lock leaves it poisoned. The
    /// fingerprint is then an error and not an empty string (0.12.0).
    #[test]
    fn a_poisoned_lock_gives_an_error_and_not_an_empty_fingerprint() {
        let material = TlsMaterial::load(&CertSource::self_signed(SelfSignedParams::new(
            "localhost",
            ["localhost"],
        )))
        .unwrap();
        let resolver = RotatingResolver::new(&material).unwrap();
        assert_eq!(
            resolver.fingerprint_sha256().unwrap(),
            material.fingerprint_sha256()
        );

        let current = Arc::clone(&resolver.current);
        let _ = std::thread::spawn(move || {
            let _held = current.write().unwrap();
            panic!("poison the lock");
        })
        .join();

        let err = resolver.fingerprint_sha256().unwrap_err();
        assert!(matches!(err, TlsError::LockPoisoned(_)), "{err:?}");
    }
}
