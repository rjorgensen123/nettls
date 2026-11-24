// SPDX-License-Identifier: MIT OR Apache-2.0
//! Private keys in memory — what is locked, what is wiped, and what is neither.
//!
//! Since 0.8.3 every private key this crate *holds* lives in a
//! [`krypto::SecretBuf`]: `mlock`ed (never swapped to disk), zeroized on drop,
//! `[REDACTED]` in `Debug`, and readable only inside an `expose` closure. That
//! covers the PKCS#8 keys of the generation triple ([`OwnMaterial`],
//! [`Pending`]), the anchor handed to the consumer ([`TlsMaterial::anchor_pkcs8`]),
//! the PEM read from disk, and the PEM written to disk.
//!
//! **The honest limit.** Two copies are outside our fence, and no amount of
//! wrapping here changes that:
//!
//! - **rustls' own key.** `TlsMaterial` keeps the key as rustls'
//!   `PrivateKeyDer` because that is the only type rustls accepts. We wrap it
//!   in [`zeroize::Zeroizing`] so it is wiped on drop, but it is ordinary heap
//!   — not locked. And when a `ServerConfig` is built, rustls/ring parse the
//!   key into their own structures, which live as long as the config does.
//! - **rcgen at generation.** The freshly generated key pair passes through
//!   rcgen's `KeyPair` before it becomes ours.
//!
//! Anything short-lived we cannot put in a `SecretBuf` (PEM handed in by the
//! consumer) is a `Zeroizing<Vec<u8>>` — guaranteed wipe, no lock. The PKCS#8
//! built from a SEC1 key has no such intermediate *(0.12.0)*: the scalar goes
//! straight into a `SecretBuf`, and the key is assembled in one buffer of its
//! final size, which `SecretBuf::from_vec` wipes as it takes it over.
//! `pem::wipe`, the best-effort loop this crate
//! carried under `forbid(unsafe_code)`, is gone: `zeroize` does the same job
//! with a guarantee, and without `unsafe` in this crate.
//!
//! `SecretBuf::from_vec` fails if the memory cannot be locked
//! (`RLIMIT_MEMLOCK`), or *(0.12.0)* if the content is over krypto's size
//! limit, `krypto::MAX_DATA_BYTES`. Both are hard errors here, never a silent
//! fallback to ordinary memory — the same rule krypto itself follows.
//!
//! [`OwnMaterial`]: crate::announcer::OwnMaterial
//! [`Pending`]: crate::announcer::Pending
//! [`TlsMaterial::anchor_pkcs8`]: crate::material::TlsMaterial::anchor_pkcs8

use krypto::SecretBuf;

use crate::error::TlsError;

/// Moves `v` into locked memory. The source is zeroized by `from_vec`.
/// Content over krypto's size limit is [`TlsError::Params`], memory that
/// cannot be locked [`TlsError::LockedMemory`] *(0.12.0)*.
pub(crate) fn hold(v: Vec<u8>) -> Result<SecretBuf, TlsError> {
    SecretBuf::from_vec(v).map_err(|e| TlsError::not_held("a private key", e))
}

/// A second locked copy. `SecretBuf` is deliberately not `Clone`; this is the
/// one place the crate copies a key, and it copies it into another lock.
pub(crate) fn copy(s: &SecretBuf) -> Result<SecretBuf, TlsError> {
    s.expose(|b| hold(b.to_vec()))
}
