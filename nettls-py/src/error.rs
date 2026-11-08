// SPDX-License-Identifier: MIT OR Apache-2.0
//! `nettls::error`: `TlsError` as exceptions, one subclass per variant.

use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyModule;

pyo3::create_exception!(
    nettls_py,
    TlsError,
    PyException,
    "Every nettls error (`nettls::TlsError`). No error carries key material."
);
pyo3::create_exception!(
    nettls_py,
    IoError,
    TlsError,
    "`TlsError::Io`: file I/O failed."
);
pyo3::create_exception!(
    nettls_py,
    PemError,
    TlsError,
    "`TlsError::Pem`: the PEM could not be parsed."
);
pyo3::create_exception!(
    nettls_py,
    KeyMismatchError,
    TlsError,
    "`TlsError::KeyMismatch`: the private key does not belong to the certificate."
);
pyo3::create_exception!(
    nettls_py,
    NotValidNowError,
    TlsError,
    "`TlsError::NotValidNow`: the certificate is expired or not yet valid."
);
pyo3::create_exception!(
    nettls_py,
    CertificateError,
    TlsError,
    "`TlsError::Certificate`: the certificate could not be parsed as X.509."
);
pyo3::create_exception!(
    nettls_py,
    GenerateError,
    TlsError,
    "`TlsError::Generate`: generating a self-signed certificate failed."
);
pyo3::create_exception!(
    nettls_py,
    RustlsError,
    TlsError,
    "`TlsError::Rustls`: rustls rejected the configuration."
);
pyo3::create_exception!(
    nettls_py,
    ParamsError,
    TlsError,
    "`TlsError::Params`: invalid parameters from the caller."
);
pyo3::create_exception!(
    nettls_py,
    FingerprintError,
    TlsError,
    "`TlsError::Fingerprint`: the fingerprint is not 32 bytes of hexadecimal."
);
pyo3::create_exception!(
    nettls_py,
    ProofError,
    TlsError,
    "`TlsError::Proof`: a signed or serialized value could not be parsed."
);
pyo3::create_exception!(
    nettls_py,
    ProofInvalidError,
    TlsError,
    "`TlsError::ProofInvalid`: a value parsed cleanly but does not hold."
);
pyo3::create_exception!(
    nettls_py,
    ChainError,
    TlsError,
    "`TlsError::Chain`: the continuity chain is broken."
);
pyo3::create_exception!(
    nettls_py,
    SignError,
    TlsError,
    "`TlsError::Sign`: signing failed, or a key could not be held in locked memory."
);
pyo3::create_exception!(
    nettls_py,
    NegotiationError,
    TlsError,
    "`TlsError::Negotiation`: no algorithm both sides can use."
);

pyo3::create_exception!(
    nettls_py,
    EnvelopeError,
    TlsError,
    "`TlsError::Envelope`: the sealed envelope or the password lock failed (0.11.0)."
);
pyo3::create_exception!(
    nettls_py,
    LockedMemoryError,
    TlsError,
    "`TlsError::LockedMemory`: a secret could not be held in locked memory (0.11.0)."
);
pyo3::create_exception!(
    nettls_py,
    RandomError,
    TlsError,
    "`TlsError::Random`: the operating system could not supply random numbers (0.11.0)."
);
pyo3::create_exception!(
    nettls_py,
    LockPoisonedError,
    TlsError,
    "`TlsError::LockPoisoned`: a thread panicked while holding one of the crate's locks (0.11.0)."
);

/// `nettls::TlsError` as the Python exception for its variant. The text is
/// Rust's `Display`.
pub(crate) fn err(e: nettls::TlsError) -> PyErr {
    use nettls::TlsError as E;
    let msg = e.to_string();
    match e {
        E::Io { .. } => IoError::new_err(msg),
        E::Pem(_) => PemError::new_err(msg),
        E::KeyMismatch(_) => KeyMismatchError::new_err(msg),
        E::NotValidNow { .. } => NotValidNowError::new_err(msg),
        E::Certificate(_) => CertificateError::new_err(msg),
        E::Generate(_) => GenerateError::new_err(msg),
        E::Rustls(_) => RustlsError::new_err(msg),
        E::Params(_) => ParamsError::new_err(msg),
        E::Fingerprint(_) => FingerprintError::new_err(msg),
        E::Proof(_) => ProofError::new_err(msg),
        E::ProofInvalid(_) => ProofInvalidError::new_err(msg),
        E::Chain(_) => ChainError::new_err(msg),
        E::Sign(_) => SignError::new_err(msg),
        E::Negotiation(_) => NegotiationError::new_err(msg),
        E::Envelope(_) => EnvelopeError::new_err(msg),
        E::LockedMemory(_) => LockedMemoryError::new_err(msg),
        E::Random(_) => RandomError::new_err(msg),
        E::LockPoisoned(_) => LockPoisonedError::new_err(msg),
        // `TlsError` is `#[non_exhaustive]`: a variant this binding does not
        // know still raises, as the base class.
        _ => TlsError::new_err(msg),
    }
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();
    m.add("TlsError", py.get_type::<TlsError>())?;
    m.add("IoError", py.get_type::<IoError>())?;
    m.add("PemError", py.get_type::<PemError>())?;
    m.add("KeyMismatchError", py.get_type::<KeyMismatchError>())?;
    m.add("NotValidNowError", py.get_type::<NotValidNowError>())?;
    m.add("CertificateError", py.get_type::<CertificateError>())?;
    m.add("GenerateError", py.get_type::<GenerateError>())?;
    m.add("RustlsError", py.get_type::<RustlsError>())?;
    m.add("ParamsError", py.get_type::<ParamsError>())?;
    m.add("FingerprintError", py.get_type::<FingerprintError>())?;
    m.add("ProofError", py.get_type::<ProofError>())?;
    m.add("ProofInvalidError", py.get_type::<ProofInvalidError>())?;
    m.add("ChainError", py.get_type::<ChainError>())?;
    m.add("SignError", py.get_type::<SignError>())?;
    m.add("NegotiationError", py.get_type::<NegotiationError>())?;
    m.add("EnvelopeError", py.get_type::<EnvelopeError>())?;
    m.add("LockedMemoryError", py.get_type::<LockedMemoryError>())?;
    m.add("RandomError", py.get_type::<RandomError>())?;
    m.add("LockPoisonedError", py.get_type::<LockPoisonedError>())?;
    Ok(())
}
