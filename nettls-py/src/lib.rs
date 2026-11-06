// SPDX-License-Identifier: MIT OR Apache-2.0
//! `nettls_py`: the Python binding for nettls (0.11.0).
//!
//! It is the Rust crate, run from Python: the same modules, names and types,
//! with the same Rust code inside. The binding has no nettls logic of its own.
//! What differs is what can be guaranteed, never what a function does. Private
//! keys stay in nettls's locked memory wherever the crate keeps them; what
//! Python itself holds (`bytes` and `str` passed in, and the copies handed
//! out) is ordinary Python memory, neither locked nor wiped.
//!
//! `Result<T, TlsError>` becomes a return value or an exception: `TlsError`,
//! with one subclass per variant (`TlsError::Pem` is `PemError`, and so on).
//!
//! One part exists only in Python: `nettls_py.stream`, which runs a rustls
//! connection over a Python socket. Rust consumers drive rustls themselves.

mod aegis;
mod announcement;
mod announcer;
mod approval;
mod canonical;
mod capability;
mod envelope;
mod error;
mod generations;
mod lockbox;
mod material;
mod pem;
mod pin;
mod provider;
mod resolver;
mod signature;
mod status;
mod stream;
mod transport;

use std::borrow::Cow;
use std::sync::{Mutex, MutexGuard};

use pyo3::prelude::*;
use pyo3::types::PyModule;

pub(crate) use error::err;

/// What Python gets for Rust's `Vec<u8>`: `bytes`, not a list of ints.
pub(crate) type Bytes = Cow<'static, [u8]>;

pub(crate) fn bytes(v: Vec<u8>) -> Bytes {
    Cow::Owned(v)
}

/// A secret from Python, held the way nettls holds its own: in locked memory.
/// A failure is the error nettls gives for the same thing (`src/secret.rs`).
pub(crate) fn hold(b: &[u8], what: &str) -> PyResult<krypto::SecretBuf> {
    krypto::SecretBuf::from_vec(b.to_vec()).map_err(|e| {
        err(nettls::TlsError::Sign(format!(
            "could not hold {what} in locked memory (mlock — check RLIMIT_MEMLOCK): {e}"
        )))
    })
}

/// A password from Python, held in locked memory.
pub(crate) fn hold_str(s: &str, what: &str) -> PyResult<krypto::SecretString> {
    krypto::SecretString::from_string(s.to_owned()).map_err(|e| {
        err(nettls::TlsError::Sign(format!(
            "could not hold {what} in locked memory (mlock — check RLIMIT_MEMLOCK): {e}"
        )))
    })
}

/// A copy of a secret for Python. The copy is ordinary Python memory.
pub(crate) fn reveal(s: &krypto::SecretBuf) -> Bytes {
    s.expose(|b| Cow::Owned(b.to_vec()))
}

/// JSON that serde cannot read is a `ValueError`, as `json.loads` gives.
pub(crate) fn json_err(e: serde_json::Error) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(format!("invalid JSON: {e}"))
}

/// A poisoned lock still guards valid state here: every method leaves it whole.
pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// `krypto::Alg`, which `lockbox`, `envelope` and `capability` take. nettls
/// does not re-export it, so in Python it lives at the root.
#[pyclass(
    eq,
    eq_int,
    frozen,
    hash,
    from_py_object,
    module = "nettls_py",
    name = "Alg"
)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Alg {
    Aegis256,
    XChaCha20Poly1305,
    Aes256Gcm,
}

impl From<Alg> for krypto::Alg {
    fn from(a: Alg) -> Self {
        match a {
            Alg::Aegis256 => krypto::Alg::Aegis256,
            Alg::XChaCha20Poly1305 => krypto::Alg::XChaCha20Poly1305,
            Alg::Aes256Gcm => krypto::Alg::Aes256Gcm,
        }
    }
}

impl Alg {
    /// `krypto::Alg` is `#[non_exhaustive]`: an algorithm this binding does
    /// not know is an error, never a guess.
    pub(crate) fn from_rust(a: krypto::Alg) -> PyResult<Self> {
        match a {
            krypto::Alg::Aegis256 => Ok(Alg::Aegis256),
            krypto::Alg::XChaCha20Poly1305 => Ok(Alg::XChaCha20Poly1305),
            krypto::Alg::Aes256Gcm => Ok(Alg::Aes256Gcm),
            other => Err(err(nettls::TlsError::Params(format!(
                "nettls_py does not know the algorithm {other:?}; update nettls-py"
            )))),
        }
    }
}

/// The submodule `nettls_py.<name>`: an attribute of the parent, and importable.
fn submodule<'py>(
    parent: &Bound<'py, PyModule>,
    name: &str,
    fill: impl FnOnce(&Bound<'py, PyModule>) -> PyResult<()>,
) -> PyResult<()> {
    let py = parent.py();
    let full = format!("nettls_py.{name}");
    let m = PyModule::new(py, &full)?;
    fill(&m)?;
    parent.add(name, &m)?;
    py.import("sys")?.getattr("modules")?.set_item(&full, &m)?;
    Ok(())
}

#[pymodule]
fn nettls_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("VERSION", nettls::VERSION)?;
    m.add("__version__", nettls::VERSION)?;
    m.add_class::<Alg>()?;

    // The root re-exports, as `src/lib.rs` has them.
    error::register(m)?;
    material::register_root(m)?;
    pin::register(m)?;
    provider::register(m)?;
    m.add_class::<resolver::RotatingResolver>()?;
    m.add_class::<transport::TransportCipher>()?;
    m.add_class::<transport::TransportPolicy>()?;

    submodule(m, "aegis", aegis::register)?;
    submodule(m, "announcement", announcement::register)?;
    submodule(m, "announcer", announcer::register)?;
    submodule(m, "approval", approval::register)?;
    submodule(m, "canonical", canonical::register)?;
    submodule(m, "capability", capability::register)?;
    submodule(m, "envelope", envelope::register)?;
    submodule(m, "error", error::register)?;
    submodule(m, "generations", generations::register)?;
    submodule(m, "lockbox", lockbox::register)?;
    submodule(m, "material", material::register)?;
    submodule(m, "pem", pem::register)?;
    submodule(m, "pin", pin::register)?;
    submodule(m, "provider", provider::register)?;
    submodule(m, "resolver", resolver::register)?;
    submodule(m, "signature", signature::register)?;
    submodule(m, "status", status::register)?;
    submodule(m, "stream", stream::register)?;
    submodule(m, "transport", transport::register)?;
    Ok(())
}
