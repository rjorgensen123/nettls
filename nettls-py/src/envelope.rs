// SPDX-License-Identifier: MIT OR Apache-2.0
//! `nettls::envelope`: a sealed envelope to one recipient (X25519).

use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::{Alg, Bytes, bytes, err, hold, reveal};

/// `nettls::envelope::RecipientKey`. The private key stays in locked memory.
#[pyclass(frozen, module = "nettls_py.envelope", name = "RecipientKey")]
pub(crate) struct RecipientKey {
    inner: nettls::envelope::RecipientKey,
}

#[pymethods]
impl RecipientKey {
    #[staticmethod]
    fn from_bytes(b: &[u8]) -> PyResult<Self> {
        let key = hold(b, "a recipient key")?;
        nettls::envelope::RecipientKey::from_bytes(key)
            .map(|inner| Self { inner })
            .map_err(err)
    }

    /// The key and its public part.
    #[staticmethod]
    fn generate() -> PyResult<(Self, Bytes)> {
        nettls::envelope::RecipientKey::generate()
            .map(|(inner, public)| (Self { inner }, bytes(public)))
            .map_err(err)
    }

    fn public(&self) -> PyResult<Bytes> {
        self.inner.public().map(bytes).map_err(err)
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.inner)
    }
}

#[pyfunction]
fn seal(recipient_public: &[u8], plaintext: &[u8]) -> PyResult<Bytes> {
    nettls::envelope::seal(recipient_public, plaintext)
        .map(bytes)
        .map_err(err)
}

#[pyfunction]
fn seal_with(recipient_public: &[u8], plaintext: &[u8], alg: Alg) -> PyResult<Bytes> {
    nettls::envelope::seal_with(recipient_public, plaintext, alg.into())
        .map(bytes)
        .map_err(err)
}

/// The plaintext comes back as `bytes`: a copy Python holds, neither locked
/// nor wiped.
#[pyfunction]
fn open(key: &RecipientKey, envelope: &[u8]) -> PyResult<Bytes> {
    nettls::envelope::open(&key.inner, envelope)
        .map(|s| reveal(&s))
        .map_err(err)
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("X25519_LEN", nettls::envelope::X25519_LEN)?;
    m.add_class::<RecipientKey>()?;
    m.add_function(wrap_pyfunction!(seal, m)?)?;
    m.add_function(wrap_pyfunction!(seal_with, m)?)?;
    m.add_function(wrap_pyfunction!(open, m)?)?;
    Ok(())
}
