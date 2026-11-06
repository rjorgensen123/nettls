// SPDX-License-Identifier: MIT OR Apache-2.0
//! `nettls::transport`: the TLS channel's cipher, the consumer's choice (§6.0b).

use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::err;

/// `nettls::TransportCipher`.
#[pyclass(
    eq,
    eq_int,
    frozen,
    hash,
    from_py_object,
    module = "nettls_py.transport",
    name = "TransportCipher"
)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum TransportCipher {
    Aes256Gcm,
    ChaCha20Poly1305,
    Aegis256,
}

impl From<TransportCipher> for nettls::TransportCipher {
    fn from(c: TransportCipher) -> Self {
        match c {
            TransportCipher::Aes256Gcm => nettls::TransportCipher::Aes256Gcm,
            TransportCipher::ChaCha20Poly1305 => nettls::TransportCipher::ChaCha20Poly1305,
            TransportCipher::Aegis256 => nettls::TransportCipher::Aegis256,
        }
    }
}

impl TransportCipher {
    /// `TransportCipher` is `#[non_exhaustive]`: a cipher this binding does
    /// not know is an error, never a guess.
    fn from_rust(c: nettls::TransportCipher) -> PyResult<Self> {
        match c {
            nettls::TransportCipher::Aes256Gcm => Ok(Self::Aes256Gcm),
            nettls::TransportCipher::ChaCha20Poly1305 => Ok(Self::ChaCha20Poly1305),
            nettls::TransportCipher::Aegis256 => Ok(Self::Aegis256),
            other => Err(err(nettls::TlsError::Params(format!(
                "nettls_py does not know the transport cipher {other:?}; update nettls-py"
            )))),
        }
    }
}

#[pymethods]
impl TransportCipher {
    fn token(&self) -> &'static str {
        nettls::TransportCipher::from(*self).token()
    }
}

/// `nettls::TransportPolicy`. `TransportPolicy()` is the default policy.
#[pyclass(
    eq,
    frozen,
    from_py_object,
    module = "nettls_py.transport",
    name = "TransportPolicy"
)]
#[derive(Clone, PartialEq)]
pub(crate) struct TransportPolicy {
    pub(crate) inner: nettls::TransportPolicy,
}

#[pymethods]
impl TransportPolicy {
    #[new]
    fn default_policy() -> Self {
        Self {
            inner: nettls::TransportPolicy::default(),
        }
    }

    #[staticmethod]
    fn only(cipher: TransportCipher) -> Self {
        Self {
            inner: nettls::TransportPolicy::only(cipher.into()),
        }
    }

    #[staticmethod]
    fn new(ciphers: Vec<TransportCipher>) -> PyResult<Self> {
        let ciphers: Vec<nettls::TransportCipher> = ciphers.into_iter().map(Into::into).collect();
        nettls::TransportPolicy::new(&ciphers)
            .map(|inner| Self { inner })
            .map_err(err)
    }

    fn ciphers(&self) -> PyResult<Vec<TransportCipher>> {
        self.inner
            .ciphers()
            .iter()
            .map(|c| TransportCipher::from_rust(*c))
            .collect()
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.inner)
    }
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<TransportCipher>()?;
    m.add_class::<TransportPolicy>()?;
    Ok(())
}
