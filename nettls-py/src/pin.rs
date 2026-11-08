// SPDX-License-Identifier: MIT OR Apache-2.0
//! `nettls::pin`: static fingerprint pinning. The configs go to
//! `nettls_py.stream`. `classify` and `Rejection` stay in Rust: Python gets the
//! same answer as the exceptions `nettls_py.stream` raises.

use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::err;
use crate::stream::ClientConfig;
use crate::transport::TransportPolicy;

/// `nettls::Expiry` (0.11.0).
#[pyclass(
    eq,
    eq_int,
    frozen,
    hash,
    from_py_object,
    module = "nettls_py.pin",
    name = "Expiry"
)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Expiry {
    Enforce,
    Ignore,
}

impl From<Expiry> for nettls::Expiry {
    fn from(e: Expiry) -> Self {
        match e {
            Expiry::Enforce => nettls::Expiry::Enforce,
            Expiry::Ignore => nettls::Expiry::Ignore,
        }
    }
}

#[pyfunction]
fn pinned_client_config(fingerprint_sha256: &str) -> PyResult<ClientConfig> {
    nettls::pinned_client_config(fingerprint_sha256)
        .map(ClientConfig::wrap)
        .map_err(err)
}

#[pyfunction]
fn pinned_client_config_with_alpn(
    fingerprint_sha256: &str,
    alpn: Vec<Vec<u8>>,
) -> PyResult<ClientConfig> {
    nettls::pinned_client_config_with_alpn(fingerprint_sha256, &alpn)
        .map(ClientConfig::wrap)
        .map_err(err)
}

#[pyfunction]
fn pinned_client_config_with(
    fingerprint_sha256: &str,
    alpn: Vec<Vec<u8>>,
    transport: &TransportPolicy,
    expiry: Expiry,
) -> PyResult<ClientConfig> {
    nettls::pinned_client_config_with(fingerprint_sha256, &alpn, &transport.inner, expiry.into())
        .map(ClientConfig::wrap)
        .map_err(err)
}

/// Accepts any server certificate, for enrollment only (0.11.0). Read it with
/// `Stream.peer_fingerprint()`; never send anything over the connection.
#[pyfunction]
fn unverified_client_config() -> PyResult<ClientConfig> {
    nettls::unverified_client_config()
        .map(ClientConfig::wrap)
        .map_err(err)
}

#[pyfunction]
fn unverified_client_config_with(
    alpn: Vec<Vec<u8>>,
    transport: &TransportPolicy,
) -> PyResult<ClientConfig> {
    nettls::unverified_client_config_with(&alpn, &transport.inner)
        .map(ClientConfig::wrap)
        .map_err(err)
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Expiry>()?;
    m.add_function(wrap_pyfunction!(pinned_client_config, m)?)?;
    m.add_function(wrap_pyfunction!(pinned_client_config_with_alpn, m)?)?;
    m.add_function(wrap_pyfunction!(pinned_client_config_with, m)?)?;
    m.add_function(wrap_pyfunction!(unverified_client_config, m)?)?;
    m.add_function(wrap_pyfunction!(unverified_client_config_with, m)?)?;
    Ok(())
}
