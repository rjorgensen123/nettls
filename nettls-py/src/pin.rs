// SPDX-License-Identifier: MIT OR Apache-2.0
//! `nettls::pin`: static fingerprint pinning. The configs go to
//! `nettls_py.stream`.

use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::err;
use crate::stream::ClientConfig;
use crate::transport::TransportPolicy;

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
) -> PyResult<ClientConfig> {
    nettls::pinned_client_config_with(fingerprint_sha256, &alpn, &transport.inner)
        .map(ClientConfig::wrap)
        .map_err(err)
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(pinned_client_config, m)?)?;
    m.add_function(wrap_pyfunction!(pinned_client_config_with_alpn, m)?)?;
    m.add_function(wrap_pyfunction!(pinned_client_config_with, m)?)?;
    Ok(())
}
