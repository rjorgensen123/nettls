// SPDX-License-Identifier: MIT OR Apache-2.0
//! `nettls::resolver`: the server certificate that follows the rotation.

use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::err;
use crate::material::TlsMaterial;
use crate::stream::ServerConfig;
use crate::transport::TransportPolicy;

/// `nettls::RotatingResolver`. A `server_config` from it follows every swap,
/// also the ones the `Announcer` it is given to makes.
#[pyclass(frozen, module = "nettls_py.resolver", name = "RotatingResolver")]
pub(crate) struct RotatingResolver {
    pub(crate) inner: Arc<nettls::RotatingResolver>,
}

#[pymethods]
impl RotatingResolver {
    #[new]
    fn py_new(material: &TlsMaterial) -> PyResult<Self> {
        Self::new(material)
    }

    #[staticmethod]
    fn new(material: &TlsMaterial) -> PyResult<Self> {
        nettls::RotatingResolver::new(&material.inner)
            .map(|r| Self { inner: Arc::new(r) })
            .map_err(err)
    }

    fn swap(&self, material: &TlsMaterial) -> PyResult<String> {
        self.inner.swap(&material.inner).map_err(err)
    }

    fn fingerprint_sha256(&self) -> String {
        self.inner.fingerprint_sha256()
    }

    fn server_config(&self) -> PyResult<ServerConfig> {
        self.inner
            .server_config()
            .map(ServerConfig::wrap)
            .map_err(err)
    }

    fn server_config_with_alpn(&self, alpn: Vec<Vec<u8>>) -> PyResult<ServerConfig> {
        self.inner
            .server_config_with_alpn(&alpn)
            .map(ServerConfig::wrap)
            .map_err(err)
    }

    fn server_config_with(
        &self,
        alpn: Vec<Vec<u8>>,
        transport: &TransportPolicy,
    ) -> PyResult<ServerConfig> {
        self.inner
            .server_config_with(&alpn, &transport.inner)
            .map(ServerConfig::wrap)
            .map_err(err)
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.inner)
    }
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<RotatingResolver>()?;
    Ok(())
}
