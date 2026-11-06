// SPDX-License-Identifier: MIT OR Apache-2.0
//! `nettls::material`: where the certificate comes from, and what it is.
//! `TlsMaterial::certified_key` gives a rustls value and has no meaning
//! outside rustls; `server_config` gives what `nettls_py.stream` takes.

use std::path::PathBuf;

use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::stream::ServerConfig;
use crate::transport::TransportPolicy;
use crate::{Bytes, bytes, err, reveal};

/// `nettls::CertOrigin`.
#[pyclass(
    eq,
    eq_int,
    frozen,
    hash,
    from_py_object,
    module = "nettls_py.material",
    name = "CertOrigin"
)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum CertOrigin {
    Files,
    Pem,
    Generated,
    Reused,
    ReusedExpired,
    Ephemeral,
}

impl CertOrigin {
    /// `CertOrigin` is `#[non_exhaustive]`: an origin this binding does not
    /// know is an error, never a guess.
    fn from_rust(o: nettls::CertOrigin) -> PyResult<Self> {
        use nettls::CertOrigin as O;
        match o {
            O::Files => Ok(Self::Files),
            O::Pem => Ok(Self::Pem),
            O::Generated => Ok(Self::Generated),
            O::Reused => Ok(Self::Reused),
            O::ReusedExpired => Ok(Self::ReusedExpired),
            O::Ephemeral => Ok(Self::Ephemeral),
            other => Err(err(nettls::TlsError::Params(format!(
                "nettls_py does not know the origin {other:?}; update nettls-py"
            )))),
        }
    }
}

/// `nettls::SelfSignedParams`. `SelfSignedParams()` is the default. In Rust
/// `valid_days` is both a field and a builder; in Python it is the field.
#[pyclass(
    get_all,
    set_all,
    from_py_object,
    module = "nettls_py.material",
    name = "SelfSignedParams"
)]
#[derive(Clone)]
pub(crate) struct SelfSignedParams {
    common_name: String,
    sans: Vec<String>,
    valid_days: u32,
}

impl SelfSignedParams {
    pub(crate) fn from_rust(p: nettls::SelfSignedParams) -> Self {
        Self {
            common_name: p.common_name,
            sans: p.sans,
            valid_days: p.valid_days,
        }
    }

    pub(crate) fn to_rust(&self) -> nettls::SelfSignedParams {
        nettls::SelfSignedParams {
            common_name: self.common_name.clone(),
            sans: self.sans.clone(),
            valid_days: self.valid_days,
        }
    }
}

#[pymethods]
impl SelfSignedParams {
    #[new]
    fn default_params() -> Self {
        Self::from_rust(nettls::SelfSignedParams::default())
    }

    #[staticmethod]
    fn new(common_name: String, sans: Vec<String>) -> Self {
        Self::from_rust(nettls::SelfSignedParams::new(common_name, sans))
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.to_rust())
    }
}

/// `nettls::CertSource`.
#[pyclass(frozen, module = "nettls_py.material", name = "CertSource")]
pub(crate) struct CertSource {
    inner: nettls::CertSource,
}

#[pymethods]
impl CertSource {
    #[staticmethod]
    fn files(cert_path: PathBuf, key_path: PathBuf) -> Self {
        Self {
            inner: nettls::CertSource::files(cert_path, key_path),
        }
    }

    #[staticmethod]
    fn pem(cert_pem: Vec<u8>, key_pem: Vec<u8>) -> Self {
        Self {
            inner: nettls::CertSource::pem(cert_pem, key_pem),
        }
    }

    #[staticmethod]
    fn self_signed(params: SelfSignedParams) -> Self {
        Self {
            inner: nettls::CertSource::self_signed(params.to_rust()),
        }
    }

    #[staticmethod]
    fn auto(dir: PathBuf, params: SelfSignedParams) -> Self {
        Self {
            inner: nettls::CertSource::auto(dir, params.to_rust()),
        }
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.inner)
    }
}

/// `nettls::TlsMaterial`. The private key stays in locked memory.
#[pyclass(frozen, module = "nettls_py.material", name = "TlsMaterial")]
pub(crate) struct TlsMaterial {
    pub(crate) inner: nettls::TlsMaterial,
}

#[pymethods]
impl TlsMaterial {
    /// Generating a key runs without the GIL.
    #[staticmethod]
    fn load(py: Python<'_>, src: &CertSource) -> PyResult<Self> {
        py.detach(|| nettls::TlsMaterial::load(&src.inner))
            .map(|inner| Self { inner })
            .map_err(err)
    }

    fn fingerprint_sha256(&self) -> String {
        self.inner.fingerprint_sha256()
    }

    fn not_after(&self) -> Option<i64> {
        self.inner.not_after()
    }

    fn not_before(&self) -> Option<i64> {
        self.inner.not_before()
    }

    fn days_until_expiry(&self) -> i64 {
        self.inner.days_until_expiry()
    }

    fn is_valid_now(&self) -> bool {
        self.inner.is_valid_now()
    }

    fn sans(&self) -> Vec<String> {
        self.inner.sans().to_vec()
    }

    fn subject(&self) -> String {
        self.inner.subject().to_string()
    }

    fn origin(&self) -> PyResult<CertOrigin> {
        CertOrigin::from_rust(self.inner.origin())
    }

    /// The chain as DER, leaf first.
    fn cert_chain(&self) -> Vec<Bytes> {
        self.inner
            .cert_chain()
            .iter()
            .map(|c| bytes(c.as_ref().to_vec()))
            .collect()
    }

    /// The anchor key as PKCS#8 DER. The copy is `bytes` Python holds, neither
    /// locked nor wiped.
    fn anchor_pkcs8(&self) -> PyResult<Bytes> {
        self.inner.anchor_pkcs8().map(|s| reveal(&s)).map_err(err)
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

    fn save_pem(&self, py: Python<'_>, dir: PathBuf) -> PyResult<()> {
        py.detach(|| self.inner.save_pem(&dir)).map_err(err)
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.inner)
    }
}

#[pyfunction]
fn is_valid_san(name: &str) -> bool {
    nettls::is_valid_san(name)
}

#[pyfunction]
fn cert_fingerprint_sha256(cert_der: &[u8]) -> String {
    nettls::cert_fingerprint_sha256(cert_der)
}

/// What `src/lib.rs` re-exports from `material`.
pub(crate) fn register_root(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("CERT_FILE", nettls::CERT_FILE)?;
    m.add("KEY_FILE", nettls::KEY_FILE)?;
    m.add("MAX_VALID_DAYS", nettls::MAX_VALID_DAYS)?;
    m.add_class::<CertOrigin>()?;
    m.add_class::<CertSource>()?;
    m.add_class::<SelfSignedParams>()?;
    m.add_class::<TlsMaterial>()?;
    m.add_function(wrap_pyfunction!(cert_fingerprint_sha256, m)?)?;
    m.add_function(wrap_pyfunction!(is_valid_san, m)?)?;
    Ok(())
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    register_root(m)
}
