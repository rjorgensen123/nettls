// SPDX-License-Identifier: MIT OR Apache-2.0
//! `nettls::capability`: signed statements of which AEAD algorithms a
//! component supports, and the choice between them.

use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::{Alg, err, hold};
use nettls::capability as c;

#[pyfunction]
fn alg_token(alg: Alg) -> &'static str {
    c::alg_token(alg.into())
}

#[pyfunction]
fn alg_from_token(token: &str) -> PyResult<Alg> {
    Alg::from_rust(c::alg_from_token(token).map_err(err)?)
}

/// `nettls::capability::SupportStatement`. `dumps` and `loads` are what serde
/// does with it in Rust.
#[pyclass(
    get_all,
    set_all,
    from_py_object,
    module = "nettls_py.capability",
    name = "SupportStatement"
)]
#[derive(Clone)]
pub(crate) struct SupportStatement {
    component: String,
    supported: Vec<String>,
    timestamp: i64,
    signature: String,
}

impl SupportStatement {
    fn from_rust(s: c::SupportStatement) -> Self {
        Self {
            component: s.component,
            supported: s.supported,
            timestamp: s.timestamp,
            signature: s.signature,
        }
    }

    fn to_rust(&self) -> c::SupportStatement {
        c::SupportStatement {
            component: self.component.clone(),
            supported: self.supported.clone(),
            timestamp: self.timestamp,
            signature: self.signature.clone(),
        }
    }
}

#[pymethods]
impl SupportStatement {
    #[new]
    fn py_new(
        component: String,
        supported: Vec<String>,
        timestamp: i64,
        signature: String,
    ) -> Self {
        Self {
            component,
            supported,
            timestamp,
            signature,
        }
    }

    #[staticmethod]
    fn signed(
        component: &str,
        supported: Vec<Alg>,
        timestamp: i64,
        anchor_pkcs8: &[u8],
    ) -> PyResult<Self> {
        let key = hold(anchor_pkcs8, "a private key")?;
        let algs: Vec<krypto::Alg> = supported.into_iter().map(Into::into).collect();
        c::SupportStatement::signed(component, &algs, timestamp, &key)
            .map(Self::from_rust)
            .map_err(err)
    }

    fn verify(&self, signer_cert_der: &[u8]) -> PyResult<Vec<Alg>> {
        let algs = self.to_rust().verify(signer_cert_der).map_err(err)?;
        algs.into_iter().map(Alg::from_rust).collect()
    }

    /// The JSON serde writes in Rust.
    fn dumps(&self) -> PyResult<String> {
        serde_json::to_string(&self.to_rust()).map_err(crate::json_err)
    }

    /// Reads the JSON serde reads in Rust.
    #[staticmethod]
    fn loads(s: &str) -> PyResult<Self> {
        serde_json::from_str(s)
            .map(Self::from_rust)
            .map_err(crate::json_err)
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.to_rust())
    }
}

#[pyfunction]
fn choose(requested: Alg, verified_supported: Option<Vec<Alg>>) -> PyResult<Alg> {
    let supported: Option<Vec<krypto::Alg>> =
        verified_supported.map(|v| v.into_iter().map(Into::into).collect());
    Alg::from_rust(c::choose(requested.into(), supported.as_deref()).map_err(err)?)
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(alg_token, m)?)?;
    m.add_function(wrap_pyfunction!(alg_from_token, m)?)?;
    m.add_class::<SupportStatement>()?;
    m.add_function(wrap_pyfunction!(choose, m)?)?;
    Ok(())
}
