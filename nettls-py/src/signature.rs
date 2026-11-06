// SPDX-License-Identifier: MIT OR Apache-2.0
//! `nettls::signature`: P-256 signatures with the anchor key, and hex.

use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::{Bytes, bytes, err, hold};

#[pyfunction]
fn from_hex(s: &str) -> PyResult<Bytes> {
    nettls::signature::from_hex(s).map(bytes).map_err(err)
}

#[pyfunction]
fn p256_public_key(cert_der: &[u8]) -> PyResult<Bytes> {
    nettls::signature::p256_public_key(cert_der)
        .map(bytes)
        .map_err(err)
}

#[pyfunction]
fn verify_p256(cert_der: &[u8], message: &[u8], signature: &[u8]) -> PyResult<()> {
    nettls::signature::verify_p256(cert_der, message, signature).map_err(err)
}

/// `pkcs8` goes straight into locked memory; the `bytes` stays as Python keeps it.
#[pyfunction]
fn sign_p256(pkcs8: &[u8], message: &[u8]) -> PyResult<Bytes> {
    let key = hold(pkcs8, "a private key")?;
    nettls::signature::sign_p256(&key, message)
        .map(bytes)
        .map_err(err)
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(from_hex, m)?)?;
    m.add_function(wrap_pyfunction!(p256_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(verify_p256, m)?)?;
    m.add_function(wrap_pyfunction!(sign_p256, m)?)?;
    Ok(())
}
