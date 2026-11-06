// SPDX-License-Identifier: MIT OR Apache-2.0
//! `nettls::lockbox`: a password lock for files at rest (§8.4). Argon2 runs
//! without the GIL.

use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::{Alg, Bytes, bytes, err, hold_str, reveal};

#[pyfunction]
fn lock(py: Python<'_>, password: &str, plaintext: &[u8]) -> PyResult<Bytes> {
    let pw = hold_str(password, "the password")?;
    py.detach(|| nettls::lockbox::lock(&pw, plaintext))
        .map(bytes)
        .map_err(err)
}

#[pyfunction]
fn lock_with(py: Python<'_>, password: &str, plaintext: &[u8], alg: Alg) -> PyResult<Bytes> {
    let pw = hold_str(password, "the password")?;
    py.detach(|| nettls::lockbox::lock_with(&pw, plaintext, alg.into()))
        .map(bytes)
        .map_err(err)
}

/// The plaintext comes back as `bytes`: a copy Python holds, neither locked
/// nor wiped.
#[pyfunction]
fn unlock(py: Python<'_>, password: &str, file: &[u8]) -> PyResult<Bytes> {
    let pw = hold_str(password, "the password")?;
    py.detach(|| nettls::lockbox::unlock(&pw, file))
        .map(|s| reveal(&s))
        .map_err(err)
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(lock, m)?)?;
    m.add_function(wrap_pyfunction!(lock_with, m)?)?;
    m.add_function(wrap_pyfunction!(unlock, m)?)?;
    Ok(())
}
