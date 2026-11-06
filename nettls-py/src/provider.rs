// SPDX-License-Identifier: MIT OR Apache-2.0
//! `nettls::provider`. `provider()` gives a rustls value and has no meaning
//! outside rustls; every config the crate builds already uses it.

use pyo3::prelude::*;
use pyo3::types::PyModule;

#[pyfunction]
fn install_crypto_provider() -> bool {
    nettls::install_crypto_provider()
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(install_crypto_provider, m)?)?;
    Ok(())
}
