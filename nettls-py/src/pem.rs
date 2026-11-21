// SPDX-License-Identifier: MIT OR Apache-2.0
//! `nettls::pem`: PEM building.

use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::{Bytes, bytes, err};

#[pyfunction]
fn encode(label: &str, der: &[u8]) -> PyResult<Bytes> {
    nettls::pem::encode(label, der).map(bytes).map_err(err)
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(encode, m)?)?;
    Ok(())
}
