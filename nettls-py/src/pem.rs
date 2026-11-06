// SPDX-License-Identifier: MIT OR Apache-2.0
//! `nettls::pem`: PEM building.

use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::{Bytes, bytes};

#[pyfunction]
fn encode(label: &str, der: &[u8]) -> Bytes {
    bytes(nettls::pem::encode(label, der))
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(encode, m)?)?;
    Ok(())
}
