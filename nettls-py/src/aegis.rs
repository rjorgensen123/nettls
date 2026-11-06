// SPDX-License-Identifier: MIT OR Apache-2.0
//! `nettls::aegis`: the code point of our AEGIS-256 suite. `suite()` gives a
//! rustls value and has no meaning outside rustls; the transport policy picks
//! the suite.

use pyo3::prelude::*;
use pyo3::types::PyModule;

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("CODEPOINT", nettls::aegis::CODEPOINT)?;
    Ok(())
}
