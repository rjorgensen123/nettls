// SPDX-License-Identifier: MIT OR Apache-2.0
//! `nettls::canonical`: the canonical strings that are signed, and the checks
//! on their fields.

use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::{Bytes, bytes, err};
use nettls::canonical as c;

#[pyfunction]
fn require_fingerprint(v: &str, field: &str) -> PyResult<()> {
    c::require_fingerprint(v, field).map_err(err)
}

#[pyfunction]
fn require_component_name(v: &str, field: &str) -> PyResult<()> {
    c::require_component_name(v, field).map_err(err)
}

#[pyfunction]
fn require_name(v: &str, field: &str, max: usize) -> PyResult<()> {
    c::require_name(v, field, max).map_err(err)
}

#[pyfunction]
fn algsupport_v1(component: &str, algs: &str, timestamp: i64) -> PyResult<Bytes> {
    c::algsupport_v1(component, algs, timestamp)
        .map(bytes)
        .map_err(err)
}

#[pyfunction]
fn approve_v1(peer: &str, fingerprint: &str, approved_by: &str, timestamp: i64) -> PyResult<Bytes> {
    c::approve_v1(peer, fingerprint, approved_by, timestamp)
        .map(bytes)
        .map_err(err)
}

#[pyfunction]
fn rotate_v2(
    announcer: &str,
    prev_fp: Option<&str>,
    curr_fp: &str,
    new_fp: &str,
    sent_at: i64,
) -> PyResult<Bytes> {
    c::rotate_v2(announcer, prev_fp, curr_fp, new_fp, sent_at)
        .map(bytes)
        .map_err(err)
}

#[pyfunction]
fn rotate_ack_v2(acker: &str, announcer: &str, new_fp: &str, sent_at: i64) -> PyResult<Bytes> {
    c::rotate_ack_v2(acker, announcer, new_fp, sent_at)
        .map(bytes)
        .map_err(err)
}

#[pyfunction]
fn pairsecret_v1(
    a: &str,
    b: &str,
    sealed_a_sha256: &str,
    sealed_b_sha256: &str,
    sent_at: i64,
) -> PyResult<Bytes> {
    c::pairsecret_v1(a, b, sealed_a_sha256, sealed_b_sha256, sent_at)
        .map(bytes)
        .map_err(err)
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("APPROVE_V1", c::APPROVE_V1)?;
    m.add("ROTATE_V2", c::ROTATE_V2)?;
    m.add("ROTATE_ACK_V2", c::ROTATE_ACK_V2)?;
    m.add("PAIRSECRET_V1", c::PAIRSECRET_V1)?;
    m.add("ALGSUPPORT_V1", c::ALGSUPPORT_V1)?;
    m.add_function(wrap_pyfunction!(require_fingerprint, m)?)?;
    m.add_function(wrap_pyfunction!(require_component_name, m)?)?;
    m.add_function(wrap_pyfunction!(require_name, m)?)?;
    m.add_function(wrap_pyfunction!(algsupport_v1, m)?)?;
    m.add_function(wrap_pyfunction!(approve_v1, m)?)?;
    m.add_function(wrap_pyfunction!(rotate_v2, m)?)?;
    m.add_function(wrap_pyfunction!(rotate_ack_v2, m)?)?;
    m.add_function(wrap_pyfunction!(pairsecret_v1, m)?)?;
    Ok(())
}
