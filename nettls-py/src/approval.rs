// SPDX-License-Identifier: MIT OR Apache-2.0
//! `nettls::approval`: the operator's approval (generation 0, §6.4), and
//! `Recognition`, which verifies either kind through one code path (M-9).
//!
//! Where Rust takes a key lookup (`&dyn Fn(&str) -> Option<Vec<u8>>`),
//! Python passes a function from key id to `bytes` or `None`. If the function
//! raises, the key counts as unknown, so the verification fails closed, and the
//! exception is raised afterwards: it is never swallowed.

use std::borrow::Cow;
use std::cell::RefCell;

use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::announcement::Announcement;
use crate::{Bytes, bytes, err, hold, json_err};
use nettls::approval as ap;

/// Runs `verify` with `look_up` as the key lookup. A Python exception from
/// `look_up` wins over the result.
fn with_lookup<R>(
    look_up: &Bound<'_, PyAny>,
    verify: impl FnOnce(&dyn Fn(&str) -> Option<Vec<u8>>) -> Result<R, nettls::TlsError>,
) -> PyResult<R> {
    let failure: RefCell<Option<PyErr>> = RefCell::new(None);
    let lookup = |key_id: &str| -> Option<Vec<u8>> {
        let keep = |e: PyErr| {
            failure.borrow_mut().get_or_insert(e);
            None
        };
        match look_up.call1((key_id,)) {
            Ok(r) if r.is_none() => None,
            Ok(r) => match r.extract::<Cow<'_, [u8]>>() {
                Ok(b) => Some(b.into_owned()),
                Err(e) => keep(e),
            },
            Err(e) => keep(e),
        }
    };
    let result = verify(&lookup);
    if let Some(e) = failure.into_inner() {
        return Err(e);
    }
    result.map_err(err)
}

/// `nettls::approval::ApprovalJson`. `dumps` and `loads` are what serde does
/// with it in Rust.
#[pyclass(
    get_all,
    set_all,
    from_py_object,
    module = "nettls_py.approval",
    name = "ApprovalJson"
)]
#[derive(Clone)]
pub(crate) struct ApprovalJson {
    v: String,
    peer: String,
    fingerprint: String,
    approved_by: String,
    timestamp: i64,
    key_id: String,
    sig: String,
}

impl ApprovalJson {
    fn from_rust(j: ap::ApprovalJson) -> Self {
        Self {
            v: j.v,
            peer: j.peer,
            fingerprint: j.fingerprint,
            approved_by: j.approved_by,
            timestamp: j.timestamp,
            key_id: j.key_id,
            sig: j.sig,
        }
    }

    fn to_rust(&self) -> ap::ApprovalJson {
        ap::ApprovalJson {
            v: self.v.clone(),
            peer: self.peer.clone(),
            fingerprint: self.fingerprint.clone(),
            approved_by: self.approved_by.clone(),
            timestamp: self.timestamp,
            key_id: self.key_id.clone(),
            sig: self.sig.clone(),
        }
    }
}

#[pymethods]
impl ApprovalJson {
    #[new]
    fn py_new(
        v: String,
        peer: String,
        fingerprint: String,
        approved_by: String,
        timestamp: i64,
        key_id: String,
        sig: String,
    ) -> Self {
        Self {
            v,
            peer,
            fingerprint,
            approved_by,
            timestamp,
            key_id,
            sig,
        }
    }

    /// The JSON serde writes in Rust.
    fn dumps(&self) -> PyResult<String> {
        serde_json::to_string(&self.to_rust()).map_err(json_err)
    }

    /// Reads the JSON serde reads in Rust.
    #[staticmethod]
    fn loads(s: &str) -> PyResult<Self> {
        serde_json::from_str(s)
            .map(Self::from_rust)
            .map_err(json_err)
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.to_rust())
    }
}

/// `nettls::approval::Approval`.
#[pyclass(
    eq,
    frozen,
    from_py_object,
    module = "nettls_py.approval",
    name = "Approval"
)]
#[derive(Clone, PartialEq)]
pub(crate) struct Approval {
    inner: ap::Approval,
}

#[pymethods]
impl Approval {
    /// `ed25519_seed` goes straight into locked memory; the `bytes` stays as
    /// Python keeps it.
    #[staticmethod]
    fn new(
        peer: &str,
        fingerprint: &str,
        approved_by: &str,
        timestamp: i64,
        key_id: &str,
        ed25519_seed: &[u8],
    ) -> PyResult<Self> {
        let seed = hold(ed25519_seed, "an Ed25519 seed")?;
        ap::Approval::new(peer, fingerprint, approved_by, timestamp, key_id, &seed)
            .map(|inner| Self { inner })
            .map_err(err)
    }

    fn canonical(&self) -> PyResult<Bytes> {
        self.inner.canonical().map(bytes).map_err(err)
    }

    /// `look_up_key(key_id)` gives the Ed25519 public key as `bytes`, or `None`.
    fn verify(&self, look_up_key: &Bound<'_, PyAny>) -> PyResult<()> {
        with_lookup(look_up_key, |f| self.inner.verify(f))
    }

    fn fingerprint(&self) -> String {
        self.inner.fingerprint().to_string()
    }

    fn peer(&self) -> String {
        self.inner.peer().to_string()
    }

    fn approved_by(&self) -> String {
        self.inner.approved_by().to_string()
    }

    fn key_id(&self) -> String {
        self.inner.key_id().to_string()
    }

    fn to_json(&self) -> ApprovalJson {
        ApprovalJson::from_rust(self.inner.to_json())
    }

    #[staticmethod]
    fn from_json(j: &ApprovalJson) -> PyResult<Self> {
        ap::Approval::from_json(&j.to_rust())
            .map(|inner| Self { inner })
            .map_err(err)
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.inner)
    }
}

/// `nettls::approval::Context`: what it takes to verify a recognition.
/// `keys(key_id)` gives the Ed25519 public key as `bytes`, or `None`.
#[pyclass(module = "nettls_py.approval", name = "Context")]
pub(crate) struct Context {
    #[pyo3(get, set)]
    keys: Py<PyAny>,
    previous_der: Option<Vec<u8>>,
    current_der: Option<Vec<u8>>,
}

#[pymethods]
impl Context {
    #[new]
    fn py_new(
        keys: Py<PyAny>,
        previous_der: Option<Vec<u8>>,
        current_der: Option<Vec<u8>>,
    ) -> Self {
        Self {
            keys,
            previous_der,
            current_der,
        }
    }

    #[getter]
    fn previous_der(&self) -> Option<Bytes> {
        self.previous_der.clone().map(bytes)
    }

    #[setter]
    fn set_previous_der(&mut self, v: Option<Vec<u8>>) {
        self.previous_der = v;
    }

    #[getter]
    fn current_der(&self) -> Option<Bytes> {
        self.current_der.clone().map(bytes)
    }

    #[setter]
    fn set_current_der(&mut self, v: Option<Vec<u8>>) {
        self.current_der = v;
    }
}

/// `nettls::approval::Recognition`: `Operator` for generation 0, `Schedule`
/// for generation 1 and on.
#[pyclass(
    eq,
    from_py_object,
    module = "nettls_py.approval",
    name = "Recognition"
)]
#[derive(Clone, PartialEq)]
pub(crate) enum Recognition {
    Operator(Approval),
    Schedule(Announcement),
}

impl Recognition {
    fn to_rust(&self) -> ap::Recognition {
        match self {
            Self::Operator(g) => ap::Recognition::Operator(g.inner.clone()),
            Self::Schedule(k) => ap::Recognition::Schedule(Box::new(k.inner.clone())),
        }
    }
}

#[pymethods]
impl Recognition {
    fn verify(&self, py: Python<'_>, k: PyRef<'_, Context>) -> PyResult<()> {
        let r = self.to_rust();
        let keys = k.keys.bind(py);
        with_lookup(keys, |f| {
            r.verify(&ap::Context {
                keys: f,
                previous_der: k.previous_der.as_deref(),
                current_der: k.current_der.as_deref(),
            })
        })
    }

    fn fingerprint(&self) -> String {
        self.to_rust().fingerprint().to_string()
    }

    fn is_anchor(&self) -> bool {
        self.to_rust().is_anchor()
    }
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ApprovalJson>()?;
    m.add_class::<Approval>()?;
    m.add_class::<Context>()?;
    m.add_class::<Recognition>()?;
    Ok(())
}
