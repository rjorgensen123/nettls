// SPDX-License-Identifier: MIT OR Apache-2.0
//! `nettls::announcement`: the rotation announcement and its receipt (§6.5,
//! §6.6), the archive, and the identity document.

use std::path::PathBuf;

use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::announcer::Mode;
use crate::{Bytes, bytes, err, hold, json_err};
use nettls::announcement as a;

#[pyfunction]
fn fingerprint_from_pem(pem: &str) -> PyResult<String> {
    a::fingerprint_from_pem(pem).map_err(err)
}

#[pyfunction]
fn der_from_pem(pem: &str) -> PyResult<Bytes> {
    a::der_from_pem(pem).map(bytes).map_err(err)
}

/// `nettls::announcement::AnnouncementJson`. `dumps` and `loads` are what
/// serde does with it in Rust.
#[pyclass(
    get_all,
    set_all,
    from_py_object,
    module = "nettls_py.announcement",
    name = "AnnouncementJson"
)]
#[derive(Clone)]
pub(crate) struct AnnouncementJson {
    v: String,
    announcer: String,
    prev_fingerprint: Option<String>,
    curr_fingerprint: String,
    new_fingerprint: String,
    new_cert_pem: String,
    sent_at: i64,
    sig_prev: Option<String>,
    sig_curr: String,
}

impl AnnouncementJson {
    fn from_rust(j: a::AnnouncementJson) -> Self {
        Self {
            v: j.v,
            announcer: j.announcer,
            prev_fingerprint: j.prev_fingerprint,
            curr_fingerprint: j.curr_fingerprint,
            new_fingerprint: j.new_fingerprint,
            new_cert_pem: j.new_cert_pem,
            sent_at: j.sent_at,
            sig_prev: j.sig_prev,
            sig_curr: j.sig_curr,
        }
    }

    fn to_rust(&self) -> a::AnnouncementJson {
        a::AnnouncementJson {
            v: self.v.clone(),
            announcer: self.announcer.clone(),
            prev_fingerprint: self.prev_fingerprint.clone(),
            curr_fingerprint: self.curr_fingerprint.clone(),
            new_fingerprint: self.new_fingerprint.clone(),
            new_cert_pem: self.new_cert_pem.clone(),
            sent_at: self.sent_at,
            sig_prev: self.sig_prev.clone(),
            sig_curr: self.sig_curr.clone(),
        }
    }
}

#[pymethods]
impl AnnouncementJson {
    #[new]
    #[allow(clippy::too_many_arguments)]
    fn py_new(
        v: String,
        announcer: String,
        prev_fingerprint: Option<String>,
        curr_fingerprint: String,
        new_fingerprint: String,
        new_cert_pem: String,
        sent_at: i64,
        sig_prev: Option<String>,
        sig_curr: String,
    ) -> Self {
        Self {
            v,
            announcer,
            prev_fingerprint,
            curr_fingerprint,
            new_fingerprint,
            new_cert_pem,
            sent_at,
            sig_prev,
            sig_curr,
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

/// `nettls::announcement::Announcement`.
#[pyclass(
    eq,
    frozen,
    from_py_object,
    module = "nettls_py.announcement",
    name = "Announcement"
)]
#[derive(Clone, PartialEq)]
pub(crate) struct Announcement {
    pub(crate) inner: a::Announcement,
}

#[pymethods]
impl Announcement {
    /// `prev` and `curr` are `(fingerprint, pkcs8)`. The keys go straight into
    /// locked memory; the `bytes` stay as Python keeps them.
    #[staticmethod]
    fn new(
        announcer: &str,
        prev: Option<(String, Vec<u8>)>,
        curr: (String, Vec<u8>),
        new_cert_pem: &str,
        sent_at: i64,
    ) -> PyResult<Self> {
        let prev_key = match &prev {
            Some((_, k)) => Some(hold(k, "a private key")?),
            None => None,
        };
        let curr_key = hold(&curr.1, "a private key")?;
        let prev_ref = match (&prev, &prev_key) {
            (Some((fp, _)), Some(k)) => Some((fp.as_str(), k)),
            _ => None,
        };
        a::Announcement::new(
            announcer,
            prev_ref,
            (curr.0.as_str(), &curr_key),
            new_cert_pem,
            sent_at,
        )
        .map(|inner| Self { inner })
        .map_err(err)
    }

    fn canonical(&self) -> PyResult<Bytes> {
        self.inner.canonical().map(bytes).map_err(err)
    }

    fn verify(&self, prev_cert_der: Option<Vec<u8>>, curr_cert_der: &[u8]) -> PyResult<()> {
        self.inner
            .verify(prev_cert_der.as_deref(), curr_cert_der)
            .map_err(err)
    }

    fn to_json(&self) -> AnnouncementJson {
        AnnouncementJson::from_rust(self.inner.to_json())
    }

    #[staticmethod]
    fn from_json(j: &AnnouncementJson) -> PyResult<Self> {
        a::Announcement::from_json(&j.to_rust())
            .map(|inner| Self { inner })
            .map_err(err)
    }

    fn announcer(&self) -> String {
        self.inner.announcer().to_string()
    }

    fn new_fingerprint(&self) -> String {
        self.inner.new_fingerprint().to_string()
    }

    fn new_cert_pem(&self) -> String {
        self.inner.new_cert_pem().to_string()
    }

    fn sent_at(&self) -> i64 {
        self.inner.sent_at()
    }

    fn is_bootstrap(&self) -> bool {
        self.inner.is_bootstrap()
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.inner)
    }
}

/// `nettls::announcement::ReceiptJson`. `dumps` and `loads` are what serde
/// does with it in Rust.
#[pyclass(
    get_all,
    set_all,
    from_py_object,
    module = "nettls_py.announcement",
    name = "ReceiptJson"
)]
#[derive(Clone)]
pub(crate) struct ReceiptJson {
    v: String,
    acker: String,
    announcer: String,
    new_fingerprint: String,
    sent_at: i64,
    sig: String,
}

impl ReceiptJson {
    fn from_rust(j: a::ReceiptJson) -> Self {
        Self {
            v: j.v,
            acker: j.acker,
            announcer: j.announcer,
            new_fingerprint: j.new_fingerprint,
            sent_at: j.sent_at,
            sig: j.sig,
        }
    }

    fn to_rust(&self) -> a::ReceiptJson {
        a::ReceiptJson {
            v: self.v.clone(),
            acker: self.acker.clone(),
            announcer: self.announcer.clone(),
            new_fingerprint: self.new_fingerprint.clone(),
            sent_at: self.sent_at,
            sig: self.sig.clone(),
        }
    }
}

#[pymethods]
impl ReceiptJson {
    #[new]
    fn py_new(
        v: String,
        acker: String,
        announcer: String,
        new_fingerprint: String,
        sent_at: i64,
        sig: String,
    ) -> Self {
        Self {
            v,
            acker,
            announcer,
            new_fingerprint,
            sent_at,
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

/// `nettls::announcement::Receipt`.
#[pyclass(
    eq,
    frozen,
    from_py_object,
    module = "nettls_py.announcement",
    name = "Receipt"
)]
#[derive(Clone, PartialEq)]
pub(crate) struct Receipt {
    inner: a::Receipt,
}

#[pymethods]
impl Receipt {
    /// `ed25519_seed` goes straight into locked memory; the `bytes` stays as
    /// Python keeps it.
    #[staticmethod]
    fn new(
        acker: &str,
        announcer: &str,
        new_fp: &str,
        sent_at: i64,
        ed25519_seed: &[u8],
    ) -> PyResult<Self> {
        let seed = hold(ed25519_seed, "an Ed25519 seed")?;
        a::Receipt::new(acker, announcer, new_fp, sent_at, &seed)
            .map(|inner| Self { inner })
            .map_err(err)
    }

    fn canonical(&self) -> PyResult<Bytes> {
        self.inner.canonical().map(bytes).map_err(err)
    }

    fn verify(&self, pinned_pubkey: &[u8], expected_new_fp: &str) -> PyResult<()> {
        self.inner
            .verify(pinned_pubkey, expected_new_fp)
            .map_err(err)
    }

    fn to_json(&self) -> ReceiptJson {
        ReceiptJson::from_rust(self.inner.to_json())
    }

    #[staticmethod]
    fn from_json(j: &ReceiptJson) -> PyResult<Self> {
        a::Receipt::from_json(&j.to_rust())
            .map(|inner| Self { inner })
            .map_err(err)
    }

    fn acker(&self) -> String {
        self.inner.acker().to_string()
    }

    fn new_fingerprint(&self) -> String {
        self.inner.new_fingerprint().to_string()
    }

    fn sent_at(&self) -> i64 {
        self.inner.sent_at()
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.inner)
    }
}

#[pyfunction]
fn archive(py: Python<'_>, dir: PathBuf, k: &Announcement) -> PyResult<()> {
    py.detach(|| a::archive(&dir, &k.inner)).map_err(err)
}

/// The announcements, and how many lines could not be read.
#[pyfunction]
fn read_archive(py: Python<'_>, dir: PathBuf) -> PyResult<(Vec<Announcement>, usize)> {
    let (list, skipped) = py.detach(|| a::read_archive(&dir)).map_err(err)?;
    Ok((
        list.into_iter()
            .map(|inner| Announcement { inner })
            .collect(),
        skipped,
    ))
}

/// `nettls::announcement::IdentityJson`. `dumps` and `loads` are what serde
/// does with it in Rust.
#[pyclass(
    get_all,
    set_all,
    from_py_object,
    module = "nettls_py.announcement",
    name = "IdentityJson"
)]
#[derive(Clone)]
pub(crate) struct IdentityJson {
    fingerprint: String,
    cert_pem: String,
    not_after: Option<String>,
    mode: Mode,
    sent_at: i64,
    announcement: Option<AnnouncementJson>,
}

impl IdentityJson {
    fn from_rust(j: a::IdentityJson) -> Self {
        Self {
            fingerprint: j.fingerprint,
            cert_pem: j.cert_pem,
            not_after: j.not_after,
            mode: j.mode.into(),
            sent_at: j.sent_at,
            announcement: j.announcement.map(AnnouncementJson::from_rust),
        }
    }

    fn to_rust(&self) -> a::IdentityJson {
        a::IdentityJson {
            fingerprint: self.fingerprint.clone(),
            cert_pem: self.cert_pem.clone(),
            not_after: self.not_after.clone(),
            mode: self.mode.into(),
            sent_at: self.sent_at,
            announcement: self.announcement.as_ref().map(AnnouncementJson::to_rust),
        }
    }
}

#[pymethods]
impl IdentityJson {
    #[staticmethod]
    fn new(
        fingerprint: String,
        cert_pem: String,
        not_after: Option<String>,
        mode: Mode,
        sent_at: i64,
        announcement: Option<PyRef<'_, Announcement>>,
    ) -> Self {
        Self::from_rust(a::IdentityJson::new(
            fingerprint,
            cert_pem,
            not_after,
            mode.into(),
            sent_at,
            announcement.as_ref().map(|k| &k.inner),
        ))
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

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("MAX_CERT_PEM_LEN", a::MAX_CERT_PEM_LEN)?;
    m.add("ARCHIVE_FILE", a::ARCHIVE_FILE)?;
    m.add_function(wrap_pyfunction!(fingerprint_from_pem, m)?)?;
    m.add_function(wrap_pyfunction!(der_from_pem, m)?)?;
    m.add_class::<AnnouncementJson>()?;
    m.add_class::<Announcement>()?;
    m.add_class::<ReceiptJson>()?;
    m.add_class::<Receipt>()?;
    m.add_function(wrap_pyfunction!(archive, m)?)?;
    m.add_function(wrap_pyfunction!(read_archive, m)?)?;
    m.add_class::<IdentityJson>()?;
    Ok(())
}
