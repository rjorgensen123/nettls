// SPDX-License-Identifier: MIT OR Apache-2.0
//! `nettls::status`: the status report for an About page or a health check.
//! `dumps` is what serde writes in Rust: the JSON shape is the contract.

use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::announcer::Status;
use crate::generations::Generations;
use crate::json_err;
use crate::material::TlsMaterial;
use nettls::status as st;

/// `nettls::status::Level`.
#[pyclass(
    eq,
    eq_int,
    frozen,
    hash,
    from_py_object,
    module = "nettls_py.status",
    name = "Level"
)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Level {
    Ok,
    Warn,
    Alert,
}

impl From<st::Level> for Level {
    fn from(l: st::Level) -> Self {
        match l {
            st::Level::Ok => Self::Ok,
            st::Level::Warn => Self::Warn,
            st::Level::Alert => Self::Alert,
        }
    }
}

impl From<Level> for st::Level {
    fn from(l: Level) -> Self {
        match l {
            Level::Ok => st::Level::Ok,
            Level::Warn => st::Level::Warn,
            Level::Alert => st::Level::Alert,
        }
    }
}

/// `nettls::status::PeerState`.
#[pyclass(
    eq,
    eq_int,
    frozen,
    hash,
    from_py_object,
    module = "nettls_py.status",
    name = "PeerState"
)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum PeerState {
    Ok,
    RotationPending,
    Broken,
}

impl From<st::PeerState> for PeerState {
    fn from(s: st::PeerState) -> Self {
        match s {
            st::PeerState::Ok => Self::Ok,
            st::PeerState::RotationPending => Self::RotationPending,
            st::PeerState::Broken => Self::Broken,
        }
    }
}

impl From<PeerState> for st::PeerState {
    fn from(s: PeerState) -> Self {
        match s {
            PeerState::Ok => st::PeerState::Ok,
            PeerState::RotationPending => st::PeerState::RotationPending,
            PeerState::Broken => st::PeerState::Broken,
        }
    }
}

/// `nettls::status::PeerReport`.
#[pyclass(
    get_all,
    set_all,
    from_py_object,
    module = "nettls_py.status",
    name = "PeerReport"
)]
#[derive(Clone)]
pub(crate) struct PeerReport {
    name: String,
    state: PeerState,
    current_fingerprint: String,
    next_fingerprint: Option<String>,
}

impl PeerReport {
    fn from_rust(p: st::PeerReport) -> Self {
        Self {
            name: p.name,
            state: p.state.into(),
            current_fingerprint: p.current_fingerprint,
            next_fingerprint: p.next_fingerprint,
        }
    }

    fn to_rust(&self) -> st::PeerReport {
        st::PeerReport {
            name: self.name.clone(),
            state: self.state.into(),
            current_fingerprint: self.current_fingerprint.clone(),
            next_fingerprint: self.next_fingerprint.clone(),
        }
    }
}

#[pymethods]
impl PeerReport {
    #[staticmethod]
    fn from_generations(name: String, g: &Generations) -> Self {
        Self::from_rust(st::PeerReport::from_generations(name, &g.get()))
    }

    #[staticmethod]
    fn broken(name: String, last_known_fingerprint: String) -> Self {
        Self::from_rust(st::PeerReport::broken(name, last_known_fingerprint))
    }

    /// The JSON serde writes in Rust.
    fn dumps(&self) -> PyResult<String> {
        serde_json::to_string(&self.to_rust()).map_err(json_err)
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.to_rust())
    }
}

/// `nettls::status::IdentityReport`.
#[pyclass(
    get_all,
    set_all,
    from_py_object,
    module = "nettls_py.status",
    name = "IdentityReport"
)]
#[derive(Clone)]
pub(crate) struct IdentityReport {
    fingerprint_sha256: String,
    origin: String,
    not_after: Option<i64>,
    days_until_expiry: i64,
    expiry_warning: bool,
}

impl IdentityReport {
    fn from_rust(i: st::IdentityReport) -> Self {
        Self {
            fingerprint_sha256: i.fingerprint_sha256,
            origin: i.origin,
            not_after: i.not_after,
            days_until_expiry: i.days_until_expiry,
            expiry_warning: i.expiry_warning,
        }
    }

    fn to_rust(&self) -> st::IdentityReport {
        st::IdentityReport {
            fingerprint_sha256: self.fingerprint_sha256.clone(),
            origin: self.origin.clone(),
            not_after: self.not_after,
            days_until_expiry: self.days_until_expiry,
            expiry_warning: self.expiry_warning,
        }
    }
}

#[pymethods]
impl IdentityReport {
    /// The JSON serde writes in Rust.
    fn dumps(&self) -> PyResult<String> {
        serde_json::to_string(&self.to_rust()).map_err(json_err)
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.to_rust())
    }
}

/// `nettls::status::RotationReport`.
#[pyclass(
    get_all,
    set_all,
    from_py_object,
    module = "nettls_py.status",
    name = "RotationReport"
)]
#[derive(Clone)]
pub(crate) struct RotationReport {
    waiting_for: Vec<String>,
    alarm: bool,
    seconds_until_stop: i64,
}

impl RotationReport {
    fn from_rust(r: st::RotationReport) -> Self {
        Self {
            waiting_for: r.waiting_for,
            alarm: r.alarm,
            seconds_until_stop: r.seconds_until_stop,
        }
    }

    fn to_rust(&self) -> st::RotationReport {
        st::RotationReport {
            waiting_for: self.waiting_for.clone(),
            alarm: self.alarm,
            seconds_until_stop: self.seconds_until_stop,
        }
    }
}

#[pymethods]
impl RotationReport {
    /// The JSON serde writes in Rust.
    fn dumps(&self) -> PyResult<String> {
        serde_json::to_string(&self.to_rust()).map_err(json_err)
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.to_rust())
    }
}

/// `nettls::status::Report`. `version` is the crate's version, which Rust
/// holds as a `&'static str`, so in Python it is read-only.
#[pyclass(from_py_object, module = "nettls_py.status", name = "Report")]
#[derive(Clone)]
pub(crate) struct Report {
    #[pyo3(get)]
    version: String,
    #[pyo3(get, set)]
    level: Level,
    #[pyo3(get, set)]
    headline: String,
    #[pyo3(get, set)]
    identity: IdentityReport,
    #[pyo3(get, set)]
    rotation: Option<RotationReport>,
    #[pyo3(get, set)]
    peers: Vec<PeerReport>,
}

impl Report {
    fn from_rust(r: st::Report) -> Self {
        Self {
            version: r.version.to_string(),
            level: r.level.into(),
            headline: r.headline,
            identity: IdentityReport::from_rust(r.identity),
            rotation: r.rotation.map(RotationReport::from_rust),
            peers: r.peers.into_iter().map(PeerReport::from_rust).collect(),
        }
    }

    fn to_rust(&self) -> st::Report {
        st::Report {
            version: nettls::VERSION,
            level: self.level.into(),
            headline: self.headline.clone(),
            identity: self.identity.to_rust(),
            rotation: self.rotation.as_ref().map(RotationReport::to_rust),
            peers: self.peers.iter().map(PeerReport::to_rust).collect(),
        }
    }
}

#[pymethods]
impl Report {
    #[staticmethod]
    fn collect(
        now: i64,
        material: &TlsMaterial,
        announcer_status: Option<Status>,
        peers: Vec<PeerReport>,
    ) -> Self {
        let status = announcer_status.map(|s| s.to_rust());
        Self::from_rust(st::Report::collect(
            now,
            &material.inner,
            status.as_ref(),
            peers.iter().map(PeerReport::to_rust).collect(),
        ))
    }

    fn summary(&self) -> Summary {
        Summary::from_rust(self.to_rust().summary())
    }

    /// The JSON serde writes in Rust.
    fn dumps(&self) -> PyResult<String> {
        serde_json::to_string(&self.to_rust()).map_err(json_err)
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.to_rust())
    }
}

/// `nettls::status::Summary`. `version` is read-only, as in `Report`.
#[pyclass(from_py_object, module = "nettls_py.status", name = "Summary")]
#[derive(Clone)]
pub(crate) struct Summary {
    #[pyo3(get)]
    version: String,
    #[pyo3(get, set)]
    level: Level,
    #[pyo3(get, set)]
    headline: String,
}

impl Summary {
    fn from_rust(s: st::Summary) -> Self {
        Self {
            version: s.version.to_string(),
            level: s.level.into(),
            headline: s.headline,
        }
    }

    fn to_rust(&self) -> st::Summary {
        st::Summary {
            version: nettls::VERSION,
            level: self.level.into(),
            headline: self.headline.clone(),
        }
    }
}

#[pymethods]
impl Summary {
    /// The JSON serde writes in Rust.
    fn dumps(&self) -> PyResult<String> {
        serde_json::to_string(&self.to_rust()).map_err(json_err)
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.to_rust())
    }
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Level>()?;
    m.add_class::<PeerState>()?;
    m.add_class::<PeerReport>()?;
    m.add_class::<IdentityReport>()?;
    m.add_class::<RotationReport>()?;
    m.add_class::<Report>()?;
    m.add_class::<Summary>()?;
    Ok(())
}
