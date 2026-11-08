// SPDX-License-Identifier: MIT OR Apache-2.0
//! `nettls::announcer`: the rotation schedule, the announcer that drives it,
//! the modes, and clock drift (§6.7–§6.11). `Pending` is made and taken only
//! inside the crate, so Python never sees one.

use std::cell::RefCell;
use std::fmt;
use std::path::PathBuf;
use std::sync::Mutex;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::announcement::Announcement;
use crate::material::SelfSignedParams;
use crate::resolver::RotatingResolver;
use crate::{Bytes, err, hold, hold_str, lock, reveal};
use nettls::announcer as an;

#[pyfunction]
fn draw_roll_time(issued: i64) -> PyResult<i64> {
    an::draw_roll_time(issued).map_err(err)
}

#[pyfunction]
fn interval_after(elapsed_s: i64) -> i64 {
    an::interval_after(elapsed_s)
}

/// `nettls::announcer::ChainState`. `waiting_for` is sorted, as the set is in
/// Rust.
#[pyclass(
    eq,
    from_py_object,
    module = "nettls_py.announcer",
    name = "ChainState"
)]
#[derive(Clone, PartialEq)]
pub(crate) enum ChainState {
    Idle {
        attempt_at: i64,
    },
    Announced {
        waiting_for: Vec<String>,
        first_announced: i64,
    },
}

impl From<&an::ChainState> for ChainState {
    fn from(s: &an::ChainState) -> Self {
        match s {
            an::ChainState::Idle { attempt_at } => Self::Idle {
                attempt_at: *attempt_at,
            },
            an::ChainState::Announced {
                waiting_for,
                first_announced,
            } => Self::Announced {
                waiting_for: waiting_for.iter().cloned().collect(),
                first_announced: *first_announced,
            },
        }
    }
}

/// `nettls::announcer::Schedule`.
#[pyclass(frozen, module = "nettls_py.announcer", name = "Schedule")]
pub(crate) struct Schedule {
    inner: Mutex<an::Schedule>,
}

impl Schedule {
    fn wrap(s: an::Schedule) -> Self {
        Self {
            inner: Mutex::new(s),
        }
    }
}

#[pymethods]
impl Schedule {
    #[new]
    fn py_new(peers: Vec<String>, attempt_at: i64) -> Self {
        Self::new(peers, attempt_at)
    }

    #[staticmethod]
    fn new(peers: Vec<String>, attempt_at: i64) -> Self {
        Self::wrap(an::Schedule::new(peers, attempt_at))
    }

    fn add_peer(&self, name: String) {
        lock(&self.inner).add_peer(name);
    }

    fn remove_peer(&self, name: &str) {
        lock(&self.inner).remove_peer(name);
    }

    fn should_announce(&self, now: i64) -> bool {
        lock(&self.inner).should_announce(now)
    }

    fn announced(&self, now: i64) {
        lock(&self.inner).announced(now);
    }

    fn acked(&self, peer: &str) {
        lock(&self.inner).acked(peer);
    }

    fn waiting_for(&self) -> Vec<String> {
        lock(&self.inner)
            .waiting_for()
            .into_iter()
            .map(String::from)
            .collect()
    }

    fn can_roll(&self, now: i64) -> bool {
        lock(&self.inner).can_roll(now)
    }

    fn rate_limit_ok(&self, now: i64) -> bool {
        lock(&self.inner).rate_limit_ok(now)
    }

    fn rolled(&self, now: i64) -> PyResult<()> {
        lock(&self.inner).rolled(now).map_err(err)
    }

    fn state(&self) -> ChainState {
        ChainState::from(lock(&self.inner).state())
    }

    fn first_announced(&self) -> Option<i64> {
        lock(&self.inner).first_announced()
    }

    fn next_retry(&self, now: i64) -> Option<i64> {
        lock(&self.inner).next_retry(now)
    }

    fn alarm(&self, now: i64) -> bool {
        lock(&self.inner).alarm(now)
    }

    fn status(&self, now: i64, expires: i64) -> Status {
        Status::from_rust(lock(&self.inner).status(now, expires))
    }

    fn restore_announced(&self, waiting_for: Vec<String>, first_announced: i64) {
        lock(&self.inner).restore_announced(waiting_for, first_announced);
    }

    fn __repr__(&self) -> String {
        format!("{:?}", lock(&self.inner))
    }
}

/// `nettls::announcer::Status`.
#[pyclass(
    eq,
    get_all,
    set_all,
    from_py_object,
    module = "nettls_py.announcer",
    name = "Status"
)]
#[derive(Clone, PartialEq)]
pub(crate) struct Status {
    waiting_for: Vec<String>,
    alarm: bool,
    seconds_until_stop: i64,
}

impl Status {
    pub(crate) fn from_rust(s: an::Status) -> Self {
        Self {
            waiting_for: s.waiting_for,
            alarm: s.alarm,
            seconds_until_stop: s.seconds_until_stop,
        }
    }

    pub(crate) fn to_rust(&self) -> an::Status {
        an::Status {
            waiting_for: self.waiting_for.clone(),
            alarm: self.alarm,
            seconds_until_stop: self.seconds_until_stop,
        }
    }
}

#[pymethods]
impl Status {
    #[new]
    fn py_new(waiting_for: Vec<String>, alarm: bool, seconds_until_stop: i64) -> Self {
        Self {
            waiting_for,
            alarm,
            seconds_until_stop,
        }
    }

    fn countdown(&self) -> String {
        self.to_rust().countdown()
    }

    fn message(&self, own_name: &str) -> Option<String> {
        self.to_rust().message(own_name)
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.to_rust())
    }
}

/// `nettls::announcer::Mode`. `str()` is Rust's `Display`.
#[pyclass(
    eq,
    eq_int,
    frozen,
    hash,
    str,
    from_py_object,
    module = "nettls_py.announcer",
    name = "Mode"
)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Mode {
    Pinning,
    Rolling,
}

impl From<an::Mode> for Mode {
    fn from(m: an::Mode) -> Self {
        match m {
            an::Mode::Pinning => Self::Pinning,
            an::Mode::Rolling => Self::Rolling,
        }
    }
}

impl From<Mode> for an::Mode {
    fn from(m: Mode) -> Self {
        match m {
            Mode::Pinning => an::Mode::Pinning,
            Mode::Rolling => an::Mode::Rolling,
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        an::Mode::from(*self).fmt(f)
    }
}

#[pyfunction]
fn mode1_should_warn(now: i64, expires: i64) -> bool {
    an::mode1_should_warn(now, expires)
}

/// `nettls::announcer::ModeCheck`.
#[pyclass(eq, from_py_object, module = "nettls_py.announcer", name = "ModeCheck")]
#[derive(Clone, PartialEq)]
pub(crate) enum ModeCheck {
    Agree(Mode),
    Disagree { ours: Mode, theirs: Mode },
}

impl ModeCheck {
    fn from_rust(c: an::ModeCheck) -> Self {
        match c {
            an::ModeCheck::Agree(m) => Self::Agree(m.into()),
            an::ModeCheck::Disagree { ours, theirs } => Self::Disagree {
                ours: ours.into(),
                theirs: theirs.into(),
            },
        }
    }

    fn to_rust(&self) -> an::ModeCheck {
        match self {
            Self::Agree(m) => an::ModeCheck::Agree((*m).into()),
            Self::Disagree { ours, theirs } => an::ModeCheck::Disagree {
                ours: (*ours).into(),
                theirs: (*theirs).into(),
            },
        }
    }
}

#[pymethods]
impl ModeCheck {
    fn message(&self, peer: &str) -> Option<String> {
        self.to_rust().message(peer)
    }

    fn can_roll(&self) -> bool {
        self.to_rust().can_roll()
    }
}

#[pyfunction]
fn check_mode(ours: Mode, theirs: Mode) -> ModeCheck {
    ModeCheck::from_rust(an::check_mode(ours.into(), theirs.into()))
}

/// `nettls::announcer::OwnMaterial`: `(fingerprint, pkcs8)` for `current`,
/// and for `previous` if there is one. The keys go straight into locked
/// memory. `Announcer.new` takes the material, as in Rust; using it
/// afterwards is a `ValueError`.
#[pyclass(frozen, module = "nettls_py.announcer", name = "OwnMaterial")]
pub(crate) struct OwnMaterial {
    inner: Mutex<Option<an::OwnMaterial>>,
}

impl OwnMaterial {
    fn take(&self) -> PyResult<an::OwnMaterial> {
        lock(&self.inner)
            .take()
            .ok_or_else(|| PyValueError::new_err("this OwnMaterial was given to an Announcer"))
    }
}

#[pymethods]
impl OwnMaterial {
    #[new]
    fn py_new(previous: Option<(String, Vec<u8>)>, current: (String, Vec<u8>)) -> PyResult<Self> {
        let previous = match previous {
            Some((fp, k)) => Some((fp, hold(&k, "a private key")?)),
            None => None,
        };
        let current = (current.0, hold(&current.1, "a private key")?);
        Ok(Self {
            inner: Mutex::new(Some(an::OwnMaterial { previous, current })),
        })
    }

    /// A copy: the key is `bytes` Python holds, neither locked nor wiped.
    #[getter]
    fn previous(&self) -> PyResult<Option<(String, Bytes)>> {
        match lock(&self.inner).as_ref() {
            Some(m) => Ok(m.previous.as_ref().map(|(fp, k)| (fp.clone(), reveal(k)))),
            None => Err(PyValueError::new_err(
                "this OwnMaterial was given to an Announcer",
            )),
        }
    }

    /// A copy: the key is `bytes` Python holds, neither locked nor wiped.
    #[getter]
    fn current(&self) -> PyResult<(String, Bytes)> {
        match lock(&self.inner).as_ref() {
            Some(m) => Ok((m.current.0.clone(), reveal(&m.current.1))),
            None => Err(PyValueError::new_err(
                "this OwnMaterial was given to an Announcer",
            )),
        }
    }
}

/// `nettls::announcer::Announcer`: load-or-init, fail-closed (§6.11b). It
/// owns the keys from generation 1 on and keeps them on disk in `dir`.
#[pyclass(frozen, module = "nettls_py.announcer", name = "Announcer")]
pub(crate) struct Announcer {
    inner: an::Announcer,
}

#[pymethods]
impl Announcer {
    #[new]
    #[allow(clippy::too_many_arguments)]
    fn py_new(
        py: Python<'_>,
        name: String,
        dir: PathBuf,
        params: SelfSignedParams,
        resolver: &RotatingResolver,
        anchor: &OwnMaterial,
        schedule: &Schedule,
        password: Option<&str>,
    ) -> PyResult<Self> {
        Self::new(py, name, dir, params, resolver, anchor, schedule, password)
    }

    /// Takes `anchor`, as in Rust. The schedule is copied in; the
    /// announcer keeps its own, as it does in Rust.
    #[staticmethod]
    #[allow(clippy::too_many_arguments)]
    fn new(
        py: Python<'_>,
        name: String,
        dir: PathBuf,
        params: SelfSignedParams,
        resolver: &RotatingResolver,
        anchor: &OwnMaterial,
        schedule: &Schedule,
        password: Option<&str>,
    ) -> PyResult<Self> {
        let password = match password {
            Some(p) => Some(hold_str(p, "the password")?),
            None => None,
        };
        let schedule = lock(&schedule.inner).clone();
        let anchor = anchor.take()?;
        let resolver = resolver.inner.clone();
        let params = params.to_rust();
        py.detach(|| an::Announcer::new(name, dir, params, resolver, anchor, schedule, password))
            .map(|inner| Self { inner })
            .map_err(err)
    }

    fn own_trio(&self) -> PyResult<OwnTrio> {
        self.inner.own_trio().map(OwnTrio::from_rust).map_err(err)
    }

    /// Making the key and writing it runs without the GIL.
    fn prepare(&self, py: Python<'_>, now: i64) -> PyResult<Announcement> {
        py.detach(|| self.inner.prepare(now))
            .map(|inner| Announcement { inner })
            .map_err(err)
    }

    fn acked(&self, py: Python<'_>, peer: &str) -> PyResult<()> {
        py.detach(|| self.inner.acked(peer)).map_err(err)
    }

    fn add_peer(&self, py: Python<'_>, name: String) -> PyResult<()> {
        py.detach(|| self.inner.add_peer(name)).map_err(err)
    }

    fn remove_peer(&self, py: Python<'_>, name: &str) -> PyResult<()> {
        py.detach(|| self.inner.remove_peer(name)).map_err(err)
    }

    fn roll_if_ready(&self, py: Python<'_>, now: i64) -> PyResult<Option<String>> {
        py.detach(|| self.inner.roll_if_ready(now)).map_err(err)
    }

    /// `safe_now()` must return `True` for the switch to happen. If it raises,
    /// nothing is switched, and the exception is raised afterwards.
    fn roll_if_ready_gated(
        &self,
        now: i64,
        safe_now: &Bound<'_, PyAny>,
    ) -> PyResult<Option<String>> {
        let failure: RefCell<Option<PyErr>> = RefCell::new(None);
        let result = self.inner.roll_if_ready_gated(now, || {
            match safe_now.call0().and_then(|v| v.extract::<bool>()) {
                Ok(b) => b,
                Err(e) => {
                    *failure.borrow_mut() = Some(e);
                    false
                }
            }
        });
        if let Some(e) = failure.into_inner() {
            return Err(e);
        }
        result.map_err(err)
    }

    fn should_announce(&self, now: i64) -> bool {
        self.inner.should_announce(now)
    }

    fn status(&self, now: i64, expires: i64) -> PyResult<Status> {
        self.inner
            .status(now, expires)
            .map(Status::from_rust)
            .map_err(err)
    }

    fn pending(&self) -> Option<Announcement> {
        self.inner.pending().map(|inner| Announcement { inner })
    }

    fn save_pending(&self, py: Python<'_>) -> PyResult<()> {
        py.detach(|| self.inner.save_pending()).map_err(err)
    }
}

/// `nettls::announcer::Drift`.
#[pyclass(
    eq,
    eq_int,
    frozen,
    hash,
    from_py_object,
    module = "nettls_py.announcer",
    name = "Drift"
)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Drift {
    Normal,
    Log,
    Warning,
}

impl From<an::Drift> for Drift {
    fn from(d: an::Drift) -> Self {
        match d {
            an::Drift::Normal => Self::Normal,
            an::Drift::Log => Self::Log,
            an::Drift::Warning => Self::Warning,
        }
    }
}

/// `nettls::announcer::ClockDrift`. `ClockDrift()` is `ClockDrift::new()`.
#[pyclass(frozen, module = "nettls_py.announcer", name = "ClockDrift")]
pub(crate) struct ClockDrift {
    inner: Mutex<an::ClockDrift>,
}

#[pymethods]
impl ClockDrift {
    #[new]
    fn py_new() -> Self {
        Self::new()
    }

    #[staticmethod]
    fn new() -> Self {
        Self {
            inner: Mutex::new(an::ClockDrift::new()),
        }
    }

    fn observe(&self, their_sent_at: i64, our_now: i64) -> Drift {
        lock(&self.inner).observe(their_sent_at, our_now).into()
    }

    fn last(&self) -> Option<i64> {
        lock(&self.inner).last()
    }

    fn max(&self) -> i64 {
        lock(&self.inner).max()
    }

    fn message(&self, peer: &str) -> Option<String> {
        lock(&self.inner).message(peer)
    }

    fn __repr__(&self) -> String {
        format!("{:?}", lock(&self.inner))
    }
}

#[pyfunction]
fn mode2_params(common_name: String, sans: Vec<String>) -> SelfSignedParams {
    SelfSignedParams::from_rust(an::mode2_params(common_name, sans))
}

#[pyfunction]
fn mode1_params(
    common_name: String,
    sans: Vec<String>,
    days: Option<u32>,
) -> PyResult<SelfSignedParams> {
    an::mode1_params(common_name, sans, days)
        .map(SelfSignedParams::from_rust)
        .map_err(err)
}

/// `nettls::announcer::Deviation`.
#[pyclass(eq, from_py_object, module = "nettls_py.announcer", name = "Deviation")]
#[derive(Clone, PartialEq)]
pub(crate) enum Deviation {
    UnknownCertificate { observed: String },
    InvalidSignature(String),
    AbandonedCertificate { observed: String },
}

impl Deviation {
    fn from_rust(d: an::Deviation) -> Self {
        match d {
            an::Deviation::UnknownCertificate { observed } => Self::UnknownCertificate { observed },
            an::Deviation::InvalidSignature(s) => Self::InvalidSignature(s),
            an::Deviation::AbandonedCertificate { observed } => {
                Self::AbandonedCertificate { observed }
            }
        }
    }

    fn to_rust(&self) -> an::Deviation {
        match self {
            Self::UnknownCertificate { observed } => an::Deviation::UnknownCertificate {
                observed: observed.clone(),
            },
            Self::InvalidSignature(s) => an::Deviation::InvalidSignature(s.clone()),
            Self::AbandonedCertificate { observed } => an::Deviation::AbandonedCertificate {
                observed: observed.clone(),
            },
        }
    }
}

#[pymethods]
impl Deviation {
    fn message(&self, peer: &str) -> String {
        self.to_rust().message(peer)
    }
}

/// `nettls::announcer::FallToMode1`.
#[pyclass(
    eq,
    get_all,
    set_all,
    from_py_object,
    module = "nettls_py.announcer",
    name = "FallToMode1"
)]
#[derive(Clone, PartialEq)]
pub(crate) struct FallToMode1 {
    deviation: Deviation,
}

impl FallToMode1 {
    fn to_rust(&self) -> an::FallToMode1 {
        an::FallToMode1 {
            deviation: self.deviation.to_rust(),
        }
    }
}

#[pymethods]
impl FallToMode1 {
    #[staticmethod]
    fn at(deviation: Deviation) -> Self {
        let f = an::FallToMode1::at(deviation.to_rust());
        Self {
            deviation: Deviation::from_rust(f.deviation),
        }
    }

    fn mode(&self) -> Mode {
        self.to_rust().mode().into()
    }

    fn can_retry(&self) -> bool {
        self.to_rust().can_retry()
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.to_rust())
    }
}

/// `nettls::announcer::OwnTrio`: fingerprints, never keys.
#[pyclass(
    eq,
    get_all,
    set_all,
    from_py_object,
    module = "nettls_py.announcer",
    name = "OwnTrio"
)]
#[derive(Clone, PartialEq)]
pub(crate) struct OwnTrio {
    previous_fingerprint: Option<String>,
    current_fingerprint: String,
    next_fingerprint: Option<String>,
}

impl OwnTrio {
    fn from_rust(t: an::OwnTrio) -> Self {
        Self {
            previous_fingerprint: t.previous_fingerprint,
            current_fingerprint: t.current_fingerprint,
            next_fingerprint: t.next_fingerprint,
        }
    }
}

#[pymethods]
impl OwnTrio {
    fn __repr__(&self) -> String {
        format!(
            "OwnTrio {{ previous_fingerprint: {:?}, current_fingerprint: {:?}, next_fingerprint: {:?} }}",
            self.previous_fingerprint, self.current_fingerprint, self.next_fingerprint
        )
    }
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("DAY_S", an::DAY_S)?;
    m.add("NOMINAL_AGE_DAYS", an::NOMINAL_AGE_DAYS)?;
    m.add("SPREAD_DAYS", an::SPREAD_DAYS)?;
    m.add("MIN_BETWEEN_ROLLS_S", an::MIN_BETWEEN_ROLLS_S)?;
    m.add("ALARM_AFTER_S", an::ALARM_AFTER_S)?;
    m.add("MODE1_WARN_DAYS", an::MODE1_WARN_DAYS)?;
    m.add("DRIFT_NORMAL_S", an::DRIFT_NORMAL_S)?;
    m.add("DRIFT_WARNING_S", an::DRIFT_WARNING_S)?;
    m.add("DRIFT_JUMP_S", an::DRIFT_JUMP_S)?;
    m.add("MODE2_LIFETIME_DAYS", an::MODE2_LIFETIME_DAYS)?;
    m.add("MODE1_MIN_DAYS", an::MODE1_MIN_DAYS)?;
    m.add("MODE1_DEFAULT_DAYS", an::MODE1_DEFAULT_DAYS)?;
    m.add("MODE1_MAX_DAYS", an::MODE1_MAX_DAYS)?;
    m.add("PENDING_FILE", an::PENDING_FILE)?;
    m.add_function(wrap_pyfunction!(draw_roll_time, m)?)?;
    m.add_function(wrap_pyfunction!(interval_after, m)?)?;
    m.add_function(wrap_pyfunction!(mode1_should_warn, m)?)?;
    m.add_function(wrap_pyfunction!(check_mode, m)?)?;
    m.add_function(wrap_pyfunction!(mode2_params, m)?)?;
    m.add_function(wrap_pyfunction!(mode1_params, m)?)?;
    m.add_class::<ChainState>()?;
    m.add_class::<Schedule>()?;
    m.add_class::<Status>()?;
    m.add_class::<Mode>()?;
    m.add_class::<ModeCheck>()?;
    m.add_class::<OwnMaterial>()?;
    m.add_class::<Announcer>()?;
    m.add_class::<Drift>()?;
    m.add_class::<ClockDrift>()?;
    m.add_class::<Deviation>()?;
    m.add_class::<FallToMode1>()?;
    m.add_class::<OwnTrio>()?;
    Ok(())
}
