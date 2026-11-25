// SPDX-License-Identifier: MIT OR Apache-2.0
//! `nettls::generations`: the peer's generations (§6.3) and `Trust`, the
//! verifier that accepts `current` and `next` and promotes on proof (§6.7).

use std::sync::Mutex;

use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::announcement::Announcement;
use crate::stream::ClientConfig;
use crate::transport::TransportPolicy;
use crate::{Bytes, bytes, err, lock};

/// `nettls::generations::Generation`: one certificate, by its fingerprint.
#[pyclass(
    eq,
    frozen,
    from_py_object,
    module = "nettls_py.generations",
    name = "Generation"
)]
#[derive(Clone, PartialEq)]
pub(crate) struct Generation {
    pub(crate) inner: nettls::generations::Generation,
}

#[pymethods]
impl Generation {
    #[staticmethod]
    fn from_der(der: Vec<u8>) -> PyResult<Self> {
        nettls::generations::Generation::from_der(der)
            .map(|inner| Self { inner })
            .map_err(err)
    }

    #[staticmethod]
    fn from_pem(pem: &str) -> PyResult<Self> {
        nettls::generations::Generation::from_pem(pem)
            .map(|inner| Self { inner })
            .map_err(err)
    }

    fn der(&self) -> Bytes {
        bytes(self.inner.der().to_vec())
    }

    fn fingerprint(&self) -> String {
        self.inner.fingerprint().to_string()
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.inner)
    }
}

/// `nettls::generations::Received`.
#[pyclass(
    eq,
    eq_int,
    frozen,
    hash,
    from_py_object,
    module = "nettls_py.generations",
    name = "Received"
)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Received {
    Stored,
    Known,
}

impl From<nettls::generations::Received> for Received {
    fn from(r: nettls::generations::Received) -> Self {
        match r {
            nettls::generations::Received::Stored => Self::Stored,
            nettls::generations::Received::Known => Self::Known,
        }
    }
}

/// `nettls::generations::Generations`.
#[pyclass(frozen, module = "nettls_py.generations", name = "Generations")]
pub(crate) struct Generations {
    inner: Mutex<nettls::generations::Generations>,
}

impl Generations {
    pub(crate) fn wrap(g: nettls::generations::Generations) -> Self {
        Self {
            inner: Mutex::new(g),
        }
    }

    pub(crate) fn get(&self) -> PyResult<nettls::generations::Generations> {
        Ok(lock(&self.inner)?.clone())
    }
}

#[pymethods]
impl Generations {
    #[staticmethod]
    fn from_approval(current: Generation) -> Self {
        Self::wrap(nettls::generations::Generations::from_approval(
            current.inner,
        ))
    }

    #[staticmethod]
    fn restore(
        previous: Option<Generation>,
        current: Generation,
        next: Option<Generation>,
    ) -> PyResult<Self> {
        nettls::generations::Generations::restore(
            previous.map(|g| g.inner),
            current.inner,
            next.map(|g| g.inner),
        )
        .map(Self::wrap)
        .map_err(err)
    }

    /// `expected_announcer` is the peer this state belongs to (0.12.0).
    fn receive(&self, k: &Announcement, expected_announcer: &str) -> PyResult<Received> {
        lock(&self.inner)?
            .receive(&k.inner, expected_announcer)
            .map(Received::from)
            .map_err(err)
    }

    fn observed(&self, fp: &str) -> PyResult<bool> {
        Ok(lock(&self.inner)?.observed(fp))
    }

    fn accepted_in_handshake(&self) -> PyResult<Vec<Generation>> {
        Ok(lock(&self.inner)?
            .accepted_in_handshake()
            .into_iter()
            .map(|g| Generation { inner: g.clone() })
            .collect())
    }

    fn for_signing(&self) -> PyResult<(Option<Generation>, Generation)> {
        let g = lock(&self.inner)?;
        let (previous, current) = g.for_signing();
        Ok((
            previous.map(|p| Generation { inner: p.clone() }),
            Generation {
                inner: current.clone(),
            },
        ))
    }

    fn current(&self) -> PyResult<Generation> {
        Ok(Generation {
            inner: lock(&self.inner)?.current().clone(),
        })
    }

    fn previous(&self) -> PyResult<Option<Generation>> {
        Ok(lock(&self.inner)?
            .previous()
            .map(|g| Generation { inner: g.clone() }))
    }

    fn next(&self) -> PyResult<Option<Generation>> {
        Ok(lock(&self.inner)?
            .next()
            .map(|g| Generation { inner: g.clone() }))
    }

    fn is_bootstrap(&self) -> PyResult<bool> {
        Ok(lock(&self.inner)?.is_bootstrap())
    }

    fn __eq__(&self, other: &Self) -> PyResult<bool> {
        Ok(self.get()? == other.get()?)
    }

    fn __repr__(&self) -> String {
        match self.get() {
            Ok(generations) => format!("{:?}", generations),
            Err(_) => "Generations(<poisoned lock>)".to_owned(),
        }
    }
}

/// `nettls::generations::Trust`. Its client config promotes `next` by itself
/// once the handshake proves the key (§6.7).
#[pyclass(frozen, module = "nettls_py.generations", name = "Trust")]
pub(crate) struct Trust {
    inner: nettls::generations::Trust,
}

#[pymethods]
impl Trust {
    #[staticmethod]
    fn from_approval(current: Generation) -> Self {
        Self {
            inner: nettls::generations::Trust::from_approval(current.inner),
        }
    }

    #[staticmethod]
    fn from_state(g: &Generations) -> PyResult<Self> {
        Ok(Self {
            inner: nettls::generations::Trust::from_state(g.get()?),
        })
    }

    /// `expected_announcer` is the peer this trust belongs to (0.12.0).
    fn receive(&self, k: &Announcement, expected_announcer: &str) -> PyResult<Received> {
        self.inner
            .receive(&k.inner, expected_announcer)
            .map(Received::from)
            .map_err(err)
    }

    fn state(&self) -> PyResult<Generations> {
        self.inner.state().map(Generations::wrap).map_err(err)
    }

    fn client_config(&self) -> PyResult<ClientConfig> {
        self.inner
            .client_config()
            .map(ClientConfig::wrap)
            .map_err(err)
    }

    fn client_config_with_alpn(&self, alpn: Vec<Vec<u8>>) -> PyResult<ClientConfig> {
        self.inner
            .client_config_with_alpn(&alpn)
            .map(ClientConfig::wrap)
            .map_err(err)
    }

    fn client_config_with(
        &self,
        alpn: Vec<Vec<u8>>,
        transport: &TransportPolicy,
        expiry: crate::pin::Expiry,
    ) -> PyResult<ClientConfig> {
        self.inner
            .client_config_with(&alpn, &transport.inner, expiry.into())
            .map(ClientConfig::wrap)
            .map_err(err)
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.inner)
    }
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Generation>()?;
    m.add_class::<Received>()?;
    m.add_class::<Generations>()?;
    m.add_class::<Trust>()?;
    Ok(())
}
