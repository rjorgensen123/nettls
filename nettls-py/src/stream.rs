// SPDX-License-Identifier: MIT OR Apache-2.0
//! `nettls_py.stream`: a rustls connection over a Python socket.
//!
//! This module exists only in Python. Rust consumers drive rustls themselves,
//! with `rustls::Stream` or `tokio-rustls`, using the configs nettls gives;
//! Python has nothing that can, so this is that piece. It has no nettls logic:
//! whom to trust is the client config's decision (`Trust`, or a pinned
//! fingerprint), and which certificate to show is the server config's (a
//! `TlsMaterial`, or a `RotatingResolver` that follows the rotation).
//!
//! The stream takes the socket over (`socket.detach()`): from then on only the
//! stream reads, writes and closes it. The socket's timeout carries over, and
//! waiting happens without the GIL. It does one thing at a time: a read that
//! waits holds the stream, so a write from another thread waits for it. Serve
//! each connection from one thread. Socket and TLS failures are `OSError`, as
//! Python's own `ssl` gives them, and a timeout is `TimeoutError`. A refused
//! server certificate is one of three `OSError` subclasses, after
//! `nettls::pin::classify` (0.11.0): `UntrustedPeerError`,
//! `CertificateExpiredError` (with `now` and `not_after`) and
//! `CertificateNotYetValidError` (with `now` and `not_before`), Unix seconds.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nettls::rustls;
use pyo3::exceptions::{PyOSError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyModule;
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, ServerConnection, StreamOwned};

use crate::{Bytes, bytes, err, lock};

pyo3::create_exception!(
    nettls_py,
    UntrustedPeerError,
    PyOSError,
    "The server's certificate is not one the client config trusts (0.11.0)."
);
pyo3::create_exception!(
    nettls_py,
    CertificateExpiredError,
    PyOSError,
    "The server's certificate is trusted but expired; `now` and `not_after` are Unix seconds (0.11.0)."
);
pyo3::create_exception!(
    nettls_py,
    CertificateNotYetValidError,
    PyOSError,
    "The server's certificate is trusted but not valid yet; `now` and `not_before` are Unix seconds (0.11.0)."
);

/// The most `read` returns in one call.
const MAX_READ: usize = 16 * 1024 * 1024;

/// A rustls client config, from `Trust.client_config()` or
/// `pinned_client_config()`. Only `Stream.connect` takes it.
#[pyclass(frozen, module = "nettls_py.stream", name = "ClientConfig")]
pub(crate) struct ClientConfig {
    inner: Arc<rustls::ClientConfig>,
}

impl ClientConfig {
    pub(crate) fn wrap(inner: Arc<rustls::ClientConfig>) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl ClientConfig {
    fn __repr__(&self) -> &'static str {
        "ClientConfig"
    }
}

/// A rustls server config, from `TlsMaterial.server_config()` or
/// `RotatingResolver.server_config()`. Only `Stream.accept` takes it.
#[pyclass(frozen, module = "nettls_py.stream", name = "ServerConfig")]
pub(crate) struct ServerConfig {
    inner: Arc<rustls::ServerConfig>,
}

impl ServerConfig {
    pub(crate) fn wrap(inner: Arc<rustls::ServerConfig>) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl ServerConfig {
    fn __repr__(&self) -> &'static str {
        "ServerConfig"
    }
}

enum Conn {
    Client(StreamOwned<ClientConnection, TcpStream>),
    Server(StreamOwned<ServerConnection, TcpStream>),
}

/// The same code for either side.
macro_rules! both {
    ($conn:expr, $s:ident => $body:expr) => {
        match $conn {
            Conn::Client($s) => $body,
            Conn::Server($s) => $body,
        }
    };
}

impl Conn {
    fn handshake(&mut self) -> io::Result<()> {
        both!(self, s => {
            while s.conn.is_handshaking() {
                s.conn.complete_io(&mut s.sock)?;
            }
            Ok(())
        })
    }

    fn alpn_protocol(&self) -> Option<Vec<u8>> {
        both!(self, s => s.conn.alpn_protocol().map(<[u8]>::to_vec))
    }

    fn peer_fingerprint(&self) -> Option<String> {
        self.peer_certificate()
            .map(|leaf| nettls::cert_fingerprint_sha256(&leaf))
    }

    fn peer_certificate(&self) -> Option<Vec<u8>> {
        both!(self, s => s
            .conn
            .peer_certificates()
            .and_then(|chain| chain.first())
            .map(|leaf| leaf.as_ref().to_vec()))
    }

    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        both!(self, s => s.read(buf))
    }

    fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        both!(self, s => {
            s.write_all(data)?;
            s.flush()
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        both!(self, s => s.flush())
    }

    /// Sends `close_notify` and shuts the socket down. A peer that has already
    /// gone is the state `close` wants, not a failure.
    fn close(&mut self) -> io::Result<()> {
        let result = both!(self, s => {
            s.conn.send_close_notify();
            let mut sent = Ok(());
            while s.conn.wants_write() {
                if let Err(e) = s.conn.write_tls(&mut s.sock) {
                    sent = Err(e);
                    break;
                }
            }
            sent.and_then(|()| s.sock.shutdown(Shutdown::Both))
        });
        match result {
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::BrokenPipe
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::NotConnected
                ) =>
            {
                Ok(())
            }
            other => other,
        }
    }
}

/// Takes the socket over: after this, the Python socket object is detached
/// and only the stream owns the descriptor.
fn take_socket(sock: &Bound<'_, PyAny>) -> PyResult<TcpStream> {
    let timeout: Option<f64> = sock.call_method0("gettimeout")?.extract()?;
    let timeout = match timeout {
        None => None,
        Some(t) if t > 0.0 => Some(Duration::try_from_secs_f64(t).map_err(|e| {
            PyValueError::new_err(format!("the socket's timeout {t} cannot be used: {e}"))
        })?),
        Some(_) => {
            return Err(PyValueError::new_err(
                "the socket is non-blocking: give it a timeout, or None to wait without one",
            ));
        }
    };
    let fd: RawFd = sock.call_method0("detach")?.extract()?;
    if fd < 0 {
        return Err(PyValueError::new_err("the socket is closed"));
    }
    // SAFETY: `socket.detach()` hands the descriptor over; the socket object
    // no longer owns or closes it, so this is its only owner.
    let tcp = TcpStream::from(unsafe { OwnedFd::from_raw_fd(fd) });
    tcp.set_nonblocking(false)?;
    tcp.set_read_timeout(timeout)?;
    tcp.set_write_timeout(timeout)?;
    Ok(tcp)
}

/// An I/O failure as Python's own sockets give it. The stream's socket is
/// blocking, so `WouldBlock` can only mean that its timeout ran out. A refused
/// certificate is the exception `nettls::pin::classify` names (0.11.0).
fn io_err(e: io::Error) -> PyErr {
    use nettls::pin::Rejection;
    if e.kind() == io::ErrorKind::WouldBlock {
        return PyErr::from(io::Error::new(io::ErrorKind::TimedOut, "timed out"));
    }
    let msg = e.to_string();
    let (err, times) = match nettls::pin::classify(&e) {
        Rejection::Untrusted => (UntrustedPeerError::new_err(msg), None),
        Rejection::Expired { now, not_after } => (
            CertificateExpiredError::new_err(msg),
            Some((now, "not_after", not_after)),
        ),
        Rejection::NotYetValid { now, not_before } => (
            CertificateNotYetValidError::new_err(msg),
            Some((now, "not_before", not_before)),
        ),
        Rejection::Other => return PyErr::from(e),
    };
    if let Some((now, name, at)) = times {
        Python::attach(|py| {
            let v = err.value(py);
            // Setting an attribute on a fresh exception cannot fail.
            let _ = v.setattr("now", now);
            let _ = v.setattr(name, at);
        });
    }
    err
}

fn closed() -> PyErr {
    PyValueError::new_err("the stream is closed")
}

/// A TLS connection over a socket: `Stream.connect` for the client side,
/// `Stream.accept` for the server side. Both complete the handshake before
/// they return.
#[pyclass(frozen, module = "nettls_py.stream", name = "Stream")]
pub(crate) struct Stream {
    inner: Mutex<Option<Conn>>,
}

impl Stream {
    fn start(py: Python<'_>, mut conn: Conn) -> PyResult<Self> {
        py.detach(|| conn.handshake()).map_err(io_err)?;
        Ok(Self {
            inner: Mutex::new(Some(conn)),
        })
    }
}

#[pymethods]
impl Stream {
    /// The client side, over a connected socket. `server_name` is the name
    /// to send; the trust decision is `config`'s.
    #[staticmethod]
    fn connect(
        py: Python<'_>,
        sock: &Bound<'_, PyAny>,
        config: &ClientConfig,
        server_name: &str,
    ) -> PyResult<Self> {
        let name = ServerName::try_from(server_name.to_owned()).map_err(|e| {
            err(nettls::TlsError::Params(format!(
                "server_name {server_name:?} is not a valid name: {e}"
            )))
        })?;
        let conn = ClientConnection::new(config.inner.clone(), name)
            .map_err(|e| err(nettls::TlsError::Rustls(e.to_string())))?;
        let tcp = take_socket(sock)?;
        Self::start(py, Conn::Client(StreamOwned::new(conn, tcp)))
    }

    /// The server side, over an accepted socket.
    #[staticmethod]
    fn accept(py: Python<'_>, sock: &Bound<'_, PyAny>, config: &ServerConfig) -> PyResult<Self> {
        let conn = ServerConnection::new(config.inner.clone())
            .map_err(|e| err(nettls::TlsError::Rustls(e.to_string())))?;
        let tcp = take_socket(sock)?;
        Self::start(py, Conn::Server(StreamOwned::new(conn, tcp)))
    }

    /// Up to `n` bytes; `b""` once the peer has closed.
    #[pyo3(signature = (n = 65536))]
    fn read(&self, py: Python<'_>, n: usize) -> PyResult<Bytes> {
        if n > MAX_READ {
            return Err(PyValueError::new_err(format!(
                "read takes at most {MAX_READ} bytes at a time, got {n}"
            )));
        }
        py.detach(|| {
            let mut guard = lock(&self.inner);
            let conn = guard.as_mut().ok_or_else(closed)?;
            let mut buf = vec![0u8; n];
            let got = conn.read(&mut buf).map_err(io_err)?;
            buf.truncate(got);
            Ok(bytes(buf))
        })
    }

    /// Writes all of `data` and flushes it; returns how many bytes that was.
    fn write(&self, py: Python<'_>, data: &[u8]) -> PyResult<usize> {
        py.detach(|| {
            let mut guard = lock(&self.inner);
            let conn = guard.as_mut().ok_or_else(closed)?;
            conn.write_all(data).map_err(io_err)?;
            Ok(data.len())
        })
    }

    fn flush(&self, py: Python<'_>) -> PyResult<()> {
        py.detach(|| {
            let mut guard = lock(&self.inner);
            let conn = guard.as_mut().ok_or_else(closed)?;
            conn.flush().map_err(io_err)
        })
    }

    /// Ends the connection. Closing a closed stream does nothing.
    fn close(&self, py: Python<'_>) -> PyResult<()> {
        py.detach(|| match lock(&self.inner).take() {
            Some(mut conn) => conn.close().map_err(io_err),
            None => Ok(()),
        })
    }

    /// The SHA-256 fingerprint of the peer's certificate, or `None` when the
    /// peer showed none.
    fn peer_fingerprint(&self) -> PyResult<Option<String>> {
        let guard = lock(&self.inner);
        let conn = guard.as_ref().ok_or_else(closed)?;
        Ok(conn.peer_fingerprint())
    }

    /// The peer's certificate as DER, or `None` when the peer showed none
    /// (0.11.0). What enrollment approves: `Generation.from_der(...)`.
    fn peer_certificate(&self) -> PyResult<Option<Bytes>> {
        let guard = lock(&self.inner);
        let conn = guard.as_ref().ok_or_else(closed)?;
        Ok(conn.peer_certificate().map(bytes))
    }

    /// The protocol ALPN agreed on, or `None` when none was offered or agreed.
    fn alpn_protocol(&self) -> PyResult<Option<Bytes>> {
        let guard = lock(&self.inner);
        let conn = guard.as_ref().ok_or_else(closed)?;
        Ok(conn.alpn_protocol().map(bytes))
    }

    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    fn __exit__(
        &self,
        py: Python<'_>,
        _exc_type: Option<&Bound<'_, PyAny>>,
        _exc: Option<&Bound<'_, PyAny>>,
        _tb: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<bool> {
        self.close(py)?;
        Ok(false)
    }

    fn __repr__(&self) -> &'static str {
        match lock(&self.inner).as_ref() {
            Some(Conn::Client(_)) => "Stream(client)",
            Some(Conn::Server(_)) => "Stream(server)",
            None => "Stream(closed)",
        }
    }
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ClientConfig>()?;
    m.add_class::<ServerConfig>()?;
    m.add_class::<Stream>()?;
    m.add("MAX_READ", MAX_READ)?;
    let py = m.py();
    m.add("UntrustedPeerError", py.get_type::<UntrustedPeerError>())?;
    m.add(
        "CertificateExpiredError",
        py.get_type::<CertificateExpiredError>(),
    )?;
    m.add(
        "CertificateNotYetValidError",
        py.get_type::<CertificateNotYetValidError>(),
    )?;
    Ok(())
}
