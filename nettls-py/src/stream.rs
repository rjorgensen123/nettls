// SPDX-License-Identifier: MIT OR Apache-2.0
//! `nettls_py.stream`: a rustls connection, over a Python socket or over bytes
//! the caller moves.
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
//!
//! `TlsConnection` (0.12.0) is the same connection without a socket, for an
//! event loop: the caller moves the ciphertext (`receive`, `take_outgoing`).
//! It never waits and never calls back into Python. `nettls_py.sslcontext`
//! builds an `ssl.SSLContext` on it.

use std::collections::VecDeque;
use std::io::{self, BufRead, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nettls::rustls;
use pyo3::exceptions::{PyConnectionResetError, PyOSError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyModule;
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, IoState, ProtocolVersion, ServerConnection, StreamOwned};

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
/// `pinned_client_config()`. `Stream.connect` and `TlsConnection.client`
/// take it.
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
/// `RotatingResolver.server_config()`. `Stream.accept` and
/// `TlsConnection.server` take it.
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

    fn peer_fingerprint(&self) -> Result<Option<String>, nettls::TlsError> {
        self.peer_certificate()
            .map(|leaf| nettls::cert_fingerprint_sha256(&leaf))
            .transpose()
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
///
/// The object must be a `socket.socket`, and that is checked before it is
/// asked for anything (0.12.0): the hand-over below is only true of a real
/// socket.
fn take_socket(sock: &Bound<'_, PyAny>) -> PyResult<TcpStream> {
    let socket_type = sock.py().import("socket")?.getattr("socket")?;
    if !sock.is_instance(&socket_type)? {
        return Err(PyTypeError::new_err(format!(
            "expected a socket.socket, got {}",
            sock.get_type().name()?
        )));
    }
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

/// The name a client sends. A name rustls cannot use is a `ParamsError`.
fn to_server_name(name: &str) -> PyResult<ServerName<'static>> {
    ServerName::try_from(name.to_owned()).map_err(|e| {
        err(nettls::TlsError::Params(format!(
            "server_name {name:?} is not a valid name: {e}"
        )))
    })
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
        let name = to_server_name(server_name)?;
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
        conn.peer_fingerprint().map_err(err)
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

struct Inner {
    conn: rustls::Connection,
    /// Ciphertext received and not yet given to rustls.
    queue: VecDeque<u8>,
    /// `receive_eof` was called.
    ended: bool,
    /// rustls has been told that the transport ended.
    end_given: bool,
    peer_closed: bool,
}

impl Inner {
    /// The rustls error goes inside an `io::Error`, as `complete_io` puts it,
    /// where `io_err` and `nettls::pin::classify` look for it.
    fn process(&mut self) -> io::Result<IoState> {
        let state = self
            .conn
            .process_new_packets()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if state.peer_has_closed() {
            self.peer_closed = true;
        }
        Ok(state)
    }

    /// Gives rustls the queued ciphertext, then the end of the transport, but
    /// only while rustls holds no plaintext.
    ///
    /// rustls's plaintext buffer is limited (16 KiB); when it is full,
    /// `read_tls` fails with `ErrorKind::Other`, which only its kind tells apart
    /// from a real failure. Feeding only into an empty buffer never reaches the
    /// limit, so every `read_tls` error here is real. Ciphertext not fed stays
    /// in `queue` until `read` has taken the plaintext and feeds again;
    /// `pending` counts it meanwhile.
    fn feed(&mut self) -> io::Result<()> {
        loop {
            if self.process()?.plaintext_bytes_to_read() > 0 {
                return Ok(());
            }
            if !self.queue.is_empty() {
                // `Ok(0)` here means `close_notify` has arrived; nothing after
                // it counts.
                if self.conn.read_tls(&mut self.queue)? == 0 {
                    self.queue.clear();
                }
            } else if self.ended && !self.end_given {
                // An empty read tells rustls the transport has ended.
                self.conn.read_tls(&mut io::empty())?;
                self.end_given = true;
            } else {
                return Ok(());
            }
        }
    }

    /// `feed`, except that a failure behind plaintext that arrived first is not
    /// raised yet: `read` raises it once that plaintext has been taken.
    fn feed_behind_plaintext(&mut self) -> io::Result<()> {
        match self.feed() {
            Err(_) if self.plaintext_waiting() > 0 => Ok(()),
            result => result,
        }
    }

    /// The size of the first piece of plaintext rustls holds; 0 for none.
    fn plaintext_waiting(&mut self) -> usize {
        self.conn.reader().fill_buf().map_or(0, <[u8]>::len)
    }
}

/// A rustls connection with no socket (0.12.0): ciphertext goes in with
/// `receive` and out with `take_outgoing`.
#[pyclass(frozen, module = "nettls_py.stream", name = "TlsConnection")]
pub(crate) struct TlsConnection {
    inner: Mutex<Inner>,
}

impl TlsConnection {
    fn wrap(conn: rustls::Connection) -> Self {
        Self {
            inner: Mutex::new(Inner {
                conn,
                queue: VecDeque::new(),
                ended: false,
                end_given: false,
                peer_closed: false,
            }),
        }
    }
}

#[pymethods]
impl TlsConnection {
    /// The client side. `alpn`, when given, replaces the config's protocols
    /// for this connection; an empty list offers none.
    #[staticmethod]
    #[pyo3(signature = (config, server_name, alpn = None))]
    fn client(
        config: &ClientConfig,
        server_name: &str,
        alpn: Option<Vec<Vec<u8>>>,
    ) -> PyResult<Self> {
        let name = to_server_name(server_name)?;
        let conn = match alpn {
            Some(alpn) => ClientConnection::new_with_alpn(config.inner.clone(), name, alpn),
            None => ClientConnection::new(config.inner.clone(), name),
        }
        .map_err(|e| err(nettls::TlsError::Rustls(e.to_string())))?;
        Ok(Self::wrap(conn.into()))
    }

    #[staticmethod]
    fn server(config: &ServerConfig) -> PyResult<Self> {
        let conn = ServerConnection::new(config.inner.clone())
            .map_err(|e| err(nettls::TlsError::Rustls(e.to_string())))?;
        Ok(Self::wrap(conn.into()))
    }

    /// Ciphertext from the peer; what rustls cannot take yet waits here.
    fn receive(&self, data: &[u8]) -> PyResult<()> {
        let mut inner = lock(&self.inner);
        inner.queue.extend(data);
        inner.feed_behind_plaintext().map_err(io_err)
    }

    /// The transport has ended; applied after the queued ciphertext.
    fn receive_eof(&self) -> PyResult<()> {
        let mut inner = lock(&self.inner);
        inner.ended = true;
        inner.feed_behind_plaintext().map_err(io_err)
    }

    /// Up to `n` bytes of plaintext: `b""` when none has arrived, `None` after
    /// the peer's `close_notify`, and `ConnectionResetError` once the
    /// plaintext is read if the transport ended without `close_notify`.
    #[pyo3(signature = (n = 65536))]
    fn read(&self, n: usize) -> PyResult<Option<Bytes>> {
        if n > MAX_READ {
            return Err(PyValueError::new_err(format!(
                "read takes at most {MAX_READ} bytes at a time, got {n}"
            )));
        }
        let mut inner = lock(&self.inner);
        let mut buf = vec![0u8; n];
        match inner.conn.reader().read(&mut buf) {
            // `Ok(0)` for a non-empty buffer means `close_notify`.
            Ok(0) if n > 0 => Ok(None),
            Ok(got) => {
                buf.truncate(got);
                // A failure is not raised with this plaintext but by a later
                // `read`: rustls keeps a failed state, and ciphertext that
                // cannot be framed stays queued and fails again.
                let _ = inner.feed();
                Ok(Some(bytes(buf)))
            }
            // A failed connection raises its error here instead of `b""`.
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                inner.feed().map_err(io_err)?;
                Ok(Some(bytes(Vec::new())))
            }
            // The transport ended without `close_notify`.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Err(
                PyConnectionResetError::new_err("the transport ended without close_notify"),
            ),
            Err(e) => Err(io_err(e)),
        }
    }

    /// Plaintext to send; returns how much rustls took. It holds at most
    /// 64 KiB (its default) not yet taken out with `take_outgoing`.
    fn write(&self, data: &[u8]) -> PyResult<usize> {
        lock(&self.inner).conn.writer().write(data).map_err(io_err)
    }

    /// All ciphertext to send, including the alert after a failure.
    fn take_outgoing(&self) -> PyResult<Bytes> {
        let mut inner = lock(&self.inner);
        let mut out = Vec::new();
        while inner.conn.wants_write() {
            inner.conn.write_tls(&mut out).map_err(io_err)?;
        }
        Ok(bytes(out))
    }

    /// Does nothing after `close_notify` or a fatal alert was queued.
    fn send_close_notify(&self) {
        lock(&self.inner).conn.send_close_notify();
    }

    fn is_handshaking(&self) -> bool {
        lock(&self.inner).conn.is_handshaking()
    }

    fn peer_closed(&self) -> bool {
        lock(&self.inner).peer_closed
    }

    /// Plaintext rustls holds plus queued ciphertext, which uvloop relies on:
    /// it reads again only while `SSLObject.pending()` or its incoming buffer
    /// is not zero.
    fn pending(&self) -> PyResult<usize> {
        let mut inner = lock(&self.inner);
        let plaintext = match inner.process() {
            Ok(state) => state.plaintext_bytes_to_read(),
            // After a failure rustls gives no total, but plaintext from before
            // it is still to be read; `read` raises the failure afterwards.
            Err(e) => match inner.plaintext_waiting() {
                0 => return Err(io_err(e)),
                first => first,
            },
        };
        Ok(plaintext + inner.queue.len())
    }

    fn alpn_protocol(&self) -> Option<Bytes> {
        lock(&self.inner)
            .conn
            .alpn_protocol()
            .map(|p| bytes(p.to_vec()))
    }

    /// The leaf as DER.
    fn peer_certificate(&self) -> Option<Bytes> {
        lock(&self.inner)
            .conn
            .peer_certificates()
            .and_then(|chain| chain.first())
            .map(|leaf| bytes(leaf.as_ref().to_vec()))
    }

    /// `"TLSv1.3"` or `"TLSv1.2"`, as Python's `ssl` writes them.
    fn protocol_version(&self) -> Option<String> {
        lock(&self.inner).conn.protocol_version().map(|v| match v {
            ProtocolVersion::TLSv1_3 => "TLSv1.3".to_owned(),
            ProtocolVersion::TLSv1_2 => "TLSv1.2".to_owned(),
            other => format!("{other:?}"),
        })
    }

    /// rustls's name for the suite; one it has no name for, such as nettls's
    /// AEGIS-256 suite, is its code point (`"0xff06"`).
    fn cipher_suite(&self) -> Option<String> {
        lock(&self.inner)
            .conn
            .negotiated_cipher_suite()
            .map(|suite| {
                let id = suite.suite();
                id.as_str()
                    .map_or_else(|| format!("{:#06x}", u16::from(id)), str::to_owned)
            })
    }
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ClientConfig>()?;
    m.add_class::<ServerConfig>()?;
    m.add_class::<Stream>()?;
    m.add_class::<TlsConnection>()?;
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
