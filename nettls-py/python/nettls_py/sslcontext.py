# SPDX-License-Identifier: MIT OR Apache-2.0
"""`nettls_py.sslcontext`: an `ssl.SSLContext` whose TLS is nettls's rustls (0.12.0).

`SSLContext(config)` takes a nettls `ClientConfig` or `ServerConfig`, for
libraries that take an `ssl.SSLContext`. Each connection is a
`nettls_py.stream.TlsConnection`; this module only moves bytes and translates
failures into the `ssl` exceptions those libraries handle.
"""

from __future__ import annotations

import socket
import ssl
import threading

from .aegis import CODEPOINT as _AEGIS_CODEPOINT
from .stream import (
    MAX_READ,
    CertificateExpiredError,
    CertificateNotYetValidError,
    ClientConfig,
    ServerConfig,
    TlsConnection,
    UntrustedPeerError,
)

__all__ = ["SSLContext"]

# The most read or written in one step; rustls takes at most 64 KiB of unsent
# output by default.
_CHUNK = 64 * 1024

# The most protocols `set_alpn_protocols` takes, the bound nettls's config
# builders put on an ALPN list (0.12.0).
_MAX_ALPN_PROTOCOLS = 16


class _UntrustedPeerSSLError(ssl.SSLCertVerificationError, UntrustedPeerError):
    pass


class _CertificateExpiredSSLError(ssl.SSLCertVerificationError, CertificateExpiredError):
    pass


class _CertificateNotYetValidSSLError(
    ssl.SSLCertVerificationError, CertificateNotYetValidError
):
    pass


_REFUSALS = (
    (UntrustedPeerError, _UntrustedPeerSSLError),
    (CertificateExpiredError, _CertificateExpiredSSLError),
    (CertificateNotYetValidError, _CertificateNotYetValidSSLError),
)


def _ssl_error(exc: OSError) -> ssl.SSLError:
    """The `ssl` exception for a `TlsConnection` failure, made with
    `(errno, message)` as `ssl` makes its own."""
    message = str(exc)
    for refusal, ssl_class in _REFUSALS:
        if isinstance(exc, refusal):
            error = ssl_class(ssl.SSL_ERROR_SSL, message)
            for name in ("now", "not_after", "not_before"):
                if hasattr(exc, name):
                    setattr(error, name, getattr(exc, name))
            return error
    # What `TlsConnection.read` raises when the transport ended without close_notify.
    if isinstance(exc, ConnectionResetError):
        return ssl.SSLEOFError(ssl.SSL_ERROR_EOF, message)
    return ssl.SSLError(ssl.SSL_ERROR_SSL, message)


def _want_read(message: str) -> ssl.SSLWantReadError:
    return ssl.SSLWantReadError(ssl.SSL_ERROR_WANT_READ, message)


def _eof(message: str) -> ssl.SSLEOFError:
    return ssl.SSLEOFError(ssl.SSL_ERROR_EOF, message)


def _secret_bits(suite: str) -> int | None:
    # The key size in rustls's suite names; ChaCha20 and nettls's AEGIS-256
    # suite (shown as its code point) use 256 bits.
    if "_256_" in suite or "CHACHA20" in suite or suite == f"{_AEGIS_CODEPOINT:#06x}":
        return 256
    if "_128_" in suite:
        return 128
    return None


class _Connected:
    """What both wrapped forms report about the connection in `_conn`."""

    _conn: TlsConnection

    def selected_alpn_protocol(self) -> str | None:
        protocol = self._conn.alpn_protocol()
        return None if protocol is None else protocol.decode()

    def getpeercert(self, binary_form: bool = False) -> bytes | dict | None:
        """The DER with `binary_form=True`, otherwise an empty dict: nettls
        does not parse the certificate."""
        if self._conn.is_handshaking():
            raise ValueError("handshake not done yet")
        der = self._conn.peer_certificate()
        if der is None:
            return None
        return der if binary_form else {}

    def version(self) -> str | None:
        if self._conn.is_handshaking():
            return None
        return self._conn.protocol_version()

    def cipher(self) -> tuple[str, str, int | None] | None:
        if self._conn.is_handshaking():
            return None
        suite = self._conn.cipher_suite()
        version = self._conn.protocol_version()
        if suite is None or version is None:
            return None
        return (suite, version, _secret_bits(suite))


class _SSLObject(_Connected):
    """What `wrap_bio` returns: the `ssl.SSLObject` methods asyncio and anyio
    use, over two memory BIOs. Every call writes the connection's output to
    `outgoing`, alerts included."""

    def __init__(self, context, conn, incoming, outgoing, server_side, server_hostname):
        self.context = context
        self.server_side = server_side
        self.server_hostname = server_hostname
        self.session = None
        self.session_reused = False
        self._conn = conn
        self._incoming = incoming
        self._outgoing = outgoing
        self._ended = False

    def _flush(self) -> None:
        data = self._conn.take_outgoing()
        if data:
            self._outgoing.write(data)

    def _call(self, method, *args):
        try:
            return method(*args)
        except OSError as exc:
            self._flush()
            raise _ssl_error(exc) from exc

    def _pump(self) -> None:
        if self._incoming.pending:
            self._call(self._conn.receive, self._incoming.read())
        if self._incoming.eof and not self._ended:
            self._ended = True
            self._call(self._conn.receive_eof)

    def do_handshake(self) -> None:
        self._pump()
        self._flush()
        if self._conn.is_handshaking():
            if self._ended:
                raise _eof("the transport ended during the TLS handshake")
            raise _want_read("the TLS handshake waits for the peer")

    def read(self, len: int = 1024, buffer=None):
        # `len` is the parameter's name in `ssl.SSLObject.read`.
        return self._read(len, buffer)

    def _read(self, size: int, buffer):
        view = None
        if buffer is not None:
            view = memoryview(buffer).cast("B")
            if size <= 0 or size > view.nbytes:
                size = view.nbytes
        elif size < 0:
            raise ValueError("size should not be negative")
        size = min(size, MAX_READ)
        self._pump()
        data = self._call(self._conn.read, size)
        self._flush()
        if data is None:  # The peer's close_notify.
            data = b""
        elif not data and size:
            raise _want_read("no application data has arrived yet")
        if view is None:
            return data
        view[: len(data)] = data
        return len(data)

    def write(self, data) -> int:
        view = memoryview(data).cast("B")
        taken = 0
        while taken < view.nbytes:
            count = self._call(self._conn.write, bytes(view[taken : taken + _CHUNK]))
            self._flush()
            if not count:
                break
            taken += count
        # rustls takes nothing only before the handshake has completed.
        if view.nbytes and not taken:
            raise _want_read("the TLS handshake must complete before more can be written")
        return taken

    def unwrap(self) -> None:
        """Sends close_notify and completes once the peer's has arrived.
        Application data arriving meanwhile is dropped."""
        self._conn.send_close_notify()
        self._flush()
        self._pump()
        while True:
            data = self._call(self._conn.read, _CHUNK)
            if data is None:
                return None
            if not data:
                raise _want_read("waiting for the peer's close_notify")

    def pending(self) -> int:
        self._pump()
        return self._call(self._conn.pending)

    def selected_npn_protocol(self) -> None:
        return None  # rustls has no NPN.

    def shared_ciphers(self) -> None:
        return None  # rustls does not say which suites the client offered.

    def compression(self) -> None:
        return None

    def get_channel_binding(self, cb_type: str = "tls-unique") -> None:
        # rustls does not provide tls-unique, and TLS 1.3 does not define it.
        if cb_type not in ssl.CHANNEL_BINDING_TYPES:
            raise ValueError(f"{cb_type} channel binding type not implemented")
        return None


class _SSLSocket(_Connected):
    """What `wrap_socket` returns: a blocking socket that carries TLS.

    `_send_lock` covers every write to the socket: application data, and the
    output the connection produces while reading, since TLS records must leave
    in the order rustls made them. `_recv_lock` covers reading. With two locks,
    one thread can send while another waits in `recv`. Where both are taken,
    `_recv_lock` comes first.
    """

    def __init__(self, sock, conn: TlsConnection, suppress_ragged_eofs: bool):
        self._sock = sock
        self._conn = conn
        self._suppress_ragged_eofs = suppress_ragged_eofs
        self._send_lock = threading.Lock()
        self._recv_lock = threading.Lock()
        self._closed = False
        self._broken = False

    def _check_usable(self) -> None:
        if self._broken:
            raise ssl.SSLError(
                ssl.SSL_ERROR_SSL, "the TLS connection is unusable after a failed send"
            )

    def _send_queued(self) -> None:
        # The caller holds `_send_lock`. Ciphertext taken out of rustls and not
        # sent is lost, so after a failed send the TLS stream is broken.
        while data := self._conn.take_outgoing():
            try:
                self._sock.sendall(data)
            except BaseException:
                self._broken = True
                raise

    def _send_after_reading(self) -> None:
        # Must not block on `_send_lock`: its holder may be stuck in `sendall`
        # to a peer that waits for this side to read, a deadlock. Output left
        # queued goes with the next send, as `_send_queued` takes everything;
        # TLS lets a key update answer wait for the next record. A failed send
        # is not raised here, so data already read is still returned; it marks
        # the connection broken, and the next call raises.
        if not self._send_lock.acquire(blocking=False):
            return
        try:
            self._send_queued()
        except OSError:
            pass
        finally:
            self._send_lock.release()

    def _receive(self, data: bytes) -> None:
        try:
            if data:
                self._conn.receive(data)
            else:
                self._conn.receive_eof()
        except OSError as exc:
            self._send_after_reading()
            raise _ssl_error(exc) from exc

    def do_handshake(self) -> None:
        with self._recv_lock, self._send_lock:
            self._check_usable()
            self._send_queued()
            while self._conn.is_handshaking():
                data = self._sock.recv(_CHUNK)
                if not data:
                    raise _eof("the transport ended during the TLS handshake")
                try:
                    self._conn.receive(data)
                except OSError as exc:
                    try:
                        self._send_queued()
                    except OSError:
                        pass  # The alert is best effort; the refusal is raised.
                    raise _ssl_error(exc) from exc
                self._send_queued()

    def _handshake_first(self) -> None:
        if self._conn.is_handshaking():
            self.do_handshake()

    def recv(self, bufsize: int, flags: int = 0) -> bytes:
        if flags:
            raise ValueError("non-zero flags are not allowed in calls to recv() on a TLS socket")
        if bufsize < 0:
            raise ValueError("negative buffersize in recv")
        self._check_usable()
        self._handshake_first()
        if bufsize == 0:
            return b""
        bufsize = min(bufsize, MAX_READ)
        with self._recv_lock:
            while True:
                try:
                    data = self._conn.read(bufsize)
                except ConnectionResetError as exc:
                    if self._suppress_ragged_eofs:
                        return b""
                    raise _ssl_error(exc) from exc
                except OSError as exc:
                    self._send_after_reading()
                    raise _ssl_error(exc) from exc
                self._send_after_reading()
                if data is None:
                    return b""
                if data:
                    return data
                self._receive(self._sock.recv(_CHUNK))

    def _send_some(self, view: memoryview) -> int:
        # The caller holds `_send_lock`.
        try:
            count = self._conn.write(bytes(view[:_CHUNK]))
        except OSError as exc:
            raise _ssl_error(exc) from exc
        self._send_queued()
        return count

    def send(self, data, flags: int = 0) -> int:
        if flags:
            raise ValueError("non-zero flags are not allowed in calls to send() on a TLS socket")
        self._check_usable()
        self._handshake_first()
        with self._send_lock:
            self._check_usable()
            return self._send_some(memoryview(data).cast("B"))

    def sendall(self, data, flags: int = 0) -> None:
        if flags:
            raise ValueError("non-zero flags are not allowed in calls to sendall() on a TLS socket")
        self._check_usable()
        self._handshake_first()
        view = memoryview(data).cast("B")
        with self._send_lock:
            self._check_usable()
            while view:
                view = view[self._send_some(view) :]

    def close(self) -> None:
        """Sends close_notify unless another thread is sending, then shuts the
        socket down and closes it, which wakes a thread blocked on it. Closing
        twice does nothing, and a peer that is already gone is not an error.
        Any other error from the TLS side is raised after the socket is closed
        (0.12.0)."""
        if self._closed:
            return
        self._closed = True
        try:
            if self._send_lock.acquire(blocking=False):
                try:
                    self._conn.send_close_notify()
                    self._send_queued()
                except OSError:
                    pass
                finally:
                    self._send_lock.release()
        finally:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._sock.close()

    def settimeout(self, value: float | None) -> None:
        if value is not None and value == 0:
            raise ValueError("the socket must block: give it a timeout, or None to wait without one")
        self._sock.settimeout(value)

    def gettimeout(self) -> float | None:
        return self._sock.gettimeout()

    def fileno(self) -> int:
        return self._sock.fileno()

    def getsockname(self):
        return self._sock.getsockname()

    def getpeername(self):
        return self._sock.getpeername()

    def __enter__(self) -> _SSLSocket:
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()


_TRUST = (
    "whom to trust is the ClientConfig's decision "
    "(pinned_client_config, Trust.client_config, unverified_client_config)"
)
_CERTIFICATE = (
    "the certificate shown is the ServerConfig's "
    "(TlsMaterial.server_config, RotatingResolver.server_config)"
)
_CIPHERS = "the cipher suites are the config's TransportPolicy, and the rest is fixed by nettls"
_UNUSED = "no connection uses the OpenSSL context inside this object"

# What would configure the unused OpenSSL context, and where the setting
# belongs instead. Reading the attributes still works; libraries read some.
_REFUSED_METHODS = {
    "load_cert_chain": _CERTIFICATE,
    "load_verify_locations": _TRUST,
    "load_default_certs": _TRUST,
    "set_default_verify_paths": _TRUST,
    "set_ciphers": _CIPHERS,
    "set_ecdh_curve": _CIPHERS,
    "load_dh_params": _CIPHERS,
    "set_servername_callback": _CERTIFICATE,
}
_REFUSED_ATTRIBUTES = {
    "verify_mode": _TRUST,
    "check_hostname": _TRUST,
    "verify_flags": _TRUST,
    "minimum_version": _CIPHERS,
    "maximum_version": _CIPHERS,
    "sni_callback": _CERTIFICATE,
    "options": _UNUSED,
    "post_handshake_auth": _UNUSED,
    "keylog_filename": _UNUSED,
    "num_tickets": _UNUSED,
}


def _refusal(name: str, reason: str) -> ValueError:
    return ValueError(f"nettls_py.sslcontext.SSLContext does not take {name}: {reason}")


def _refused_method(name: str, reason: str):
    def refused(self, *args, **kwargs):
        raise _refusal(name, reason)

    refused.__name__ = refused.__qualname__ = name
    return refused


def _hostname(name: str | bytes | None) -> str | None:
    # anyio passes the name IDNA-encoded, as bytes.
    return name.decode("ascii") if isinstance(name, bytes) else name


class SSLContext(ssl.SSLContext):
    """An `ssl.SSLContext` made from a nettls `ClientConfig` or `ServerConfig`.
    The OpenSSL context it inherits is never used; the methods and attributes
    in `_REFUSED_METHODS` and `_REFUSED_ATTRIBUTES` raise `ValueError`."""

    def __new__(cls, config: ClientConfig | ServerConfig) -> SSLContext:
        # The unused OpenSSL context matches the config's side, for libraries
        # that read it.
        if isinstance(config, ClientConfig):
            protocol = ssl.PROTOCOL_TLS_CLIENT
        elif isinstance(config, ServerConfig):
            protocol = ssl.PROTOCOL_TLS_SERVER
        else:
            raise TypeError(
                f"SSLContext takes a nettls ClientConfig or ServerConfig, not {type(config).__name__}"
            )
        return super().__new__(cls, protocol)

    def __init__(self, config: ClientConfig | ServerConfig) -> None:
        self._config = config
        self._client = isinstance(config, ClientConfig)
        self._alpn: list[bytes] | None = None

    def __setattr__(self, name: str, value) -> None:
        reason = _REFUSED_ATTRIBUTES.get(name)
        if reason is not None:
            raise _refusal(name, reason)
        super().__setattr__(name, value)

    def set_alpn_protocols(self, alpn_protocols) -> None:
        if not self._client:
            raise ValueError(
                "a server context's ALPN protocols are fixed in its ServerConfig: "
                "make it with server_config_with_alpn([...]) instead"
            )
        protocols = []
        for protocol in alpn_protocols:
            # Refused at the first protocol over the bound, so an iterable
            # without an end is never walked further than that.
            if len(protocols) == _MAX_ALPN_PROTOCOLS:
                raise ValueError(
                    f"set_alpn_protocols was given more than {_MAX_ALPN_PROTOCOLS} protocols"
                )
            name = protocol.encode("ascii")
            if not 1 <= len(name) <= 255:
                raise ValueError("ALPN protocols must be 1 to 255 bytes long")
            protocols.append(name)
        self._alpn = protocols

    def _connection(self, server_side, server_hostname, session, alpn) -> TlsConnection:
        if session is not None:
            raise ValueError("nettls does not resume sessions: session must be None")
        if server_side:
            if self._client:
                raise ssl.SSLError(
                    ssl.SSL_ERROR_SSL,
                    "this context holds a ClientConfig and cannot serve: make it from a ServerConfig",
                )
            return TlsConnection.server(self._config)
        if not self._client:
            raise ssl.SSLError(
                ssl.SSL_ERROR_SSL,
                "this context holds a ServerConfig and cannot connect: make it from a ClientConfig",
            )
        if server_hostname is None:
            raise ValueError("a client connection needs server_hostname, the name it sends")
        return TlsConnection.client(self._config, server_hostname, alpn)

    def wrap_bio(self, incoming, outgoing, server_side=False, server_hostname=None, session=None):
        hostname = _hostname(server_hostname)
        conn = self._connection(server_side, hostname, session, self._alpn)
        return _SSLObject(self, conn, incoming, outgoing, server_side, hostname)

    def wrap_socket(
        self,
        sock,
        server_side=False,
        do_handshake_on_connect=True,
        suppress_ragged_eofs=True,
        server_hostname=None,
        session=None,
    ):
        """Takes `sock` over. A non-blocking socket is refused and left to the
        caller; after a failed handshake `sock` is closed, as `ssl` closes it."""
        if sock.gettimeout() == 0:
            raise ValueError(
                "the socket is non-blocking: give it a timeout, or None to wait without one"
            )
        alpn = self._alpn
        if alpn is not None:
            # h2 is dropped from the `set_alpn_protocols` list (a config's own
            # list is used as it is): httpx (through httpcore) chooses HTTP/2
            # only for a real `ssl.SSLSocket` and speaks HTTP/1.1 over this
            # object whatever ALPN agreed, so a server that agreed to h2 would
            # get HTTP/1.1. `wrap_bio` keeps h2; there the library asks the
            # object what was agreed.
            alpn = [protocol for protocol in alpn if protocol != b"h2"]
        conn = self._connection(server_side, _hostname(server_hostname), session, alpn)
        wrapped = _SSLSocket(sock, conn, suppress_ragged_eofs)
        if do_handshake_on_connect:
            try:
                wrapped.do_handshake()
            except BaseException:
                sock.close()
                raise
        return wrapped


for _name, _reason in _REFUSED_METHODS.items():
    setattr(SSLContext, _name, _refused_method(_name, _reason))
del _name, _reason
