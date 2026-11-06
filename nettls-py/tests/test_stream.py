# SPDX-License-Identifier: MIT OR Apache-2.0
"""`nettls_py.stream`: a rustls connection over a Python socket.

Client and server run in the same process, in two threads. That also shows the
GIL is let go while a handshake waits: otherwise one side would block the other.
Whom to trust is the client config's decision, and the certificate shown is the
server config's; the stream only carries the bytes.
"""

from __future__ import annotations

import socket
import threading
import time

import nettls_py as nettls
import pytest

from nettls_py.generations import Generation, Received, Trust
from nettls_py.stream import MAX_READ, Stream

A = nettls.announcer


def identity(name: str) -> nettls.TlsMaterial:
    params = nettls.SelfSignedParams.new(name, ["localhost", "127.0.0.1"])
    params.valid_days = 30
    return nettls.TlsMaterial.load(nettls.CertSource.self_signed(params))


def serve_once(config, handler):
    """Accepts one connection on a free port and runs `handler(stream)` on it."""
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    result: dict = {}

    def run():
        try:
            sock, _ = listener.accept()
            sock.settimeout(10)
            with Stream.accept(sock, config) as tls:
                result["value"] = handler(tls)
        except Exception as e:  # noqa: BLE001
            result["error"] = e
        finally:
            listener.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return port, thread, result


def echo_line(tls: Stream) -> bytes:
    data = b""
    while not data.endswith(b"\n"):
        chunk = tls.read()
        if not chunk:
            break
        data += chunk
    tls.write(data)
    return data


def connect(port: int, config, timeout: float = 10) -> Stream:
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    return Stream.connect(sock, config, "localhost")


def test_a_pinned_connection_carries_bytes_both_ways():
    m = identity("server")
    port, thread, result = serve_once(m.server_config(), echo_line)
    with connect(port, nettls.pinned_client_config(m.fingerprint_sha256())) as tls:
        assert tls.peer_fingerprint() == m.fingerprint_sha256()
        assert tls.write(b"hello\n") == 6
        assert tls.read() == b"hello\n"
    thread.join(10)
    assert result == {"value": b"hello\n"}


def test_alpn_is_agreed_and_shown_on_both_sides():
    m = identity("server")
    seen: dict = {}

    def handler(tls):
        seen["server"] = tls.alpn_protocol()
        return echo_line(tls)

    port, thread, result = serve_once(m.server_config_with_alpn([b"h2", b"nettls/1"]), handler)
    config = nettls.pinned_client_config_with_alpn(m.fingerprint_sha256(), [b"nettls/1"])
    with connect(port, config) as tls:
        assert tls.alpn_protocol() == b"nettls/1"
        tls.write(b"x\n")
        assert tls.read() == b"x\n"
    thread.join(10)
    assert seen["server"] == b"nettls/1" and "error" not in result

    # Without ALPN, nothing is agreed.
    port, thread, _ = serve_once(m.server_config(), echo_line)
    with connect(port, nettls.pinned_client_config(m.fingerprint_sha256())) as tls:
        assert tls.alpn_protocol() is None
        tls.write(b"x\n")
        tls.read()
    thread.join(10)


def test_the_wrong_pin_fails_the_handshake():
    m = identity("server")
    other = identity("other")
    port, thread, result = serve_once(m.server_config(), echo_line)
    with pytest.raises(OSError):
        connect(port, nettls.pinned_client_config(other.fingerprint_sha256()))
    thread.join(10)
    assert isinstance(result.get("error"), OSError)


def test_trust_promotes_next_once_the_handshake_proves_it():
    m0, m1 = identity("server"), identity("server")
    resolver = nettls.RotatingResolver(m0)
    trust = Trust.from_approval(Generation.from_der(m0.cert_chain()[0]))

    # The server announces its next certificate, and the client stores it.
    pem1 = nettls.pem.encode("CERTIFICATE", m1.cert_chain()[0]).decode()
    k = nettls.announcement.Announcement.new(
        "server", None, (m0.fingerprint_sha256(), m0.anchor_pkcs8()), pem1, int(time.time())
    )
    assert trust.receive(k) == Received.Stored

    # The server switches. The client config accepts `next`, and promotes it.
    resolver.swap(m1)
    port, thread, result = serve_once(resolver.server_config(), echo_line)
    with connect(port, trust.client_config()) as tls:
        assert tls.peer_fingerprint() == m1.fingerprint_sha256()
        tls.write(b"after the switch\n")
        assert tls.read() == b"after the switch\n"
    thread.join(10)
    assert "error" not in result
    state = trust.state()
    assert state.current().fingerprint() == m1.fingerprint_sha256()
    assert state.previous().fingerprint() == m0.fingerprint_sha256()


def test_a_silent_server_times_out():
    listener = socket.create_server(("127.0.0.1", 0))
    try:
        port = listener.getsockname()[1]
        with pytest.raises(TimeoutError):
            connect(port, nettls.pinned_client_config("ab" * 32), timeout=0.5)
    finally:
        listener.close()


def test_a_non_blocking_socket_is_refused_and_left_alone():
    listener = socket.create_server(("127.0.0.1", 0))
    sock = socket.create_connection(listener.getsockname())
    try:
        sock.setblocking(False)
        with pytest.raises(ValueError, match="non-blocking"):
            Stream.connect(sock, nettls.pinned_client_config("ab" * 32), "localhost")
        assert sock.fileno() >= 0, "a refused socket stays the caller's"
    finally:
        sock.close()
        listener.close()


def test_a_closed_stream_refuses_and_closes_once():
    m = identity("server")
    port, thread, _ = serve_once(m.server_config(), echo_line)
    tls = connect(port, nettls.pinned_client_config(m.fingerprint_sha256()))
    tls.write(b"x\n")
    assert tls.read() == b"x\n"
    tls.close()
    tls.close()
    assert repr(tls) == "Stream(closed)"
    with pytest.raises(ValueError, match="closed"):
        tls.read()
    with pytest.raises(ValueError, match="at most"):
        tls.read(MAX_READ + 1)
    thread.join(10)
