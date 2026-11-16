# SPDX-License-Identifier: MIT OR Apache-2.0
"""`nettls_py.stream.TlsConnection`: client and server wired together in memory."""

from __future__ import annotations

import os

import nettls_py as nettls
import pytest

from nettls_py.stream import TlsConnection, UntrustedPeerError


def identity(name: str) -> nettls.TlsMaterial:
    params = nettls.SelfSignedParams.new(name, ["localhost", "127.0.0.1"])
    params.valid_days = 30
    return nettls.TlsMaterial.load(nettls.CertSource.self_signed(params))


def connect(client: TlsConnection, server: TlsConnection) -> None:
    """Moves each side's output to the other until neither has any."""
    while True:
        moved = False
        for sender, receiver in ((client, server), (server, client)):
            data = sender.take_outgoing()
            if data:
                receiver.receive(data)
                moved = True
        if not moved:
            return


def write_all(conn: TlsConnection, data: bytes) -> bytes:
    """The ciphertext for all of `data`."""
    out = b""
    view = memoryview(data)
    while view:
        taken = conn.write(bytes(view))
        assert taken > 0
        view = view[taken:]
        out += conn.take_outgoing()
    return out


@pytest.fixture(scope="module")
def server_identity() -> nettls.TlsMaterial:
    return identity("server")


def pair(m: nettls.TlsMaterial) -> tuple[TlsConnection, TlsConnection]:
    client = TlsConnection.client(
        nettls.pinned_client_config(m.fingerprint_sha256()), "localhost", [b"nettls/1"]
    )
    server = TlsConnection.server(m.server_config_with_alpn([b"h2", b"nettls/1"]))
    connect(client, server)
    return client, server


def test_a_handshake_in_memory_carries_bytes_both_ways(server_identity):
    m = server_identity
    client, server = pair(m)
    assert not client.is_handshaking() and not server.is_handshaking()
    assert client.peer_certificate() == m.cert_chain()[0]
    assert server.peer_certificate() is None
    assert client.alpn_protocol() == server.alpn_protocol() == b"nettls/1"
    assert client.protocol_version() == server.protocol_version() == "TLSv1.3"
    assert client.cipher_suite() == server.cipher_suite() == "TLS13_AES_256_GCM_SHA384"

    assert client.read() == b"", "nothing has arrived yet"
    server.receive(write_all(client, b"ping"))
    assert server.read() == b"ping"
    client.receive(write_all(server, b"pong"))
    assert client.read() == b"pong"
    assert client.pending() == 0 and client.read() == b""


def test_a_large_payload_arrives_whole_and_pending_counts_what_waits(server_identity):
    client, server = pair(server_identity)
    payload = os.urandom(300 * 1024)
    taken = server.write(payload)
    assert 0 < taken < len(payload), "rustls takes a limited amount at a time"
    client.receive(server.take_outgoing() + write_all(server, payload[taken:]))

    # Most of it waits as ciphertext; pending() counts it.
    assert client.pending() > 64 * 1024
    got = b""
    while len(got) < len(payload):
        chunk = client.read()
        assert chunk, f"read stalled after {len(got)} bytes with pending()={client.pending()}"
        got += chunk
        if len(got) < len(payload):
            assert client.pending() > 0
    assert got == payload
    assert client.pending() == 0 and client.read() == b""


def test_close_notify_reads_as_none(server_identity):
    client, server = pair(server_identity)
    client.receive(write_all(server, b"last words"))
    server.send_close_notify()
    client.receive(server.take_outgoing())
    assert client.read() == b"last words"
    assert client.read() is None
    assert client.peer_closed()


def test_a_transport_that_ends_without_close_notify_is_a_reset(server_identity):
    client, server = pair(server_identity)
    client.receive(write_all(server, b"cut"))
    client.receive_eof()
    assert client.read() == b"cut", "what arrived is read first"
    with pytest.raises(ConnectionResetError):
        client.read()
    assert not client.peer_closed()


def test_a_wrong_pin_is_refused_and_leaves_an_alert_to_send(server_identity):
    other = identity("other")
    client = TlsConnection.client(
        nettls.pinned_client_config(other.fingerprint_sha256()), "localhost"
    )
    server = TlsConnection.server(server_identity.server_config())
    server.receive(client.take_outgoing())
    with pytest.raises(UntrustedPeerError):
        client.receive(server.take_outgoing())
    alert = client.take_outgoing()
    assert alert, "the client tells the server why"
    with pytest.raises(OSError):
        server.receive(alert)
    with pytest.raises(UntrustedPeerError):
        client.read()


def test_garbage_instead_of_a_client_hello_is_refused(server_identity):
    server = TlsConnection.server(server_identity.server_config())
    with pytest.raises(OSError) as e:
        server.receive(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
    assert not isinstance(e.value, UntrustedPeerError)
    assert server.is_handshaking()


# 100 bytes: the good and the bad record reach rustls in one `receive`.
# 40 KiB: the bad record waits in the queue until `read` has made room.
@pytest.mark.parametrize("size", [100, 40 * 1024])
def test_plaintext_that_arrived_before_a_bad_record_is_read_first(server_identity, size):
    client, server = pair(server_identity)
    good = os.urandom(size)
    bad = write_all(server, good) + write_all(server, b"tampered")
    client.receive(bad[:-1] + bytes([bad[-1] ^ 1]))
    got = b""
    with pytest.raises(OSError):
        while True:
            chunk = client.read()
            assert chunk, "the failure is raised, not reported as nothing"
            got += chunk
    assert got == good
    assert client.take_outgoing(), "the alert for the bad record"
