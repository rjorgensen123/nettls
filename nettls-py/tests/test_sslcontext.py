# SPDX-License-Identifier: MIT OR Apache-2.0
"""`nettls_py.sslcontext.SSLContext` with unchanged libraries: asyncio streams,
uvicorn (`ssl_context_factory`) and httpx (`verify=`), sync and async, and with
the rest of nettls: `Trust`, enrollment, the transport policy and `Stream`. Only
127.0.0.1, on ports the system picks.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import socket
import ssl
import threading
import time

import httpx
import nettls_py as nettls
import pytest
import uvicorn

from nettls_py.generations import Generation, Received, Trust
from nettls_py.sslcontext import SSLContext
from nettls_py.stream import (
    CertificateExpiredError,
    CertificateNotYetValidError,
    Stream,
    TlsConnection,
    UntrustedPeerError,
)
from test_stream import EXPIRED, NOT_YET_VALID, resigned


def identity(name: str) -> nettls.TlsMaterial:
    params = nettls.SelfSignedParams.new(name, ["localhost", "127.0.0.1"])
    params.valid_days = 30
    return nettls.TlsMaterial.load(nettls.CertSource.self_signed(params))


SERVER = identity("server")
PIN = SERVER.fingerprint_sha256()
# The default server config offers h2 first; uvicorn speaks HTTP/1.1 only.
HTTP11 = SERVER.server_config_with_alpn([b"http/1.1"])


def client_context(pin: str = PIN) -> SSLContext:
    return SSLContext(nettls.pinned_client_config(pin))


def causes(exc: BaseException | None) -> list[BaseException]:
    """`exc` and the exceptions it came from. httpcore re-raises `from None`,
    which keeps only `__context__`."""
    chain = []
    while exc is not None:
        chain.append(exc)
        exc = exc.__cause__ or exc.__context__
    return chain


# --------------------------------------------------------------------------- #
# uvicorn
# --------------------------------------------------------------------------- #


async def app(scope, receive, send):
    """`/echo` returns the body; other paths the scheme and the client's port."""
    body = b""
    more = True
    while more:
        message = await receive()
        body += message.get("body", b"")
        more = message.get("more_body", False)
    out = body if scope["path"] == "/echo" else f"{scope['scheme']} {scope['client'][1]}".encode()
    headers = [(b"content-length", str(len(out)).encode())]
    await send({"type": "http.response.start", "status": 200, "headers": headers})
    await send({"type": "http.response.body", "body": out})


@contextlib.contextmanager
def serving(server_config, **options):
    """uvicorn on a free port with `SSLContext(server_config)`; yields its URL."""
    sock = socket.create_server(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    config = uvicorn.Config(
        app,
        lifespan="off",
        log_level="warning",
        ssl_context_factory=lambda _config, _default: SSLContext(server_config),
        **options,
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started:
            assert thread.is_alive() and time.monotonic() < deadline, "uvicorn did not start"
            time.sleep(0.01)
        yield f"https://localhost:{port}"
    finally:
        server.should_exit = True
        thread.join(10)
        sock.close()
    assert not thread.is_alive(), "uvicorn did not shut down"


@pytest.fixture(scope="module")
def site():
    with serving(HTTP11) as url:
        yield url


# --------------------------------------------------------------------------- #
# asyncio
# --------------------------------------------------------------------------- #


async def start_server(handler, config=HTTP11):
    server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=SSLContext(config))
    return server, server.sockets[0].getsockname()[1]


def test_asyncio_streams_carry_200_kb_each_way_and_close_cleanly():
    payload = os.urandom(200_000)

    async def main():
        served = asyncio.get_running_loop().create_future()

        async def handle(reader, writer):
            data = await reader.readexactly(len(payload))
            writer.write(data[::-1])
            await writer.drain()
            rest = await reader.read()
            writer.close()
            await writer.wait_closed()
            served.set_result((data, rest))

        server, port = await start_server(handle)
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", port, ssl=client_context(), server_hostname="localhost"
        )
        negotiated = writer.get_extra_info("ssl_object").version(), writer.get_extra_info("cipher")
        writer.write(payload)
        await writer.drain()
        back = await reader.readexactly(len(payload))
        writer.close()
        await writer.wait_closed()
        data, rest = await asyncio.wait_for(served, 5)
        server.close()
        await server.wait_closed()
        return negotiated, back, data, rest

    negotiated, back, data, rest = asyncio.run(main())
    assert negotiated == ("TLSv1.3", ("TLS13_AES_256_GCM_SHA384", "TLSv1.3", 256))
    assert data == payload and back == payload[::-1]
    assert rest == b"", "the server saw the client's close_notify as the end"


def test_asyncio_reports_a_refused_certificate_as_both_ssl_and_nettls_errors():
    expired = resigned(identity("server"), *EXPIRED)
    not_yet_valid = resigned(identity("server"), *NOT_YET_VALID)
    cases = [
        (SERVER, identity("other").fingerprint_sha256(), UntrustedPeerError),
        (expired, expired.fingerprint_sha256(), CertificateExpiredError),
        (not_yet_valid, not_yet_valid.fingerprint_sha256(), CertificateNotYetValidError),
    ]

    async def refused(m, pin):
        server, port = await start_server(lambda reader, writer: writer.close(), m.server_config())
        try:
            with pytest.raises(ssl.SSLError) as e:
                await asyncio.open_connection(
                    "127.0.0.1", port, ssl=client_context(pin), server_hostname="localhost"
                )
            return e.value
        finally:
            server.close()
            await server.wait_closed()

    for m, pin, nettls_class in cases:
        error = asyncio.run(refused(m, pin))
        assert isinstance(error, ssl.SSLCertVerificationError)
        assert isinstance(error, nettls_class) and isinstance(error.__cause__, nettls_class)
        assert error.errno == ssl.SSL_ERROR_SSL and str(error) == str(error.__cause__)
        if nettls_class is CertificateExpiredError:
            assert error.not_after == expired.not_after() < error.now
        if nettls_class is CertificateNotYetValidError:
            assert error.now < error.not_before == not_yet_valid.not_before()


# --------------------------------------------------------------------------- #
# uvicorn and httpx
# --------------------------------------------------------------------------- #


def test_httpx_reaches_uvicorn_and_reuses_the_connection(site):
    body = os.urandom(1024 * 1024)
    with httpx.Client(verify=client_context()) as client:
        first = client.get(f"{site}/").text.split()
        echoed = client.post(f"{site}/echo", content=body)
        second = client.get(f"{site}/").text.split()
    assert first[0] == "https", "the app sees TLS"
    assert echoed.http_version == "HTTP/1.1" and echoed.content == body
    assert first[1] == second[1], "one connection carried all three requests"


def test_async_httpx_reaches_uvicorn_and_reuses_the_connection(site):
    body = os.urandom(1024 * 1024)

    async def main():
        async with httpx.AsyncClient(verify=client_context()) as client:
            first = (await client.get(f"{site}/")).text.split()
            echoed = await client.post(f"{site}/echo", content=body)
            second = (await client.get(f"{site}/")).text.split()
        return first, echoed, second

    first, echoed, second = asyncio.run(main())
    assert first[0] == "https"
    assert echoed.http_version == "HTTP/1.1" and echoed.content == body
    assert first[1] == second[1]


def test_a_wrong_pin_is_a_connect_error_caused_by_the_nettls_refusal(site):
    wrong = client_context(identity("other").fingerprint_sha256())

    with pytest.raises(httpx.ConnectError) as e:
        httpx.get(f"{site}/", verify=wrong)
    assert any(isinstance(x, UntrustedPeerError) for x in causes(e.value))

    async def main():
        async with httpx.AsyncClient(verify=wrong) as client:
            with pytest.raises(httpx.ConnectError) as e:
                await client.get(f"{site}/")
            return e.value

    assert any(isinstance(x, UntrustedPeerError) for x in causes(asyncio.run(main())))

    # The refused handshakes left nothing behind on the server.
    assert httpx.get(f"{site}/", verify=client_context()).status_code == 200


def test_a_rotation_shows_the_new_certificate_to_new_connections():
    old, new = identity("server"), identity("server")
    resolver = nettls.RotatingResolver(old)
    with serving(resolver.server_config_with_alpn([b"http/1.1"])) as url:
        assert httpx.get(url, verify=client_context(old.fingerprint_sha256())).status_code == 200
        resolver.swap(new)
        assert httpx.get(url, verify=client_context(new.fingerprint_sha256())).status_code == 200
        with pytest.raises(httpx.ConnectError):
            httpx.get(url, verify=client_context(old.fingerprint_sha256()))


def test_a_keep_alive_connection_the_server_closed_is_replaced():
    async def go(url):
        async with httpx.AsyncClient(verify=client_context()) as client:
            first = await client.get(f"{url}/")
            await asyncio.sleep(0.6)
            return first, await client.get(f"{url}/")

    with serving(HTTP11, timeout_keep_alive=0.2) as url:
        with httpx.Client(verify=client_context()) as client:
            first = client.get(f"{url}/")
            time.sleep(0.6)
            second = client.get(f"{url}/")
        pairs = [(first, second), asyncio.run(go(url))]
    for first, second in pairs:
        assert first.status_code == second.status_code == 200
        assert first.text.split()[1] != second.text.split()[1], "a new connection, a new port"


# --------------------------------------------------------------------------- #
# Robustness
# --------------------------------------------------------------------------- #


def test_garbage_and_a_client_that_leaves_mid_handshake_do_not_stop_the_server(site):
    address = ("127.0.0.1", int(site.rsplit(":", 1)[1]))

    # Plain HTTP instead of a ClientHello: the server refuses it and hangs up.
    with socket.create_connection(address, timeout=5) as raw:
        raw.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        while raw.recv(4096):
            pass

    # Half a ClientHello, and then the client is gone.
    hello = TlsConnection.client(nettls.pinned_client_config(PIN), "localhost").take_outgoing()
    with socket.create_connection(address, timeout=5) as raw:
        raw.sendall(hello[: len(hello) // 2])

    assert httpx.get(f"{site}/", verify=client_context()).status_code == 200


def test_a_server_that_hangs_up_mid_body_is_an_error_not_a_hang():
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]

    def serve():
        for _ in range(2):
            conn, _ = listener.accept()
            conn.settimeout(5)
            tls = SSLContext(HTTP11).wrap_socket(conn, server_side=True)
            request = b""
            while b"\r\n\r\n" not in request:
                request += tls.recv(4096)
            tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n" + b"x" * 1000)
            # Gone without close_notify, 99 000 bytes short.
            conn.shutdown(socket.SHUT_RDWR)
            conn.close()

    async def go():
        async with httpx.AsyncClient(verify=client_context(), timeout=5) as client:
            with pytest.raises(httpx.RemoteProtocolError):
                await client.get(f"https://localhost:{port}/")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        with httpx.Client(verify=client_context(), timeout=5) as client:
            with pytest.raises(httpx.RemoteProtocolError):
                client.get(f"https://localhost:{port}/")
        asyncio.run(go())
    finally:
        thread.join(5)
        listener.close()


def test_a_transport_that_ends_during_the_handshake_is_an_eof_error():
    listener = socket.create_server(("127.0.0.1", 0))

    def hang_up():
        conn, _ = listener.accept()
        conn.recv(65536)  # The ClientHello, so that closing sends no reset.
        conn.close()

    thread = threading.Thread(target=hang_up, daemon=True)
    thread.start()
    try:
        sock = socket.create_connection(listener.getsockname(), timeout=5)
        with pytest.raises(ssl.SSLEOFError) as e:
            client_context().wrap_socket(sock, server_hostname="localhost")
        assert e.value.errno == ssl.SSL_ERROR_EOF
        assert sock.fileno() == -1, "the socket is closed after a failed handshake"
    finally:
        thread.join(5)
        listener.close()


def tls_pair():
    """A client and a server from `wrap_socket` over a socket pair."""
    a, b = socket.socketpair()
    server = {}
    thread = threading.Thread(
        target=lambda: server.update(tls=SSLContext(HTTP11).wrap_socket(b, server_side=True))
    )
    thread.start()
    client = client_context().wrap_socket(a, server_hostname="localhost")
    thread.join(5)
    return client, server["tls"]


def test_a_failed_send_leaves_the_socket_unusable():
    client, server = tls_pair()
    client.settimeout(0.3)
    with pytest.raises(TimeoutError):
        client.sendall(bytes(4 * 1024 * 1024))  # The server reads nothing.
    for call in (lambda: client.sendall(b"x"), lambda: client.send(b"x"), lambda: client.recv(1)):
        with pytest.raises(ssl.SSLError, match="unusable"):
            call()
    client.close()
    server.close()


def test_a_failed_send_in_the_handshake_leaves_the_socket_unusable():
    a, b = socket.socketpair()
    b.close()
    tls = client_context().wrap_socket(a, server_hostname="localhost", do_handshake_on_connect=False)
    with pytest.raises(BrokenPipeError):
        tls.do_handshake()
    for call in (tls.do_handshake, lambda: tls.send(b"x"), lambda: tls.sendall(b"x"), lambda: tls.recv(1)):
        with pytest.raises(ssl.SSLError, match="unusable"):
            call()
    tls.close()


def test_close_wakes_a_thread_blocked_in_sendall():
    client, server = tls_pair()
    failed = []

    def send():
        try:
            client.sendall(bytes(4 * 1024 * 1024))  # The server reads nothing.
        except OSError as exc:
            failed.append(exc)

    sender = threading.Thread(target=send, daemon=True)
    sender.start()
    time.sleep(0.2)
    closer = threading.Thread(target=client.close, daemon=True)
    closer.start()
    closer.join(2)
    sender.join(2)
    server.close()
    assert not closer.is_alive() and not sender.is_alive() and failed


# --------------------------------------------------------------------------- #
# The socket form and ALPN
# --------------------------------------------------------------------------- #


def test_the_socket_form_serves_connects_and_does_not_offer_h2():
    listener = socket.create_server(("127.0.0.1", 0))
    seen = {}

    def serve():
        conn, _ = listener.accept()
        conn.settimeout(5)
        # The default server config: h2 first, then http/1.1.
        with SSLContext(SERVER.server_config()).wrap_socket(conn, server_side=True) as tls:
            seen["alpn"] = tls.selected_alpn_protocol()
            tls.sendall(tls.recv(100))

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        context = client_context()
        context.set_alpn_protocols(["h2", "http/1.1"])
        sock = socket.create_connection(listener.getsockname(), timeout=5)
        with context.wrap_socket(sock, server_hostname="localhost") as tls:
            assert tls.selected_alpn_protocol() == "http/1.1"
            assert tls.version() == "TLSv1.3"
            assert tls.cipher() == ("TLS13_AES_256_GCM_SHA384", "TLSv1.3", 256)
            assert tls.getpeercert(binary_form=True) == SERVER.cert_chain()[0]
            assert tls.getpeercert() == {}
            tls.sendall(b"hello")
            assert tls.recv(100) == b"hello"
            assert tls.recv(100) == b"", "the server closed"
        tls.close()
    finally:
        thread.join(5)
        listener.close()
    assert seen == {"alpn": "http/1.1"}


# --------------------------------------------------------------------------- #
# What the context refuses
# --------------------------------------------------------------------------- #


def test_configuring_the_unused_openssl_context_is_refused():
    context = client_context()
    calls = [
        lambda: context.load_cert_chain("cert.pem"),
        lambda: context.load_verify_locations(cafile="ca.pem"),
        context.load_default_certs,
        context.set_default_verify_paths,
        lambda: context.set_ciphers("ALL"),
        lambda: context.set_ecdh_curve("prime256v1"),
        lambda: context.load_dh_params("dh.pem"),
        lambda: context.set_servername_callback(None),
    ]
    for call in calls:
        with pytest.raises(ValueError, match="does not take"):
            call()
    assignments = {
        "verify_mode": ssl.CERT_NONE,
        "check_hostname": False,
        "minimum_version": ssl.TLSVersion.TLSv1_3,
        "maximum_version": ssl.TLSVersion.TLSv1_3,
        "options": ssl.OP_ALL,
        "verify_flags": ssl.VERIFY_DEFAULT,
        "sni_callback": None,
        "post_handshake_auth": True,
        "keylog_filename": os.devnull,
        "num_tickets": 0,
    }
    for name, value in assignments.items():
        with pytest.raises(ValueError, match=f"does not take {name}"):
            setattr(context, name, value)
    # Reading keeps working, as libraries read some of these.
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.options == ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).options
    assert context


def test_each_context_keeps_its_side_and_a_server_its_alpn():
    client, server = client_context(), SSLContext(HTTP11)
    bios = ssl.MemoryBIO(), ssl.MemoryBIO()

    with pytest.raises(ValueError, match="server_config_with_alpn"):
        server.set_alpn_protocols(["h2"])
    with pytest.raises(ssl.SSLError) as e:
        client.wrap_bio(*bios, server_side=True)
    assert e.value.errno == ssl.SSL_ERROR_SSL
    with pytest.raises(ssl.SSLError):
        server.wrap_bio(*bios, server_side=False, server_hostname="localhost")
    with pytest.raises(ValueError, match="server_hostname"):
        client.wrap_bio(*bios)
    with pytest.raises(ValueError, match="session"):
        client.wrap_bio(*bios, server_hostname="localhost", session=object())
    with pytest.raises(TypeError):
        SSLContext(SERVER)

    with socket.socket() as sock:
        sock.setblocking(False)
        with pytest.raises(ValueError, match="non-blocking"):
            client.wrap_socket(sock, server_hostname="localhost")
        assert sock.fileno() >= 0, "a refused socket stays the caller's"


# --------------------------------------------------------------------------- #
# With the rest of nettls: Trust, enrollment, the transport policy, and Stream
# --------------------------------------------------------------------------- #


def test_trust_accepts_and_promotes_the_next_certificate_through_httpx():
    old, new = identity("server"), identity("server")
    resolver = nettls.RotatingResolver(old)
    trust = Trust.from_approval(Generation.from_der(old.cert_chain()[0]))
    context = SSLContext(trust.client_config())
    with serving(resolver.server_config_with_alpn([b"http/1.1"])) as url:
        assert httpx.get(url, verify=context).status_code == 200
        pem = nettls.pem.encode("CERTIFICATE", new.cert_chain()[0]).decode()
        announcement = nettls.announcement.Announcement.new(
            "server", None, (old.fingerprint_sha256(), old.anchor_pkcs8()), pem, int(time.time())
        )
        assert trust.receive(announcement, "server") == Received.Stored
        resolver.swap(new)
        # The same context: the config reads the trust state at every handshake.
        assert httpx.get(url, verify=context).status_code == 200
    state = trust.state()
    assert state.current().fingerprint() == new.fingerprint_sha256()
    assert state.previous().fingerprint() == old.fingerprint_sha256()


def test_trust_refuses_a_stranger_through_async_httpx():
    trust = Trust.from_approval(Generation.from_der(SERVER.cert_chain()[0]))

    async def get(url):
        async with httpx.AsyncClient(verify=SSLContext(trust.client_config())) as client:
            return (await client.get(url)).status_code

    with serving(HTTP11) as url:
        assert asyncio.run(get(url)) == 200
    with serving(identity("stranger").server_config_with_alpn([b"http/1.1"])) as url:
        with pytest.raises(httpx.ConnectError) as refused:
            asyncio.run(get(url))
    assert any(isinstance(e, UntrustedPeerError) for e in causes(refused.value))


def test_the_enrollment_config_reads_an_unknown_peers_certificate(site):
    context = SSLContext(nettls.unverified_client_config())
    assert httpx.get(f"{site}/", verify=context).status_code == 200
    port = int(site.rsplit(":", 1)[1])
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    with context.wrap_socket(sock, server_hostname="localhost") as tls:
        assert tls.getpeercert(binary_form=True) == SERVER.cert_chain()[0]


def test_the_aegis_transport_policy_holds_on_both_sides():
    policy = nettls.TransportPolicy.only(nettls.TransportCipher.Aegis256)
    aegis_client = SSLContext(
        nettls.pinned_client_config_with(PIN, [], policy, nettls.Expiry.Enforce)
    )
    with serving(SERVER.server_config_with([b"http/1.1"], policy)) as url:
        assert httpx.get(url, verify=aegis_client).status_code == 200
        port = int(url.rsplit(":", 1)[1])
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        with aegis_client.wrap_socket(sock, server_hostname="localhost") as tls:
            assert tls.cipher() == (f"{nettls.aegis.CODEPOINT:#06x}", "TLSv1.3", 256)
    # A server with the default policy has no suite in common with it.
    with serving(HTTP11) as url:
        with pytest.raises(httpx.ConnectError):
            httpx.get(url, verify=aegis_client)
        assert httpx.get(url, verify=client_context()).status_code == 200


def test_a_stream_client_reaches_a_server_on_the_context():
    async def go():
        async def upper(reader, writer):
            writer.write((await reader.readline()).upper())
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server, port = await start_server(upper, SERVER.server_config())

        def client():
            sock = socket.create_connection(("127.0.0.1", port), timeout=5)
            with Stream.connect(sock, nettls.pinned_client_config(PIN), "localhost") as tls:
                tls.write(b"hello\n")
                return tls.read()

        answer = await asyncio.to_thread(client)
        server.close()
        await server.wait_closed()
        return answer

    assert asyncio.run(go()) == b"HELLO\n"


def test_a_client_on_the_context_reaches_a_stream_server():
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]

    def serve():
        sock, _ = listener.accept()
        sock.settimeout(5)
        with Stream.accept(sock, SERVER.server_config()) as tls:
            tls.write(tls.read().upper())

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        with client_context().wrap_socket(sock, server_hostname="localhost") as tls:
            tls.sendall(b"hello")
            assert tls.recv(100) == b"HELLO"
    finally:
        thread.join(5)
        listener.close()
