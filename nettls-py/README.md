# nettls-py

The Python module of [nettls](https://github.com/rjorgensen123/nettls): self-signed certificates
with SANs, SHA-256 fingerprint pinning, and certificate rotation with two-signature continuity.
It is the same API as the Rust crate `nettls`, with the same names, and the same Rust code runs
inside it — the TLS too, which is rustls, not OpenSSL.

```sh
pip install nettls-py
```

It needs Python 3.11 or newer.

```python
import socket
import nettls_py as nettls

params = nettls.SelfSignedParams.new("my service", ["localhost", "127.0.0.1"])
material = nettls.TlsMaterial.load(nettls.CertSource.auto("/tls", params))
fingerprint = material.fingerprint_sha256()

# The server side: the stream takes the accepted socket over.
listener = socket.create_server(("127.0.0.1", 8443))
sock, _ = listener.accept()
with nettls.stream.Stream.accept(sock, material.server_config()) as tls:
    tls.write(b"hello\n")

# The client side, pinned to exactly that certificate.
sock = socket.create_connection(("127.0.0.1", 8443), timeout=10)
config = nettls.pinned_client_config(fingerprint)
with nettls.stream.Stream.connect(sock, config, "localhost") as tls:
    print(tls.read())
```

Errors are exceptions, one per kind, all under `nettls_py.TlsError`. Socket and TLS failures in
`nettls_py.stream` are `OSError`, as Python's own `ssl` gives them.

The private keys live in nettls's locked memory, kept out of core dumps and wiped when dropped.
What Python itself holds — the `bytes` and `str` you pass in, and the copies handed out — is
ordinary Python memory, neither locked nor wiped.

- **[How to use it](https://github.com/rjorgensen123/nettls/blob/main/docs/Python.md)**, with
  examples
- **[The API](https://github.com/rjorgensen123/nettls/blob/main/docs/API.md)**, one for Rust and
  Python, and what Python cannot guarantee
- **[Changes](https://github.com/rjorgensen123/nettls/blob/main/CHANGELOG.md)**
