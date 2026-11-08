# How to use nettls from Python

**In short:** `nettls-py` is nettls in Python *(0.11.0)*. It has the same modules, functions, types
and constants as the Rust crate, with the same names, and the same Rust code runs inside it — the
TLS too, which is rustls. There is one implementation, not two.

This page shows the Python code. The *why* behind each step is the same in both languages and
lives in **[Using nettls](Usage.md)**, the Rust guide; each section here links to its counterpart
there. **[API](API.md)** is the reference for both, and its section on
[what differs](API.md#what-is-guaranteed-and-where-python-differs) says exactly what Python cannot
guarantee.

---

## Getting started

```sh
pip install nettls-py
```

It needs Python 3.11 or newer.

```python
import nettls_py as nettls
```

`install_crypto_provider()` is there as in Rust. nettls's own configs do not need it — they carry
their provider — but other rustls code in the same process does.

## Turn on HTTPS — [Usage: step 2](Usage.md#step-2--turn-on-https)

```python
params = nettls.SelfSignedParams.new("my service", ["localhost", "10.0.0.5"])
material = nettls.TlsMaterial.load(nettls.CertSource.auto("/tls", params))
print(material.origin(), material.fingerprint_sha256(), material.days_until_expiry())
```

Log `origin()` at startup, for the reason Usage gives. A stored identity that cannot be loaded is
an error, not a reason for a new one.

The connection is `nettls_py.stream`, the one part that exists only in Python: Rust consumers drive
rustls themselves, and Python has nothing that can. It takes a socket Python has accepted or
connected, and runs TLS over it with the config nettls gives:

```python
import socket
from nettls_py.stream import Stream

listener = socket.create_server(("0.0.0.0", 8443))
sock, _ = listener.accept()
sock.settimeout(30)
with Stream.accept(sock, material.server_config()) as tls:
    request = tls.read()
    tls.write(b"hello\n")
```

The stream takes the socket over, completes the handshake before it returns, keeps the socket's
timeout, and waits without holding the GIL — so serve each connection from its own thread. It
does one thing at a time: a read that waits holds the stream, so another thread's write waits for
it. Keep each connection in one thread.

With ALPN, the configs that take it (`server_config_with_alpn`, `pinned_client_config_with_alpn`,
`Trust.client_config_with_alpn`) offer it, and `tls.alpn_protocol()` says what was agreed.

## The client side — [Usage: step 3](Usage.md#step-3--the-client-side)

```python
config = nettls.pinned_client_config(fingerprint)
sock = socket.create_connection(("10.0.0.5", 8443), timeout=30)
with Stream.connect(sock, config, "localhost") as tls:
    tls.write(b"hello\n")
    print(tls.read(), tls.peer_fingerprint())
```

The fingerprint is the identity; the name is only what is sent. A refused certificate fails the
handshake with an `OSError` subclass from `nettls_py.stream`, as Python's own `ssl` has
`SSLCertVerificationError`: `UntrustedPeerError` for a certificate the config does not trust,
`CertificateExpiredError` and `CertificateNotYetValidError` for one outside its dates, with `now`
and `not_after` or `not_before` in Unix seconds. A timeout is a `TimeoutError`.

```python
from nettls_py.stream import CertificateExpiredError, UntrustedPeerError

try:
    tls = Stream.connect(sock, config, "localhost")
except UntrustedPeerError:
    ...                      # not who we trust — treat as a possible attack
except CertificateExpiredError as e:
    ...                      # trusted, but expired at e.not_after — someone must renew it
```

An expired certificate can be accepted on purpose:
`nettls.pinned_client_config_with(fp, [], policy, nettls.Expiry.Ignore)`, and the same last
argument on `Trust.client_config_with`.

## Enrollment: looking before trusting — [API: the enrollment rule](API.md#the-enrollment-rule--trust-over-an-unverified-connection-contract)

Before a peer is approved there is nothing to pin, and its certificate has to be fetched over a
connection nobody has verified. `unverified_client_config()` is the client for that *(0.11.0)*: it
accepts any certificate, whatever its dates, but the server must prove it holds the key, so a
copied certificate does not get through.

```python
from nettls_py.generations import Generation, Trust

sock = socket.create_connection((host, port), timeout=30)
with Stream.connect(sock, nettls.unverified_client_config(), "localhost") as tls:
    der = tls.peer_certificate()
print(nettls.cert_fingerprint_sha256(der))   # compare with the peer's own startup log

# Once the operator has approved that fingerprint:
trust = Trust.from_approval(Generation.from_der(der))
```

That connection is for looking, never for transferring: no secrets, no changes, nothing that
carries data. The contract in API.md says exactly what is allowed.

## Mode 2: rotation — [Usage: step 5](Usage.md#step-5--if-you-chose-mode-2)

**The side that trusts** keeps a `Trust` per peer. Its client config accepts `current` and `next`,
and promotes `next` by itself once a handshake proves the key (§6.7):

```python
from nettls_py.generations import Generation, Trust

trust = Trust.from_approval(Generation.from_pem(approved_cert_pem))   # generation 0
trust.receive(announcement)            # the peer's announcement, verified, stored as `next`
with Stream.connect(sock, trust.client_config(), "localhost") as tls:
    ...
state = trust.state()                  # previous, current and next, to store and restore
```

**The side that rotates** binds a `RotatingResolver` once and lets the `Announcer` drive it. The
announcer keeps its own keys on disk, locked with the password, and picks up where it was after a
restart:

```python
from nettls_py import announcer as an

anchor = nettls.TlsMaterial.load(nettls.CertSource.auto("/tls", an.mode2_params("gw", ["gw"])))
resolver = nettls.RotatingResolver(anchor)
server_config = resolver.server_config()          # bind once; it follows the swaps

announcer = an.Announcer.new(
    "gw", "/tls/rotation", an.mode2_params("gw", ["gw"]), resolver,
    an.OwnMaterial(None, (anchor.fingerprint_sha256(), anchor.anchor_pkcs8())),
    an.Schedule(["peer"], 0), password,
)

announcement = announcer.prepare(now)             # make, store, announce
announcer.acked("peer")                           # a receipt came in, and it verified
old = announcer.roll_if_ready(now)                # switches only when everyone has acked
```

The rhythm is yours, as in Rust: nothing happens unless you call it. A receipt is verified against
the peer's pinned Ed25519 key, which comes from krypto, as in Rust — `krypto_py.sign` in Python.

## Errors

Every failure is an exception, one per `TlsError` variant, all under `nettls_py.TlsError`:

```python
try:
    nettls.TlsMaterial.load(nettls.CertSource.files("cert.pem", "key.pem"))
except nettls.KeyMismatchError as e:
    print("the key does not belong to the certificate:", e)
except nettls.TlsError as e:
    print("nettls:", e)
```

JSON that cannot be read is a `ValueError`, as `json.loads` gives. The messages travel as the JSON
serde writes in Rust: `announcement.to_json().dumps()` out, and
`Announcement.from_json(AnnouncementJson.loads(text))` in.

## Lock and envelope

```python
from nettls_py import envelope, lockbox

locked = lockbox.lock(password, b"what must be kept")
assert lockbox.unlock(password, locked) == b"what must be kept"

key, public = envelope.RecipientKey.generate()
sealed = envelope.seal(public, b"only the recipient may see")
assert envelope.open(key, sealed) == b"only the recipient may see"
```

What comes back is `bytes` Python holds, neither locked nor wiped; the keys stay in nettls's
locked memory. See [what differs](API.md#what-is-guaranteed-and-where-python-differs).

## The status report

```python
from nettls_py import status

report = status.Report.collect(now, material, None, [])
print(report.dumps())            # the same JSON as in Rust
```

---

## Further

- **[Using nettls](Usage.md)** — the order, the traps, and why
- **[API](API.md)** — the reference for both languages, and what Python cannot guarantee
- **[Home](Home.md)** — what nettls is, and what it is not
