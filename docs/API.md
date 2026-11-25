# API — the contract

Every public type and function in `nettls`, grouped by module — precise enough to reimplement
the crate from. To get started, or to understand the order things are done in, read
**[Usage](Usage.md)** first. What the crate is and is not, is in **[Home](Home.md)**.

**The authoritative source is `src/` + `CHANGELOG.md`; on divergence the code wins.** The
version (the `VERSION: &str` constant, derived from `Cargo.toml`; in Python also
`nettls_py.__version__`, the same value) is the anchor for the active feature set — the mapping
version → capabilities lives in `CHANGELOG.md`. Every public name must appear in this file
(enforced by a doc-guard test).

Everything returns `Result<_, TlsError>` where something can fail. The crate does not panic on
input.

Some signatures name types from the `krypto` crate: `krypto::SecretBuf`, `krypto::SecretString`
and `krypto::Alg`. They are the types of krypto 0.9 *(0.12.0)*, so a caller that names them
depends on `krypto = "0.9"` itself.

Two normative rules bind whoever *changes* the surface:

- **Verify input and output.** All input is validated (type, length, range, character set —
  fail-closed; unknown values are rejected, never silently skipped), and output never carries
  key material. An uncovered case → update this document.
- **The feedback contract.** What the crate answers — success, errors and status — lives HERE:
  `Result` with [`TlsError`](#error--tlserror) (never empty error messages — every variant
  carries enough context for the operator to see WHAT is wrong), plus the announcer's
  [`Status`](#status--for-alerting) for alerting. No error path carries key material. An answer
  not written here is a gap in the contract and should be reported — not interpreted.

## The wire format — all-English, FROZEN

The wire went English in 0.7.0 while it was still free (no service spoke the
§6 wire yet); the signed canonical bytes were unchanged. **The table below is frozen — changing
it is breaking regardless of semver:**

| What | Value |
|---|---|
| Canonical prefixes | `nettls-approve/v1` · `nettls-rotate/v2` · `nettls-rotate-ack/v2` · `nettls-pairsecret/v1` · `nettls-algsupport/v1` *(additive, 0.8.2)* · `nettls-rotate-handled/v1` *(additive, 0.12.0)* |
| Canonical form | UTF-8, LF between lines, **no** trailing LF; `prev` serializes as `-` when absent |
| JSON field names | all English: `approved_by`, `timestamp`, `mode`, `announcement`, …; a key the type does not know is refused when the JSON is read *(0.12.0)* |
| Mode values | `"pinning"` and `"rolling"` |
| File names on disk | `cert.pem` · `key.pem` · `pending-rotation.json` · `announcements.jsonl` · `material.locked` (the material, locked with the password) · `previous-key.locked`, or `previous-key.json` without a password (the previous key) · `new/` (the next identity, before the switch) |
| Blob magics | `NETTLS\x01\x00` (lockbox) · `NETENV\x01\x00` (envelope) · FAFN (krypto) |
| KDF labels | `nettls/local-state/v1` (lockbox) · `nettls/envelope/v1` (envelope); the `key_id` in the FAFN header beside them is `nettls-local-st1` (lockbox) · `nettls-envelope1` (envelope), not part of the derivation |
| Test vectors | `testvectors/canonical.json` + `errors.json` — `canonical_hex` values byte-identical since 0.6 |

---

## Root — what you meet first

```rust
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub fn install_crypto_provider() -> bool;   // idempotent; true if THIS call installed it
pub fn provider() -> Arc<rustls::crypto::CryptoProvider>;
```

Re-exported from the root: `TlsMaterial`, `CertSource`, `SelfSignedParams`, `CertOrigin`,
`is_valid_san`, `CERT_FILE`, `KEY_FILE`, `MAX_VALID_DAYS`, `RotatingResolver`, `TlsError`,
`pinned_client_config`, `pinned_client_config_with_alpn`, `pinned_client_config_with`,
`cert_fingerprint_sha256`, `TransportCipher`, `TransportPolicy` *(0.8.3)*, `Expiry`,
`unverified_client_config`, `unverified_client_config_with` *(0.11.0)*.

`pub use rustls` — so you do not have to list rustls as a dependency just for the types (and
risk a line of your own with the wrong features).

The test helpers `pkcs8_for_test`, `pem_encode_for_test` and `fingerprint_for_test` are gone
*(0.11.0)*; they were made for the cross-test against the Python twin. Use
`TlsMaterial::anchor_pkcs8()`, `pem::encode` and `cert_fingerprint_sha256`.

**`pem` — building PEM** *(public since 0.8.1)*:

```rust
pub fn encode(label: &str, der: &[u8]) -> Result<Vec<u8>, TlsError>;   // RFC 7468, 64-char lines
```

PEM is TLS domain, so building it lives here. The base64 body is `krypto::base64` (canonical);
the intermediate is zeroized — the DER may be a private key. The returned buffer is the caller's
to protect; `save_pem` holds a key's PEM in a `SecretBuf` until it is on disk (0.8.3). Reading PEM goes through
`rustls-pki-types`' built-in `pem` module (0.8.1 — `rustls-pemfile` is out; it was flagged
unmaintained).

`encode` fails with `TlsError::Encode` when the DER is over krypto's size limit, or the memory for
the base64 or the PEM text could not be reserved *(0.12.0)*.

**Traits of the public types:**

| Traits | Types |
|---|---|
| `Debug`, `Clone`, `Copy`, `PartialEq`, `Eq` | `CertOrigin`, `Received`, `Rejection`, `Drift`; `Expiry` with `Default`; `TransportCipher` with `Hash`; `Level`, `PeerState` with `Serialize`; `Mode` with `Serialize`, `Deserialize` and `Display` (`pinning`, `rolling`) |
| `Debug`, `Clone`, `PartialEq`, `Eq` | `Generations`, `TransportPolicy` (with `Default`), `Announcement`, `Receipt`, `Handled`, `Approval`, `Recognition`, `ChainState`, `Status`, `ModeCheck`, `Deviation`, `FallToMode1`, `OwnTrio` |
| `Debug`, `Clone`, `Serialize`, `Deserialize` | `AnnouncementJson`, `ReceiptJson`, `HandledJson`, `ApprovalJson`, `IdentityJson`, `SupportStatement` |
| `Debug`, `Clone`, `Serialize` | `PeerReport`, `IdentityReport`, `RotationReport`, `Report`, `Summary` |
| `Debug`, `Clone` | `SelfSignedParams` (with `Default`), `Schedule`, `ClockDrift` (with `Default`), `RotatingResolver` (a clone shares the state) |
| `Clone`, `PartialEq`, `Eq`; `Debug` shows the first 16 hex digits of the fingerprint | `Generation` |
| `Clone` (a clone shares the state), `Debug` | `Trust` |
| `Clone` (a clone of a `pem` source copies the key PEM), `Debug` with the key redacted | `CertSource` |
| `Debug` with the key redacted | `TlsMaterial`, `RecipientKey`, `Pending` |
| `Debug`, `Display`, `std::error::Error`; no `From` conversions | `TlsError` |
| none | `OwnMaterial`, `Announcer`, `Context` |

---

## `material` — the certificate

| | |
|---|---|
| `CERT_FILE: &str` · `KEY_FILE: &str` | the file names `auto`/`save_pem` use (`cert.pem`, `key.pem`) |
| `MAX_VALID_DAYS: u32` | 397 — browsers reject lifetimes longer than 398 days; 397 leaves a margin |
| `is_valid_san(name: &str) -> bool` | is this a valid SAN? (syntax only, never DNS lookups), by the SAN rules under `SelfSignedParams`. A wildcard is accepted only as the whole first label with at least two labels after it, as in `*.example.no`; `*` and `*.no` are refused *(0.12.0)* |

### `CertOrigin`

Where the certificate came from. **Log this.**

`Files` · `Pem` · `Generated` · `Reused` · `ReusedExpired` · `Ephemeral` — `#[non_exhaustive]`

> `Ephemeral` means `save_pem` failed, for any reason, for the identity `auto` generated. When
> the certificate was not put in place, the next start generates another → a new fingerprint →
> everyone who pinned you loses you. When it was, the pair is settled and reused at the next
> start. `ReusedExpired` means an expired certificate was kept
> deliberately — regeneration must be an operator action, or every pinned pairing breaks
> silently. Both deserve loud log lines.
>
> `auto` makes a new identity only when the directory holds none. A stored one it cannot load is
> returned as an error, and the files are left untouched *(0.10.0)*. A `Pem`, `KeyMismatch`,
> `Certificate` or `Io` error names the directory; `Params`, `LockedMemory` and `Encode`
> are returned as they are, without it.
> What an interrupted save left in the directory is settled first, as described under
> `TlsMaterial` below *(0.12.0)*.

### `SelfSignedParams`

```rust
pub struct SelfSignedParams { pub common_name: String, pub sans: Vec<String>, pub valid_days: u32 }

impl SelfSignedParams {
    pub fn new(common_name: impl Into<String>, sans: impl IntoIterator<Item = impl Into<String>>) -> Self;
    pub fn valid_days(self, days: u32) -> Self;
}
```
`Default` is CN `"nettls self-signed"`, SANs `localhost` and `127.0.0.1`, 365 days; `new` also
sets 365 days. Strings that parse as IP addresses become IP SANs, the rest DNS SANs.

The parameters are checked when a certificate is generated (`self_signed`, `auto` when it
generates, `Announcer::prepare`); a stored pair that loads is reused without them being checked.
Each failure is `Params`: the SAN list is empty; `valid_days` is outside 1 to 397; the common name
is empty or only whitespace, longer than 64 characters, or has a control character. A SAN that
parses as an IP address is taken as it is. A DNS name is at most 253 bytes, a trailing dot
counted, may end in one dot, has no empty part, and each part is at most 63 bytes of ASCII letters
(either case), digits and hyphens, with no hyphen first or last; the wildcard rule is under
`is_valid_san`. A failure inside rcgen is `Generate`.

### `CertSource`

```rust
impl CertSource {
    pub fn files(cert_path: impl Into<PathBuf>, key_path: impl Into<PathBuf>) -> Self;
    pub fn pem(cert_pem: impl Into<Vec<u8>>, key_pem: impl Into<Vec<u8>>) -> Self;
    pub fn self_signed(params: SelfSignedParams) -> Self;
    pub fn auto(dir: impl Into<PathBuf>, params: SelfSignedParams) -> Self;
}
```
`Debug` is redacted — it never reveals key material.

`files` and `pem` need at least one CERTIFICATE block, the first being the leaf the key is checked
against, and a PRIVATE KEY, RSA PRIVATE KEY or EC PRIVATE KEY block; a missing or unreadable
block is `Pem` at `load`. A key that does not belong to the leaf, or that the provider does not
take, is `KeyMismatch`.

### `TlsMaterial`

```rust
impl TlsMaterial {
    pub fn load(src: &CertSource) -> Result<Self, TlsError>;

    // facts
    pub fn fingerprint_sha256(&self) -> String;      // hex of the SHA-256 of the leaf DER — what clients pin
    pub fn not_after(&self) -> Option<i64>;          // unix
    pub fn not_before(&self) -> Option<i64>;
    pub fn days_until_expiry(&self) -> i64;          // negative when expired
    pub fn is_valid_now(&self) -> bool;
    pub fn sans(&self) -> &[String];
    pub fn subject(&self) -> &str;
    pub fn origin(&self) -> CertOrigin;
    pub fn cert_chain(&self) -> &[CertificateDer<'static>];

    // use
    pub fn certified_key(&self) -> Result<Arc<rustls::sign::CertifiedKey>, TlsError>;
    pub fn server_config(&self) -> Result<Arc<ServerConfig>, TlsError>;   // TLS 1.3+1.2, ALPN h2+http/1.1
    pub fn server_config_with_alpn(&self, alpn: &[Vec<u8>]) -> Result<Arc<ServerConfig>, TlsError>;
    pub fn server_config_with(&self, alpn: &[Vec<u8>], transport: &TransportPolicy)
        -> Result<Arc<ServerConfig>, TlsError>;                           // 0.8.3 — see `transport`
    pub fn save_pem(&self, dir: &Path) -> Result<(), TlsError>;           // atomic; cert.pem 0644, key.pem 0600; both staged first (0.12.0)
    pub fn anchor_pkcs8(&self) -> Result<krypto::SecretBuf, TlsError>;    // 0.8.1 — see below
}
```

`load` refuses a leaf certificate whose SAN extension cannot be read, or that has a control
character in its subject or in a name in its SAN list, with `TlsError::Certificate` *(0.12.0)*.
Only control characters are refused; the stricter rules for names nettls generates itself do not
apply to a certificate that is loaded.

**Saving the pair** *(0.12.0)*. `save_pem` writes both files to temp files beside them,
`cert.tmp` and `key.tmp`, and syncs the directory, before either is put in place; then it renames the certificate and
syncs the directory, then renames the key and syncs the directory again, so the certificate's
rename is on disk before the key's is made. A failure before the first rename leaves the stored
pair as it was. If the sync after the first rename or the key's rename fails, the new certificate
is in place, its key is left in `key.tmp`, and the error says so. If only the last sync fails,
the error says that the files are in place. What an interrupted save left is settled before
every save, and before `auto`, or an `Announcer` without a password, loads the pair: `cert.tmp`,
with or without `key.tmp`, means nothing was put in place, and both are removed; `key.tmp` alone
is put in place when it belongs to the certificate in place, by the same check `load` makes, and
removed when it does not. A temp file that is a symbolic link is removed and never read; one that
is not a regular file, or cannot be read or removed, is an error that names it. `save_pem` creates
`dir` and any missing parent with mode 0700; an existing directory keeps its mode. A private key
form it cannot write as PEM is `Pem`.

**`anchor_pkcs8` (0.8.1)** is the ONE documented place the key crosses from the TLS domain into
the §6 domain: it feeds `Announcer::new`'s anchor, so announcements are signed with the same
identity the server serves. It is not a general key export — the output is PKCS#8 for the anchor
construction, nothing else. **Since 0.8.3 it is a `krypto::SecretBuf`** (was `Vec<u8>`): locked
memory, wiped on drop, `[REDACTED]` in `Debug`, readable only through `expose`. A PKCS#8 key is
passed through as it is, whatever its algorithm. A SEC1 key (EC PRIVATE KEY) is built into PKCS#8
with the public point from the certificate: a certificate whose key is not an uncompressed P-256
point is `ProofInvalid`, and a SEC1 key not in the strict P-256 form is `Sign`. Any other key, an
RSA PRIVATE KEY, is `Sign`.

**Private keys in memory (0.8.3).** Every key the crate *holds* — the generation triple in
`OwnMaterial`/`Pending`, the anchor above, PEM read from or written to disk — is a `SecretBuf`.
Short-lived buffers that cannot be (the key PEM handed in via `CertSource::pem`, the base64 inside
`pem::encode`, a leftover `key.tmp` as it is read back) are `zeroize::Zeroizing` — guaranteed
wipe, no lock. What nettls does not wipe:

- The previous key as it is written to JSON and read back from it, with or without a password.
  It is held in an ordinary `Vec<u8>` that is wiped on drop, but the JSON buffer grows as it is
  written and the key vector grows as it is read, and the buffers they outgrow are freed without
  being wiped.
- Without a password, the cleartext JSON written to `previous-key.json`, and that file as it is
  read back: ordinary buffers.
- The copies of the key `TlsMaterial` hands to rustls (`clone_key()`); rustls' ring provider
  loads them under `Zeroizing`.
- The base64 buffer inside the PEM reader of `rustls-pki-types`.

**The honest limit:** `TlsMaterial` keeps the
key as rustls' `PrivateKeyDer` (wrapped in `Zeroizing`, ordinary heap), and rustls/ring hold
their own parsed copy for as long as a `ServerConfig` lives; rcgen holds the fresh key pair
during generation. Neither can be locked from here. `SecretBuf::from_vec` failing (`mlock`,
`RLIMIT_MEMLOCK`, or *(0.12.0)* content over krypto's size limit, `krypto::MAX_DATA_BYTES`) is a
hard error — never a silent fallback to ordinary memory.

---

### `cert_fingerprint_sha256`

```rust
pub fn cert_fingerprint_sha256(cert_der: &[u8]) -> Result<String, TlsError>;
```

The SHA-256 fingerprint of a certificate in DER — the same value as
`TlsMaterial::fingerprint_sha256`, but for a certificate you have merely **seen**. The way into
"observing is not trusting": connect unverified only to *read* the peer's identity and show it
to the operator (the certificate is sent in cleartext in every handshake anyway). *(Lived in the
retired `rotation` module before 0.8.2.)*

It fails with `TlsError::Encode` when the fingerprint cannot be encoded as hex *(0.12.0)*. It
hashes the bytes it is given and does not check that they are a certificate.

Every fingerprint nettls gives out (`TlsMaterial::fingerprint_sha256`, `Generation::fingerprint`,
`cert_fingerprint_sha256`) is 64 lowercase hex characters, with no prefix and no separators. Where
a fingerprint comes in as text to compare (`Generations::observed`, the `expected_new_fp` of
`Receipt::verify` and `Handled::verify`), the text is compared exactly, so another form of the same
fingerprint never matches.

## `provider` · `pin` · `resolver`

```rust
// provider
pub fn provider() -> Arc<CryptoProvider>;
pub fn install_crypto_provider() -> bool;

// pin — static pinning; against a ROTATING peer, use generations::Trust instead
pub fn pinned_client_config(fingerprint_sha256: &str) -> Result<Arc<ClientConfig>, TlsError>;
pub fn pinned_client_config_with_alpn(fingerprint_sha256: &str, alpn: &[Vec<u8>]) -> Result<Arc<ClientConfig>, TlsError>;
pub fn pinned_client_config_with(fingerprint_sha256: &str, alpn: &[Vec<u8>], transport: &TransportPolicy,
                                 expiry: Expiry) -> Result<Arc<ClientConfig>, TlsError>;   // 0.8.3, expiry 0.11.0

pub enum Expiry { Enforce, Ignore }                                          // 0.11.0; Default = Enforce
pub enum Rejection { Untrusted, Expired { now: i64, not_after: i64 },
                     NotYetValid { now: i64, not_before: i64 }, Other }      // 0.11.0
pub fn classify(err: &(dyn std::error::Error + 'static)) -> Rejection;      // 0.11.0

// enrollment only — see the enrollment rule (0.11.0)
pub fn unverified_client_config() -> Result<Arc<ClientConfig>, TlsError>;
pub fn unverified_client_config_with(alpn: &[Vec<u8>], transport: &TransportPolicy)
    -> Result<Arc<ClientConfig>, TlsError>;
```

**Enrollment** *(0.11.0)*. `unverified_client_config` accepts any server certificate, whatever its
dates, so a peer nobody has approved yet can be looked at. The handshake signature is still
verified in full: the server must hold the key for the certificate it shows. Read the certificate
from the connection (`peer_certificates()`) and approve its fingerprint out of band; the
connection itself is for looking only — [the enrollment rule](#the-enrollment-rule--trust-over-an-unverified-connection-contract).

**Dates** *(0.11.0)*. The client checks the identity first, then the certificate's dates against
the handshake's time. One that is expired or not yet valid is refused with rustls' own
`CertificateError::ExpiredContext` or `NotValidYetContext`, which carry the dates; an unknown
certificate is refused as untrusted whatever its dates. The short forms always check;
`Expiry::Ignore` in the `_with` forms turns the date check off, as an explicit choice. The same
holds for `Trust`. `classify` takes the error a connection returned — a `rustls::Error`, the
`io::Error` tokio-rustls gives, or any error with one in its `source()` chain — and says whether it
was untrusted, expired or not yet valid, with the dates in Unix seconds. The server side does not
check its own dates: it serves what it has, and the status report warns.

**The pin.** `fingerprint_sha256` is 64 hex digits, either case. Whitespace around it is trimmed,
one prefix `sha256:`, `SHA256:` or `sha256-` is dropped, and colons, spaces, hyphens, tabs and line
breaks between the digits are skipped; any other character, or another number of digits, is
`TlsError::Fingerprint`.

**What is checked.** The pinned and `Trust` verifiers ignore the server name and any intermediate
certificates: the identity is the SHA-256 of the leaf alone. `RotatingResolver` ignores SNI. A poisoned lock
during a handshake makes `Trust` refuse the certificate as untrusted, and the resolver offer no
certificate. The client configs without an `alpn` argument (`pinned_client_config`,
`unverified_client_config`, `Trust::client_config`) set no ALPN, and an empty `alpn` list turns
ALPN off in every config builder that takes one.

### `transport` — the channel's cipher is the consumer's choice *(new in 0.8.3)*

The same principle as the at-rest cipher menu — the crate offers, the consumer chooses —
applied to the TLS channel itself. Every config builder has a `*_with`
variant taking a `TransportPolicy`; the builders without one use `TransportPolicy::default()`.

```rust
#[non_exhaustive]
pub enum TransportCipher { Aes256Gcm, ChaCha20Poly1305, Aegis256 }   // wire names: TLS has ChaCha20, not XChaCha20
impl TransportCipher { pub fn token(self) -> &'static str; }   // "aes256gcm" · "chacha20poly1305" · "aegis256"

pub struct TransportPolicy { .. }                             // Default = AES-256-GCM only
impl TransportPolicy {
    pub fn only(cipher: TransportCipher) -> Self;
    pub fn new(ciphers: &[TransportCipher]) -> Result<Self, TlsError>;   // consumer's order; empty/repeated → Params
    pub fn ciphers(&self) -> &[TransportCipher];
}
```

- **Default: AES-256-GCM only** (decided 2026-09-04) — the one AEAD every party in the
  party speaks: rustls, OpenSSL, every browser since 2014. Up to 0.8.2 the configs
  offered ring's full list (nine suites, AES-128 included); that list is gone.
- **The consumer's list, in the consumer's order.** rustls picks the first suite in *our* list
  the peer also offers; the server's list decides. Nothing outside the list is ever used.
- **No common suite → hard handshake failure** (`NoCipherSuitesInCommon` server-side, an alert
  client-side). No fallback, no renegotiation on the peer's word. Widening a server policy
  never breaks a default client: keep `Aes256Gcm` in the list.
- One choice covers **both protocol versions** — the TLS 1.3 suite and the TLS 1.2 ECDHE pair
  with the same AEAD — so keeping TLS 1.2 for older browsers does not reopen a weaker AEAD.
- AEGIS-256 in the transport is the third choice, built as a deliberate deviation — see
  `aegis` below. The process-global provider (`install_crypto_provider`, for *other*
  libraries in the process) is ring's full default and is not touched by a policy.

### `aegis` — AEGIS-256 in the channel: a deliberate deviation, built to be replaced *(0.8.3)*

```rust
pub const CODEPOINT: u16 = 0xFF06;        // TLS private use — NOT the IANA TLS_AEGIS_256_SHA512 (0x1306)
pub fn suite() -> SupportedCipherSuite;   // what TransportCipher::Aegis256 puts in the list
```

Offered only when a consumer lists `TransportCipher::Aegis256`; **never the default**. Two nettls
ends speak it, from Rust or from Python (`nettls-py`, 0.11.0); a foreign peer (OpenSSL, a browser)
skips it as an unknown suite — the fallback rule realised by TLS itself: list `[Aegis256, Aes256Gcm]`
and a nettls peer lands on AEGIS, everyone else on AES-256-GCM, with no negotiation code of ours.

**Why it deviates (decided 2026-09-04):** rustls 0.23 gives every TLS 1.3 AEAD a fixed 12-byte
IV (`NONCE_LEN`), its development line allows at most 16 (`Iv::MAX_LEN`), and AEGIS-256 needs
32; rustls issue #3428 (opened 2026-11-13) asks for 32 and had no maintainer answer on
2026-11-16. So this suite, written down as what it is:

| Deviation | What we do |
|---|---|
| nonce | rustls' 12-byte TLS 1.3 nonce (`iv XOR seq`), left-aligned, zero-padded to 32 — unique per key because the TLS nonce is |
| code point | `0xFF06` (private use), echoing `0x1306` — a non-standard suite does not squat on the IANA point |
| hash pairing | SHA-384 HKDF, reusing ring's `TLS13_AES_256_GCM_SHA384` providers; the standard pairs SHA-512, but ring's hash types are private to rustls and we add no primitive glue |

The AEAD is the `aegis` crate (the primitive krypto uses at rest, vector-verified), 256-bit key,
128-bit tag, record AAD exactly as rustls computes it. TLS 1.3 only. Nothing cryptographic is
implemented here — the file is the seam between rustls' record layer and the primitive.

**The exit:** when rustls ships AEGIS suites or a 32-byte IV, `aegis.rs` is *replaced* — drop the
padding and the private point, use `0x1306` with SHA-512 — and `TransportCipher::Aegis256` stays
as the consumer's name. The unit test `the_deviation_still_has_its_reason` fails once rustls'
TLS 1.3 IV is no longer a fixed 12-byte array (`NONCE_LEN` or the size of `Iv` changes), so the
exit is announced by the build.

### `RotatingResolver` — change certificates without a restart

```rust
impl RotatingResolver {
    pub fn new(material: &TlsMaterial) -> Result<Self, TlsError>;
    pub fn swap(&self, material: &TlsMaterial) -> Result<String, TlsError>;  // → the old fingerprint
    pub fn fingerprint_sha256(&self) -> Result<String, TlsError>;            // what is served NOW
        // a poisoned lock is `LockPoisoned` (0.12.0)
    pub fn server_config(&self) -> Result<Arc<ServerConfig>, TlsError>;
    pub fn server_config_with_alpn(&self, alpn: &[Vec<u8>]) -> Result<Arc<ServerConfig>, TlsError>;
    pub fn server_config_with(&self, alpn: &[Vec<u8>], transport: &TransportPolicy)
        -> Result<Arc<ServerConfig>, TlsError>;                           // 0.8.3 — see `transport`
}
```
Implements `ResolvesServerCert`. **Build the config once** — it is live, and `swap` takes effect
on it. `Clone` shares state. `swap` validates before switching: a rejected certificate
(`KeyMismatch`) never replaces one that works.

---

## `generations` — which certificates apply

```rust
pub struct Generation { .. }
impl Generation {
    pub fn from_der(der: impl Into<Vec<u8>>) -> Result<Self, TlsError>;
    pub fn from_pem(pem: &str) -> Result<Self, TlsError>;
    pub fn der(&self) -> &[u8];
    pub fn fingerprint(&self) -> &str;
}

pub enum Received { Stored, Known }   // Known = idempotent re-receipt, not an error
```

A `Generation` is always exactly one X.509 certificate, of any key type: `from_der`, and `from_pem`
after reading the one CERTIFICATE block, refuse anything else, bytes left over after the
certificate included, with `TlsError::Certificate` *(0.12.0)*. `from_pem` refuses PEM that has
not exactly one CERTIFICATE block with `Pem`.

`Generation::from_der` fails with `TlsError::Encode` when the fingerprint cannot be encoded as hex
*(0.12.0)*.

### `Generations` — the state for ONE peer

```rust
impl Generations {
    pub fn from_approval(current: Generation) -> Self;
    pub fn restore(previous: Option<Generation>, current: Generation, next: Option<Generation>)
        -> Result<Self, TlsError>;   // your own storage back in; shape-checked, trust not verifiable (0.12.0)
    pub fn receive(&mut self, k: &Announcement, expected_announcer: &str)
        -> Result<Received, TlsError>;   // another announcer is refused, nothing stored (0.12.0)
    pub fn observed(&mut self, fp: &str) -> bool;                    // promotion ON OBSERVATION
    pub fn accepted_in_handshake(&self) -> Vec<&Generation>;         // current + next — NEVER previous
    pub fn for_signing(&self) -> (Option<&Generation>, &Generation); // (previous, current)
    pub fn current(&self) -> &Generation;
    pub fn previous(&self) -> Option<&Generation>;
    pub fn next(&self) -> Option<&Generation>;
    pub fn is_bootstrap(&self) -> bool;
}
```

The two roles do not overlap: `previous` verifies announcements but lets no one into a
handshake.

`restore` checks the shape only: `previous`, `current` and `next` must be pairwise different, else
`Params`.

`receive` takes the name of the peer the state belongs to, and passes it on to
`Announcement::verify`: an announcement from another announcer is refused, and nothing is stored
*(0.12.0)*.

`receive` verifies the announcement first, also when it names the certificate already stored as
`next`: `Stored` and `Known` are given only to an announcement that verifies, and one that does not
is an error *(0.12.0)*. The one who receives acknowledges every time. On `Stored` it sends the
[`Receipt`](#receipt--the-gate). On `Known` it has handled this announcement before: it sends the
`Receipt` first, unchanged, and then a [`Handled`](#handled--the-acknowledgement-once-more-0120)
*(0.12.0)*. `Trust::receive` verifies and answers the same way.

### `Trust` — the thread-safe wrapper, wired to TLS

```rust
impl Trust {
    pub fn from_approval(current: Generation) -> Self;
    pub fn from_state(g: Generations) -> Self;
    pub fn receive(&self, k: &Announcement, expected_announcer: &str)
        -> Result<Received, TlsError>;   // &self, not &mut; expected_announcer (0.12.0)
    pub fn state(&self) -> Result<Generations, TlsError>;                    // snapshot for storage
    pub fn client_config(&self) -> Result<Arc<ClientConfig>, TlsError>;      // LIVE — build once
    pub fn client_config_with_alpn(&self, alpn: &[Vec<u8>]) -> Result<Arc<ClientConfig>, TlsError>;
    pub fn client_config_with(&self, alpn: &[Vec<u8>], transport: &TransportPolicy, expiry: Expiry)
        -> Result<Arc<ClientConfig>, TlsError>;                           // 0.8.3, expiry 0.11.0
}
```

An expired or not yet valid certificate is refused as in `pin` *(0.11.0)*.

The verifier promotes `next` only after the handshake signature holds *(0.10.0)*.

---

## `announcement` — "here is my next certificate"

```rust
pub fn fingerprint_from_pem(pem: &str) -> Result<String, TlsError>;
pub fn der_from_pem(pem: &str) -> Result<Vec<u8>, TlsError>;   // exactly ONE CERTIFICATE block

pub const MAX_CERT_PEM_LEN: usize = 16 * 1024;      // DoS cap on incoming PEM
pub const ARCHIVE_FILE: &str = "announcements.jsonl";
pub fn archive(dir: &Path, k: &Announcement) -> Result<(), TlsError>;             // append-only audit
        // created 0600; one write per record (0.12.0); Proof if it cannot be serialized
pub fn read_archive(dir: &Path) -> Result<(Vec<Announcement>, usize), TlsError>;  // → (read, skipped)
        // form-checked only, nothing verified; a line that is not UTF-8 is skipped too (0.12.0)
        // no file → (empty, 0); a line of only ASCII whitespace is ignored and not counted
```

### `Announcement`

```rust
impl Announcement {
    pub fn new(
        announcer: &str,
        prev: Option<(&str, &krypto::SecretBuf)>,   // (fingerprint, PKCS#8) — None at the very first rotation
        curr: (&str, &krypto::SecretBuf),           // (fingerprint, PKCS#8) — SecretBuf since 0.8.3
        new_cert_pem: &str,
        sent_at: i64,
    ) -> Result<Self, TlsError>;

    pub fn canonical(&self) -> Result<Vec<u8>, TlsError>;
    pub fn verify(&self, expected_announcer: &str, prev_cert_der: Option<&[u8]>, curr_cert_der: &[u8])
        -> Result<(), TlsError>;   // expected_announcer (0.12.0)
    pub fn to_json(&self) -> Result<AnnouncementJson, TlsError>;
    pub fn from_json(j: &AnnouncementJson) -> Result<Self, TlsError>;   // fail-closed

    pub fn announcer(&self) -> &str;
    pub fn new_fingerprint(&self) -> &str;
    pub fn new_cert_pem(&self) -> &str;
    pub fn sent_at(&self) -> i64;
    pub fn is_bootstrap(&self) -> bool;
}
```

> If `prev` is available, both signatures **must** be made. An announcement that could have been
> double-signed but is not, is a weakened announcement.
>
> `verify` checks against the **receiver's own** state: a single signature is accepted only when
> the receiver has no previous — and (A8) a receiver holding **only an anchor** accepts a
> double-signed announcement whose `curr` matches the anchor: generation numbering is local to
> the receiver.

`verify` checks the announcer first: an announcement from another peer than `expected_announcer`
is refused before anything else *(0.12.0)*.

`verify` requires `new_cert_pem` to be an X.509 certificate with a P-256 key, right after the
fingerprint check and before the rest is checked: it is the key the next announcement is signed
with *(0.12.0)*.

`AnnouncementJson` (serialized form; the field names are contract): `v` · `announcer` ·
`prev_fingerprint` · `curr_fingerprint` · `new_fingerprint` · `new_cert_pem` · `sent_at` ·
`sig_prev` · `sig_curr`. `prev_fingerprint` and `sig_prev` are optional, and left out of the JSON
when absent.

`to_json` fails with `TlsError::Encode` when a signature cannot be encoded as hex *(0.12.0)*.

### `Receipt` — the gate

```rust
impl Receipt {
    pub fn new(acker: &str, announcer: &str, new_fp: &str, sent_at: i64, ed25519_seed: &krypto::SecretBuf)
        -> Result<Self, TlsError>;
    pub fn canonical(&self) -> Result<Vec<u8>, TlsError>;
    pub fn verify(&self, expected_acker: &str, pinned_pubkey: &[u8], expected_new_fp: &str)
        -> Result<(), TlsError>;   // expected_acker (0.12.0)
    pub fn to_json(&self) -> Result<ReceiptJson, TlsError>;
    pub fn from_json(j: &ReceiptJson) -> Result<Self, TlsError>;
    pub fn acker(&self) -> &str;
    pub fn announcer(&self) -> &str;   // (0.12.0)
    pub fn new_fingerprint(&self) -> &str;
    pub fn sent_at(&self) -> i64;
}
```

`ReceiptJson`: `v` · `acker` · `announcer` · `new_fingerprint` · `sent_at` · `sig`

`to_json` fails with `TlsError::Encode` when the signature cannot be encoded as hex *(0.12.0)*.

`verify` requires the expected acker, the pinned key and the expected fingerprint: a genuine
receipt from another peer is refused before anything else *(0.12.0)*, and a genuine receipt for a
*different* rotation is a replay and must not make you roll.

### `Handled` — the acknowledgement once more *(0.12.0)*

```rust
impl Handled {
    pub fn new(acker: &str, announcer: &str, new_fp: &str, sent_at: i64, ed25519_seed: &krypto::SecretBuf)
        -> Result<Self, TlsError>;
    pub fn canonical(&self) -> Result<Vec<u8>, TlsError>;
    pub fn verify(&self, expected_acker: &str, pinned_pubkey: &[u8], expected_new_fp: &str)
        -> Result<(), TlsError>;   // expected_acker (0.12.0)
    pub fn to_json(&self) -> Result<HandledJson, TlsError>;
    pub fn from_json(j: &HandledJson) -> Result<Self, TlsError>;
    pub fn acker(&self) -> &str;
    pub fn announcer(&self) -> &str;   // (0.12.0)
    pub fn new_fingerprint(&self) -> &str;
    pub fn sent_at(&self) -> i64;
}
```

`HandledJson`: `v` · `acker` · `announcer` · `new_fingerprint` · `sent_at` · `sig`

"This I have handled; here is the acknowledgement once more." The one who receives an announcement
and gets `Received::Known` sends the `Receipt` first, unchanged, and then this. It carries the
receipt's fields under its own first line, `nettls-rotate-handled/v1`, signed once with the acker's
Ed25519 key, so a receipt's signature never holds for it, nor the other way round. `verify`
requires the expected acker *(0.12.0)*, the pinned key and the expected fingerprint, as for a
receipt. `to_json` fails with `TlsError::Encode` when the signature cannot be encoded as hex.

For the one who announces, a `Handled` that verifies counts as a receipt: an earlier receipt may
have been lost, but the peer is ready. Hand it to `Announcer::acked_handled`, which verifies it
before it strikes the peer, as `Announcer::acked` does a receipt *(0.12.0)*.

An older node that does not know this message accepts the receipt. When it reads the handled
message, it refuses it with "unknown message version" (`Receipt::from_json` checks `v`) and changes
nothing. That is why the receipt goes first.

### `IdentityJson` — what a service publishes

Fields: `fingerprint` (stored as given: `new` neither adds nor checks a `sha256:` prefix) ·
`cert_pem` · `not_after` · `mode` · `sent_at` ·
`announcement` *(field names ARE the wire names — the wire went fully English in 0.7.0)*.
`not_after` (optional; the expiry as ISO 8601 text, stored as given) and `announcement` (an
optional `AnnouncementJson`) are left out of the JSON when absent; `mode` is a `Mode`, `sent_at` an
`i64`.

```rust
impl IdentityJson {
    pub fn new(fingerprint: impl Into<String>, cert_pem: impl Into<String>,
               not_after: Option<String>, mode: Mode, sent_at: i64,
               announcement: Option<&Announcement>) -> Result<Self, TlsError>;
}
```

Read `fingerprint`/`cert_pem` **from what is actually served** (the resolver), never from a
cached startup value. `new` fails with `TlsError::Encode` when the announcement's signatures cannot
be encoded as hex *(0.12.0)*.

Reading an `IdentityJson` (serde, and `loads` in Python) requires `fingerprint`, written as
lowercase hex with or without its `sha256:` prefix, to be the SHA-256 of the one certificate in
`cert_pem`. A mismatch, or a `cert_pem` that is not exactly one X.509 certificate, fails the read
*(0.12.0)*.

---

## `approval` — the operator's approval

```rust
impl Approval {
    pub fn new(peer: &str, fingerprint: &str, approved_by: &str, timestamp: i64,
               key_id: &str, ed25519_seed: &krypto::SecretBuf) -> Result<Self, TlsError>;
    pub fn canonical(&self) -> Result<Vec<u8>, TlsError>;
    pub fn verify(&self, expected_peer: &str, look_up_key: &dyn Fn(&str) -> Option<Vec<u8>>)
        -> Result<(), TlsError>;   // expected_peer (0.12.0)
    pub fn fingerprint(&self) -> &str;
    pub fn peer(&self) -> &str;
    pub fn approved_by(&self) -> &str;
    pub fn key_id(&self) -> &str;
    pub fn timestamp(&self) -> i64;   // (0.12.0)
    pub fn to_json(&self) -> Result<ApprovalJson, TlsError>;
    pub fn from_json(j: &ApprovalJson) -> Result<Self, TlsError>;
}

pub struct Context<'a> {
    pub peer: &'a str,                                  // the counterpart expected (0.12.0)
    pub keys: &'a dyn Fn(&str) -> Option<Vec<u8>>,      // key_id → Ed25519 pubkey
    pub previous_der: Option<&'a [u8]>,                 // the receiver's previous generation
    pub current_der: Option<&'a [u8]>,                  // the receiver's current generation
}

pub enum Recognition { Operator(Approval), Schedule(Box<Announcement>) }
impl Recognition {
    pub fn verify(&self, k: &Context<'_>) -> Result<(), TlsError>;   // ONE code path for gen 0 and n
    pub fn peer(&self) -> &str;         // the approval's peer or the announcement's announcer (0.12.0)
    pub fn fingerprint(&self) -> &str;
    pub fn is_anchor(&self) -> bool;    // operator approval = the root
}
```

`Approval::verify` checks the peer first, then the operator key, before the key is looked up;
**Names** under [`canonical`](#canonical--what-actually-gets-signed) has the rule *(0.12.0)*.

`ApprovalJson`: `v` · `peer` · `fingerprint` · `approved_by` · `timestamp` · `key_id` · `sig`
*(field names ARE the wire names)*

`Approval::to_json` fails with `TlsError::Encode` when the signature cannot be encoded as hex
*(0.12.0)*.

---

## `announcer` — the rhythm and the state machine

### Constants

| Group | Type | Names |
|---|---|---|
| Time | `i64` | `DAY_S` (86 400) · `NOMINAL_AGE_DAYS` (7) · `SPREAD_DAYS` (±2) · `MIN_BETWEEN_ROLLS_S` (86 400) · `ALARM_AFTER_S` (12 h) |
| Lifetime | `u32`; `MODE1_WARN_DAYS` is `i64` | `MODE2_LIFETIME_DAYS` (30) · `MODE1_MIN_DAYS` (47) · `MODE1_DEFAULT_DAYS` (90) · `MODE1_MAX_DAYS` (365) · `MODE1_WARN_DAYS` (30) |
| Clock drift | `i64` | `DRIFT_NORMAL_S` (5) · `DRIFT_WARNING_S` (30) · `DRIFT_JUMP_S` (10) |
| File | `&str` | `PENDING_FILE` (`pending-rotation.json`) |

### Mode

```rust
pub enum Mode { Pinning, Rolling }     // wire values: "pinning" / "rolling"
pub enum ModeCheck { Agree(Mode), Disagree { ours: Mode, theirs: Mode } }

pub fn check_mode(ours: Mode, theirs: Mode) -> ModeCheck;  // compares, NEVER negotiates
impl ModeCheck { pub fn message(&self, peer: &str) -> Option<String>; pub fn can_roll(&self) -> bool; }

pub fn mode2_params(common_name: impl Into<String>, sans: impl IntoIterator<Item = impl Into<String>>)
    -> SelfSignedParams;                                                           // always 30 days
pub fn mode1_params(common_name: impl Into<String>, sans: impl IntoIterator<Item = impl Into<String>>,
                    days: Option<u32>) -> Result<SelfSignedParams, TlsError>;
                    // None → 90 days; below 47 or above 365 → Params
pub fn mode1_should_warn(now: i64, expires: i64) -> bool;                          // at 30 days left
```

### `Schedule` — the state machine (pure logic, no I/O)

```rust
pub enum ChainState { Idle { attempt_at: i64 }, Announced { waiting_for: BTreeSet<String>, first_announced: i64 } }

impl Schedule {
    pub fn new(peers: impl IntoIterator<Item = String>, attempt_at: i64) -> Self;
    pub fn add_peer(&mut self, name: impl Into<String>);
    pub fn remove_peer(&mut self, name: &str);   // no proof: the operator's named way out (0.12.0)
    pub fn should_announce(&self, now: i64) -> bool;
    pub fn announced(&mut self, now: i64);
    pub fn acked(&mut self, peer: &str, receipt: &Receipt, pinned_pubkey: &[u8], expected_new_fp: &str)
        -> Result<(), TlsError>;                 // verifies before it strikes (0.12.0)
    pub fn acked_handled(&mut self, peer: &str, handled: &Handled, pinned_pubkey: &[u8],
                         expected_new_fp: &str) -> Result<(), TlsError>;   // the same, for a Handled (0.12.0)
    pub fn waiting_for(&self) -> Vec<&str>;      // empty = ready to roll
    pub fn can_roll(&self, now: i64) -> bool;
    pub fn rate_limit_ok(&self, now: i64) -> bool;
    pub fn rolled(&mut self, now: i64) -> Result<(), TlsError>;
    pub fn state(&self) -> &ChainState;
    pub fn first_announced(&self) -> Option<i64>;
    pub fn status(&self, now: i64, expires: i64) -> Status;
    pub fn next_retry(&self, now: i64) -> Option<i64>;
    pub fn alarm(&self, now: i64) -> bool;
    pub fn restore_announced(&mut self, waiting_for: Vec<String>, first_announced: i64);  // after restart;
                                       // only peers in the list given to `new` (0.11.0)
}

pub fn draw_roll_time(issued: i64) -> Result<i64, TlsError>;   // issued + 7 d ± 2 d (CSPRNG)
pub fn interval_after(elapsed_s: i64) -> i64;                  // retry cadence: tight, then sparser
```

`acked` and `acked_handled` take the peer's message and verify it before anything is struck from
the waiting list *(0.12.0)*: something must be announced, `peer` must be one of the peers, and the
message must verify (`Receipt::verify`, `Handled::verify`) as from `peer`, against `pinned_pubkey`
and `expected_new_fp`. The state machine does not know the announcement, so the caller gives the
fingerprint. A peer that has already acknowledged and acknowledges again with a valid message gets
`Ok`, and nothing changes. A refusal is `TlsError::ProofInvalid` and changes nothing. `remove_peer`
takes no proof: it is the operator's named way out, not an acknowledgement.

Peer names are not checked when they are given (`Schedule::new`, `add_peer`, `Announcer::add_peer`). The
acker of a receipt or handled message must be a component name and equal to the peer's name, so a
peer listed under another form of name is never acknowledged.

### `Status` — for alerting

```rust
pub struct Status { pub waiting_for: Vec<String>, pub alarm: bool, pub seconds_until_stop: i64 }
impl Status {
    pub fn countdown(&self) -> String;                          // "d days hh:mm:ss"
    pub fn message(&self, own_name: &str) -> Option<String>;      // always names WHO is blocking
}
```

`seconds_until_stop` counts to the moment communication actually **stops** (certificate expiry)
— not to the next retry, not to the alarm.

### `Announcer` — the one that binds it together

```rust
pub struct OwnMaterial {                       // keys as SecretBuf since 0.8.3 (were Vec<u8>)
    pub previous: Option<(String, krypto::SecretBuf)>,   // (fingerprint, PKCS#8)
    pub current: (String, krypto::SecretBuf),            // build from TlsMaterial::anchor_pkcs8()
}
pub struct Pending {                           // Debug (redacted) — NOT Clone since 0.8.3
    pub announcement: Announcement, pub new_cert_pem: String, pub new_pkcs8: krypto::SecretBuf }
pub struct OwnTrio {                           // fingerprints only — never keys
    pub previous_fingerprint: Option<String>,
    pub current_fingerprint: String,
    pub next_fingerprint: Option<String>,
}

impl Announcer {
    pub fn new(name: impl Into<String>, dir: impl Into<PathBuf>, params: SelfSignedParams,
               resolver: Arc<RotatingResolver>, anchor: OwnMaterial, schedule: Schedule,
               password: Option<krypto::SecretString>) -> Result<Self, TlsError>;
        // load-or-init, fail-closed: disk state overrides the anchor; unreadable state = error
        // the restored certificate is put into the resolver (0.12.0)

    pub fn own_trio(&self) -> Result<OwnTrio, TlsError>;
    pub fn prepare(&self, now: i64) -> Result<Announcement, TlsError>;   // create + persist + announce; idempotent
    pub fn acked(&self, peer: &str, receipt: &Receipt, pinned_pubkey: &[u8])
        -> Result<(), TlsError>;   // verifies before it strikes; persists (0.12.0)
    pub fn acked_handled(&self, peer: &str, handled: &Handled, pinned_pubkey: &[u8])
        -> Result<(), TlsError>;   // the same, for a Handled (0.12.0)
    pub fn add_peer(&self, name: impl Into<String>) -> Result<(), TlsError>;   // persists (0.11.0)
    pub fn remove_peer(&self, name: &str) -> Result<(), TlsError>;             // persists (0.11.0)
        // no proof: the operator's named way out (0.12.0)
    pub fn roll_if_ready(&self, now: i64) -> Result<Option<String>, TlsError>;
    pub fn roll_if_ready_gated(&self, now: i64, safe_now: impl FnOnce() -> bool)
        -> Result<Option<String>, TlsError>;   // the consumer's last word; chain+serving switch together
        // refused if what lies in `new/` is not the certificate that was announced (0.12.0)
    pub fn should_announce(&self, now: i64) -> Result<bool, TlsError>;
    pub fn status(&self, now: i64, expires: i64) -> Result<Status, TlsError>;
    pub fn pending(&self) -> Result<Option<Announcement>, TlsError>;
        // should_announce and pending: a poisoned lock is `LockPoisoned` (0.12.0)
    pub fn save_pending(&self) -> Result<(), TlsError>;   // prepare/acked call it (0.10.0); NOT the key
        // acked_handled calls it too (0.12.0); Proof if the promise cannot be serialized
}
```

`acked` and `acked_handled` take the peer's message and the key pinned for that peer, and verify
before anything is struck from the waiting list *(0.12.0)*: an announcement must be pending, the
message must be to this announcer (its `announcer` is this announcer's name), `peer` must be one of
the peers, and the message must verify as from `peer`, against the key and the fingerprint
announced. A peer that has already acknowledged and acknowledges again with a valid message gets
`Ok`, and nothing changes: a receipt and a handled message can arrive one after the other. A
refusal is `TlsError::ProofInvalid`, and neither the waiting list nor the saved promise changes.
`acked_handled` saves the promise as `acked` does. `remove_peer` takes no proof: it is the
operator's named way out, not an acknowledgement.

`prepare` and `acked` save the promise themselves, so a restart resumes it *(0.10.0)*. A switch
writes the file with the previous key, then the new pair, and reads them back before anything in
memory moves: if one of these steps fails, nothing in memory moves and the next call tries again,
but nothing already written is undone: the file with the previous key may be written, and the new
pair may be in place, or, without a password, only the new certificate, with its key left in
`key.tmp`. At start, the stored chain is checked against the material,
and the 24-hour cap holds across the restart. The file with the previous key must name the
certificate it belongs to and when the pair came about. One that lacks either, as files written
before 0.10.0 do, is refused at start *(0.12.0)*.

`Announcer::new` passes an error from opening `material.locked` or `previous-key.locked` through
as `lockbox::unlock` gives it, not as `Chain`; any error loading the pair in `new/` at start is `Chain`. It
does not check the announcer's `name` or the fingerprints in `anchor`: `prepare` checks them when
it builds the announcement, after it has written `new/`.

| In `dir` | Holds | Mode |
|---|---|---|
| `material.locked`, or `cert.pem` + `key.pem` without a password | the current pair | 0600; `cert.pem` 0644 |
| `previous-key.locked`, or `previous-key.json` without a password | the previous key | 0600 |
| `pending-rotation.json` | the promise; `save_pending` removes it when nothing is pending | 0600 |
| `new/` | the announced pair: `material.locked`, or `cert.pem` + `key.pem` | 0700 |

The previous-key file and `pending-rotation.json` refuse a JSON key they do not know when they are
read at start *(0.12.0)*. The locked and JSON files are written through a temp file beside each (`material.tmp`,
`previous-key.tmp`, `pending-rotation.tmp`, `new/material.tmp`), created 0600; a leftover one is
removed before the next write. `cert.pem` and `key.pem` go through `cert.tmp` and `key.tmp`, as
under `save_pem`. A directory a save creates is made 0700. After a switch, `pending-rotation.json`
and `new/` are removed; a failure there is `Io`, saying the switch is done. `Announcer::new`
removes the `.tmp-material` staging directories in `dir` and `new/`, and removes the promise and
`new/` when the promised certificate is already the current one.

`password: None` means **key material in cleartext on disk**. Legitimate (mode 1 with an
operator-uploaded certificate), but it is a choice, and it must be visible as one: each
`Announcer::new` without a password writes a note saying so to stderr. *(0.12.0)* A
password over `krypto::password::MAX_PASSWORD_BYTES` is `Params`, refused before anything on disk
is read or written.

### Deviation and downgrade

```rust
pub enum Deviation {
    UnknownCertificate { observed: String },
    InvalidSignature(String),
    AbandonedCertificate { observed: String },
}
impl Deviation { pub fn message(&self, peer: &str) -> String; }

pub struct FallToMode1 { pub deviation: Deviation }
impl FallToMode1 {
    pub fn at(deviation: Deviation) -> Self;   // or the struct literal, `deviation` being pub; no way back without an operator
    pub fn mode(&self) -> Mode;            // always Pinning
    pub fn can_retry(&self) -> bool;       // always false
}
```

### `ClockDrift` — diagnostics

```rust
pub enum Drift { Normal, Log, Warning }
impl ClockDrift {
    pub fn new() -> Self;                  // + Default
    pub fn observe(&mut self, their_sent_at: i64, our_now: i64) -> Drift;
    pub fn last(&self) -> Option<i64>;     // positive = the peer is ahead
    pub fn max(&self) -> i64;
    pub fn message(&self, peer: &str) -> Option<String>;
}
```
Pure diagnostics — clock drift steers nothing.

---

## `capability` — the signed AEAD support statement *(new in 0.8.2)*

The decided pattern: **the best algorithm (AEGIS-256) is the default; fallback is an explicit,
authenticated exception; falling back to nothing does not exist.** `lockbox`/`envelope` already
default to AEGIS-256 with `_with` variants for an explicit per-call choice — this module is the
authenticated basis for choosing.

```rust
pub const ALGSUPPORT_V1: &str = "nettls-algsupport/v1";        // in `canonical`
pub fn algsupport_v1(component: &str, algs: &str, timestamp: i64) -> Result<Vec<u8>, TlsError>;  // in `canonical`

pub fn alg_token(alg: Alg) -> &'static str;                    // krypto-cli's vocabulary
pub fn alg_from_token(token: &str) -> Result<Alg, TlsError>;   // fail-closed: the three tokens, case-sensitive; else Params

pub struct SupportStatement { pub component: String, pub supported: Vec<String>, pub timestamp: i64, pub signature: String }
impl SupportStatement {
    pub fn signed(component: &str, supported: &[Alg], timestamp: i64, anchor_pkcs8: &krypto::SecretBuf) -> Result<Self, TlsError>;
        // an empty list, an algorithm twice or a component name that breaks the rule → Params; the order is normalised
    pub fn verify(&self, expected_component: &str, signer_cert_der: &[u8]) -> Result<Vec<Alg>, TlsError>;
        // expected_component (0.12.0)
        // then: a token list or component that breaks the rules → Params, a signature that is empty or not lowercase hex → Proof,
        // anything from the signature check, the certificate included → ProofInvalid
}

pub fn choose(requested: Alg, verified_supported: Option<&[Alg]>) -> Result<Alg, TlsError>;
```

- **Only the party that does NOT support an algorithm can authorize a downgrade** — with its
  P-256 anchor signature over the canonical statement (fixed token order; unknown tokens,
  duplicates and reordering are rejected — one spelling per support set).
- **`choose` is the rule:** no statement → the requested stands; a verified statement without
  it → the best the peer declared, by the fixed preference order (aegis256 · xchacha20 ·
  aes256gcm); nothing acceptable → `TlsError::Negotiation` — **the connection fails, never
  silently weaker**. An unverifiable statement authorizes nothing, nor does one from another
  component than `expected_component` *(0.12.0)*.
- From Python it is the same module, `nettls_py.capability` *(0.11.0)*. The
  `algsupport-01-python-bridge` vector fixes the canonical bytes.
- `SupportStatement` is `Serialize` and `Deserialize`; its field names are the JSON names.

## `status` — the About contribution *(new in 0.8.2)*

Every service shows status for its parts; the TLS part is this crate's to describe. The crate
owns the **vocabulary**, the **derivation** (what counts as a warning — thresholds live in ONE
place) and the **headline**; the consumer owns the transport.

```rust
pub enum Level { Ok, Warn, Alert }                       // the traffic light, crate-derived
#[non_exhaustive]
pub enum PeerState { Ok, RotationPending, Broken, Unreachable }   // Unreachable, non_exhaustive: 0.11.0

pub struct PeerReport { pub name: String, pub state: PeerState, pub current_fingerprint: String,
                        pub next_fingerprint: Option<String> }
impl PeerReport {
    pub fn from_generations(name: impl Into<String>, g: &Generations) -> Self;   // derives Ok/RotationPending
    pub fn broken(name: impl Into<String>, last_known_fingerprint: impl Into<String>) -> Self;
        // only the consumer sees Chain errors
    pub fn unreachable(name: impl Into<String>, last_known_fingerprint: impl Into<String>) -> Self;
        // only the consumer tries to connect (0.11.0)
}

pub struct IdentityReport { pub fingerprint_sha256: String, pub origin: String,   // CertOrigin's Debug form
                            pub not_after: Option<i64>, pub days_until_expiry: i64, pub expiry_warning: bool }
pub struct RotationReport { pub waiting_for: Vec<String>, pub alarm: bool, pub seconds_until_stop: i64 }

pub struct Report { pub version: &'static str, pub level: Level, pub headline: String,
                    pub identity: IdentityReport, pub rotation: Option<RotationReport>, pub peers: Vec<PeerReport> }
impl Report {
    pub fn collect(now: i64, material: &TlsMaterial,
                   announcer_status: Option<&Status>, peers: Vec<PeerReport>) -> Report;
    pub fn summary(&self) -> Summary;
}

pub struct Summary { pub version: &'static str, pub level: Level, pub headline: String }
```

**The instruction to consumers — two views, two audiences:**

| View | Audience | Serve it on |
|---|---|---|
| `Report::summary()` — version, traffic light, headline; nothing else | every logged-in user | the general About surface |
| `Report` — identity, rotation state, per-peer trust | admin only (peer names and waiting lists are operations data) | the admin surface |

Everything serializes with serde — drop it straight into your status JSON. The five report types
are `Serialize` only. `Level` serializes as `ok`, `warn`, `alert`; `PeerState` as `ok`,
`rotation_pending`, `broken`, `unreachable`. No I/O, no clock:
you pass `now` (Unix seconds). The `expiry_warning` flag and the `level` are the crate's own
rules — never re-derive them.

**A peer that does not answer** *(0.11.0)* is `PeerState::Unreachable`, set by the consumer with
`PeerReport::unreachable` — it decides after how many failed attempts, or how long. The report is
`Alert` with the headline `no answer from <names>`; a broken trust chain or an expiring
certificate of our own takes the headline first. Where the headline names peers (a broken trust
chain, no answer, a rotation alarm), `summary()` gives it without the names *(0.12.0)*. **`PeerState` is `#[non_exhaustive]` from
0.11.0:** a `match` on it outside the crate needs a `_` arm, and how a state it does not know is
shown is the consumer's own choice. A state added later changes nothing for anyone.

**The expiry rule** *(0.11.0)* is the same for every lifetime and counts from `now`: `Warn`
once half the certificate's lifetime has passed, `Alert` from the last day before expiry and
after it. In mode 2, which rotates after about a week, `Warn` therefore means the rotation has
failed. `days_until_expiry` is rounded down, so it is negative from the first second after
expiry.

---

## `signature` — the §6 rules over krypto's primitives

Since 0.8.0 the primitives live in `krypto` (0.5): encoding is `krypto::hex::encode`, Ed25519 is
`krypto::sign::ed25519_*` (seeds as `krypto::SecretBuf`, constants `ED25519_SEED_LEN`/
`ED25519_PUBLIC_LEN` are krypto's). What remains here is the §6 domain:

```rust
pub fn from_hex(s: &str) -> Result<Vec<u8>, TlsError>;    // §6.5 field: non-empty + krypto::hex::decode
                                                          // (lowercase, fail-closed; never panics on UTF-8)

pub fn p256_public_key(cert_der: &[u8]) -> Result<Vec<u8>, TlsError>;             // X.509 → SEC1 point
pub fn sign_p256(pkcs8: &krypto::SecretBuf, message: &[u8]) -> Result<Vec<u8>, TlsError>;  // → krypto::sign; key never leaves the lock (0.8.3)
pub fn verify_p256(cert_der: &[u8], message: &[u8], signature: &[u8]) -> Result<(), TlsError>;
```

`p256_public_key` refuses bytes left over after the certificate, and a key whose parameters do not
name the curve P-256 (OID 1.2.840.10045.3.1.7) *(0.12.0)*. It needs an EC key (id-ecPublicKey)
with an uncompressed point of 65 bytes: another key kind is `ProofInvalid`, and bytes that are not
exactly one certificate are `Certificate`. `verify_p256` reads the key the same way.

## `canonical` — what actually gets signed

Domain separators: `APPROVE_V1` · `ROTATE_V2` · `ROTATE_ACK_V2` · `PAIRSECRET_V1` ·
`ROTATE_HANDLED_V1` *(0.12.0)*

```rust
pub const APPROVE_V1: &str = "nettls-approve/v1";
pub const ROTATE_V2: &str = "nettls-rotate/v2";
pub const ROTATE_ACK_V2: &str = "nettls-rotate-ack/v2";
pub const ROTATE_HANDLED_V1: &str = "nettls-rotate-handled/v1";
pub const PAIRSECRET_V1: &str = "nettls-pairsecret/v1";

pub fn approve_v1(peer: &str, fingerprint: &str, approved_by: &str, timestamp: i64) -> Result<Vec<u8>, TlsError>;
pub fn rotate_v2(announcer: &str, prev_fp: Option<&str>, curr_fp: &str, new_fp: &str, sent_at: i64)
    -> Result<Vec<u8>, TlsError>;
pub fn rotate_ack_v2(acker: &str, announcer: &str, new_fp: &str, sent_at: i64) -> Result<Vec<u8>, TlsError>;
pub fn rotate_handled_v1(acker: &str, announcer: &str, new_fp: &str, sent_at: i64)
    -> Result<Vec<u8>, TlsError>;   // the receipt's fields under its own first line (0.12.0)
pub fn pairsecret_v1(a: &str, b: &str, sealed_a_sha256: &str, sealed_b_sha256: &str, sent_at: i64)
    -> Result<Vec<u8>, TlsError>;

pub fn require_fingerprint(v: &str, field: &str) -> Result<(), TlsError>;
pub fn require_component_name(v: &str, field: &str) -> Result<(), TlsError>;   // strict: [a-z0-9-]{1,32}
pub fn require_name(v: &str, field: &str, max: usize) -> Result<(), TlsError>; // usernames: looser, no control chars
```

> Use these if you verify outside the crate. Building the string yourself is a fine way to get a
> signature that looks right and is not.

| Rule (each refusal is `Params`) | Fields |
|---|---|
| component name, `require_component_name`: `[a-z0-9-]{1,32}` | `peer` (`approve_v1`), `announcer`, `acker`, `a`, `b`, `component` (`algsupport_v1`) |
| fingerprint, `require_fingerprint`: exactly 64 lowercase hex characters, no prefix | `fingerprint`, `prev_fp` (when given), `curr_fp`, `new_fp`, `sealed_a_sha256`, `sealed_b_sha256` |
| name, `require_name`: not empty, at most `max` characters (characters, not bytes), no control characters | `approved_by` and an approval's `key_id`, both with `max` 64 |

`rotate_v2` also refuses `prev_fp`, `curr_fp` and `new_fp` that are not all different, and
`algsupport_v1` an empty token list.

`from_json` of `Announcement`, `Receipt`, `Handled` and `Approval` checks the fields by these rules
(`Params`), and `new_cert_pem` against `MAX_CERT_PEM_LEN` (`Params`). It refuses with `Proof` a
`v` that is not exactly the form's first line, a `prev_fingerprint` without `sig_prev` or the
reverse, and a signature that is empty or not lowercase hex. `Announcement::from_json` does not
check that the fingerprints differ, that `new_cert_pem` is a certificate, or that
`new_fingerprint` is its hash; `verify` does, and gives `Params` for an announcement that names one
certificate twice.

**Time.** nettls does not judge the age of a message. `timestamp` and `sent_at` are the sender's own
clock, signed with the message, and are there for logs and for the caller. No `verify` compares them
with a clock, so a signed approval or support statement does not grow too old by itself. A caller
that wants a rule about freshness reads the field and applies its own.

An announcement and a receipt are bound to state instead: the announcement must fit the certificates
the receiver holds, and the receipt must name the fingerprint that was announced. A handled message
is bound as the receipt is *(0.12.0)*.

**Names** *(0.12.0)*. Every `verify` takes the name of the counterpart the caller expects, as its
first argument (`Recognition::verify` in `Context::peer`), and refuses a message about another:
the approval's `peer`, the announcement's `announcer`, the receipt's and the handled message's
`acker`, the support statement's `component`. A genuine message for one peer says nothing about
another. The names are compared exactly as they are, and the refusal is `TlsError::ProofInvalid`,
naming both. `Generations::receive` and `Trust::receive` take the name after the announcement and
pass it on. An operator key, a `key_id` of the form `op:<name>`, may sign only approvals that name
`<name>` as approver (`approved_by`); other key ids, such as `portal`, are not affected.

## `envelope` — seal to one recipient

```rust
pub const X25519_LEN: usize = 32;

impl RecipientKey {                       // Debug: [REDACTED]; the key lives in a SecretBuf
    pub fn from_bytes(b: krypto::SecretBuf) -> Result<Self, TlsError>;   // consumes — the secret-types rule
    pub fn generate() -> Result<(Self, Vec<u8>), TlsError>;   // (private, public)
    pub fn public(&self) -> Result<Vec<u8>, TlsError>;          // Envelope if krypto refuses the key
}

pub fn seal(recipient_public: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, TlsError>;   // AEGIS-256
pub fn seal_with(recipient_public: &[u8], plaintext: &[u8], alg: krypto::Alg) -> Result<Vec<u8>, TlsError>;
pub fn open(key: &RecipientKey, envelope: &[u8]) -> Result<krypto::SecretBuf, TlsError>;
```

Whoever seals holds no key and cannot open. `seal_with(_, _, Alg::Aes256Gcm)` is the interop
bridge for a recipient without AEGIS; `open` reads the algorithm from the header.
The key exchange is `krypto::exchange` (0.8.0) — a low-order recipient point is **rejected at
sealing** (non-contributory result), it no longer yields an envelope.
The envelope has **no sender** *(0.11.0)*: anyone with the recipient's public key can seal one,
and an old one can be delivered again. Who sealed it, and when, must come from the channel or
the content. Envelope and lock failures are `TlsError::Envelope` (too short: under 40 bytes, the
header and the salt or ephemeral key; wrong format; key generation, derivation or sealing),
except: a recipient key of the wrong length, or a low-order
public key, is `Params`; a wrong key or password, sealed content that was altered, and an invalid
ephemeral key in `open`, are `ProofInvalid`; a lock whose salt cannot be drawn is `Random`;
plaintext, or the envelope's key material, that cannot be held in locked memory is
`LockedMemory`, and *(0.12.0)* so is the content `open` or `unlock` has opened, or the shared
secret of the key exchange, when it cannot be held. *(0.12.0)* A plaintext over
`krypto::MAX_DATA_BYTES`, or a password over `krypto::password::MAX_PASSWORD_BYTES`, is `Params`,
and a locked file or envelope whose blob is over krypto's limit for a blob
(`krypto::MAX_DATA_BYTES` + 86 bytes) is `Envelope`, refused before the password or key is used.
*(0.12.0)* An inner blob that is not a krypto blob, or content krypto refuses as too large after
opening, is `Envelope`.

## `lockbox` — lock with a password

```rust
pub fn lock(password: &krypto::SecretString, plaintext: &[u8]) -> Result<Vec<u8>, TlsError>;      // AEGIS-256
pub fn lock_with(password: &krypto::SecretString, plaintext: &[u8], alg: krypto::Alg) -> Result<Vec<u8>, TlsError>;
pub fn unlock(password: &krypto::SecretString, file: &[u8]) -> Result<krypto::SecretBuf, TlsError>;
```

argon2id + FAFN. No verification hash is stored — a wrong password is an AEAD authentication
failure, and an unknown format is reported as **wrong format**, not a wrong password.

---

## `error` — `TlsError`

```rust
#[non_exhaustive]
pub enum TlsError {
    Io { path: Option<PathBuf>, detail: String },
    Pem(String),
    KeyMismatch(String),                                    // the classic upload mistake
    Certificate(String),
    Generate(String),
    Rustls(String),
    Params(String),          // invalid consumer input (empty SAN list, valid_days out of range, …); over krypto's size limit (0.12.0)
    Fingerprint(String),
    Proof(String),           // could not be PARSED — fail-closed
    ProofInvalid(String),    // parses fine but does NOT hold (signature, wrong identity, replay)
    Chain(String),           // the chain does not connect, or its stored state cannot be used — see the table; the system's best-explained error
    Sign(String),
    Negotiation(String),     // no authenticated common AEAD — hard failure (0.8.2)
    Envelope(String),        // the envelope or the password lock failed (0.11.0); too long (0.12.0); content too large after opening (0.12.0)
    LockedMemory(String),    // a secret could not be held in locked memory (0.11.0); loading `new/` at start, and locking the serialized previous key at a switch, give `Chain`
    Random(String),          // random numbers could not be obtained; the message says why (0.11.0)
    LockPoisoned(String),    // a thread panicked holding a lock — a bug (0.11.0)
    Encode(String),          // a value could not be encoded as hex, base64 or PEM (0.12.0)
}
```

| Variant | When |
|---|---|
| `Io` | file/directory |
| `Pem` | the PEM could not be read |
| `KeyMismatch` | the key does not belong to the certificate; the message gives the certificate's SHA-256 fingerprint, and both file names when the pair was read from files *(0.12.0)* |
| `Certificate` | the certificate could not be parsed |
| `Generate` | generation failed |
| `Rustls` | rustls rejected the config |
| `Params` | invalid parameters in; also an input krypto refuses as over its size limit: a password, a plaintext, or a private key to be held in locked memory *(0.12.0)*; except that any error loading the pair in `new/` at start is `Chain`, and so is the serialized previous key a switch cannot hold in locked memory |
| `Fingerprint` | the fingerprint has the wrong shape |
| `Proof` | the proof/message could not be parsed |
| `ProofInvalid` | parsed fine but does not hold |
| `Chain` | the chain does not connect: fingerprints that do not fit together (an announcement for another current or previous, a previous key for another material, previous and current alike, a `new/` that is not what was announced), an approval signed with a key not in the registry, or an announcement to verify without a current generation. Also a previous-key file that cannot be parsed, lacks a field, or is stored in the other form than the password setup; a promised rotation whose `new/` cannot be loaded at start, whatever the error; and at a switch, a previous key whose serialized form cannot be made or held in locked memory, or files that, read back, hold another certificate or previous key than was written, or no previous-key file (a read-back that fails to load gives that load's own error) |
| `Sign` | signing failed |
| `Negotiation` | no *authenticated* common AEAD — the connection must fail, never silently weaken *(0.8.2)* |
| `Envelope` | the sealed envelope or the password lock failed: too short, wrong format, or a key, derivation or sealing step *(0.11.0)*; too long for krypto's largest blob *(0.12.0)*; content krypto refuses as too large after opening *(0.12.0)* |
| `LockedMemory` | a secret could not be held in locked memory (`mlock`, `RLIMIT_MEMLOCK`) *(0.11.0)*; a secret over krypto's size limit is `Params` *(0.12.0)*; any error loading the pair in `new/` at start is `Chain` (the copy of its key made afterwards is `LockedMemory` or `Params` as usual), and so, for either reason, is the serialized previous key a switch cannot hold in locked memory |
| `Random` | random numbers could not be obtained; the message says why *(0.11.0)* |
| `LockPoisoned` | a thread panicked while holding one of the crate's locks — a bug, not an input error *(0.11.0)* |
| `Encode` | a value could not be encoded as hex, base64 or PEM: it is over krypto's size limit, or the memory for the text could not be reserved *(0.12.0)* |

The `Proof` / `ProofInvalid` split is worth noting: the first is a shape error, the second is a
signature that does not hold. Only the second is a security finding. `#[non_exhaustive]` — new
variants may appear.

**Never empty error messages** — every variant carries enough context for the operator to see
*what* is wrong. **No variant ever carries key material** (a `TlsError` gets logged, and a
logged private key is a compromised private key). The `Chain` message says what failed, and
names the fingerprints where they do not fit together. When the chain is broken,
communication stands still until an operator re-approves, so it must be the system's
best-explained error.

---

## The enrollment rule — trust over an unverified connection (CONTRACT)

Before a peer is approved, or when the chain is broken (`PeerState::Broken`), three principles
apply for every consumer of this crate:

1. **Observing an identity is not trusting it.** A certificate is public — connecting
   unverified *only to read the peer's certificate/fingerprint* gives an attacker nothing new.
   The connection may be used to **look**, never to **transfer**.
2. **The order layer is protected independently of TLS.** Every request is verified with
   Ed25519 signatures against pinned keys — an attacker on an unverified connection loses you
   confidentiality, not integrity. Unverified mode is *uncomfortable*, not *dangerous*.
3. **The fingerprint is verified out of band.** A service logs its own fingerprint at startup
   and exposes it on its health surface; the surface asking for approval SHALL urge the
   operator to compare against the peer's own startup log. Without that comparison the
   approval is effectively TOFU.

The client for that look is `pin::unverified_client_config` *(0.11.0)*: any certificate, but the
handshake signature must hold, so a server cannot show a certificate whose key it does not have.
Do not build one of your own.

**The contract for unverified mode:**

| Allowed | **Not allowed** |
|---|---|
| fetching and showing the peer's certificate/fingerprint | credential deposits — secrets must **never** cross an unverified connection |
| health checks | any mutating operation against devices/data |
| the operator's approval of a fingerprint | anything carrying customer data or configuration |

---

## Stability

**Safe to build on:** the wire format (the frozen table
at the top — changing it is breaking regardless of semver) · the `TlsError` branches
(`#[non_exhaustive]`) · the `CertSource`/`TlsMaterial` surface · the pinning model (full
signature verification, constant-time fingerprint comparison, resumption off) · the §6
message forms and verification orders · the generation pair's two roles · the `Announcer::new`
contract (load-or-init, fail-closed) · the switch point (chain + serving together, consumer's
port) · the algorithm layers (AEGIS-256 default, AES-256-GCM as the bridge, algorithm from the
header, hard failure).

**Deliberate non-mechanisms** *(decided 2026-08-27)*: the Ed25519 **request-signing keys do
not rotate on a schedule** — §6 rotates certificates; the signing keys are static, and their
replacement is *regeneration per service + a new operator approval* (the gen 0 path). The
trust model leans on the gen 0/init step by design. And the crate has **no CA/issuer role**:
it offers certificate functions (self-signed issuance, pinning, §6 rotation) — it never issues
on anyone's behalf.

**In motion:**

- **AEGIS-256 in the TLS transport is a deliberate deviation, not a wait (0.8.3).** Checked
  against the source 2026-09-04: rustls 0.23 has a 12-byte nonce, 0.24.0-dev.1 *and* git-main
  cap `Iv::MAX_LEN` at 16 (PR#2737 made the IV variable-length, never 32), and nobody upstream
  is working on it. So `aegis` ships our own suite — private code point, zero-padded nonce,
  SHA-384 pairing, all written down — as a consumer choice (`TransportCipher::Aegis256`),
  never the default. The default transport is AES-256-GCM. The exit (rustls ships AEGIS or a
  32-byte IV) is caught by a test, `the_deviation_still_has_its_reason` in `aegis`, which fails
  when rustls' TLS 1.3 IV is no longer the fixed 12-byte array.
- ~~Guaranteed zeroing of PEM buffers belongs in `krypto::SecretBuf`; `pem::wipe` is a
  documented, bounded compromise under `forbid(unsafe_code)`.~~ **Done in 0.8.3:** private keys
  the crate holds are `SecretBuf`; `pem::wipe` is gone (`zeroize` covers part of the short-lived
  rest). What remains outside the fence is rustls'/ring's own copy and the short-lived buffers
  that are not wiped — see *Private keys in memory* under `TlsMaterial`.

**Breaking 0.x shifts that have happened** *(precedent)*: 0.3.0 deprecated the §5 model; 0.6.x
absorbed the recovery calls into `Announcer::new`; **0.7.0 switched the whole API surface to
English**, and the JSON names on the wire with it; the signed canonical bytes were unchanged;
**0.8.0 removed the crate's own primitives in favour of krypto** (hex/Ed25519 out of the
surface, seeds as `SecretBuf`) — still without touching the wire format; **0.8.2 removed the
retired §5 model entirely** (`chain` + `rotation`: `TrustChain`, `RotationProof`,
`PROOF_VERSION`, `ROTATION_PROOF_FILE`, the `sign_successor`/`sign_rotation`/
`verify_successor` methods and the `rotation.proof` file) — the whole app is in its build
phase, nothing to migrate (`cert_fingerprint_sha256` survived; it moved to `material`);
**0.11.0 replaced the Python twin** (`python/nettls.py`, a second implementation with its own
API) with `nettls-py`, this crate run from Python — still without touching the wire format —
and made clients refuse an expired certificate, with `Expiry` as a new last argument of the
`_with` forms and `TlsError::NotValidNow` gone.
Recorded here, and every entry above carries the version it applies from.

## Python — `nettls-py` *(0.11.0)*

The same API from Python 3.11 or newer: `pip install nettls-py`, then `import nettls_py`. Every
function, type, constant and module in this document exists there, with the same name, and does the
same thing, because it is the same Rust code. A test (`nettls-py/tests/surface.rs`) fails the build
if a name is on one side only without a written reason; `nettls_py.sslcontext` is pure Python and
outside that test. What differs is what can be guaranteed
(below). How to use it, with examples: **[Python](Python.md)**.

How the Rust forms read in Python:

| Rust | Python |
|---|---|
| `nettls::TlsMaterial`, `nettls::announcer::Announcer`, … | `nettls_py.TlsMaterial`, `nettls_py.announcer.Announcer`, … — the same modules and the same root re-exports |
| `&[u8]`, `Vec<u8>` | `bytes`. Where Rust takes `&[u8]` or a key (`SecretBuf`), and in `Stream.write`, `TlsConnection.receive` and `TlsConnection.write`, only `bytes` is taken. A `Vec<u8>` or `impl Into<Vec<u8>>` argument, an item of an ALPN list, `Announcement.verify`'s `prev_cert_der`, `Context`'s `previous_der` and `current_der`, and a key inside a tuple (`Announcement.new`, `OwnMaterial(…)`) also take a `bytearray` or a sequence of ints from 0 to 255 |
| `Vec<T>`, `&[T]`; tuples | `list` (`cert_chain()` is a `list` of `bytes`). A list argument takes any sequence except a `str`; a `str`, a set or a generator is a `TypeError`. Tuples are `tuple`s: `RecipientKey.generate()` gives `(RecipientKey, bytes)`, `read_archive` `(list, int)` |
| `i64`, `u32`, `usize`, … | `int`; one outside the Rust type's range is an `OverflowError` |
| `&str`, `String` | `str` |
| `impl Into<PathBuf>`, `&Path` | `str` or a path object |
| `Option<T>` | `T` or `None` |
| `Result<T, TlsError>` | `T`, or an exception |
| `TlsError::Pem`, `TlsError::Params`, … | `PemError`, `ParamsError`, …, all subclasses of `TlsError`, also in `nettls_py.error`. `IoError` has no `path` or `detail` attribute; its message carries them. `TlsError` derives from `Exception`, so `IoError` is not an `OSError`. `RustlsError` is also raised when rustls refuses to start a connection (`Stream`, `TlsConnection`), and `ParamsError` when nettls returns an enum value the binding does not know |
| `Mode::Rolling`, `ChainState::Idle { attempt_at }`, … | `Mode.Rolling`, `ChainState.Idle(attempt_at=…)`, … — enums with data too |
| A plain enum: `Alg`, `CertOrigin`, `Drift`, `Expiry`, `Level`, `Mode`, `PeerState`, `Received`, `TransportCipher` | `int()` is the variant's position from 0, and the variant equals that `int`; hashable; `repr()` is `Class.Variant`; `str(Mode.Rolling)` is `"rolling"` |
| An enum variant with data | Read-only attributes: a named field by its name, a tuple field as `._0` or `[0]` (`ModeCheck.Agree`, `Deviation.InvalidSignature`, `Recognition.Operator`, `Recognition.Schedule`) |
| A set (`ChainState::Announced`'s `waiting_for`) | A sorted `list` |
| A struct's `pub` fields | Attributes. `SelfSignedParams::valid_days` is both a field and a builder in Rust; in Python it is the field. Read-only: `OwnMaterial.previous` and `.current` (`current` is `(fingerprint, bytes)`, the key a copy, and `previous` the same or `None`; both raise `ValueError` once the `OwnMaterial` has been given to an `Announcer`), `Report.version`, `Summary.version`. Reading an attribute that holds a list or an object gives a copy (`Context.keys`, a function, is given as it is): changing the copy changes nothing; assign the attribute |
| `X::new(…)` | `X.new(…)`. `X(…)` too for `AnnouncementJson`, `ReceiptJson`, `HandledJson` *(0.12.0)*, `ApprovalJson`, `Context`, `SupportStatement`, `Status`, `OwnMaterial`, `Schedule`, `Announcer`, `ClockDrift` and `RotatingResolver`; `SelfSignedParams()` and `TransportPolicy()` give the `Default` |
| `&krypto::SecretBuf`, `krypto::SecretString` taken in | `bytes`, `str`, copied straight into locked memory |
| `krypto::SecretBuf` handed out (`unlock`, `open`, `anchor_pkcs8`) | `bytes` |
| `krypto::Alg` | `nettls_py.Alg`: `Aegis256`, `XChaCha20Poly1305`, `Aes256Gcm` |
| A closure (`roll_if_ready_gated`, an approval's key lookup) | A function. An exception it raises fails the call closed, and is raised afterwards. The gate must return a `bool` (PyO3 also takes NumPy's), and a key lookup `None` or what a `Vec<u8>` argument takes; anything else fails the call closed the same way, with the `TypeError` (or `OverflowError`) the conversion gives: nothing is switched, and the key counts as unknown |
| A value taken by value (`OwnMaterial` into `Announcer::new`) | The `OwnMaterial` is taken; using it afterwards is a `ValueError`. It is taken before `Announcer::new` runs, so a constructor that then fails leaves it used up. A `Schedule` given to `Announcer.new` and `Generations` given to `Trust.from_state` are copied and stay usable, and every other object a call takes by value is copied in |
| `serde_json` on the JSON types and the status report | `x.dumps()`, and `X.loads(s)` where Rust can read it back. What serde refuses in `loads`, the fingerprint check of `IdentityJson` included, is `ValueError("invalid JSON: …")` |
| `Debug` | `repr()`: the Rust `Debug` text, keys `[REDACTED]` as in Rust (`TlsMaterial`, `CertSource`, `RecipientKey`). `ClientConfig`, `ServerConfig` and `Stream` give a short name of their own, a plain enum `Class.Variant`. `OwnMaterial`, `Announcer`, `TlsConnection`, `Context` and the enums with data (`ChainState`, `ModeCheck`, `Deviation`, `Recognition`) have Python's default |
| `PartialEq` | `==` by value for `Announcement`, `Receipt`, `Handled`, `Approval`, `Recognition`, `Generation`, `Generations`, `TransportPolicy`, `Status`, `ChainState`, `ModeCheck`, `Deviation`, `FallToMode1` and `OwnTrio`, which are therefore not hashable. Other classes, the plain enums aside, compare by identity |
| rustls `ClientConfig`, `ServerConfig` | Objects that `nettls_py.stream` and `nettls_py.sslcontext` take |

No Python form: `pub use rustls`, `provider()`, `aegis::suite()` and `TlsMaterial::certified_key`
give rustls values with no meaning outside rustls; the crate never hands out a `Pending`; and
`pin::classify` and `Rejection` read a Rust error, where Python has the three exceptions of
`stream` instead. The report types (`PeerReport`, `IdentityReport`, `RotationReport`, `Report`,
`Summary`), `OwnTrio` and `FallToMode1` have no constructor: they come from the calls that return
them (`Report.collect`, `PeerReport.broken`, `Announcer.own_trio`, `FallToMode1.at`, …). `Expiry`
has no `default()`. `nettls_py.stream.ClientConfig` and `ServerConfig` have no constructor and
nothing to inspect: they come from the config builders. `nettls_py.stream.MAX_READ` is importable.

### `stream` — TLS over a Python socket, or without one (Python only)

```python
Stream.connect(sock, config: ClientConfig, server_name: str) -> Stream   # the client side
Stream.accept(sock, config: ServerConfig) -> Stream                      # the server side
stream.read(n=65536) -> bytes          # b"" after the peer's close_notify, OSError at an end
                                       # without one; n above MAX_READ (16 MiB) is ValueError
stream.write(data) -> int              # all of it, flushed
stream.flush(); stream.close()         # close sends close_notify; closing twice does nothing
stream.peer_fingerprint() -> str | None
stream.peer_certificate() -> bytes | None   # the leaf as DER, for enrollment (0.11.0)
stream.alpn_protocol() -> bytes | None   # what ALPN agreed on
```

Rust consumers drive rustls themselves, with `rustls::Stream` or `tokio-rustls`; Python has nothing
that can, so this is that piece, with no nettls logic in it. Whom to trust is the client config's
decision — `Trust::client_config` accepts `current` and `next` and promotes on proof (§6.7),
`pinned_client_config` accepts one fingerprint — and the certificate shown is the server config's,
so a `RotatingResolver` server follows the rotation. Both constructors complete the handshake
before they return; an invalid `server_name` is `ParamsError`. `Stream` is a context manager that
closes on exit, and its methods raise `ValueError` after `close`. The stream takes the socket over
(`socket.detach()`), and its timeout carries over; the object must be a `socket.socket`, and
anything else is a `TypeError` *(0.12.0)*. `read`, `write`, `flush`, `close` and the
handshake wait without the GIL; `peer_fingerprint`, `peer_certificate`, `alpn_protocol` and
`repr()` wait for the stream's lock while holding the GIL. A non-blocking socket (timeout 0) is refused
with `ValueError` and left to the caller; a closed socket is `ValueError` too. A failed handshake
closes the descriptor the stream took over. `close` takes a broken pipe, a reset or a socket that
is not connected as closed, and raises any other error after closing.
The stream does one thing at a time: a read that waits holds it, so a write from another thread
waits for that read. Serve each connection from one thread.
Socket and TLS failures are `OSError`, as Python's `ssl` gives them, and a timeout is
`TimeoutError`. A refused server certificate is one of three `OSError` subclasses, as `classify`
names it *(0.11.0)*: `UntrustedPeerError`, `CertificateExpiredError` (with `now` and `not_after`)
and `CertificateNotYetValidError` (with `now` and `not_before`), Unix seconds. `peer_fingerprint`
raises `EncodeError` when the fingerprint cannot be encoded as hex *(0.12.0)*. For asyncio and
other event loops there is `TlsConnection`, and `nettls_py.sslcontext` on top of it (below).

#### `TlsConnection` — the same connection without a socket *(0.12.0)*

```python
TlsConnection.client(config: ClientConfig, server_name: str, alpn: list[bytes] | None = None)
TlsConnection.server(config: ServerConfig)
conn.receive(data)                  # ciphertext from the peer
conn.receive_eof()                  # the transport has ended
conn.take_outgoing() -> bytes       # ciphertext to send; after a failure, the alert
conn.read(n=65536) -> bytes | None  # b"" while nothing has arrived; None after close_notify;
                                    # n above MAX_READ is ValueError
conn.write(data) -> int             # how much rustls took
conn.send_close_notify()
conn.is_handshaking() -> bool;  conn.peer_closed() -> bool
conn.pending() -> int               # plaintext held, plus ciphertext waiting for room;
                                    # can raise the connection's failure
conn.alpn_protocol() -> bytes | None;  conn.peer_certificate() -> bytes | None
conn.protocol_version() -> str | None   # "TLSv1.3" or "TLSv1.2"
conn.cipher_suite() -> str | None       # rustls' name, e.g. "TLS13_AES_256_GCM_SHA384";
                                        # nettls's AEGIS-256 suite is its code point "0xff06"
```

The caller moves the ciphertext; nothing waits, and nothing calls back into Python. `alpn`
replaces the config's protocols for that connection, and an empty list offers none; an invalid
`server_name` is `ParamsError`. While rustls holds plaintext, ciphertext that arrives
waits in the connection until `read` has taken that plaintext, and `pending()` counts it; that
queue has no limit. `write` can take less than it is given: take the output, then write the rest. A transport that ended
without `close_notify` is `ConnectionResetError` once the plaintext that arrived has been read.
Other failures are the stream's exceptions, a refused certificate included. A handshake or
certificate failure is raised by `receive` or `receive_eof`; a failure that arrives behind
plaintext is raised by `read` once that plaintext has been taken.

#### `nettls_py.sslcontext.SSLContext` — for libraries that take an `ssl.SSLContext` *(0.12.0)*

```python
from nettls_py.sslcontext import SSLContext

SSLContext(config: ClientConfig | ServerConfig)   # a subclass of ssl.SSLContext
ctx.wrap_bio(incoming, outgoing, server_side=False, server_hostname=None, session=None)
ctx.wrap_socket(sock, server_side=False, do_handshake_on_connect=True,
                suppress_ragged_eofs=True, server_hostname=None, session=None)
ctx.set_alpn_protocols(alpn_protocols)   # client only, else ValueError; an iterable (else TypeError)
                                         # of str of 1 to 255 ASCII characters: another length is
                                         # ValueError, a non-ASCII str UnicodeEncodeError, an item
                                         # that is not a str (bytes too) AttributeError; a bare str
                                         # such as "h2" is itself such an iterable: "h" and "2"
```

The context is for libraries that take an `ssl.SSLContext`: asyncio, uvicorn
(`ssl_context_factory`), httpx (`verify=`). Each connection is a `TlsConnection`; the context
holds no TLS logic. `SSLContext` with anything but a nettls config is `TypeError`.

`wrap_bio` gives the `ssl.SSLObject` methods asyncio and anyio use, with `context`, `server_side`,
`server_hostname`, `session_reused` (`False`) and `read(len=1024, buffer=None)`, and raises
`ssl.SSLWantReadError` while it waits for the peer. In both forms `server_hostname` may be `bytes`,
decoded as ASCII. `shared_ciphers`, `compression`, `selected_npn_protocol` and
`get_channel_binding` give `None`, `session` is
`None`, and `get_verified_chain`, `get_unverified_chain` and `verify_client_post_handshake` are
absent. Its `pending()` counts plaintext plus queued ciphertext, where Python's own counts
plaintext only, and its `unwrap()` drops application data that arrives while it waits for the
peer's `close_notify`. `wrap_socket` gives a blocking socket with the methods httpx's synchronous
client uses (`recv`, `send`, `sendall`, `settimeout`, `close`); it has no `makefile` or
`recv_into`, so `http.client` and the libraries built on it cannot use it. `read` on the
`wrap_bio` object and `recv` on the socket form cap the size at `MAX_READ`, and refuse a negative
size (`read` when it is given no buffer) with `ValueError`.

- **ALPN.** In front of an HTTP/1.1 server, such as uvicorn, make the server config with
  `server_config_with_alpn([b"http/1.1"])`: the default server config offers `h2` first. A list
  given with `set_alpn_protocols` replaces the `ClientConfig`'s own on both forms; the config's
  list is used as it is only where `set_alpn_protocols` was never called. `wrap_socket` drops
  `h2` from that list, which httpx sets on every connection, because httpx speaks HTTP/1.1 over
  any socket that is not a real `ssl.SSLSocket`. A server's protocols are fixed in its
  `ServerConfig`, so `set_alpn_protocols` on a server context raises `ValueError`.
- **Refused configuration.** The OpenSSL context the class inherits never carries a connection.
  The following raise `ValueError`:
  `load_cert_chain`, `load_verify_locations`, `load_default_certs`, `set_default_verify_paths`,
  `set_ciphers`, `set_ecdh_curve`, `load_dh_params`, `set_servername_callback`, and assigning
  `verify_mode`, `check_hostname`, `minimum_version`, `maximum_version`, `options`,
  `verify_flags`, `sni_callback`, `post_handshake_auth`, `keylog_filename`, `num_tickets`.
  Reading them works. The members of `ssl.SSLContext` that nettls neither refuses nor replaces act on the unused OpenSSL context,
  made for the config's side (`PROTOCOL_TLS_CLIENT` or `PROTOCOL_TLS_SERVER`), and change nothing
  for connections; what is read from it is that context's state.
- **A refused certificate** is `ssl.SSLCertVerificationError` and also the nettls exception
  (`UntrustedPeerError`, `CertificateExpiredError` or `CertificateNotYetValidError`, with its
  times), raised from it. httpx turns it into `httpx.ConnectError`, with the nettls exception in
  its exception chain.
- **Other failures.** Any other TLS failure is `ssl.SSLError`. A transport that ended during the
  handshake or without `close_notify` is `ssl.SSLEOFError`; with `suppress_ragged_eofs=True`,
  `recv` on the socket form gives `b""` for a missing `close_notify` after the handshake, while an
  end during the handshake stays `ssl.SSLEOFError`. On the socket form, socket errors pass through
  unchanged: a timeout is `TimeoutError`, a reset `ConnectionResetError`. The wrong side
  (`server_side=True` on a client context, or the reverse) is `ssl.SSLError`; a client without
  `server_hostname`, and any `session`, are `ValueError`.
- **The socket form.** `wrap_socket` refuses a non-blocking socket with `ValueError` and leaves it
  to the caller, and closes the socket after a failed handshake; with
  `do_handshake_on_connect=False` the first `recv` or `send` does the handshake. One thread can
  send while another waits in `recv`, unlike `Stream`. After a failed send the connection is
  unusable, and every later `recv`, `send` and `sendall` raises `ssl.SSLError`. `close()` sends
  `close_notify` unless another thread is sending, and shuts the socket down so a blocked thread
  wakes; closing twice does nothing. After `close()` it does not refuse calls itself: they go on
  to the connection and the closed socket. `send` takes at most 64 KiB per call, and a `flags`
  other than 0 to `recv`, `send` or `sendall` is `ValueError`. It also has `gettimeout`, `fileno`,
  `getsockname`, `getpeername`, `do_handshake`, `selected_alpn_protocol` and context-manager
  support; `settimeout(0)` raises `ValueError`.
- **What the connection reports.** `getpeercert()` gives `{}`, the DER with `binary_form=True`,
  and `None` when the peer showed no certificate; during the handshake it raises `ValueError`.
  `version()` and `cipher()` give `None` during the handshake. `cipher()` is the rustls suite
  name, the version and the key bits, with nettls's AEGIS-256 suite as `"0xff06"`.

### What is guaranteed, and where Python differs

| | Rust | Python |
|---|---|---|
| Private keys the crate holds (`TlsMaterial`, `Announcer`, `RecipientKey`) | `Announcer` and `RecipientKey`: in krypto's locked memory, kept out of core dumps on Linux, wiped on drop. `TlsMaterial`: rustls' `PrivateKeyDer` in `Zeroizing`, wiped on drop, ordinary heap, not locked; rustls holds its own parsed copy for as long as a config or resolver built from it lives, the resolver an `Announcer` switches included | The same: the objects hold Rust memory |
| What goes in | `SecretBuf`, `SecretString` | Copied in. The `bytes` or `str` passed stays as Python keeps it, neither locked nor wiped. A key given inside a tuple (`Announcement.new`, `OwnMaterial(…)`) passes through an ordinary buffer that is not wiped before it is held |
| What comes out | `SecretBuf` | `bytes`: a copy Python holds, neither locked nor wiped |
| Locked memory | Counted against `RLIMIT_MEMLOCK` of the process | The same, in the Python process |
| `fork` | The child's copies of locked pages are not locked | The same |
| TLS | rustls, with the configs above | The same rustls, through `stream` and `sslcontext`; OpenSSL never carries a connection |
| Long calls | — | These release the GIL: `TlsMaterial.load` and `save_pem`; `lockbox.lock`, `lock_with` and `unlock`; `announcement.archive` and `read_archive`; the `Announcer`'s constructor, `prepare`, `acked`, `acked_handled` *(0.12.0)*, `add_peer`, `remove_peer`, `roll_if_ready` and `save_pending`; and `Stream`'s handshake, `read`, `write`, `flush` and `close`. Every other call holds it, `roll_if_ready_gated` and `RecipientKey.generate()` included |
| A panic inside nettls | Unwinds to the caller | Becomes `pyo3_runtime.PanicException`. An object whose lock was held when the panic came then raises `LockPoisonedError` from every call that reads or changes its state; `close` on a `Stream` and on the socket from `wrap_socket` releases the socket first, and `repr()` does not raise *(0.12.0)*. The binding's own locks are in `Schedule`, `ClockDrift`, `Generations`, `OwnMaterial`, `Stream` and `TlsConnection`; `repr()` of `Schedule`, `ClockDrift`, `Generations` and `Stream` then shows `Schedule(<poisoned lock>)` and so on |
| `unsafe` | None in `nettls` (`forbid(unsafe_code)`) | One block in the binding: taking over the socket's descriptor |

---

## Further

- **[Home](Home.md)** — what nettls is, and what it is not
- **[Usage](Usage.md)** — the order, the traps, and what you do yourself
- **[Python](Python.md)** — the same, from Python
