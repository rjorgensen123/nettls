# Development

How nettls's code is laid out, and the rules a change has to follow. Several of the rules are
held by tests, named as the guard under the rule. A guard checks what is said beside it; where
that is only a part of the rule, the text says which part. What nettls is and how to use it is in
the [README](README.md) and under [`docs/`](docs/Home.md).

## Layout

| Path | What it is |
|---|---|
| `src/` | The crate. `lib.rs` is the public root; each module is one area: `provider` (the crypto provider), `material` (certificate and key, and what can be said about them), `pin` (fingerprint pinning on the client side), `resolver` (swapping the served certificate without a restart), `announcement` (the announcement, the receipt, the handled message and the archive), `approval` (recognitions), `generations` (the generation pair), `announcer` (the rotation), `canonical` (what gets signed), `signature` (signing and verification), `lockbox` (local state locked with a password), `envelope` (sealed envelopes), `capability` (the signed AEAD support statement), `transport` (the TLS channel's cipher), `aegis` (the AEGIS-256 TLS suite), `status` (the status report), `pem` (PEM out, and writing files), `error`; private: `fingerprint`, `pkcs8`, `secret` (private keys in memory) |
| `nettls-py/` | The Python binding, built from the same code. `src/` has one file per public nettls module, and `stream.rs`, which only Python has; `python/nettls_py/` is the Python package, with `sslcontext.py`; `tests/` holds the binding's tests |
| `tests/` | Integration tests, one file per area |
| `testvectors/` | `canonical.json`, the normative vectors, and `errors.json`, the error corpus |
| `examples/ringnode.rs` | A ring node in Rust, which the Python ring tests run |
| `docs/` | `API.md` is the contract; `Usage.md`, `Python.md` and `Home.md` explain; `Reviews.md` lists the reviews |
| `.gitea/workflows/`, `.github/workflows/` | CI on Gitea and on GitHub, with the same checks in both |

## Fixed design constraints

- **No cryptographic primitive of its own.** Signatures, key agreement, key derivation, hashing,
  encryption at rest and random numbers are krypto's; TLS is rustls with the ring provider, and
  certificates are made by rcgen on the same ring backend. One deliberate exception, stated in
  `src/aegis.rs`: the AEGIS-256 TLS suite takes its primitive from the `aegis` crate.
- **One crypto provider, chosen explicitly.** `install_crypto_provider()` makes ring the process
  default when none is installed, and every configuration the crate builds names its provider. A
  second provider must not enter the lock file. Guard: `no_other_crypto_provider_in_cargo_lock` in
  `tests/provider.rs`, which fails when `aws-lc-rs` or `aws-lc-sys` is in `Cargo.lock`.
- **No async runtime and no web framework in the library.** It returns configurations and facts;
  the consumer binds, schedules and logs. nettls's own code does not log and writes nothing to
  stdout or stderr. rustls is built with its `logging` feature, so it writes `log` records when
  the consumer installs a logger.
- **Fail-closed.** What cannot be done as promised is an error, never a weaker result.
- **Private keys the crate holds are in krypto's locked memory** and wiped when dropped. The
  exceptions are stated in `src/secret.rs`: rustls' copy of the key is not locked, short-lived
  buffers are wiped but not locked, and a new key passes through rcgen before the crate holds it.
  Types that hold a key do not show it in `Debug`. Guards, for `TlsMaterial`, `CertSource` and
  `RecipientKey`: `debug_never_leaks_the_key` in `tests/selfsigned.rs` and
  `the_key_is_redacted_in_debug` in `src/envelope.rs`.
- **`unsafe`:** the library forbids it (`#![forbid(unsafe_code)]`). The binding has one `unsafe`
  block, in `nettls-py/src/stream.rs`, with its reason written beside it.
- **State on disk is kept in the directories the consumer gives:** the announcer's files, the
  certificate pair and the archive. A peer's state is the consumer's to keep.
- **The minimum Rust version is `rust-version` in `Cargo.toml`.** CI checks every target with
  exactly that version, and runs the rest on the newest stable Rust. CI runs on Linux; the build,
  test and minimum-version jobs run in the `rust:1-bookworm` container. The Python package
  declares Linux, and the stable ABI from Python 3.11 (`abi3-py311`).

## Input

**Input is validated before it is used:** type, length, range and character set, fail-closed.
`docs/API.md` states this rule at its top.

**An input a change adds gets an upper bound,** an error that says so, and a line in
`docs/API.md`. Bounded: certificate names (SANs and the common name) and their number,
fingerprints in messages and the pin an operator writes, signatures read from messages, a
certificate as PEM wherever nettls parses one for an announcement, an identity or a `Generation`, a
certificate as DER wherever nettls parses one and the DER `cert_fingerprint_sha256` hashes, the size
of a certificate nettls generates, the validity in days, certificate and key files and PEM given
directly, the files the announcer keeps, the archive and its lines, peer names and their number,
ALPN lists, PEM labels, the JSON text `loads` takes in Python, the ciphertext a Python
`TlsConnection` holds, the locked file and the envelope, and passwords; whatever reaches krypto is
bounded by krypto's limits. A file is checked against its bound before it is read, and no more than
one byte past the bound is ever read.

Not every existing input has a bound. Among those without one: the names, fingerprints and list of
peers the status report takes (`PeerReport`, `Report::collect`); the `fingerprint` given to
`IdentityJson::new`, and the `not_after` of an `IdentityJson`; the `supported` list of a
`SupportStatement`, which `verify` joins before it checks it; the text the `message` calls of
`Status`, `ModeCheck`, `ClockDrift` and `Deviation` put into their messages; the announcer's `name`
and the fingerprints in its `OwnMaterial`, which `Announcer::new` keeps unchecked until `prepare`;
the list `Schedule::restore_announced` takes; and text that is only compared, such as the name a
`verify` expects, the peer given to `remove_peer` and the fingerprint given to
`Generations::observed`. `Announcement::verify` hashes the receiver's own certificates
(`prev_cert_der`, `curr_cert_der`) before the 1 MiB bound applies to them.

**No input makes the crate panic.** Guard, for the announcement, the receipt and the approval, and
the cases in the corpus (the handled message *(0.12.0)* is not in it): the error corpus
`testvectors/errors.json`, run by `incoming_announcement_is_rejected`,
`incoming_receipt_is_rejected` and `incoming_approval_is_rejected` in `tests/errors.rs`, and by
the same tests with a `test_` prefix in `nettls-py/tests/test_errors.py`. A panic fails them.
Guard, for corrupted input: `tests/corrupted_input.rs` takes one valid instance of the
announcement, the receipt, the handled message, the approval, the identity (`IdentityJson`), the
support statement, a certificate as PEM and as DER, the certificate and key PEM `CertSource::pem`
takes, the pin, the envelope, the locked file, the announcer's `pending-rotation.json`,
`previous-key.json`, `cert.pem` and `key.pem`, and the archive. It replaces, cuts off, inserts and
repeats bytes in it, each corruption drawn from a fixed seed, and hands the corrupted instance to
the public call that reads it. A panic fails the test; what a call answers to a corrupted instance
is not checked. A valid instance made with a fresh key, salt or signature differs from run to run,
so a panic is reported with the corrupted input. The locked file is corrupted only in what
`lockbox::unlock` checks before it derives a key from the password (the header, and that the file
holds header and salt), and an instance that would pass those checks is not handed on. The
announcer's files are read without a password, so its locked files are not covered, and neither is
the pair in `new/`, which is loaded by the same code as `cert.pem` and `key.pem`.

## Answers

**An error names what actually failed.** When locking, sealing, opening, signing, encoding or
holding a secret fails because krypto refused what it was given as too large or malformed, or
could not hold a secret in locked memory, krypto's own text is in the message. A signature, a
sealed value or a public key that does not verify, or cannot be checked, gets nettls's own text.
The classes are the `TlsError` variants in `src/error.rs`, and `docs/API.md` says which one each
case gives. In Python each variant is its own exception, a subclass of `TlsError`. Guards, for
the texts of `LockedMemory`, `Random`, `LockPoisoned`, `Envelope`, `Encode`, and `Params` for
content krypto refuses: `the_new_variants_say_what_failed`,
`not_held_tells_refused_content_from_locked_memory` and `encode_says_what_could_not_be_encoded`
in `src/error.rs`.

**No error carries key material, a password or plaintext.** This rule has no guard: it is read
against the code.

## Formats

**What is on the wire and on disk is frozen:** the table at the top of `docs/API.md` (canonical
prefixes and form, JSON field names, mode values, file names on disk, blob magics and KDF labels). A
new need gets a new version beside the old one. The handled message *(0.12.0)* is one:
`nettls-rotate-handled/v1` beside the receipt, `nettls-rotate-ack/v2`. The one who receives an
announcement it has already handled sends the receipt first and then the handled message, so an
older node accepts the receipt and refuses the handled message with "unknown message version",
changing nothing; the one who announces treats a verified handled message as a receipt. Section
numbers such as `§6.5` in comments and docs refer to the specification the crate was built from; it
is not in this repository.

**The canonical bytes are held by normative vectors** in `testvectors/canonical.json`. Guard:
`vectors_match_byte_for_byte` in `tests/testvectors.rs`; from Python,
`test_vectors_match_byte_for_byte` and `test_no_vector_is_missing` in
`nettls-py/tests/test_nettls.py`. `testvectors/canonical.json` is regenerated with
`WRITE_VECTORS=1 cargo test --test testvectors`, which writes what the code builds and does not
compare.

## The public surface

**`docs/API.md` is the contract.** Every public name is in it. Guard:
`every_public_name_is_in_the_contract_docs` in `tests/docs.rs`, which checks that each name
declared `pub` in `src/` (functions, constants, types, traits and modules) and each name in the
root's `pub use` lists appears in the document. What the text says about behaviour has no guard:
it is read against the code.

**Rust and Python have the same surface.** Anything only one side has is listed with a written
reason. Guard: `the_python_api_is_the_rust_api` in `nettls-py/tests/surface.rs`.

## Dependencies

`Cargo.lock` is committed, and CI builds with `--locked`. `cargo deny --workspace check` runs in CI
against `deny.toml`: advisories (yanked crates refused), a license allow list, banned crates
(`aws-lc-rs`, `aws-lc-sys`, `rsa`) and sources (crates.io only). The Python packages CI needs are
pinned in `nettls-py/requirements-ci.txt`. A new crate or Python package gets a row in
`THIRD_PARTY_LICENSES.md`. Guard: the tests in `tests/third_party.rs`.

`rustls`, `rcgen` and `tokio-rustls` (the last for the tests only) are taken with
`default-features = false`: the default features of rustls and tokio-rustls bring in aws-lc-rs, a
second provider. The comment at the top of the dependencies in `Cargo.toml` gives the rules.
krypto comes from crates.io as published.

## Language, changelog and commits

- Everything in the repository is in English: code and names, comments, documentation,
  `CHANGELOG.md` and commit messages.
- `CHANGELOG.md` has an entry for every change, with its date, and describes the result for the
  one who uses nettls. A change that breaks an existing use is marked ⚠. It refers to nothing
  outside nettls: no case or issue numbers, reviews or other systems.
- The documentation says what the code does, and no more.
- The developer approves every changelog entry and every commit message before the commit is made.

## Reviews

A review of nettls is added to `docs/Reviews.md` with its date, reviewer, version and kind, and its
reviewer is named in the Reviews section of `README.md` and `docs/Home.md`.

## Versions and comments

- The version is written in `Cargo.toml` and in `nettls-py/Cargo.toml`, which the Python package
  takes its version from, and `CHANGELOG.md` has a heading for it. The code derives it from
  `Cargo.toml`: `nettls::VERSION` and `nettls_py.__version__`. Guards:
  `changelog_has_an_entry_for_the_current_version`, `version_constant_mirrors_cargo_toml` and
  `the_binding_has_the_crates_version` in `tests/version.rs`, and `test_the_version_is_the_crates`
  in `nettls-py/tests/test_nettls.py`.
- Every Rust and Python source file starts with its SPDX license line.
- Documentation and doc comments mark the version a statement applies from: `*(x.y.z)*` in
  Markdown and doc comments, `(x.y.z)` in plain comments and strings.
- Comments are in English and say what and why. They contain no status such as "tested" or
  "pending".

## Tests

- CI runs, the same in both workflow files:
  - `cargo fmt --all --check`, `cargo clippy --all-targets --locked -- -D warnings`,
    `cargo test --locked --all-targets` and `cargo package --locked`;
  - for the binding, in a virtual environment with the packages from
    `nettls-py/requirements-ci.txt`:
    `cargo clippy --locked -p nettls-py --all-targets -- -D warnings`,
    `maturin develop --locked -m nettls-py/Cargo.toml`, `cargo test --locked -p nettls-py` and
    `pytest nettls-py/tests`; the two cargo commands need `PYO3_PYTHON` set to its Python;
  - with the Rust named in `rust-version`:
    `PYO3_NO_PYTHON=1 PYO3_BUILD_EXTENSION_MODULE=1 cargo check --workspace --all-targets --locked`;
  - `cargo deny --workspace check`.
- The tests hold secrets in locked memory, and CI runs them under a memlock limit of 1 MiB
  (`ulimit -l 1024` sets the same locally). The Python ring tests start
  `cargo run --example ringnode`, so `cargo`, with a Rust no older than `rust-version`, must be on
  the path; without `cargo` they are skipped.
- A new rule the code is to keep gets a test that fails when it is broken; the rules above that
  have no guard say so. CI runs on pull requests and on `main`.
