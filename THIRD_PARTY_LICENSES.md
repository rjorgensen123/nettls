# Third-party licenses

nettls's own code is licensed under MIT OR Apache-2.0, at the recipient's choice; see
[`LICENSE-MIT`](LICENSE-MIT) and [`LICENSE-APACHE`](LICENSE-APACHE). This file lists what nettls
builds on that is not its own, and the license each part declares. Nothing in the repository
itself is third-party code. `CODE_OF_CONDUCT.md` is adapted from the Contributor Covenant,
version 2.1, as the file itself says.

The license given for each part is the one the part itself declares: the `license` field of the
crate's manifest for the Rust crates, and the package metadata for the Python packages.

## Rust crates

These are not in the repository: cargo fetches them from crates.io. The list covers every package
in `Cargo.lock` except the workspace's own two, `nettls` and `nettls-py`, with one row per crate
name; the versions are in `Cargo.lock`.

"Used by" says what compiles the crate, on any target platform: `nettls and nettls-py` (the
binding is built on the library, so what the library uses, the binding uses too), `nettls-py`,
`tests and build only` (the dependencies of the tests, the example and build scripts), or
`not built` (an optional dependency that is in `Cargo.lock` but that no build of nettls enables).

| Crate | License | Used by |
|---|---|---|
| aead | MIT OR Apache-2.0 | nettls and nettls-py |
| aegis | MIT | nettls and nettls-py |
| aes | MIT OR Apache-2.0 | nettls and nettls-py |
| aes-gcm | Apache-2.0 OR MIT | nettls and nettls-py |
| argon2 | MIT OR Apache-2.0 | nettls and nettls-py |
| asn1-rs | MIT OR Apache-2.0 | nettls and nettls-py |
| asn1-rs-derive | MIT OR Apache-2.0 | nettls and nettls-py |
| asn1-rs-impl | MIT/Apache-2.0 | nettls and nettls-py |
| autocfg | Apache-2.0 OR MIT | tests and build only |
| base16ct | Apache-2.0 OR MIT | nettls and nettls-py |
| base64 | MIT OR Apache-2.0 | nettls and nettls-py |
| base64ct | Apache-2.0 OR MIT | nettls and nettls-py |
| bit-vec | Apache-2.0 OR MIT | not built |
| blake2 | MIT OR Apache-2.0 | nettls and nettls-py |
| block-buffer | MIT OR Apache-2.0 | nettls and nettls-py |
| bytes | MIT | tests and build only |
| cc | MIT OR Apache-2.0 | tests and build only |
| cfg-if | MIT OR Apache-2.0 | nettls and nettls-py |
| chacha20 | MIT OR Apache-2.0 | nettls and nettls-py |
| chacha20poly1305 | Apache-2.0 OR MIT | nettls and nettls-py |
| cipher | MIT OR Apache-2.0 | nettls and nettls-py |
| cmov | Apache-2.0 OR MIT | nettls and nettls-py |
| const-oid | Apache-2.0 OR MIT | nettls and nettls-py |
| cpubits | MIT OR Apache-2.0 | nettls and nettls-py |
| cpufeatures | MIT OR Apache-2.0 | nettls and nettls-py |
| crypto-bigint | Apache-2.0 OR MIT | nettls and nettls-py |
| crypto-common | MIT OR Apache-2.0 | nettls and nettls-py |
| ctr | MIT OR Apache-2.0 | nettls and nettls-py |
| ctutils | Apache-2.0 OR MIT | nettls and nettls-py |
| curve25519-dalek | BSD-3-Clause | nettls and nettls-py |
| curve25519-dalek-derive | MIT/Apache-2.0 | nettls and nettls-py |
| data-encoding | MIT | nettls and nettls-py |
| der | Apache-2.0 OR MIT | nettls and nettls-py |
| der-parser | MIT OR Apache-2.0 | nettls and nettls-py |
| deranged | MIT OR Apache-2.0 | nettls and nettls-py |
| digest | MIT OR Apache-2.0 | nettls and nettls-py |
| displaydoc | MIT OR Apache-2.0 | nettls and nettls-py |
| ecdsa | Apache-2.0 OR MIT | nettls and nettls-py |
| ed25519 | Apache-2.0 OR MIT | nettls and nettls-py |
| ed25519-dalek | BSD-3-Clause | nettls and nettls-py |
| elliptic-curve | Apache-2.0 OR MIT | nettls and nettls-py |
| ff | MIT/Apache-2.0 | nettls and nettls-py |
| fiat-crypto | MIT OR Apache-2.0 OR BSD-1-Clause | nettls and nettls-py |
| find-msvc-tools | MIT OR Apache-2.0 | tests and build only |
| getrandom | MIT OR Apache-2.0 | nettls and nettls-py |
| ghash | Apache-2.0 OR MIT | nettls and nettls-py |
| group | MIT/Apache-2.0 | nettls and nettls-py |
| heck | MIT OR Apache-2.0 | nettls-py |
| hkdf | MIT OR Apache-2.0 | nettls and nettls-py |
| hmac | MIT OR Apache-2.0 | nettls and nettls-py |
| hybrid-array | MIT OR Apache-2.0 | nettls and nettls-py |
| inout | MIT OR Apache-2.0 | nettls and nettls-py |
| itoa | MIT OR Apache-2.0 | nettls and nettls-py |
| krypto | MIT OR Apache-2.0 | nettls and nettls-py |
| lazy_static | MIT OR Apache-2.0 | nettls and nettls-py |
| libc | MIT OR Apache-2.0 | nettls and nettls-py |
| log | MIT OR Apache-2.0 | nettls and nettls-py |
| memchr | Unlicense OR MIT | nettls and nettls-py |
| minimal-lexical | MIT/Apache-2.0 | nettls and nettls-py |
| mio | MIT | tests and build only |
| nom | MIT | nettls and nettls-py |
| num-bigint | MIT OR Apache-2.0 | nettls and nettls-py |
| num-conv | MIT OR Apache-2.0 | nettls and nettls-py |
| num-integer | MIT OR Apache-2.0 | nettls and nettls-py |
| num-traits | MIT OR Apache-2.0 | nettls and nettls-py |
| oid-registry | MIT OR Apache-2.0 | nettls and nettls-py |
| once_cell | MIT OR Apache-2.0 | nettls and nettls-py |
| p256 | Apache-2.0 OR MIT | nettls and nettls-py |
| password-hash | MIT OR Apache-2.0 | nettls and nettls-py |
| pem | MIT | nettls and nettls-py |
| pem-rfc7468 | Apache-2.0 OR MIT | nettls and nettls-py |
| phc | Apache-2.0 OR MIT | nettls and nettls-py |
| pin-project-lite | Apache-2.0 OR MIT | tests and build only |
| pkcs8 | Apache-2.0 OR MIT | nettls and nettls-py |
| poly1305 | Apache-2.0 OR MIT | nettls and nettls-py |
| polyval | Apache-2.0 OR MIT | nettls and nettls-py |
| portable-atomic | Apache-2.0 OR MIT | nettls-py |
| powerfmt | MIT OR Apache-2.0 | nettls and nettls-py |
| primefield | Apache-2.0 OR MIT | nettls and nettls-py |
| primeorder | Apache-2.0 OR MIT | nettls and nettls-py |
| proc-macro2 | MIT OR Apache-2.0 | nettls and nettls-py |
| pyo3 | MIT OR Apache-2.0 | nettls-py |
| pyo3-build-config | MIT OR Apache-2.0 | tests and build only |
| pyo3-ffi | MIT OR Apache-2.0 | nettls-py |
| pyo3-macros | MIT OR Apache-2.0 | nettls-py |
| pyo3-macros-backend | MIT OR Apache-2.0 | nettls-py |
| quote | MIT OR Apache-2.0 | nettls and nettls-py |
| r-efi | MIT OR Apache-2.0 OR LGPL-2.1-or-later | nettls and nettls-py |
| rand_core | MIT OR Apache-2.0 | nettls and nettls-py |
| rcgen | MIT OR Apache-2.0 | nettls and nettls-py |
| rfc6979 | Apache-2.0 OR MIT | nettls and nettls-py |
| ring | Apache-2.0 AND ISC | nettls and nettls-py |
| rustc_version | MIT OR Apache-2.0 | tests and build only |
| rusticata-macros | MIT/Apache-2.0 | nettls and nettls-py |
| rustls | Apache-2.0 OR ISC OR MIT | nettls and nettls-py |
| rustls-pki-types | MIT OR Apache-2.0 | nettls and nettls-py |
| rustls-webpki | ISC | nettls and nettls-py |
| sec1 | Apache-2.0 OR MIT | nettls and nettls-py |
| semver | MIT OR Apache-2.0 | tests and build only |
| serde | MIT OR Apache-2.0 | nettls and nettls-py |
| serde_core | MIT OR Apache-2.0 | nettls and nettls-py |
| serde_derive | MIT OR Apache-2.0 | nettls and nettls-py |
| serde_json | MIT OR Apache-2.0 | nettls and nettls-py |
| serdect | Apache-2.0 OR MIT | not built |
| sha2 | MIT OR Apache-2.0 | nettls and nettls-py |
| shlex | MIT OR Apache-2.0 | tests and build only |
| signature | Apache-2.0 OR MIT | nettls and nettls-py |
| socket2 | MIT OR Apache-2.0 | tests and build only |
| softaes | MIT | nettls and nettls-py |
| spki | Apache-2.0 OR MIT | nettls and nettls-py |
| subtle | BSD-3-Clause | nettls and nettls-py |
| syn | MIT OR Apache-2.0 | nettls and nettls-py |
| synstructure | MIT | nettls and nettls-py |
| target-lexicon | Apache-2.0 WITH LLVM-exception | tests and build only |
| thiserror | MIT OR Apache-2.0 | nettls and nettls-py |
| thiserror-impl | MIT OR Apache-2.0 | nettls and nettls-py |
| time | MIT OR Apache-2.0 | nettls and nettls-py |
| time-core | MIT OR Apache-2.0 | nettls and nettls-py |
| time-macros | MIT OR Apache-2.0 | nettls and nettls-py |
| tokio | MIT | tests and build only |
| tokio-macros | MIT | tests and build only |
| tokio-rustls | MIT OR Apache-2.0 | tests and build only |
| typenum | MIT OR Apache-2.0 | nettls and nettls-py |
| unicode-ident | (MIT OR Apache-2.0) AND Unicode-3.0 | nettls and nettls-py |
| universal-hash | MIT OR Apache-2.0 | nettls and nettls-py |
| untrusted | ISC | nettls and nettls-py |
| wasi | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | nettls and nettls-py |
| windows-link | MIT OR Apache-2.0 | tests and build only |
| windows-sys | MIT OR Apache-2.0 | nettls and nettls-py |
| windows-targets | MIT OR Apache-2.0 | nettls and nettls-py |
| windows_aarch64_gnullvm | MIT OR Apache-2.0 | nettls and nettls-py |
| windows_aarch64_msvc | MIT OR Apache-2.0 | nettls and nettls-py |
| windows_i686_gnu | MIT OR Apache-2.0 | nettls and nettls-py |
| windows_i686_gnullvm | MIT OR Apache-2.0 | nettls and nettls-py |
| windows_i686_msvc | MIT OR Apache-2.0 | nettls and nettls-py |
| windows_x86_64_gnu | MIT OR Apache-2.0 | nettls and nettls-py |
| windows_x86_64_gnullvm | MIT OR Apache-2.0 | nettls and nettls-py |
| windows_x86_64_msvc | MIT OR Apache-2.0 | nettls and nettls-py |
| wnaf | Apache-2.0 OR MIT | nettls and nettls-py |
| x25519-dalek | BSD-3-Clause | nettls and nettls-py |
| x509-parser | MIT OR Apache-2.0 | nettls and nettls-py |
| yasna | MIT OR Apache-2.0 | nettls and nettls-py |
| zeroize | Apache-2.0 OR MIT | nettls and nettls-py |
| zmij | MIT | nettls and nettls-py |

## Python packages

These are not part of the `nettls-py` package, which depends on nothing at run time: its
`pyproject.toml` lists no dependencies. They are what CI installs to build and test it: the build
tool, the test runner and what the tests use, pinned with their versions in
`nettls-py/requirements-ci.txt`.

| Package | License | Used by |
|---|---|---|
| anyio | MIT | tests (pulled in by httpx) |
| certifi | MPL-2.0 | tests (pulled in by httpx) |
| click | BSD-3-Clause | tests (pulled in by uvicorn) |
| h11 | MIT | tests (pulled in by uvicorn and httpx) |
| httpcore | BSD-3-Clause | tests (pulled in by httpx) |
| httpx | BSD-3-Clause | tests |
| idna | BSD-3-Clause | tests (pulled in by httpx) |
| iniconfig | MIT | test runner (pulled in by pytest) |
| krypto-py | MIT OR Apache-2.0 | tests |
| maturin | MIT OR Apache-2.0 | build tool |
| packaging | Apache-2.0 OR BSD-2-Clause | test runner (pulled in by pytest) |
| pluggy | MIT | test runner (pulled in by pytest) |
| Pygments | BSD-2-Clause | test runner (pulled in by pytest) |
| pytest | MIT | test runner |
| typing_extensions | PSF-2.0 | tests (pulled in by httpx) |
| uvicorn | BSD-3-Clause | tests |
