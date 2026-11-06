# SPDX-License-Identifier: MIT OR Apache-2.0
"""What the Python tests share: paths, and fresh identities made by the Rust code."""

from __future__ import annotations

from pathlib import Path

import krypto_py
import nettls_py as nettls

ROOT = Path(__file__).resolve().parents[2]
TESTVECTORS = ROOT / "testvectors"


def material(name: str, days: int = 30) -> tuple[str, bytes, str, bytes]:
    """A fresh self-signed identity: (cert PEM, PKCS#8 key, fingerprint, DER)."""
    params = nettls.SelfSignedParams.new(name, [name])
    params.valid_days = days
    m = nettls.TlsMaterial.load(nettls.CertSource.self_signed(params))
    der = m.cert_chain()[0]
    pem = nettls.pem.encode("CERTIFICATE", der).decode()
    return pem, m.anchor_pkcs8(), m.fingerprint_sha256(), der


def ed25519_public(seed: bytes) -> bytes:
    """The Ed25519 public key for a seed. Ed25519 is krypto's, in Rust too."""
    return krypto_py.sign.ed25519_public(krypto_py.SecretBuf.from_vec(bytearray(seed)))


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    return krypto_py.sign.ed25519_sign(krypto_py.SecretBuf.from_vec(bytearray(seed)), message)
