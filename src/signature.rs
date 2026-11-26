// SPDX-License-Identifier: MIT OR Apache-2.0
//! Signing and verification for the §6 messages.
//!
//! Two signature types, because §6 has two kinds of senders:
//!
//! | Type | Key | Used for |
//! |---|---|---|
//! | **ECDSA P-256** | the certificate's key | the announcement (§6.5) — two signatures, from `prev` and `curr` |
//! | **Ed25519** | the service's signing key | the receipt (§6.6b), the operator approval (§6.4), the pair rotation (§8.5b) |
//!
//! The reason there are two and not one: the certificate lineage **rotates**,
//! and that rotation is exactly what the two signatures on the announcement
//! protect. The Ed25519 keys, by contrast, are stable, operator-distributed
//! identities the peer already pins — and a receipt moves no identity, so it
//! needs authenticity, not continuity.
//!
//! ## The primitives are `krypto`'s
//!
//! Since krypto 0.5 the actual cryptography lives in `krypto::sign` (Ed25519,
//! deterministic ECDSA P-256 — bit-compatible with what this crate produced
//! via `ring`) and `krypto::hex`. §8d.1 added them precisely so no consumer
//! carries its own signature layer — this crate was the consumer in question.
//! What remains here is the **TLS end** of the §6 domain: getting the P-256
//! key out of an X.509 certificate, and the §6 field rules. X.509 stays with
//! nettls by the boundary agreed with `krypto`.
//!
//! ## Serialization: **hex**, always
//!
//! Not base64. Not "whatever your library happens to give you". The choice is
//! normative (§6.5), and the reason is in the spec: Rust picked hex and Python
//! base64 last time, and the result was two legal choices and one unusable
//! protocol. The canonical form is `krypto::hex` — lowercase, fail-closed.

use crate::error::TlsError;

/// The longest signature a message read from JSON may carry, in hex: 144
/// characters, the 72 bytes of the longest DER-encoded ECDSA P-256 signature.
/// An Ed25519 signature, 64 bytes, fits under it *(0.12.0)*.
const MAX_SIGNATURE_HEX_LEN: usize = 144;

/// Hex → bytes for a §6 message field (a signature or a key).
///
/// The wire form is normative (§6.5): **lowercase**, even length — and a §6
/// field is never empty. The decoding itself is `krypto::hex::decode`
/// (canonical and fail-closed: uppercase, odd length or non-hex are errors,
/// never a guess). The empty-check is the one §6 rule added on top: an empty
/// signature field is a protocol error, not "zero bytes of signature".
///
/// Only an error krypto gives for the text itself says the hex is invalid;
/// any other, such as memory that could not be reserved, says the hex could
/// not be decoded *(0.12.0)*.
pub fn from_hex(s: &str) -> Result<Vec<u8>, TlsError> {
    if s.is_empty() {
        return Err(TlsError::Proof("empty hex string".into()));
    }
    krypto::hex::decode(s).map_err(|e| match e {
        krypto::Error::Format(_) => TlsError::Proof(format!("invalid hex (§6.5): {e}")),
        _ => TlsError::Proof(format!("the hex could not be decoded: {e}")),
    })
}

/// [`from_hex`] for the signature field `field` of a message read from JSON.
/// A text over [`MAX_SIGNATURE_HEX_LEN`] bytes is [`TlsError::Proof`], refused
/// before it is decoded *(0.12.0)*. Every signature field nettls reads from a
/// message is decoded here.
pub(crate) fn signature_from_hex(s: &str, field: &str) -> Result<Vec<u8>, TlsError> {
    if s.len() > MAX_SIGNATURE_HEX_LEN {
        return Err(TlsError::Proof(format!(
            "{field} is {} bytes of hex, over the bound of {MAX_SIGNATURE_HEX_LEN} for a signature; \
             it was not decoded",
            s.len()
        )));
    }
    from_hex(s)
}

// --------------------------------------------------------------------------- //
// ECDSA P-256 — the certificate lineage
// --------------------------------------------------------------------------- //

/// Extracts the public P-256 key from a DER-encoded certificate.
///
/// Refuses everything but uncompressed P-256. A different key type is not an
/// "unexpected configuration" here — it means the certificate cannot take part
/// in §6 at all, and then it must say so at once.
///
/// The bytes must be exactly one certificate, nothing after it, and the key's
/// parameters must name the curve P-256 (OID 1.2.840.10045.3.1.7) *(0.12.0)*.
/// More than 1 MiB of DER is [`TlsError::Params`], refused before it is parsed
/// *(0.12.0)*.
pub fn p256_public_key(cert_der: &[u8]) -> Result<Vec<u8>, TlsError> {
    let cert = crate::material::read_certificate(cert_der)?;
    let spki = cert.public_key();

    // 1.2.840.10045.2.1 = id-ecPublicKey.
    let alg = spki.algorithm.algorithm.to_id_string();
    if alg != "1.2.840.10045.2.1" {
        return Err(TlsError::ProofInvalid(format!(
            "the certificate has key type OID {alg}, not ECDSA (id-ecPublicKey) — \
             §6 signatures are defined for ECDSA P-256"
        )));
    }

    // 1.2.840.10045.3.1.7 = prime256v1, the curve P-256. The point length alone
    // does not tell P-256 from another curve of the same size.
    let curve = match &spki.algorithm.parameters {
        Some(p) if p.tag() == x509_parser::asn1_rs::Tag::Oid => {
            p.as_oid().ok().map(|oid| oid.to_id_string())
        }
        _ => None,
    };
    if curve.as_deref() != Some("1.2.840.10045.3.1.7") {
        let named = match &curve {
            Some(oid) => format!("the curve OID {oid}"),
            None => "no curve OID".to_string(),
        };
        return Err(TlsError::ProofInvalid(format!(
            "the certificate's EC key parameters name {named}, not P-256 \
             (1.2.840.10045.3.1.7) — §6 signatures are defined for ECDSA P-256"
        )));
    }

    let point = spki.subject_public_key.data.as_ref();
    if point.len() != 65 || point[0] != 0x04 {
        return Err(TlsError::ProofInvalid(format!(
            "expected an uncompressed P-256 point (65 bytes, first byte 0x04), got {} bytes \
             starting with 0x{:02x}",
            point.len(),
            point.first().copied().unwrap_or(0)
        )));
    }
    Ok(point.to_vec())
}

/// Verifies an ECDSA P-256 signature against the **issuer's certificate**.
///
/// It is the certificate and not the fingerprint that must come in: a
/// fingerprint is a hash, and a public key cannot be derived from it. That is
/// the whole reason the announcement carries the certificate in full (§6.5).
///
/// The key is read with [`p256_public_key`], so the certificate must be
/// exactly one certificate with a P-256 key *(0.12.0)*, of at most 1 MiB
/// *(0.12.0)*.
pub fn verify_p256(cert_der: &[u8], message: &[u8], signature: &[u8]) -> Result<(), TlsError> {
    let key = p256_public_key(cert_der)?;
    krypto::sign::ecdsa_p256_verify(&key, message, signature).map_err(|_| {
        TlsError::ProofInvalid(
            "the ECDSA P-256 signature does not hold against the issuer's certificate".into(),
        )
    })
}

/// Signs a §6 message with a certificate's P-256 key (PKCS#8 DER form).
///
/// The signing itself is `krypto::sign::ecdsa_p256_sign` — deterministic
/// (RFC 6979) and ASN.1 DER, bit-compatible with what `ring` verified. This
/// function is the boundary where the certificate key, which must exist as
/// raw DER for rustls' sake, enters krypto's fence for the signing operation.
///
/// **0.8.3:** the key arrives as a `krypto::SecretBuf` — it has been in locked
/// memory since it was built (`TlsMaterial::anchor_pkcs8`), and is never
/// copied out of it here.
///
/// **0.12.0:** a failure is [`TlsError::Sign`] with krypto's reason, which
/// names the key or the message, whichever krypto refused.
pub fn sign_p256(pkcs8: &krypto::SecretBuf, message: &[u8]) -> Result<Vec<u8>, TlsError> {
    krypto::sign::ecdsa_p256_sign(pkcs8, message)
        .map_err(|e| TlsError::Sign(format!("ECDSA P-256 signing failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::material::TlsMaterial;
    use crate::{CertSource, SelfSignedParams};

    fn cert_and_pkcs8() -> (Vec<u8>, krypto::SecretBuf) {
        let m = TlsMaterial::load(&CertSource::self_signed(SelfSignedParams::new(
            "test",
            ["test"],
        )))
        .expect("self-signed");
        let der = m.cert_chain()[0].as_ref().to_vec();
        let pkcs8 = crate::pkcs8::pkcs8_p256(m.key_der(), &der).expect("pkcs8");
        (der, pkcs8)
    }

    // --- ECDSA P-256 -------------------------------------------------------- //

    #[test]
    fn p256_rejects_altered_message() {
        let (der, pkcs8) = cert_and_pkcs8();
        let sig = sign_p256(&pkcs8, b"hey").unwrap();
        assert!(verify_p256(&der, b"hez", &sig).is_err());
    }

    #[test]
    fn p256_key_requires_one_certificate_on_the_p256_curve() {
        // 0.12.0
        let (der, _) = cert_and_pkcs8();
        let mut trailing = der.clone();
        trailing.push(0);
        let err = p256_public_key(&trailing).unwrap_err();
        assert!(
            format!("{err}").contains("there is data after the certificate (1 of"),
            "{err}"
        );

        // The curve OID 1.2.840.10045.3.1.7 with its last arc set to 1: the
        // point keeps its 65 bytes, so only the curve check can refuse it.
        let p256 = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
        let at = der
            .windows(p256.len())
            .position(|w| w == p256)
            .expect("the P-256 curve OID");
        let mut other_curve = der.clone();
        other_curve[at + p256.len() - 1] = 0x01;
        let err = p256_public_key(&other_curve).unwrap_err();
        assert!(
            format!("{err}").contains("the curve OID 1.2.840.10045.3.1.1, not P-256"),
            "{err}"
        );
    }

    #[test]
    fn p256_signing_with_a_key_that_is_not_p256_says_so() {
        // 0.12.0: the reason is krypto's own, so it names what was refused.
        let not_p256 = krypto::SecretBuf::from_vec(vec![7u8; 32]).unwrap();
        let err = sign_p256(&not_p256, b"hey").unwrap_err();
        assert!(matches!(err, TlsError::Sign(_)), "{err:?}");
        assert!(
            format!("{err}").contains("format error: the private key is not ECDSA P-256 in PKCS#8"),
            "{err}"
        );
    }

    #[test]
    fn p256_rejects_tampered_signature() {
        let (der, pkcs8) = cert_and_pkcs8();
        let mut sig = sign_p256(&pkcs8, b"hey").unwrap();
        let last = sig.len() - 1;
        sig[last] ^= 0x01;
        assert!(verify_p256(&der, b"hey", &sig).is_err());
    }

    // --- the two types must not be confusable ------------------------------- //

    #[test]
    fn an_ed25519_signature_does_not_hold_as_p256() {
        let (der, _) = cert_and_pkcs8();
        let seed = krypto::SecretBuf::from_vec(vec![7u8; 32]).unwrap();
        let sig = krypto::sign::ed25519_sign(&seed, b"hey").unwrap();
        assert!(
            verify_p256(&der, b"hey", &sig).is_err(),
            "the signature types must not be confusable"
        );
    }
}
