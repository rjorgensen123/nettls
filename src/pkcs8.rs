// SPDX-License-Identifier: MIT OR Apache-2.0
//! PKCS#8-building for P-256 keys — internal helpers behind
//! [`TlsMaterial::anchor_pkcs8`](crate::material::TlsMaterial::anchor_pkcs8):
//! the documented crossing TLS domain → §6 anchor. Lived in the retired §5
//! module (`rotation.rs`, removed 0.8.2); the helpers are §6's too, so they
//! moved here rather than dying with it.

use krypto::SecretBuf;
use rustls::pki_types::PrivateKeyDer;

use crate::error::TlsError;
use crate::secret;
use crate::signature::p256_public_key as ec_p256_public_key;

/// Produces the key as PKCS#8, the form `krypto::sign::ecdsa_p256_sign` wants
/// it in — in locked memory (0.8.3, see `secret.rs`).
///
/// - `Pkcs8` (what `nettls` itself generates, and what `save_pem`/`load`
///   preserves) is passed straight through.
/// - `Sec1` (`-----BEGIN EC PRIVATE KEY-----`, i.e. what `openssl ecparam`
///   emits) gets wrapped: we extract the 32-byte private scalar and combine it
///   with the public point from the certificate. Without this, a perfectly
///   ordinary operator-supplied EC key could not rotate, and the failure would
///   have been incomprehensible.
/// - Everything else (RSA) → an explanatory error.
///
/// On the `Sec1` path the scalar is in locked memory from the moment it is
/// read out, and the PKCS#8 is assembled in one buffer that is moved into
/// locked memory and wiped *(0.12.0)*.
pub(crate) fn pkcs8_p256(
    key: &PrivateKeyDer<'static>,
    cert_der: &[u8],
) -> Result<SecretBuf, TlsError> {
    match key {
        PrivateKeyDer::Pkcs8(k) => secret::hold(k.secret_pkcs8_der().to_vec()),
        PrivateKeyDer::Sec1(k) => {
            // The point first: reading it from the certificate is the step
            // that can fail, and no secret has been copied yet.
            let point = ec_p256_public_key(cert_der)?;
            let point: &[u8; POINT_LEN] = point.as_slice().try_into().map_err(|_| {
                TlsError::Sign(
                    "the public key in the certificate is not an uncompressed P-256 point"
                        .to_string(),
                )
            })?;
            let scalar = sec1_private_scalar(k.secret_sec1_der())?;
            scalar.expose(|s| {
                let s: &[u8; SCALAR_LEN] = s.try_into().map_err(|_| sec1_form_error())?;
                secret::hold(pkcs8_from_parts(s, point))
            })
        }
        _ => Err(TlsError::Sign(
            "the private key is not an EC key (probably RSA) — signing requires ECDSA \
             P-256, which is what `nettls` generates itself. An RSA certificate can still be \
             served and pinned statically, it just cannot rotate."
                .to_string(),
        )),
    }
}

/// The private scalar of a P-256 key, in bytes.
const SCALAR_LEN: usize = 32;
/// An uncompressed P-256 point: `0x04`, X, Y.
const POINT_LEN: usize = 65;

fn sec1_form_error() -> TlsError {
    TlsError::Sign(
        "the EC private key (SEC1) does not have the expected form SEQUENCE { INTEGER 1, \
         OCTET STRING (32 bytes), … } for P-256"
            .to_string(),
    )
}

/// Extracts the private scalar from a SEC1 `ECPrivateKey`, straight into
/// locked memory *(0.12.0)*.
///
/// ```text
/// ECPrivateKey ::= SEQUENCE {
///     version        INTEGER { ecPrivkeyVer1(1) },
///     privateKey     OCTET STRING,          ← 32 byte for P-256
///     parameters [0] ECParameters OPTIONAL,
///     publicKey  [1] BIT STRING OPTIONAL }
/// ```
///
/// We read only the first two fields, and we read them **strictly**: anything
/// that deviates from the form above is an error, not something to guess past.
fn sec1_private_scalar(der: &[u8]) -> Result<SecretBuf, TlsError> {
    let err = sec1_form_error;
    // SEQUENCE header: tag 0x30, then short or long length form.
    let mut i = 0usize;
    if der.first() != Some(&0x30) {
        return Err(err());
    }
    i += 1;
    let len_byte = *der.get(i).ok_or_else(err)?;
    i += 1;
    if len_byte & 0x80 != 0 {
        let n = (len_byte & 0x7f) as usize;
        if n == 0 || n > 4 {
            return Err(err());
        }
        i += n;
    }
    // version INTEGER 1
    if der.get(i..i + 3) != Some(&[0x02, 0x01, 0x01][..]) {
        return Err(err());
    }
    i += 3;
    // privateKey OCTET STRING (32)
    if der.get(i..i + 2) != Some(&[0x04, 0x20][..]) {
        return Err(err());
    }
    i += 2;
    let raw = der.get(i..i + SCALAR_LEN).ok_or_else(err)?;
    secret::hold(raw.to_vec())
}

/// Builds a PKCS#8 v1 key (version 0, `id-ecPublicKey` / `prime256v1`) around
/// scalar + point; the point goes in the inner `ECPrivateKey`, not at the
/// PKCS#8 level.
///
/// The scalar is 32 bytes and the point 65, so every length is known before
/// anything is written. The key is assembled in one buffer of its final size,
/// which is therefore never moved, and the caller moves it straight into locked
/// memory, which wipes the buffer *(0.12.0)*.
fn pkcs8_from_parts(scalar: &[u8; SCALAR_LEN], point: &[u8; POINT_LEN]) -> Vec<u8> {
    // AlgorithmIdentifier { id-ecPublicKey, prime256v1 }
    const ALG: [u8; 21] = [
        0x30, 0x13, // SEQUENCE
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // 1.2.840.10045.2.1
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // 1.2.840.10045.3.1.7
    ];
    // The lengths, from the inside out:
    //   BIT STRING content: the unused-bits byte and the point
    const BIT: u8 = 1 + POINT_LEN as u8;
    //   [1] content: the BIT STRING with its header
    const TAGGED: u8 = 2 + BIT;
    //   ECPrivateKey content: version, the scalar's OCTET STRING, [1]
    const EC: u8 = 3 + 2 + SCALAR_LEN as u8 + 2 + TAGGED;
    //   privateKey OCTET STRING content: the ECPrivateKey with its header
    const EC_SEQ: u8 = 2 + EC;
    //   PKCS#8 content: version, AlgorithmIdentifier, privateKey
    const INNER: u8 = 3 + ALG.len() as u8 + 2 + EC_SEQ;
    //   the whole key: SEQUENCE in the long length form, since INNER is over 127
    const TOTAL: usize = 3 + INNER as usize;

    let mut out = Vec::with_capacity(TOTAL);
    out.extend_from_slice(&[0x30, 0x81, INNER]);
    out.extend_from_slice(&[0x02, 0x01, 0x00]); // version 0
    out.extend_from_slice(&ALG);
    out.extend_from_slice(&[0x04, EC_SEQ]); // privateKey OCTET STRING
    // ECPrivateKey with publicKey [1]:
    //   SEQUENCE { INTEGER 1, OCTET STRING (32), [1] { BIT STRING (0x04||X||Y) } }
    out.extend_from_slice(&[0x30, EC]);
    out.extend_from_slice(&[0x02, 0x01, 0x01]); // version 1
    out.extend_from_slice(&[0x04, SCALAR_LEN as u8]);
    out.extend_from_slice(scalar);
    out.extend_from_slice(&[0xa1, TAGGED, 0x03, BIT, 0x00]); // [1] EXPLICIT BIT STRING
    out.extend_from_slice(point);
    debug_assert_eq!(out.len(), TOTAL);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::material::TlsMaterial;
    use crate::{CertSource, SelfSignedParams};

    #[test]
    fn a_sec1_key_becomes_the_pkcs8_of_its_certificate() {
        let m = TlsMaterial::load(&CertSource::self_signed(SelfSignedParams::new(
            "gateway",
            ["gateway"],
        )))
        .unwrap();
        let cert = m.cert_chain()[0].as_ref().to_vec();
        // The same key in the SEC1 form an operator may hand in: the scalar
        // from the generated PKCS#8, in a bare `ECPrivateKey`.
        let PrivateKeyDer::Pkcs8(generated) = m.key_der() else {
            panic!("a generated key is PKCS#8");
        };
        let der = generated.secret_pkcs8_der();
        let at = der
            .windows(5)
            .position(|w| w == [0x02, 0x01, 0x01, 0x04, 0x20])
            .unwrap()
            + 5;
        let mut sec1 = vec![0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20];
        sec1.extend_from_slice(&der[at..at + SCALAR_LEN]);
        let key = PrivateKeyDer::Sec1(sec1.into());

        let pkcs8 = pkcs8_p256(&key, &cert).unwrap();
        let signature = crate::signature::sign_p256(&pkcs8, b"message").unwrap();
        crate::signature::verify_p256(&cert, b"message", &signature).unwrap();

        // A certificate that cannot be read is an error, before the key is touched.
        assert!(pkcs8_p256(&key, b"not a certificate").is_err());
    }
}
