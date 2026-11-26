// SPDX-License-Identifier: MIT OR Apache-2.0
//! The announcement — "here is my next certificate" (SPEC-nettls §6.5).
//!
//! This is the message that makes the rotation **asynchronous**. The receiver
//! learns the counterpart's next identity *before* it is taken into use, and
//! thus never needs to know **when** the switch happens — it accepts both from
//! the moment the announcement is stored.
//!
//! ## Two signatures, and why
//!
//! The announcement is signed with the **previous** and the **current** key.
//! Forging it therefore requires *two consecutive* private keys. If an attacker
//! steals only the current one, he lacks the previous — and he cannot wait his
//! way to it either, for at the next generation he does own the "previous",
//! but lacks the new current one.
//!
//! By comparison, the model this replaced signed each proof with **only** the
//! outgoing key.
//! One stolen key was enough to sign one's way forward indefinitely, and it
//! looked like legitimate rotation.
//!
//! ## The exception: the very first rotation
//!
//! At rotation 1 only `cert0` exists. The anchor is the operator's approval
//! (generation 0), but it is signed with **portal's** Ed25519 key, which the
//! announcer does not have. The first announcement is therefore **single-signed** (§6.3).
//!
//! This is not a tolerance, but a rule with a precise condition: a single
//! signature is accepted **only** when the receiver itself does not yet have a
//! previous certificate. The condition is tied to the **receiver's state**, not
//! to a flag in the message — otherwise an attacker could have asked to be let
//! through by omitting `prev`.

use serde::{Deserialize, Serialize};

use crate::canonical;
use crate::error::{TlsError, to_hex};
use crate::fingerprint::same_fingerprint;
use crate::signature::{p256_public_key, signature_from_hex, verify_p256};
use krypto::sha256;

/// The fingerprint of a PEM certificate: SHA-256 over DER, hex without prefix.
/// The PEM is bounded as [`der_from_pem`] bounds it *(0.12.0)*.
pub fn fingerprint_from_pem(pem: &str) -> Result<String, TlsError> {
    to_hex("the certificate fingerprint", &sha256(&der_from_pem(pem)?))
}

/// PEM → DER. Fail-closed on anything that is not exactly one CERTIFICATE block.
///
/// A PEM over [`MAX_CERT_PEM_LEN`] bytes is [`TlsError::Params`], refused
/// before it is parsed *(0.12.0)*. Every certificate PEM nettls parses for an
/// announcement, an identity or a [`Generation`](crate::generations::Generation)
/// goes through here.
pub fn der_from_pem(pem: &str) -> Result<Vec<u8>, TlsError> {
    use rustls_pki_types::pem::PemObject;
    check_cert_pem_len("the certificate PEM", pem)?;
    let mut found: Option<Vec<u8>> = None;
    for cert in rustls_pki_types::CertificateDer::pem_slice_iter(pem.as_bytes()) {
        let cert = cert.map_err(|e| TlsError::Pem(format!("invalid PEM: {e}")))?;
        if found.is_some() {
            return Err(TlsError::Pem(
                "the PEM contains multiple certificates — an announcement carries exactly one"
                    .into(),
            ));
        }
        found = Some(cert.as_ref().to_vec());
    }
    found.ok_or_else(|| TlsError::Pem("found no CERTIFICATE block in the PEM".into()))
}

/// Refuses a certificate PEM (`what`) over [`MAX_CERT_PEM_LEN`] bytes with
/// [`TlsError::Params`] *(0.12.0)*.
pub(crate) fn check_cert_pem_len(what: &str, pem: &str) -> Result<(), TlsError> {
    if pem.len() > MAX_CERT_PEM_LEN {
        return Err(TlsError::Params(format!(
            "{what} is {} bytes, over the bound of {MAX_CERT_PEM_LEN} bytes; it was not parsed",
            pem.len()
        )));
    }
    Ok(())
}

/// Serialized form (§6.5). The field names are part of the contract. A key
/// the type does not know is refused when the JSON is read *(0.12.0)*.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnnouncementJson {
    /// Always `"nettls-rotate/v2"`.
    pub v: String,
    /// The service name of the announcer.
    pub announcer: String,
    /// The previous generation's fingerprint. `None` only at the first rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_fingerprint: Option<String>,
    /// The current generation's fingerprint.
    pub curr_fingerprint: String,
    /// The fingerprint of the new certificate.
    pub new_fingerprint: String,
    /// The new certificate, in its entirety.
    pub new_cert_pem: String,
    /// The sender's own clock, unix seconds UTC (§6.7b). Signed; no `verify`
    /// compares it with a clock.
    pub sent_at: i64,
    /// Signature with the previous key, hex. `None` only at the first rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig_prev: Option<String>,
    /// Signature with the current key, hex.
    pub sig_curr: String,
}

/// An announcement, fully verified or under construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announcement {
    announcer: String,
    prev_fp: Option<String>,
    curr_fp: String,
    new_fp: String,
    new_cert_pem: String,
    sent_at: i64,
    sig_prev: Option<Vec<u8>>,
    sig_curr: Vec<u8>,
}

impl Announcement {
    /// Builds and signs an announcement.
    ///
    /// `prev` is `None` at the very first rotation. If it is `Some`, both
    /// signatures **must** be made — it is not optional, and an announcement that
    /// could have been double-signed but is not, is a weakened announcement.
    ///
    /// A `new_cert_pem` over [`MAX_CERT_PEM_LEN`] bytes is [`TlsError::Params`],
    /// refused before it is parsed *(0.12.0)*.
    pub fn new(
        announcer: &str,
        prev: Option<(&str, &krypto::SecretBuf)>,
        curr: (&str, &krypto::SecretBuf),
        new_cert_pem: &str,
        sent_at: i64,
    ) -> Result<Self, TlsError> {
        let new_fp = fingerprint_from_pem(new_cert_pem)?;
        let (curr_fp, curr_pkcs8) = curr;
        let prev_fp = prev.map(|(fp, _)| fp.to_string());

        let message =
            canonical::rotate_v2(announcer, prev_fp.as_deref(), curr_fp, &new_fp, sent_at)?;

        let sig_curr = crate::signature::sign_p256(curr_pkcs8, &message)?;
        let sig_prev = match prev {
            Some((_, pkcs8)) => Some(crate::signature::sign_p256(pkcs8, &message)?),
            None => None,
        };

        Ok(Self {
            announcer: announcer.to_string(),
            prev_fp,
            curr_fp: curr_fp.to_string(),
            new_fp,
            new_cert_pem: new_cert_pem.to_string(),
            sent_at,
            sig_prev,
            sig_curr,
        })
    }

    /// The canonical string this announcement signs.
    pub fn canonical(&self) -> Result<Vec<u8>, TlsError> {
        canonical::rotate_v2(
            &self.announcer,
            self.prev_fp.as_deref(),
            &self.curr_fp,
            &self.new_fp,
            self.sent_at,
        )
    }

    /// Verify the announcement against the receiver's **own** state.
    ///
    /// `expected_announcer` is the peer the receiver expects the announcement
    /// from. `prev_cert_der` is the receiver's previous generation,
    /// `curr_cert_der` the current one. That the condition for a single
    /// signature is tied to the *receiver's* state and not to a field in the
    /// message is the whole point: otherwise an attacker could have asked to be
    /// let through by omitting `prev`.
    ///
    /// The order is not accidental either. The announcer is checked first: an
    /// announcement from another peer is refused before anything else
    /// *(0.12.0)*. **The fingerprint comes next**: if `new_cert_pem` was
    /// swapped in transit, that must be discovered before we use that key for
    /// anything at all.
    ///
    /// Right after it, `new_cert_pem` must be an X.509 certificate with a P-256
    /// key, the key the next announcement is signed with; a certificate of
    /// another kind is refused before the rest is checked *(0.12.0)*.
    ///
    /// The receiver's certificates are read with [`verify_p256`], so each is
    /// at most 1 MiB of DER *(0.12.0)*.
    pub fn verify(
        &self,
        expected_announcer: &str,
        prev_cert_der: Option<&[u8]>,
        curr_cert_der: &[u8],
    ) -> Result<(), TlsError> {
        // 0. The announcement must be from the peer we expect it from.
        if self.announcer != expected_announcer {
            return Err(TlsError::ProofInvalid(format!(
                "the announcement is from the announcer {:?}, but {expected_announcer:?} was \
                 expected — an announcement from one peer says nothing about another",
                self.announcer
            )));
        }

        // 1. The certificate MUST hash to the stated fingerprint (§6.5).
        let actual = fingerprint_from_pem(&self.new_cert_pem)?;
        if !same_fingerprint(&actual, &self.new_fp) {
            return Err(TlsError::ProofInvalid(format!(
                "new_cert_pem hashes to {actual}, but the announcement says {} — \
                 the certificate was swapped in transit",
                self.new_fp
            )));
        }

        // 1b. The new certificate carries the key the next announcement is
        // signed with, so it must be X.509 with a P-256 key.
        p256_public_key(&der_from_pem(&self.new_cert_pem)?).map_err(|e| match e {
            TlsError::Certificate(s) => {
                TlsError::Certificate(format!("new_cert_pem in the announcement: {s}"))
            }
            TlsError::ProofInvalid(s) => {
                TlsError::ProofInvalid(format!("new_cert_pem in the announcement: {s}"))
            }
            other => other,
        })?;

        // 2. The announcement must apply to the identity we actually have.
        let actual_curr = to_hex("the certificate fingerprint", &sha256(curr_cert_der))?;
        if !same_fingerprint(&actual_curr, &self.curr_fp) {
            return Err(TlsError::Chain(format!(
                "the announcement is issued by {}, but we know {actual_curr} as current — \
                 we have missed a rotation, or this is a different instance",
                self.curr_fp
            )));
        }

        let message = self.canonical()?;

        // 3. The current signature is ALWAYS required.
        verify_p256(curr_cert_der, &message, &self.sig_curr)?;

        // 4. The previous signature: required as soon as the receiver HAS a previous.
        match (prev_cert_der, &self.prev_fp, &self.sig_prev) {
            (Some(der), Some(fp), Some(sig)) => {
                let actual_prev = to_hex("the certificate fingerprint", &sha256(der))?;
                if !same_fingerprint(&actual_prev, fp) {
                    return Err(TlsError::Chain(format!(
                        "the announcement states {fp} as previous, we have {actual_prev}"
                    )));
                }
                verify_p256(der, &message, sig)
            }
            // The receiver HAS a previous, but the announcement is single-signed.
            // This is the attempt to ask one's way through with fewer signatures.
            (Some(_), _, _) => Err(TlsError::ProofInvalid(
                "the announcement is single-signed, but we already have a previous certificate — \
                 two signatures are required from rotation 2 onwards (§6.3)"
                    .into(),
            )),
            // The receiver has NO previous: this is rotation 1 from OUR
            // perspective, and a single signature is the natural form.
            (None, None, None) => Ok(()),
            // The receiver holds only an anchor, but the announcement is
            // double-signed: the announcer is mid-life and does not know we
            // (re)anchored. A8 (decided 2026-08-14): the generation numbering
            // is LOCAL to the receiver — the chain belongs to the relation,
            // not the announcer. The operator's approval carries generation 0
            // exactly like a prev-signature carries generation n, so we
            // verify what we CAN verify — `sig_curr` against the anchor
            // (already done in step 3 above) — and the stated `prev`, which
            // we cannot check, is not grounds for rejection. Security equals
            // bootstrap: the operator just vouched for `curr`, an attacker
            // cannot induce the anchor-only state, and a replayed old
            // announcement fails the curr-vs-anchor check in step 2. This
            // also covers the late joiner: a fresh consumer meeting a
            // long-running announcer.
            (None, Some(_), Some(_)) => Ok(()),
            (None, _, _) => Err(TlsError::ProofInvalid(
                "prev_fingerprint and sig_prev must either both be present or both be absent"
                    .into(),
            )),
        }
    }

    /// To serialized form. Fails with [`TlsError::Encode`] when a signature
    /// cannot be encoded as hex *(0.12.0)*.
    pub fn to_json(&self) -> Result<AnnouncementJson, TlsError> {
        Ok(AnnouncementJson {
            v: canonical::ROTATE_V2.to_string(),
            announcer: self.announcer.clone(),
            prev_fingerprint: self.prev_fp.clone(),
            curr_fingerprint: self.curr_fp.clone(),
            new_fingerprint: self.new_fp.clone(),
            new_cert_pem: self.new_cert_pem.clone(),
            sent_at: self.sent_at,
            sig_prev: self
                .sig_prev
                .as_deref()
                .map(|sig| to_hex("the signature with the previous key", sig))
                .transpose()?,
            sig_curr: to_hex("the signature with the current key", &self.sig_curr)?,
        })
    }

    /// From serialized form. **Fail-closed** on anything that does not add up.
    pub fn from_json(j: &AnnouncementJson) -> Result<Self, TlsError> {
        if j.v != canonical::ROTATE_V2 {
            return Err(TlsError::Proof(format!(
                "unknown message version \"{}\", expected \"{}\"",
                j.v,
                canonical::ROTATE_V2
            )));
        }
        // The fields are validated here, not at use: a value that cannot be part
        // of a canonical string must never get further than this.
        canonical::require_component_name(&j.announcer, "announcer")?;
        // DoS surface (D-item, 2026-08-11 review): the PEM comes straight off
        // the network. A P-256 leaf is ~1 KiB; 16 KiB is generous headroom,
        // and anything beyond it is not a certificate.
        if j.new_cert_pem.len() > MAX_CERT_PEM_LEN {
            return Err(TlsError::Params(format!(
                "new_cert_pem is {} bytes — above the cap of {MAX_CERT_PEM_LEN}; \
                 that is not a certificate",
                j.new_cert_pem.len()
            )));
        }
        canonical::require_fingerprint(&j.curr_fingerprint, "curr_fingerprint")?;
        canonical::require_fingerprint(&j.new_fingerprint, "new_fingerprint")?;
        if let Some(p) = &j.prev_fingerprint {
            canonical::require_fingerprint(p, "prev_fingerprint")?;
        }
        // `prev_fingerprint` and `sig_prev` belong together: one without the other
        // is half an announcement, and we do not guess at what was meant.
        if j.prev_fingerprint.is_some() != j.sig_prev.is_some() {
            return Err(TlsError::Proof(
                "prev_fingerprint and sig_prev must either both be present or both be absent"
                    .into(),
            ));
        }
        Ok(Self {
            announcer: j.announcer.clone(),
            prev_fp: j.prev_fingerprint.clone(),
            curr_fp: j.curr_fingerprint.clone(),
            new_fp: j.new_fingerprint.clone(),
            new_cert_pem: j.new_cert_pem.clone(),
            sent_at: j.sent_at,
            sig_prev: j
                .sig_prev
                .as_deref()
                .map(|s| signature_from_hex(s, "sig_prev"))
                .transpose()?,
            sig_curr: signature_from_hex(&j.sig_curr, "sig_curr")?,
        })
    }

    /// The service name of the one who announced.
    pub fn announcer(&self) -> &str {
        &self.announcer
    }
    /// The fingerprint of the new certificate.
    pub fn new_fingerprint(&self) -> &str {
        &self.new_fp
    }
    /// The new certificate, in its entirety.
    pub fn new_cert_pem(&self) -> &str {
        &self.new_cert_pem
    }
    /// The sender's clock when the message was created.
    pub fn sent_at(&self) -> i64 {
        self.sent_at
    }
    /// Is this a first rotation (single-signed)?
    pub fn is_bootstrap(&self) -> bool {
        self.prev_fp.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::material::TlsMaterial;
    use crate::{CertSource, SelfSignedParams};

    pub(super) struct Gen {
        pub(super) pem: String,
        der: Vec<u8>,
        pub(super) pkcs8: krypto::SecretBuf,
        pub(super) fp: String,
    }

    pub(super) fn generation(name: &str) -> Gen {
        let m = TlsMaterial::load(&CertSource::self_signed(SelfSignedParams::new(
            name,
            [name],
        )))
        .expect("self-signed");
        let der = m.cert_chain()[0].as_ref().to_vec();
        let pkcs8 = crate::pkcs8::pkcs8_p256(m.key_der(), &der).expect("pkcs8");
        let pem = String::from_utf8(crate::pem::encode("CERTIFICATE", &der).unwrap()).unwrap();
        let fp = krypto::hex::encode(&sha256(&der)).unwrap();
        Gen {
            pem,
            der,
            pkcs8,
            fp,
        }
    }

    // --- bootstrap: rotation 1 ------------------------------------------------ //

    #[test]
    fn single_signature_rejected_when_receiver_has_a_previous() {
        // The emphasis is on HAS: it is the receiver's own state that decides,
        // not a field in the message. This is the attack the rule exists for —
        // asking one's way through with fewer signatures by omitting `prev`.
        let c0 = generation("c0");
        let c1 = generation("c1");
        let c2 = generation("c2");
        let k = Announcement::new("gateway", None, (&c1.fp, &c1.pkcs8), &c2.pem, 100).unwrap();

        let err = k.verify("gateway", Some(&c0.der), &c1.der).unwrap_err();
        assert!(
            format!("{err}").contains("single-signed"),
            "unexpected error: {err}"
        );
    }

    // --- steady state: two signatures ------------------------------------------ //

    #[test]
    fn wrong_previous_signature_rejected() {
        let c0 = generation("c0");
        let foreign = generation("foreign");
        let c1 = generation("c1");
        let c2 = generation("c2");
        // Signed with a FOREIGN key as "previous", but states c0's fingerprint.
        let k = Announcement::new(
            "gateway",
            Some((&c0.fp, &foreign.pkcs8)),
            (&c1.fp, &c1.pkcs8),
            &c2.pem,
            100,
        )
        .unwrap();
        assert!(k.verify("gateway", Some(&c0.der), &c1.der).is_err());
    }

    #[test]
    fn wrong_current_signature_rejected() {
        let c0 = generation("c0");
        let foreign = generation("foreign");
        let c1 = generation("c1");
        let c2 = generation("c2");
        let k = Announcement::new(
            "gateway",
            Some((&c0.fp, &c0.pkcs8)),
            (&c1.fp, &foreign.pkcs8),
            &c2.pem,
            100,
        )
        .unwrap();
        assert!(k.verify("gateway", Some(&c0.der), &c1.der).is_err());
    }

    // --- the fingerprint is checked before the signatures --------------------- //

    #[test]
    fn a_received_announcement_naming_one_certificate_twice_is_rejected() {
        let c0 = generation("c0");
        let c1 = generation("c1");
        let c2 = generation("c2");
        let k = Announcement::new(
            "gateway",
            Some((&c0.fp, &c0.pkcs8)),
            (&c1.fp, &c1.pkcs8),
            &c2.pem,
            100,
        )
        .unwrap();

        // What a receiver can be sent: the current certificate named as the new one.
        let mut j = k.to_json().unwrap();
        j.new_cert_pem = c1.pem.clone();
        j.new_fingerprint = c1.fp.clone();
        let received = Announcement::from_json(&j).unwrap();

        let err = received
            .verify("gateway", Some(&c0.der), &c1.der)
            .unwrap_err();
        assert!(
            format!("{err}").contains("new_fp and curr_fp are the same fingerprint"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn swapped_certificate_rejected_even_with_valid_signatures() {
        let c0 = generation("c0");
        let c1 = generation("c1");
        let c2 = generation("c2");
        let evil = generation("evil");

        let k = Announcement::new(
            "gateway",
            Some((&c0.fp, &c0.pkcs8)),
            (&c1.fp, &c1.pkcs8),
            &c2.pem,
            100,
        )
        .unwrap();

        // Swap out the PEM but keep everything else — the signatures cover the
        // fingerprint, not the certificate, so they are still valid.
        let mut j = k.to_json().unwrap();
        j.new_cert_pem = evil.pem.clone();
        let tampered = Announcement::from_json(&j).unwrap();

        let err = tampered
            .verify("gateway", Some(&c0.der), &c1.der)
            .unwrap_err();
        assert!(
            format!("{err}").contains("swapped in transit"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn a_new_certificate_without_a_p256_key_is_rejected() {
        // 0.12.0: it carries the key the next announcement must be signed with.
        let c0 = generation("c0");
        let c1 = generation("c1");
        let ed25519 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let ed25519_cert = rcgen::CertificateParams::new(vec!["c2".to_string()])
            .unwrap()
            .self_signed(&ed25519)
            .unwrap();
        let not_a_certificate =
            String::from_utf8(crate::pem::encode("CERTIFICATE", b"not a certificate").unwrap())
                .unwrap();

        for new_cert_pem in [ed25519_cert.pem(), not_a_certificate] {
            let k = Announcement::new(
                "gateway",
                Some((&c0.fp, &c0.pkcs8)),
                (&c1.fp, &c1.pkcs8),
                &new_cert_pem,
                100,
            )
            .unwrap();
            let err = k.verify("gateway", Some(&c0.der), &c1.der).unwrap_err();
            assert!(
                format!("{err}").contains("new_cert_pem in the announcement"),
                "unexpected error: {err}"
            );
        }
    }

    #[test]
    fn announcement_from_another_generation_rejected() {
        let c0 = generation("c0");
        let c1 = generation("c1");
        let c2 = generation("c2");
        let c3 = generation("c3");
        // Announced by c2, but the receiver is on c1.
        let k = Announcement::new(
            "gateway",
            Some((&c1.fp, &c1.pkcs8)),
            (&c2.fp, &c2.pkcs8),
            &c3.pem,
            100,
        )
        .unwrap();
        let err = k.verify("gateway", Some(&c0.der), &c1.der).unwrap_err();
        assert!(
            format!("{err}").contains("missed a rotation"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn an_announcement_from_another_announcer_is_refused() {
        // 0.12.0: a genuine announcement from one peer says nothing about another.
        let c0 = generation("c0");
        let c1 = generation("c1");
        let k = Announcement::new("gateway", None, (&c0.fp, &c0.pkcs8), &c1.pem, 100).unwrap();
        let err = k.verify("service", None, &c0.der).unwrap_err();
        assert!(matches!(err, TlsError::ProofInvalid(_)), "{err:?}");
        assert!(
            format!("{err}")
                .contains("from the announcer \"gateway\", but \"service\" was expected"),
            "unexpected error: {err}"
        );
        k.verify("gateway", None, &c0.der)
            .expect("its own announcer");
    }

    // --- serialization ---------------------------------------------------------- //

    #[test]
    fn json_round_trip_preserves_everything() {
        let c0 = generation("c0");
        let c1 = generation("c1");
        let c2 = generation("c2");
        let k = Announcement::new(
            "gateway",
            Some((&c0.fp, &c0.pkcs8)),
            (&c1.fp, &c1.pkcs8),
            &c2.pem,
            1_700_000_000,
        )
        .unwrap();

        let text = serde_json::to_string(&k.to_json().unwrap()).unwrap();
        let read_back: AnnouncementJson = serde_json::from_str(&text).unwrap();
        assert_eq!(Announcement::from_json(&read_back).unwrap(), k);
    }

    #[test]
    fn bootstrap_omits_prev_fields_in_json() {
        let c0 = generation("c0");
        let c1 = generation("c1");
        let k = Announcement::new("gateway", None, (&c0.fp, &c0.pkcs8), &c1.pem, 100).unwrap();
        let text = serde_json::to_string(&k.to_json().unwrap()).unwrap();
        assert!(!text.contains("prev_fingerprint"), "{text}");
        assert!(!text.contains("sig_prev"), "{text}");
    }

    #[test]
    fn a_certificate_pem_over_the_bound_is_refused_before_it_is_parsed() {
        // 0.12.0: `der_from_pem` bounds every PEM parsed for an announcement or
        // an identity; `IdentityJson::new` stores its PEM and is bounded itself.
        let c = generation("c");
        let at_bound = format!("{}{}", c.pem, "\n".repeat(MAX_CERT_PEM_LEN - c.pem.len()));
        assert_eq!(der_from_pem(&at_bound).unwrap(), c.der);

        let over = format!("{at_bound}\n");
        let text = "is 16385 bytes, over the bound of 16384 bytes";
        for err in [
            der_from_pem(&over).unwrap_err(),
            IdentityJson::new(
                &c.fp,
                over.clone(),
                None,
                crate::announcer::Mode::Rolling,
                5,
                None,
            )
            .unwrap_err(),
        ] {
            assert!(matches!(err, TlsError::Params(_)), "{err:?}");
            assert!(err.to_string().contains(text), "{err}");
        }
        let mut read = serde_json::to_value(
            IdentityJson::new(
                &c.fp,
                c.pem.clone(),
                None,
                crate::announcer::Mode::Rolling,
                5,
                None,
            )
            .unwrap(),
        )
        .unwrap();
        read["cert_pem"] = over.into();
        let err = serde_json::from_value::<IdentityJson>(read).unwrap_err();
        assert!(err.to_string().contains(text), "{err}");
    }

    #[test]
    fn a_signature_over_144_hex_characters_is_refused_before_it_is_decoded() {
        // 0.12.0: 146 characters of valid lowercase hex, 73 bytes.
        let c0 = generation("c0");
        let c1 = generation("c1");
        let k = Announcement::new("gateway", None, (&c0.fp, &c0.pkcs8), &c1.pem, 100).unwrap();
        let mut j = k.to_json().unwrap();
        j.sig_curr = "00".repeat(73);
        let err = Announcement::from_json(&j).unwrap_err();
        assert!(matches!(err, TlsError::Proof(_)), "{err:?}");
        assert!(
            err.to_string()
                .contains("sig_curr is 146 bytes of hex, over the bound of 144 for a signature"),
            "{err}"
        );
    }

    #[test]
    fn an_announcement_with_an_unknown_key_is_refused() {
        let c0 = generation("c0");
        let c1 = generation("c1");
        let k = Announcement::new("gateway", None, (&c0.fp, &c0.pkcs8), &c1.pem, 100).unwrap();
        let mut j = serde_json::to_value(k.to_json().unwrap()).unwrap();
        j["extra"] = 1.into();
        let err = serde_json::from_str::<AnnouncementJson>(&j.to_string()).unwrap_err();
        assert!(err.to_string().contains("unknown field `extra`"), "{err}");
    }
}

// --------------------------------------------------------------------------- //
// The receipt (§6.6)
// --------------------------------------------------------------------------- //

/// Serialized receipt (§6.6). A key the type does not know is refused when
/// the JSON is read *(0.12.0)*.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptJson {
    /// Always `"nettls-rotate-ack/v2"`.
    pub v: String,
    /// The one who acks.
    pub acker: String,
    /// The one who announced.
    pub announcer: String,
    /// The fingerprint being acked.
    pub new_fingerprint: String,
    /// The acker's own clock (§6.7b). Signed; no `verify` compares it with a
    /// clock.
    pub sent_at: i64,
    /// Ed25519 signature, hex.
    pub sig: String,
}

/// "I have stored your next certificate."
///
/// Without it we do not roll (§6.8a): if A rolls before B has stored the new
/// one, B's handshake fails that very moment — exactly the breakage §6 exists to
/// avoid. The receipt is not a courtesy; it is the condition that makes the
/// asynchronous rotation safe.
///
/// **One** signature, with Ed25519 (§6.6b). Two signatures protect *continuity*,
/// and a receipt moves no identity — it confirms receipt. Its requirement is
/// authenticity, and one signature from a pinned key covers that fully.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    acker: String,
    announcer: String,
    new_fp: String,
    sent_at: i64,
    sig: Vec<u8>,
}

impl Receipt {
    /// Create and sign a receipt with the acker's Ed25519 seed.
    pub fn new(
        acker: &str,
        announcer: &str,
        new_fp: &str,
        sent_at: i64,
        ed25519_seed: &krypto::SecretBuf,
    ) -> Result<Self, TlsError> {
        let message = canonical::rotate_ack_v2(acker, announcer, new_fp, sent_at)?;
        let sig = krypto::sign::ed25519_sign(ed25519_seed, &message)
            .map_err(|e| TlsError::Sign(format!("Ed25519 signing failed: {e}")))?
            .to_vec();
        Ok(Self {
            acker: acker.to_string(),
            announcer: announcer.to_string(),
            new_fp: new_fp.to_string(),
            sent_at,
            sig,
        })
    }

    /// The canonical string this receipt signs.
    pub fn canonical(&self) -> Result<Vec<u8>, TlsError> {
        canonical::rotate_ack_v2(&self.acker, &self.announcer, &self.new_fp, self.sent_at)
    }

    /// Verify that the receipt is from `expected_acker`, against the acker's
    /// **pinned** Ed25519 key, and against the fingerprint we actually
    /// announced.
    ///
    /// All three are required. The acker is checked first: a receipt from
    /// another peer is refused before anything else *(0.12.0)*. A receipt that
    /// is genuine but applies to a *different* rotation is a replay — and it
    /// must not make us roll.
    pub fn verify(
        &self,
        expected_acker: &str,
        pinned_pubkey: &[u8],
        expected_new_fp: &str,
    ) -> Result<(), TlsError> {
        if self.acker != expected_acker {
            return Err(TlsError::ProofInvalid(format!(
                "the receipt is from the acker {:?}, but {expected_acker:?} was expected — \
                 this is a receipt from another peer",
                self.acker
            )));
        }
        if !same_fingerprint(&self.new_fp, expected_new_fp) {
            return Err(TlsError::ProofInvalid(format!(
                "the receipt covers {}, but we announced {expected_new_fp} — \
                 this is a receipt for a different rotation",
                self.new_fp
            )));
        }
        let message = self.canonical()?;
        krypto::sign::ed25519_verify(pinned_pubkey, &message, &self.sig)
            .map_err(|_| TlsError::ProofInvalid("the Ed25519 signature does not hold".into()))
    }

    /// To serialized form. Fails with [`TlsError::Encode`] when the signature
    /// cannot be encoded as hex *(0.12.0)*.
    pub fn to_json(&self) -> Result<ReceiptJson, TlsError> {
        Ok(ReceiptJson {
            v: canonical::ROTATE_ACK_V2.to_string(),
            acker: self.acker.clone(),
            announcer: self.announcer.clone(),
            new_fingerprint: self.new_fp.clone(),
            sent_at: self.sent_at,
            sig: to_hex("the signature", &self.sig)?,
        })
    }

    /// From serialized form. Fail-closed.
    pub fn from_json(j: &ReceiptJson) -> Result<Self, TlsError> {
        if j.v != canonical::ROTATE_ACK_V2 {
            return Err(TlsError::Proof(format!(
                "unknown message version \"{}\", expected \"{}\"",
                j.v,
                canonical::ROTATE_ACK_V2
            )));
        }
        canonical::require_component_name(&j.acker, "acker")?;
        canonical::require_component_name(&j.announcer, "announcer")?;
        canonical::require_fingerprint(&j.new_fingerprint, "new_fingerprint")?;
        Ok(Self {
            acker: j.acker.clone(),
            announcer: j.announcer.clone(),
            new_fp: j.new_fingerprint.clone(),
            sent_at: j.sent_at,
            sig: signature_from_hex(&j.sig, "sig")?,
        })
    }

    /// Who acked.
    pub fn acker(&self) -> &str {
        &self.acker
    }
    /// The one who announced *(0.12.0)*.
    pub fn announcer(&self) -> &str {
        &self.announcer
    }
    /// The fingerprint that was acked.
    pub fn new_fingerprint(&self) -> &str {
        &self.new_fp
    }
    /// The acker's clock.
    pub fn sent_at(&self) -> i64 {
        self.sent_at
    }
}

#[cfg(test)]
mod receipt_tests {
    use super::*;
    use krypto::SecretBuf;

    const FP: &str = "aa00112233445566778899aabbccddeeff00112233445566778899aabbccddee";
    const OTHER_FP: &str = "bb00112233445566778899aabbccddeeff00112233445566778899aabbccddee";

    fn seed() -> SecretBuf {
        SecretBuf::from_vec(vec![3u8; 32]).unwrap()
    }

    fn public(s: &SecretBuf) -> Vec<u8> {
        krypto::sign::ed25519_public(s).unwrap().to_vec()
    }

    #[test]
    fn receipt_for_another_rotation_rejected() {
        // Replay: the receipt is genuine, but applies to something else. It
        // must not make us roll.
        let pk = public(&seed());
        let k = Receipt::new("service", "gateway", OTHER_FP, 100, &seed()).unwrap();
        let err = k.verify("service", &pk, FP).unwrap_err();
        assert!(
            format!("{err}").contains("a different rotation"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn a_receipt_from_another_acker_is_refused() {
        // 0.12.0: a genuine receipt from one peer says nothing about another.
        let pk = public(&seed());
        let k = Receipt::new("service", "gateway", FP, 100, &seed()).unwrap();
        let err = k.verify("portal", &pk, FP).unwrap_err();
        assert!(matches!(err, TlsError::ProofInvalid(_)), "{err:?}");
        assert!(
            format!("{err}").contains("from the acker \"service\", but \"portal\" was expected"),
            "unexpected: {err}"
        );
        k.verify("service", &pk, FP).expect("its own acker");
    }

    #[test]
    fn receipt_from_wrong_sender_rejected() {
        let other_key = public(&SecretBuf::from_vec(vec![9u8; 32]).unwrap());
        let k = Receipt::new("service", "gateway", FP, 100, &seed()).unwrap();
        assert!(k.verify("service", &other_key, FP).is_err());
    }

    #[test]
    fn tampered_field_breaks_signature() {
        let pk = public(&seed());
        let k = Receipt::new("service", "gateway", FP, 100, &seed()).unwrap();
        let mut j = k.to_json().unwrap();
        j.sent_at = 101;
        let tampered = Receipt::from_json(&j).unwrap();
        assert!(tampered.verify("service", &pk, FP).is_err());

        let mut j2 = k.to_json().unwrap();
        j2.acker = "portal".into();
        let tampered2 = Receipt::from_json(&j2).unwrap();
        assert!(tampered2.verify("portal", &pk, FP).is_err());
    }

    #[test]
    fn json_round_trip_preserves_everything() {
        let k = Receipt::new("service", "gateway", FP, 1_700_000_000, &seed()).unwrap();
        let text = serde_json::to_string(&k.to_json().unwrap()).unwrap();
        let read_back: ReceiptJson = serde_json::from_str(&text).unwrap();
        assert_eq!(Receipt::from_json(&read_back).unwrap(), k);
        assert_eq!(k.announcer(), "gateway");
    }

    #[test]
    fn a_receipt_with_an_unknown_key_is_refused() {
        let k = Receipt::new("service", "gateway", FP, 100, &seed()).unwrap();
        let mut j = serde_json::to_value(k.to_json().unwrap()).unwrap();
        j["extra"] = 1.into();
        let err = serde_json::from_str::<ReceiptJson>(&j.to_string()).unwrap_err();
        assert!(err.to_string().contains("unknown field `extra`"), "{err}");
    }
}

// --------------------------------------------------------------------------- //
// The handled message (0.12.0)
// --------------------------------------------------------------------------- //

/// Serialized handled message *(0.12.0)*. A key the type does not know is
/// refused when the JSON is read.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandledJson {
    /// Always `"nettls-rotate-handled/v1"`.
    pub v: String,
    /// The one who acks.
    pub acker: String,
    /// The one who announced.
    pub announcer: String,
    /// The fingerprint being acked.
    pub new_fingerprint: String,
    /// The acker's own clock (§6.7b). Signed; no `verify` compares it with a
    /// clock.
    pub sent_at: i64,
    /// Ed25519 signature, hex.
    pub sig: String,
}

/// "This I have handled; here is the acknowledgement once more" *(0.12.0)*.
///
/// The one who receives an announcement it has already handled
/// ([`Received::Known`](crate::generations::Received::Known)) sends the
/// ordinary [`Receipt`] first, unchanged, and then this. Verified, it counts as
/// a receipt: an earlier receipt may have been lost, but the peer is ready. The
/// announcer hands it to
/// [`Announcer::acked_handled`](crate::announcer::Announcer::acked_handled),
/// which verifies it before it strikes the peer from the waiting list
/// *(0.12.0)*.
///
/// A node that does not know this message and reads it as a receipt refuses
/// it with "unknown message version", and changes nothing. That is why the
/// receipt goes first.
///
/// **One** signature, with the acker's Ed25519 key, as the receipt, over a
/// canonical form of its own ([`canonical::rotate_handled_v1`]): a receipt's
/// signature never holds for it, nor the other way round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handled {
    acker: String,
    announcer: String,
    new_fp: String,
    sent_at: i64,
    sig: Vec<u8>,
}

impl Handled {
    /// Create and sign a handled message with the acker's Ed25519 seed.
    pub fn new(
        acker: &str,
        announcer: &str,
        new_fp: &str,
        sent_at: i64,
        ed25519_seed: &krypto::SecretBuf,
    ) -> Result<Self, TlsError> {
        let message = canonical::rotate_handled_v1(acker, announcer, new_fp, sent_at)?;
        let sig = krypto::sign::ed25519_sign(ed25519_seed, &message)
            .map_err(|e| TlsError::Sign(format!("Ed25519 signing failed: {e}")))?
            .to_vec();
        Ok(Self {
            acker: acker.to_string(),
            announcer: announcer.to_string(),
            new_fp: new_fp.to_string(),
            sent_at,
            sig,
        })
    }

    /// The canonical string this handled message signs.
    pub fn canonical(&self) -> Result<Vec<u8>, TlsError> {
        canonical::rotate_handled_v1(&self.acker, &self.announcer, &self.new_fp, self.sent_at)
    }

    /// Verify that the handled message is from `expected_acker`, against the
    /// acker's **pinned** Ed25519 key, and against the fingerprint we actually
    /// announced.
    ///
    /// All three are required, as for a [`Receipt`]. The acker is checked
    /// first: a handled message from another peer is refused before anything
    /// else *(0.12.0)*. A handled message that is genuine but applies to a
    /// *different* rotation is a replay — and it must not make us roll.
    pub fn verify(
        &self,
        expected_acker: &str,
        pinned_pubkey: &[u8],
        expected_new_fp: &str,
    ) -> Result<(), TlsError> {
        if self.acker != expected_acker {
            return Err(TlsError::ProofInvalid(format!(
                "the handled message is from the acker {:?}, but {expected_acker:?} was \
                 expected — this is a handled message from another peer",
                self.acker
            )));
        }
        if !same_fingerprint(&self.new_fp, expected_new_fp) {
            return Err(TlsError::ProofInvalid(format!(
                "the handled message covers {}, but we announced {expected_new_fp} — \
                 this is a handled message for a different rotation",
                self.new_fp
            )));
        }
        let message = self.canonical()?;
        krypto::sign::ed25519_verify(pinned_pubkey, &message, &self.sig)
            .map_err(|_| TlsError::ProofInvalid("the Ed25519 signature does not hold".into()))
    }

    /// To serialized form. Fails with [`TlsError::Encode`] when the signature
    /// cannot be encoded as hex.
    pub fn to_json(&self) -> Result<HandledJson, TlsError> {
        Ok(HandledJson {
            v: canonical::ROTATE_HANDLED_V1.to_string(),
            acker: self.acker.clone(),
            announcer: self.announcer.clone(),
            new_fingerprint: self.new_fp.clone(),
            sent_at: self.sent_at,
            sig: to_hex("the signature", &self.sig)?,
        })
    }

    /// From serialized form. Fail-closed.
    pub fn from_json(j: &HandledJson) -> Result<Self, TlsError> {
        if j.v != canonical::ROTATE_HANDLED_V1 {
            return Err(TlsError::Proof(format!(
                "unknown message version \"{}\", expected \"{}\"",
                j.v,
                canonical::ROTATE_HANDLED_V1
            )));
        }
        canonical::require_component_name(&j.acker, "acker")?;
        canonical::require_component_name(&j.announcer, "announcer")?;
        canonical::require_fingerprint(&j.new_fingerprint, "new_fingerprint")?;
        Ok(Self {
            acker: j.acker.clone(),
            announcer: j.announcer.clone(),
            new_fp: j.new_fingerprint.clone(),
            sent_at: j.sent_at,
            sig: signature_from_hex(&j.sig, "sig")?,
        })
    }

    /// Who acked.
    pub fn acker(&self) -> &str {
        &self.acker
    }
    /// The one who announced *(0.12.0)*.
    pub fn announcer(&self) -> &str {
        &self.announcer
    }
    /// The fingerprint that was acked.
    pub fn new_fingerprint(&self) -> &str {
        &self.new_fp
    }
    /// The acker's clock.
    pub fn sent_at(&self) -> i64 {
        self.sent_at
    }
}

#[cfg(test)]
mod handled_tests {
    use super::*;
    use krypto::SecretBuf;

    const FP: &str = "aa00112233445566778899aabbccddeeff00112233445566778899aabbccddee";
    const OTHER_FP: &str = "bb00112233445566778899aabbccddeeff00112233445566778899aabbccddee";

    fn seed() -> SecretBuf {
        SecretBuf::from_vec(vec![3u8; 32]).unwrap()
    }

    fn public(s: &SecretBuf) -> Vec<u8> {
        krypto::sign::ed25519_public(s).unwrap().to_vec()
    }

    #[test]
    fn handled_round_trip_verifies_and_refuses_another_rotation_or_key() {
        let pk = public(&seed());
        let h = Handled::new("service", "gateway", FP, 1_700_000_000, &seed()).unwrap();
        let text = serde_json::to_string(&h.to_json().unwrap()).unwrap();
        let read_back = Handled::from_json(&serde_json::from_str(&text).unwrap()).unwrap();
        assert_eq!(read_back, h);
        assert_eq!(read_back.announcer(), "gateway");
        read_back.verify("service", &pk, FP).expect("must hold");

        let other_rotation = Handled::new("service", "gateway", OTHER_FP, 100, &seed()).unwrap();
        let err = other_rotation.verify("service", &pk, FP).unwrap_err();
        assert!(
            format!("{err}").contains("a different rotation"),
            "unexpected: {err}"
        );

        let other_key = public(&SecretBuf::from_vec(vec![9u8; 32]).unwrap());
        assert!(read_back.verify("service", &other_key, FP).is_err());

        // A node that does not know the message reads it as a receipt, the
        // fields being the same, and refuses it by its version.
        let as_receipt: ReceiptJson = serde_json::from_str(&text).unwrap();
        let err = Receipt::from_json(&as_receipt).unwrap_err();
        assert!(
            format!("{err}").contains("unknown message version"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn a_receipt_signature_does_not_hold_for_a_handled_message_nor_the_reverse() {
        let pk = public(&seed());
        let receipt = Receipt::new("service", "gateway", FP, 100, &seed())
            .unwrap()
            .to_json()
            .unwrap();
        let handled = Handled::new("service", "gateway", FP, 100, &seed())
            .unwrap()
            .to_json()
            .unwrap();

        let mut handled_with_receipt_sig = handled.clone();
        handled_with_receipt_sig.sig = receipt.sig.clone();
        let err = Handled::from_json(&handled_with_receipt_sig)
            .unwrap()
            .verify("service", &pk, FP)
            .unwrap_err();
        assert!(format!("{err}").contains("does not hold"), "{err}");

        let mut receipt_with_handled_sig = receipt;
        receipt_with_handled_sig.sig = handled.sig;
        let err = Receipt::from_json(&receipt_with_handled_sig)
            .unwrap()
            .verify("service", &pk, FP)
            .unwrap_err();
        assert!(format!("{err}").contains("does not hold"), "{err}");
    }

    #[test]
    fn a_handled_message_from_another_acker_is_refused() {
        // 0.12.0: a genuine handled message from one peer says nothing about another.
        let pk = public(&seed());
        let h = Handled::new("service", "gateway", FP, 100, &seed()).unwrap();
        let err = h.verify("portal", &pk, FP).unwrap_err();
        assert!(matches!(err, TlsError::ProofInvalid(_)), "{err:?}");
        assert!(
            format!("{err}").contains("from the acker \"service\", but \"portal\" was expected"),
            "unexpected: {err}"
        );
        h.verify("service", &pk, FP).expect("its own acker");
    }

    #[test]
    fn a_handled_message_with_an_unknown_key_is_refused() {
        let h = Handled::new("service", "gateway", FP, 100, &seed()).unwrap();
        let mut j = serde_json::to_value(h.to_json().unwrap()).unwrap();
        j["extra"] = 1.into();
        let err = serde_json::from_str::<HandledJson>(&j.to_string()).unwrap_err();
        assert!(err.to_string().contains("unknown field `extra`"), "{err}");
    }
}

// --------------------------------------------------------------------------- //
// The archive (§6.9) — audit trail, not a recovery mechanism
// --------------------------------------------------------------------------- //

/// Upper bound for an incoming certificate PEM (D-item, 2026-08-11 review).
pub const MAX_CERT_PEM_LEN: usize = 16 * 1024;

/// The append-only archive of sent announcements, next to the material.
pub const ARCHIVE_FILE: &str = "announcements.jsonl";

/// Put an announcement in the archive, **append-only**.
///
/// # Why the archive exists now
///
/// In the model this replaced, the archive was a **recovery mechanism**: a client that had been
/// down read its way forward through the proofs. With §6 that job is gone —
/// the counterpart knows the next certificate before it is taken into use, so
/// there is nothing to catch up on.
///
/// What the archive does now is something else, and narrower: **an operator who
/// must decide whether a deviation is a bug or an attack must be able to see
/// what was actually announced and when.** Without that she is left with a
/// fingerprint she does not recognize and no history to hold it up against.
///
/// Append-only on purpose: a log that can be edited is not an audit trail.
/// We do not enforce it in the filesystem — that belongs in operations — but the
/// code here never writes anywhere but at the end.
///
/// The file is created for the owner only (0600), like the other state files;
/// a file that exists keeps the mode it has. Each record is written in one
/// call, so two calls at the same time give two whole lines *(0.12.0)*.
///
/// A record longer than [`read_archive`] reads, 64 KiB, is [`TlsError::Params`],
/// and nothing is written; the file is not even opened *(0.12.0)*.
pub fn archive(dir: &std::path::Path, k: &Announcement) -> Result<(), TlsError> {
    use std::io::Write;
    let mut line = serde_json::to_string(&k.to_json()?)
        .map_err(|e| TlsError::Proof(format!("could not serialize the announcement: {e}")))?;
    if line.len() > MAX_ARCHIVE_LINE_LEN {
        return Err(TlsError::Params(format!(
            "the archive record is {} bytes, over the bound of {MAX_ARCHIVE_LINE_LEN} bytes a \
             line may have to be read back; nothing was written",
            line.len()
        )));
    }
    line.push('\n');
    let path = dir.join(ARCHIVE_FILE);
    let mut open = std::fs::OpenOptions::new();
    open.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.mode(0o600);
    }
    let mut f = open.open(&path).map_err(|e| TlsError::io(&path, e))?;
    // The record and its line break go in one write. The file is opened for
    // appending, so the system puts each write at the end as one piece.
    f.write_all(line.as_bytes())
        .map_err(|e| TlsError::io(&path, e))?;
    Ok(())
}

/// The longest archive [`read_archive`] reads, in bytes *(0.12.0)*.
const MAX_ARCHIVE_LEN: usize = 64 * 1024 * 1024;
/// The longest line [`read_archive`] parses, in bytes *(0.12.0)*.
const MAX_ARCHIVE_LINE_LEN: usize = 64 * 1024;

/// Read the archive, oldest first.
///
/// **Skips lines that cannot be parsed**, and reports how many. An archive is an
/// audit trail: one broken line must not make the rest unreadable precisely when
/// someone needs to read it. A line that is not valid UTF-8 is skipped and
/// counted like any other *(0.12.0)*.
///
/// What comes back is checked for form only, as [`Announcement::from_json`]
/// does: no signature is verified. [`Announcement::verify`] is the call for that.
///
/// An archive over 64 MiB is [`TlsError::Io`], refused before it is read, and
/// so is one that grows past 64 MiB while it is read. A line over 64 KiB is
/// skipped and counted without being parsed *(0.12.0)*.
pub fn read_archive(dir: &std::path::Path) -> Result<(Vec<Announcement>, usize), TlsError> {
    let path = dir.join(ARCHIVE_FILE);
    let mut file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), 0)),
        Err(e) => return Err(TlsError::io(&path, e)),
    };
    let bytes = crate::pem::read_capped(
        &mut file,
        MAX_ARCHIVE_LEN,
        |e| TlsError::io(&path, e),
        |len| crate::pem::over_bound(&path, "the archive", MAX_ARCHIVE_LEN, len),
    )?;
    let mut out = Vec::new();
    let mut skipped = 0usize;
    for line in bytes
        .split(|b| *b == b'\n')
        .filter(|l| !l.iter().all(u8::is_ascii_whitespace))
    {
        if line.len() > MAX_ARCHIVE_LINE_LEN {
            skipped += 1;
            continue;
        }
        match std::str::from_utf8(line)
            .ok()
            .and_then(|l| serde_json::from_str::<AnnouncementJson>(l).ok())
            .and_then(|j| Announcement::from_json(&j).ok())
        {
            Some(k) => out.push(k),
            None => skipped += 1,
        }
    }
    Ok((out, skipped))
}

#[cfg(test)]
mod archive_tests {
    use super::*;
    use crate::material::TlsMaterial;
    use crate::{CertSource, SelfSignedParams};

    fn announcement(n: &str) -> Announcement {
        let m = TlsMaterial::load(&CertSource::self_signed(SelfSignedParams::new(n, [n]))).unwrap();
        let der = m.cert_chain()[0].as_ref().to_vec();
        let pkcs8 = crate::pkcs8::pkcs8_p256(m.key_der(), &der).unwrap();
        let fp = krypto::hex::encode(&sha256(&der)).unwrap();
        let m2 = TlsMaterial::load(&CertSource::self_signed(SelfSignedParams::new(
            "fresh",
            ["fresh"],
        )))
        .unwrap();
        let pem = String::from_utf8(
            crate::pem::encode("CERTIFICATE", m2.cert_chain()[0].as_ref()).unwrap(),
        )
        .unwrap();
        Announcement::new("gateway", None, (&fp, &pkcs8), &pem, 1).unwrap()
    }

    fn tmpdir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("nettls-archive-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn empty_archive_is_not_an_error() {
        let d = tmpdir("empty");
        let (v, skipped) = read_archive(&d).unwrap();
        assert!(v.is_empty());
        assert_eq!(skipped, 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn archive_preserves_order() {
        let d = tmpdir("order");
        let a = announcement("a");
        let b = announcement("b");
        archive(&d, &a).unwrap();
        archive(&d, &b).unwrap();
        let (v, _) = read_archive(&d).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0], a);
        assert_eq!(v[1], b);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn the_archive_is_created_for_the_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmpdir("mode");
        archive(&d, &announcement("a")).unwrap();
        let mode = std::fs::metadata(d.join(ARCHIVE_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn one_corrupt_line_does_not_make_the_rest_unreadable() {
        // An audit trail must be readable WHEN someone needs it, and then "one
        // line is corrupt, hence everything is lost" is the worst conceivable answer.
        let d = tmpdir("corrupt");
        archive(&d, &announcement("a")).unwrap();
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(d.join(ARCHIVE_FILE))
                .unwrap();
            writeln!(f, "{{ this is not valid json").unwrap();
            // And one that is not even text.
            f.write_all(&[0xff, 0xfe, b'\n']).unwrap();
        }
        archive(&d, &announcement("b")).unwrap();

        let (v, skipped) = read_archive(&d).unwrap();
        assert_eq!(v.len(), 2, "the valid lines must be read");
        assert_eq!(skipped, 2, "and the broken ones must be counted");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_record_over_the_line_bound_is_not_archived_and_the_file_is_not_created() {
        // 0.12.0: control characters after the certificate block keep the PEM
        // under its own bound, and JSON writes each as six bytes.
        let m =
            TlsMaterial::load(&CertSource::self_signed(SelfSignedParams::new("a", ["a"]))).unwrap();
        let der = m.cert_chain()[0].as_ref().to_vec();
        let pkcs8 = crate::pkcs8::pkcs8_p256(m.key_der(), &der).unwrap();
        let fp = krypto::hex::encode(&sha256(&der)).unwrap();
        let fresh = TlsMaterial::load(&CertSource::self_signed(SelfSignedParams::new(
            "fresh",
            ["fresh"],
        )))
        .unwrap();
        let mut pem = String::from_utf8(
            crate::pem::encode("CERTIFICATE", fresh.cert_chain()[0].as_ref()).unwrap(),
        )
        .unwrap();
        pem.push_str(&"\u{1}".repeat(MAX_CERT_PEM_LEN - pem.len()));
        let k = Announcement::new("gateway", None, (&fp, &pkcs8), &pem, 1).unwrap();

        let d = tmpdir("record-over-bound");
        let err = archive(&d, &k).unwrap_err();
        assert!(matches!(err, TlsError::Params(_)), "{err:?}");
        assert!(
            err.to_string().contains(
                "over the bound of 65536 bytes a line may have to be read back; nothing was written"
            ),
            "{err}"
        );
        assert!(!d.join(ARCHIVE_FILE).exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn an_archive_over_64_mib_is_refused_and_a_line_over_64_kib_is_skipped() {
        // 0.12.0: a valid record padded with spaces to the line bound is read;
        // one byte more and it is skipped and counted without being parsed.
        use std::io::Write;
        let d = tmpdir("bounds");
        let record = serde_json::to_string(&announcement("a").to_json().unwrap()).unwrap();
        let padded = |len: usize| format!("{record}{}\n", " ".repeat(len - record.len()));
        std::fs::File::create(d.join(ARCHIVE_FILE))
            .unwrap()
            .write_all(
                format!(
                    "{}{}",
                    padded(MAX_ARCHIVE_LINE_LEN),
                    padded(MAX_ARCHIVE_LINE_LEN + 1)
                )
                .as_bytes(),
            )
            .unwrap();
        let (v, skipped) = read_archive(&d).unwrap();
        assert_eq!((v.len(), skipped), (1, 1));

        // The file is made longer with a hole, without writing data.
        std::fs::OpenOptions::new()
            .write(true)
            .open(d.join(ARCHIVE_FILE))
            .unwrap()
            .set_len(MAX_ARCHIVE_LEN as u64 + 1)
            .unwrap();
        let err = read_archive(&d).unwrap_err();
        assert!(matches!(err, TlsError::Io { .. }), "{err:?}");
        assert!(
            err.to_string()
                .contains("the archive is 67108865 bytes, over the bound of 67108864 bytes"),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}

// --------------------------------------------------------------------------- //
// `GET /v1/tls/identity` — the entire response shape (§6.14)
// --------------------------------------------------------------------------- //

/// The response to `GET /v1/tls/identity`.
///
/// # Why the crate owns the whole shape, not just the announcement
///
/// `nettls` owns the communication, and thereby **the contract** (§6.14). If we
/// let each service assemble the rest of the response itself — mode here,
/// `sent_at` there — we would have three places that must be kept identical, and
/// that is exactly the drift §6.14 is meant to prevent. The hex-versus-base64
/// discrepancy arose in exactly that way: two sides each filling in their part
/// of a shape nobody owned.
///
/// # Reading it
///
/// Deserializing requires `fingerprint`, written as lowercase hex with or
/// without its `sha256:` prefix, to be the SHA-256 of the one certificate in
/// `cert_pem`. A mismatch, or a `cert_pem` that is not exactly one X.509
/// certificate, fails the read *(0.12.0)*. So does a key the type does not
/// know, in `announcement` as well *(0.12.0)*, and a `cert_pem` over
/// [`MAX_CERT_PEM_LEN`] bytes *(0.12.0)*.
#[derive(Debug, Clone, Serialize)]
pub struct IdentityJson {
    /// The fingerprint being served right now, with the `sha256:` prefix.
    pub fingerprint: String,
    /// The certificate in its entirety.
    pub cert_pem: String,
    /// Expiry (ISO 8601), when it can be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    /// The mode **this** instance is configured with (§6.9b).
    ///
    /// Announced, never negotiated. The client compares against its own and
    /// reports disagreement as an active error.
    pub mode: crate::announcer::Mode,
    /// The sender's own clock (§6.7b).
    pub sent_at: i64,
    /// Pending announcement, if a rotation has been prepared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub announcement: Option<AnnouncementJson>,
}

impl IdentityJson {
    /// Build the response.
    ///
    /// `fingerprint` and `cert_pem` must be read **from what is actually being
    /// served**, not from a cached startup value. An advertised identity that
    /// lags one step behind what the server presents makes the client pin
    /// something it will never get to see — and then every single handshake
    /// fails. (That was not hypothetical: the first draft of the rotation did
    /// exactly that.)
    ///
    /// Fails with [`TlsError::Encode`] when the announcement's signatures
    /// cannot be encoded as hex *(0.12.0)*. A `cert_pem` over
    /// [`MAX_CERT_PEM_LEN`] bytes is [`TlsError::Params`] *(0.12.0)*.
    pub fn new(
        fingerprint: impl Into<String>,
        cert_pem: impl Into<String>,
        not_after: Option<String>,
        mode: crate::announcer::Mode,
        sent_at: i64,
        announcement: Option<&Announcement>,
    ) -> Result<Self, TlsError> {
        let cert_pem = cert_pem.into();
        check_cert_pem_len("cert_pem", &cert_pem)?;
        Ok(Self {
            fingerprint: fingerprint.into(),
            cert_pem,
            not_after,
            mode,
            sent_at,
            announcement: announcement.map(Announcement::to_json).transpose()?,
        })
    }
}

/// The fields of [`IdentityJson`] as they come off the wire, before the
/// fingerprint is checked against the certificate.
#[derive(Deserialize)]
#[serde(rename = "IdentityJson")]
#[serde(deny_unknown_fields)]
struct IdentityJsonWire {
    fingerprint: String,
    cert_pem: String,
    #[serde(default)]
    not_after: Option<String>,
    mode: crate::announcer::Mode,
    sent_at: i64,
    #[serde(default)]
    announcement: Option<AnnouncementJson>,
}

impl<'de> Deserialize<'de> for IdentityJson {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let w = IdentityJsonWire::deserialize(deserializer)?;
        require_served_fingerprint(&w.fingerprint, &w.cert_pem)
            .map_err(serde::de::Error::custom)?;
        Ok(Self {
            fingerprint: w.fingerprint,
            cert_pem: w.cert_pem,
            not_after: w.not_after,
            mode: w.mode,
            sent_at: w.sent_at,
            announcement: w.announcement,
        })
    }
}

/// Requires `fingerprint`, as lowercase hex with or without its `sha256:`
/// prefix, to be the SHA-256 of the one certificate in `cert_pem`. The error
/// says which of the two is wrong. A `cert_pem` over [`MAX_CERT_PEM_LEN`]
/// bytes is refused by [`der_from_pem`] before it is parsed *(0.12.0)*.
fn require_served_fingerprint(fingerprint: &str, cert_pem: &str) -> Result<(), String> {
    let not_one = |e: TlsError| format!("cert_pem is not exactly one X.509 certificate: {e}");
    let der = der_from_pem(cert_pem).map_err(not_one)?;
    crate::material::read_certificate(&der).map_err(not_one)?;
    let actual = to_hex("the certificate fingerprint", &sha256(&der)).map_err(|e| e.to_string())?;
    let stated = fingerprint.strip_prefix("sha256:").unwrap_or(fingerprint);
    if !same_fingerprint(stated, &actual) {
        return Err(format!(
            "the fingerprint {fingerprint:?} is not the SHA-256 of cert_pem, which is {actual}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod identity_tests {
    use super::tests::generation;
    use super::*;
    use crate::announcer::Mode;

    #[test]
    fn without_pending_rotation_announcement_is_omitted() {
        let c = generation("gateway");
        let i = IdentityJson::new(
            format!("sha256:{}", c.fp),
            c.pem.clone(),
            None,
            Mode::Rolling,
            100,
            None,
        )
        .unwrap();
        let t = serde_json::to_string(&i).unwrap();
        assert!(!t.contains("announcement"), "{t}");
        assert!(!t.contains("not_after"), "{t}");
    }

    #[test]
    fn mode_and_sent_at_are_always_present() {
        // Both are part of the contract: mode because the client must compare
        // (§6.9b), sent_at because drift must be measurable (§6.7b).
        let c = generation("gateway");
        let i = IdentityJson::new(
            format!("sha256:{}", c.fp),
            c.pem.clone(),
            None,
            Mode::Pinning,
            1_700_000_000,
            None,
        )
        .unwrap();
        let t = serde_json::to_string(&i).unwrap();
        assert!(t.contains("\"mode\":\"pinning\""), "{t}");
        assert!(t.contains("\"sent_at\":1700000000"), "{t}");
    }

    #[test]
    fn round_trip_preserves_everything() {
        let c = generation("gateway");
        let i = IdentityJson::new(
            format!("sha256:{}", c.fp),
            c.pem.clone(),
            Some("2026-09-10T12:00:00Z".into()),
            Mode::Rolling,
            5,
            None,
        )
        .unwrap();
        let t = serde_json::to_string(&i).unwrap();
        let out: IdentityJson = serde_json::from_str(&t).unwrap();
        assert_eq!(out.fingerprint, i.fingerprint);
        assert_eq!(out.mode, Mode::Rolling);
        assert_eq!(out.not_after.as_deref(), Some("2026-09-10T12:00:00Z"));
    }

    #[test]
    fn reading_requires_the_fingerprint_of_cert_pem() {
        // 0.12.0: the identity read must describe the certificate it carries.
        let c = generation("gateway");
        let other = generation("other");
        let not_a_certificate =
            String::from_utf8(crate::pem::encode("CERTIFICATE", b"not a certificate").unwrap())
                .unwrap();
        let read = |fingerprint: String, cert_pem: &str| {
            let i = IdentityJson::new(fingerprint, cert_pem, None, Mode::Rolling, 5, None).unwrap();
            serde_json::from_str::<IdentityJson>(&serde_json::to_string(&i).unwrap())
        };

        assert!(read(format!("sha256:{}", c.fp), &c.pem).is_ok());
        assert!(read(c.fp.clone(), &c.pem).is_ok());

        let err = read(format!("sha256:{}", other.fp), &c.pem).unwrap_err();
        assert!(
            err.to_string().contains("is not the SHA-256 of cert_pem"),
            "{err}"
        );

        let own = krypto::hex::encode(&sha256(b"not a certificate")).unwrap();
        let err = read(own, &not_a_certificate).unwrap_err();
        assert!(
            err.to_string()
                .contains("cert_pem is not exactly one X.509 certificate"),
            "{err}"
        );
    }

    #[test]
    fn an_identity_with_an_unknown_key_is_refused() {
        let c = generation("gateway");
        let i =
            IdentityJson::new(c.fp.clone(), c.pem.clone(), None, Mode::Rolling, 5, None).unwrap();
        let mut j = serde_json::to_value(&i).unwrap();
        j["extra"] = 1.into();
        let err = serde_json::from_str::<IdentityJson>(&j.to_string()).unwrap_err();
        assert!(err.to_string().contains("unknown field `extra`"), "{err}");
    }

    #[test]
    fn an_identity_whose_announcement_has_an_unknown_key_is_refused() {
        let c = generation("gateway");
        let next = generation("next");
        let k = Announcement::new("gateway", None, (&c.fp, &c.pkcs8), &next.pem, 5).unwrap();
        let i = IdentityJson::new(
            c.fp.clone(),
            c.pem.clone(),
            None,
            Mode::Rolling,
            5,
            Some(&k),
        )
        .unwrap();
        let mut j = serde_json::to_value(&i).unwrap();
        j["announcement"]["extra"] = 1.into();
        let err = serde_json::from_str::<IdentityJson>(&j.to_string()).unwrap_err();
        assert!(err.to_string().contains("unknown field `extra`"), "{err}");
    }
}
