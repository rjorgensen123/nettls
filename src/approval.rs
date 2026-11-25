// SPDX-License-Identifier: MIT OR Apache-2.0
//! Recognitions — **one code path** for generation 0 and generation *n* (§6.3).
//!
//! A recognition is a signed claim that an identity has been accepted. There
//! are two kinds:
//!
//! | Generation | Signed by | Canonical prefix |
//! |---|---|---|
//! | **0** | the operator, via portal's Ed25519 key | `nettls-approve/v1` |
//! | **1..n** | previous + current certificate | `nettls-rotate/v2` |
//!
//! ## Why they share a code path
//!
//! The spec is explicit: *"the verification is one code path"* (§6.3, requirement M-9).
//! It is not tidiness — it is that an anchor verified somewhere other than the
//! rest of the chain is an anchor nobody looks at when something goes wrong. Two
//! verification paths mean two places to get it wrong, and one of them is never audited.
//!
//! [`Recognition`] is therefore one type with **one** `verify`. The call site
//! does not need to know which kind it is holding.
//!
//! ## What the operator's approval actually is
//!
//! Not an act of trust the app interprets, but a **signature** — made with the
//! approving party's Ed25519 key, which its peers already pin. The actor is
//! inside the signed string (§6.4): a signature that does not cover who acted
//! does not say who acted.

use serde::{Deserialize, Serialize};

use crate::announcement::Announcement;
use crate::canonical;
use crate::error::{TlsError, to_hex};
use crate::signature::from_hex;

/// Serialized operator approval (§6.4). A key the type does not know is
/// refused when the JSON is read *(0.12.0)*.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalJson {
    /// Always `"nettls-approve/v1"`.
    pub v: String,
    /// The peer being approved.
    pub peer: String,
    /// The fingerprint being approved (64 hex, no prefix).
    pub fingerprint: String,
    /// The operator's username — **inside** the signed string.
    pub approved_by: String,
    /// Timestamp, unix seconds UTC: the signer's own clock. Signed; no `verify`
    /// compares it with a clock.
    pub timestamp: i64,
    /// Who signed. Today `"portal"`; later `"op:<name>"` if the operator gets
    /// their own key. The shape does not change — only the key (§6.4).
    pub key_id: String,
    /// Ed25519 signature, hex.
    pub sig: String,
}

/// Generation 0: the operator's approval, expressed as a signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    peer: String,
    fingerprint: String,
    approved_by: String,
    timestamp: i64,
    key_id: String,
    sig: Vec<u8>,
}

impl Approval {
    /// Create and sign an approval.
    pub fn new(
        peer: &str,
        fingerprint: &str,
        approved_by: &str,
        timestamp: i64,
        key_id: &str,
        ed25519_seed: &krypto::SecretBuf,
    ) -> Result<Self, TlsError> {
        let message = canonical::approve_v1(peer, fingerprint, approved_by, timestamp)?;
        canonical::require_name(key_id, "key_id", 64)?;
        let sig = krypto::sign::ed25519_sign(ed25519_seed, &message)
            .map_err(|e| TlsError::Sign(format!("Ed25519 signing failed: {e}")))?
            .to_vec();
        Ok(Self {
            peer: peer.to_string(),
            fingerprint: fingerprint.to_string(),
            approved_by: approved_by.to_string(),
            timestamp,
            key_id: key_id.to_string(),
            sig,
        })
    }

    /// The canonical string this approval signs.
    pub fn canonical(&self) -> Result<Vec<u8>, TlsError> {
        canonical::approve_v1(
            &self.peer,
            &self.fingerprint,
            &self.approved_by,
            self.timestamp,
        )
    }

    /// Verify that the approval is for `expected_peer`, against the pinned key
    /// for `key_id`.
    ///
    /// The peer is checked first: an approval for another peer is refused
    /// before anything else, since it says nothing about the peer expected
    /// *(0.12.0)*. An operator key, a `key_id` of the form `op:<name>`, may
    /// sign only an approval that names `<name>` in `approved_by`; other key
    /// ids, such as `portal`, are not affected *(0.12.0)*.
    ///
    /// `look_up_key` is the call site's key registry. That the lookup comes
    /// from outside is the point of the `key_id` mechanism: if the operator one
    /// day moves from portal-attested to their own key, the lookup changes — not
    /// the message shape (§6.4).
    pub fn verify(
        &self,
        expected_peer: &str,
        look_up_key: &dyn Fn(&str) -> Option<Vec<u8>>,
    ) -> Result<(), TlsError> {
        if self.peer != expected_peer {
            return Err(TlsError::ProofInvalid(format!(
                "the approval is for the peer {:?}, but {expected_peer:?} was expected — \
                 an approval for one peer says nothing about another",
                self.peer
            )));
        }
        if let Some(operator) = self.key_id.strip_prefix("op:")
            && operator != self.approved_by
        {
            return Err(TlsError::ProofInvalid(format!(
                "the approval is signed with the operator key {:?}, which may sign only \
                 approvals by {operator:?}, but it names {:?} as approver",
                self.key_id, self.approved_by
            )));
        }
        let Some(pk) = look_up_key(&self.key_id) else {
            return Err(TlsError::Chain(format!(
                "the approval is signed with \"{}\", which does not exist in the key registry — \
                 we cannot verify the anchor, and then it is not an anchor",
                self.key_id
            )));
        };
        krypto::sign::ed25519_verify(&pk, &self.canonical()?, &self.sig)
            .map_err(|_| TlsError::ProofInvalid("the Ed25519 signature does not hold".into()))
    }

    /// The fingerprint that was approved.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
    /// The peer the approval applies to.
    pub fn peer(&self) -> &str {
        &self.peer
    }
    /// Who approved.
    pub fn approved_by(&self) -> &str {
        &self.approved_by
    }
    /// The key that signed.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    /// The timestamp, unix seconds UTC: the signer's own clock *(0.12.0)*.
    pub fn timestamp(&self) -> i64 {
        self.timestamp
    }

    /// To serialized form. Fails with [`TlsError::Encode`] when the signature
    /// cannot be encoded as hex *(0.12.0)*.
    pub fn to_json(&self) -> Result<ApprovalJson, TlsError> {
        Ok(ApprovalJson {
            v: canonical::APPROVE_V1.to_string(),
            peer: self.peer.clone(),
            fingerprint: self.fingerprint.clone(),
            approved_by: self.approved_by.clone(),
            timestamp: self.timestamp,
            key_id: self.key_id.clone(),
            sig: to_hex("the signature", &self.sig)?,
        })
    }

    /// From serialized form. Fail-closed.
    pub fn from_json(j: &ApprovalJson) -> Result<Self, TlsError> {
        if j.v != canonical::APPROVE_V1 {
            return Err(TlsError::Proof(format!(
                "unknown message version \"{}\", expected \"{}\"",
                j.v,
                canonical::APPROVE_V1
            )));
        }
        canonical::require_component_name(&j.peer, "peer")?;
        canonical::require_fingerprint(&j.fingerprint, "fingerprint")?;
        canonical::require_name(&j.approved_by, "approved_by", 64)?;
        canonical::require_name(&j.key_id, "key_id", 64)?;
        Ok(Self {
            peer: j.peer.clone(),
            fingerprint: j.fingerprint.clone(),
            approved_by: j.approved_by.clone(),
            timestamp: j.timestamp,
            key_id: j.key_id.clone(),
            sig: from_hex(&j.sig)?,
        })
    }
}

/// What it takes to verify a recognition.
///
/// Gathers the two kinds' needs in one place, so `verify` has **one** signature
/// no matter which kind it receives.
pub struct Context<'a> {
    /// The counterpart the caller expects: the approval's `peer` or the
    /// announcement's `announcer` must be this name *(0.12.0)*.
    pub peer: &'a str,
    /// Key registry for `key_id` → Ed25519 public key (generation 0).
    pub keys: &'a dyn Fn(&str) -> Option<Vec<u8>>,
    /// The receiver's previous generation, if it exists (generation 1..n).
    pub previous_der: Option<&'a [u8]>,
    /// The receiver's current generation (generation 1..n).
    pub current_der: Option<&'a [u8]>,
}

/// A signed claim that an identity has been accepted — regardless of generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recognition {
    /// Generation 0: the operator's approval.
    Operator(Approval),
    /// Generation 1..n: an announcement.
    Schedule(Box<Announcement>),
}

impl Recognition {
    /// **One code path** (M-9). The call site does not need to know which kind it has.
    ///
    /// `k.peer` goes on to [`Approval::verify`] or [`Announcement::verify`],
    /// so a recognition about another peer is refused *(0.12.0)*.
    pub fn verify(&self, k: &Context<'_>) -> Result<(), TlsError> {
        match self {
            Recognition::Operator(g) => g.verify(k.peer, k.keys),
            Recognition::Schedule(r) => {
                let Some(current) = k.current_der else {
                    return Err(TlsError::Chain(
                        "an announcement cannot be verified without a current generation to \
                         verify it against"
                            .into(),
                    ));
                };
                r.verify(k.peer, k.previous_der, current)
            }
        }
    }

    /// The name this recognition is about: the approval's `peer`, or the
    /// announcement's `announcer` *(0.12.0)*.
    pub fn peer(&self) -> &str {
        match self {
            Recognition::Operator(g) => g.peer(),
            Recognition::Schedule(r) => r.announcer(),
        }
    }

    /// The fingerprint this recognition designates.
    pub fn fingerprint(&self) -> &str {
        match self {
            Recognition::Operator(g) => g.fingerprint(),
            Recognition::Schedule(r) => r.new_fingerprint(),
        }
    }

    /// Is this the anchor (generation 0)?
    pub fn is_anchor(&self) -> bool {
        matches!(self, Recognition::Operator(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::material::TlsMaterial;
    use crate::{CertSource, SelfSignedParams};
    use krypto::SecretBuf;

    const FP: &str = "aa00112233445566778899aabbccddeeff00112233445566778899aabbccddee";

    fn seed() -> SecretBuf {
        SecretBuf::from_vec(vec![5u8; 32]).unwrap()
    }

    fn register() -> impl Fn(&str) -> Option<Vec<u8>> {
        move |id: &str| {
            if id == "portal" {
                krypto::sign::ed25519_public(&seed())
                    .ok()
                    .map(|p| p.to_vec())
            } else {
                None
            }
        }
    }

    #[test]
    fn unknown_key_id_says_anchor_cannot_be_verified() {
        let g = Approval::new("gateway", FP, "operator", 100, "op:operator", &seed()).unwrap();
        let r = register();
        let err = g.verify("gateway", &r).unwrap_err();
        assert!(
            format!("{err}").contains("not an anchor"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn changed_actor_breaks_signature() {
        // `approved_by` lies INSIDE the signed string (§6.4): a signature that
        // does not cover who acted does not say who acted.
        let g = Approval::new("gateway", FP, "operator", 100, "portal", &seed()).unwrap();
        let mut j = g.to_json().unwrap();
        j.approved_by = "someone-else".into();
        let tampered = Approval::from_json(&j).unwrap();
        let r = register();
        assert!(tampered.verify("gateway", &r).is_err());
    }

    #[test]
    fn changed_fingerprint_breaks_signature() {
        let g = Approval::new("gateway", FP, "operator", 100, "portal", &seed()).unwrap();
        let mut j = g.to_json().unwrap();
        j.fingerprint = "bb".repeat(32);
        let tampered = Approval::from_json(&j).unwrap();
        let r = register();
        assert!(tampered.verify("gateway", &r).is_err());
    }

    #[test]
    fn an_approval_for_another_peer_is_refused() {
        // 0.12.0: a genuine approval for one peer says nothing about another.
        let g = Approval::new("gateway", FP, "operator", 100, "portal", &seed()).unwrap();
        let r = register();
        let err = g.verify("service", &r).unwrap_err();
        assert!(matches!(err, TlsError::ProofInvalid(_)), "{err:?}");
        assert!(
            format!("{err}").contains("for the peer \"gateway\", but \"service\" was expected"),
            "unexpected: {err}"
        );
        g.verify("gateway", &r).expect("its own peer");
    }

    #[test]
    fn an_operator_key_signs_only_approvals_by_its_operator() {
        // 0.12.0: `op:<name>` may sign only what names `<name>` as approver.
        let r = |id: &str| {
            ["portal", "op:bob"]
                .contains(&id)
                .then(|| krypto::sign::ed25519_public(&seed()).unwrap().to_vec())
        };
        let by_alice = Approval::new("gateway", FP, "alice", 100, "op:bob", &seed()).unwrap();
        let err = by_alice.verify("gateway", &r).unwrap_err();
        assert!(matches!(err, TlsError::ProofInvalid(_)), "{err:?}");
        assert!(
            format!("{err}").contains("\"op:bob\", which may sign only approvals by \"bob\""),
            "unexpected: {err}"
        );

        let by_bob = Approval::new("gateway", FP, "bob", 100, "op:bob", &seed()).unwrap();
        by_bob.verify("gateway", &r).expect("op:bob for bob");
        let via_portal = Approval::new("gateway", FP, "alice", 100, "portal", &seed()).unwrap();
        via_portal
            .verify("gateway", &r)
            .expect("portal is not affected");
    }

    #[test]
    fn json_round_trip() {
        let g = Approval::new(
            "gateway",
            FP,
            "bjørn-øyvind",
            1_700_000_000,
            "portal",
            &seed(),
        )
        .unwrap();
        let t = serde_json::to_string(&g.to_json().unwrap()).unwrap();
        let read_back: ApprovalJson = serde_json::from_str(&t).unwrap();
        assert_eq!(Approval::from_json(&read_back).unwrap(), g);
        assert_eq!(g.timestamp(), 1_700_000_000);
    }

    #[test]
    fn an_approval_with_an_unknown_key_is_refused() {
        let g = Approval::new("gateway", FP, "operator", 100, "portal", &seed()).unwrap();
        let mut j = serde_json::to_value(g.to_json().unwrap()).unwrap();
        j["extra"] = 1.into();
        let err = serde_json::from_str::<ApprovalJson>(&j.to_string()).unwrap_err();
        assert!(err.to_string().contains("unknown field `extra`"), "{err}");
    }

    // --- the ONE code path (M-9) ---------------------------------------------- //

    #[test]
    fn both_generations_verified_by_same_call() {
        // The requirement itself: the call site does not distinguish between
        // kinds. An anchor verified somewhere other than the rest of the chain
        // is an anchor nobody looks at when something goes wrong.
        let m0 =
            TlsMaterial::load(&CertSource::self_signed(SelfSignedParams::new("a", ["a"]))).unwrap();
        let der0 = m0.cert_chain()[0].as_ref().to_vec();
        let pkcs8 = crate::pkcs8::pkcs8_p256(m0.key_der(), &der0).unwrap();
        let fp0 = krypto::hex::encode(&krypto::sha256(&der0)).unwrap();

        let m1 =
            TlsMaterial::load(&CertSource::self_signed(SelfSignedParams::new("b", ["b"]))).unwrap();
        let pem1 = String::from_utf8(
            crate::pem::encode("CERTIFICATE", m1.cert_chain()[0].as_ref()).unwrap(),
        )
        .unwrap();

        let r = register();
        let recognitions = vec![
            Recognition::Operator(
                Approval::new("gateway", &fp0, "operator", 1, "portal", &seed()).unwrap(),
            ),
            Recognition::Schedule(Box::new(
                Announcement::new("gateway", None, (&fp0, &pkcs8), &pem1, 2).unwrap(),
            )),
        ];

        // ONE loop, one call, both kinds.
        for a in &recognitions {
            a.verify(&Context {
                peer: "gateway",
                keys: &r,
                previous_der: None,
                current_der: Some(&der0),
            })
            .unwrap_or_else(|e| panic!("recognition failed: {e}"));
        }

        // The same call for another peer refuses both kinds.
        for a in &recognitions {
            assert!(
                a.verify(&Context {
                    peer: "service",
                    keys: &r,
                    previous_der: None,
                    current_der: Some(&der0),
                })
                .is_err()
            );
        }

        assert!(recognitions[0].is_anchor());
        assert!(!recognitions[1].is_anchor());
        assert_eq!(recognitions[0].fingerprint(), fp0);
        assert_eq!(
            recognitions
                .iter()
                .map(Recognition::peer)
                .collect::<Vec<_>>(),
            ["gateway", "gateway"]
        );
    }

    #[test]
    fn announcement_without_current_generation_rejected() {
        let m0 =
            TlsMaterial::load(&CertSource::self_signed(SelfSignedParams::new("a", ["a"]))).unwrap();
        let der0 = m0.cert_chain()[0].as_ref().to_vec();
        let pkcs8 = crate::pkcs8::pkcs8_p256(m0.key_der(), &der0).unwrap();
        let fp0 = krypto::hex::encode(&krypto::sha256(&der0)).unwrap();
        let m1 =
            TlsMaterial::load(&CertSource::self_signed(SelfSignedParams::new("b", ["b"]))).unwrap();
        let pem1 = String::from_utf8(
            crate::pem::encode("CERTIFICATE", m1.cert_chain()[0].as_ref()).unwrap(),
        )
        .unwrap();

        let a = Recognition::Schedule(Box::new(
            Announcement::new("gateway", None, (&fp0, &pkcs8), &pem1, 2).unwrap(),
        ));
        let r = register();
        assert!(
            a.verify(&Context {
                peer: "gateway",
                keys: &r,
                previous_der: None,
                current_der: None,
            })
            .is_err()
        );
    }
}
