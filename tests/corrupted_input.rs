// SPDX-License-Identifier: MIT OR Apache-2.0
//! Corrupted input: no input makes the crate panic.
//!
//! For each kind of input nettls reads from others, one valid instance is
//! corrupted in four ways (a byte replaced, the input cut off, bytes inserted, a
//! slice repeated in place), and each corrupted instance is handed to the public
//! call a program would use. The call must return, with an error or an
//! acceptance. The corruptions come from a generator with a fixed seed; a valid
//! instance made with a fresh key, salt or signature differs from run to run, so
//! a panic is reported with the corrupted input.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::Arc;

use krypto::{Alg, SecretBuf, SecretString};
use nettls::announcement::{self as ann, Announcement, AnnouncementJson, Handled, HandledJson};
use nettls::announcement::{IdentityJson, Receipt, ReceiptJson};
use nettls::announcer::{Announcer, Mode, OwnMaterial, PENDING_FILE, Schedule};
use nettls::approval::{Approval, ApprovalJson};
use nettls::capability::SupportStatement;
use nettls::envelope::{self, RecipientKey};
use nettls::generations::Generation;
use nettls::signature::from_hex;
use nettls::{CertSource, RotatingResolver, SelfSignedParams, TlsMaterial, lockbox, pem};

/// The seed the generator starts from in every call of [`feed`].
const SEED: u64 = 0x6e65_7474_6c73_2d31;
/// Corrupted instances per kind of corruption, for an input that is cheap to read.
const ITERATIONS: usize = 40;
/// Corrupted instances per kind of corruption, for a file the announcer reads
/// at start: each is a fresh copy of the announcer's directory.
const ANNOUNCER_ITERATIONS: usize = 20;
/// Bytes of a corrupted input shown when a call panics on it.
const SHOWN_BYTES: usize = 1024;
/// The corruptions, in the order a span per kind is given to [`feed`].
const KINDS: [Kind; 4] = [Kind::Replace, Kind::Cut, Kind::Insert, Kind::Repeat];
/// Corruptions placed anywhere in the input.
const WHOLE: [usize; 4] = [usize::MAX; 4];

#[derive(Clone, Copy, Debug)]
enum Kind {
    Replace,
    Cut,
    Insert,
    Repeat,
}

/// xorshift64, so every run makes the same corruptions.
struct Rng(u64);

impl Rng {
    /// A number below `n`.
    fn below(&mut self, n: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % n.max(1) as u64) as usize
    }

    /// `input` with one corruption of `kind`, placed in its first `span`
    /// bytes. `input` is not empty.
    fn corrupt(&mut self, input: &[u8], kind: Kind, span: usize) -> Vec<u8> {
        let span = span.min(input.len());
        let at = self.below(span);
        let mut out = input.to_vec();
        match kind {
            Kind::Replace => out[at] ^= 1 + self.below(255) as u8,
            Kind::Cut => out.truncate(at),
            Kind::Insert => {
                for _ in 0..1 + self.below(8) {
                    out.insert(at, self.below(256) as u8);
                }
            }
            Kind::Repeat => {
                let end = at + 1 + self.below((span - at).min(64));
                out.splice(end..end, input[at..end].iter().copied());
            }
        }
        out
    }
}

/// Hands `call` `n` corruptions of `valid` of each kind, each placed in the
/// first bytes `spans` gives for its kind, and returns a line for every call
/// that panicked. `call` says whether it accepted the input, or `None` when it
/// did not hand it on. The valid instance must not be refused, or the
/// corruptions would probe only the first check.
fn feed(
    row: &str,
    valid: &[u8],
    n: usize,
    spans: [usize; 4],
    call: impl Fn(&[u8]) -> Option<bool>,
) -> Vec<String> {
    assert_ne!(call(valid), Some(false), "{row}: valid instance refused");
    let mut rng = Rng(SEED);
    let (mut accepted, mut refused, mut not_given, mut panics) = (0, 0, 0, Vec::new());
    for (kind, span) in KINDS.into_iter().zip(spans) {
        for i in 0..n {
            let input = rng.corrupt(valid, kind, span);
            match catch_unwind(AssertUnwindSafe(|| call(&input))) {
                Ok(Some(true)) => accepted += 1,
                Ok(Some(false)) => refused += 1,
                Ok(None) => not_given += 1,
                Err(payload) => {
                    let text = (payload.downcast_ref::<String>().cloned())
                        .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                        .unwrap_or_default();
                    let shown = &input[..input.len().min(SHOWN_BYTES)];
                    let hex = krypto::hex::encode(shown).unwrap_or_default();
                    let len = input.len();
                    panics.push(format!("{row}, {kind:?} #{i}: {text}; {len} bytes: {hex}"));
                }
            }
        }
    }
    println!("{row}: {accepted} accepted, {refused} refused, {not_given} not given");
    panics
}

/// [`feed`] over the whole input, every corrupted instance handed on.
fn feed_all(row: &str, valid: &[u8], n: usize, call: impl Fn(&[u8]) -> bool) -> Vec<String> {
    feed(row, valid, n, WHOLE, |input| Some(call(input)))
}

fn no_panics(panics: Vec<String>) {
    assert!(panics.is_empty(), "{}", panics.join("\n"));
}

/// `text` read as a `T`, as serde reads it off the wire.
fn json<T: serde::de::DeserializeOwned>(text: &[u8]) -> Option<T> {
    serde_json::from_slice(text).ok()
}

/// The valid messages of the error corpus, with the certificates and the
/// Ed25519 key they are signed for.
fn baseline() -> serde_json::Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/testvectors/errors.json");
    let raw = std::fs::read_to_string(path).expect("the error corpus");
    serde_json::from_str::<serde_json::Value>(&raw).expect("JSON")["_valid"].take()
}

fn field<'a>(v: &'a serde_json::Value, key: &str) -> &'a str {
    v[key].as_str().expect(key)
}

fn baseline_announcement(b: &serde_json::Value) -> Announcement {
    Announcement::from_json(&serde_json::from_value(b["announcement"].clone()).unwrap()).unwrap()
}

fn self_signed() -> TlsMaterial {
    let params = SelfSignedParams::new("localhost", ["localhost"]);
    TlsMaterial::load(&CertSource::self_signed(params)).expect("self-signed")
}

#[test]
fn a_corrupted_announcement_never_panics() {
    let b = baseline();
    let prev = ann::der_from_pem(field(&b, "prev_cert_pem")).unwrap();
    let curr = ann::der_from_pem(field(&b, "curr_cert_pem")).unwrap();
    let text = serde_json::to_vec(&b["announcement"]).unwrap();
    no_panics(feed_all("announcement", &text, ITERATIONS, |t| {
        json::<AnnouncementJson>(t)
            .and_then(|j| Announcement::from_json(&j).ok())
            .is_some_and(|k| k.verify("gateway", Some(&prev), &curr).is_ok())
    }));
}

#[test]
fn a_corrupted_receipt_or_handled_message_never_panics() {
    let b = baseline();
    let pk = from_hex(field(&b, "ed25519_pub")).unwrap();
    let seed = SecretBuf::from_vec(from_hex(field(&b, "ed25519_seed")).unwrap()).unwrap();
    let fp = field(&b["receipt"], "new_fingerprint");
    let sent_at = b["receipt"]["sent_at"].as_i64().unwrap();
    let handled = Handled::new("service", "gateway", fp, sent_at, &seed).unwrap();
    let receipt_text = serde_json::to_vec(&b["receipt"]).unwrap();
    let handled_text = serde_json::to_vec(&handled.to_json().unwrap()).unwrap();
    let receipts = feed_all("receipt", &receipt_text, ITERATIONS, |t| {
        json::<ReceiptJson>(t)
            .and_then(|j| Receipt::from_json(&j).ok())
            .is_some_and(|m| m.verify("service", &pk, fp).is_ok())
    });
    let handled = feed_all("handled message", &handled_text, ITERATIONS, |t| {
        json::<HandledJson>(t)
            .and_then(|j| Handled::from_json(&j).ok())
            .is_some_and(|m| m.verify("service", &pk, fp).is_ok())
    });
    no_panics([receipts, handled].concat());
}

#[test]
fn a_corrupted_approval_never_panics() {
    let b = baseline();
    let pk = from_hex(field(&b, "ed25519_pub")).unwrap();
    let keys = move |id: &str| (id == "portal").then(|| pk.clone());
    let text = serde_json::to_vec(&b["approval"]).unwrap();
    no_panics(feed_all("approval", &text, ITERATIONS, |t| {
        json::<ApprovalJson>(t)
            .and_then(|j| Approval::from_json(&j).ok())
            .is_some_and(|a| a.verify("gateway", &keys).is_ok())
    }));
}

#[test]
fn a_corrupted_identity_or_support_statement_never_panics() {
    let b = baseline();
    let pem = field(&b, "curr_cert_pem");
    let fp = format!("sha256:{}", ann::fingerprint_from_pem(pem).unwrap());
    let date = Some("2030-01-01T00:00:00Z".to_string());
    let k = baseline_announcement(&b);
    let identity = IdentityJson::new(fp, pem, date, Mode::Rolling, 1, Some(&k)).unwrap();
    let identity_text = serde_json::to_vec(&identity).unwrap();
    let m = self_signed();
    let (der, pkcs8) = (m.cert_chain()[0].as_ref(), m.anchor_pkcs8().unwrap());
    let algs = [Alg::Aegis256, Alg::Aes256Gcm];
    let statement = SupportStatement::signed("service", &algs, 1, &pkcs8).unwrap();
    let statement_text = serde_json::to_vec(&statement).unwrap();
    let identities = feed_all("identity", &identity_text, ITERATIONS, |t| {
        json::<IdentityJson>(t).is_some()
    });
    let statements = feed_all("support statement", &statement_text, ITERATIONS, |t| {
        json::<SupportStatement>(t).is_some_and(|s| s.verify("service", der).is_ok())
    });
    no_panics([identities, statements].concat());
}

#[test]
fn a_corrupted_certificate_never_panics() {
    let pem = field(&baseline(), "curr_cert_pem").to_string();
    let der = ann::der_from_pem(&pem).unwrap();
    // `from_pem` takes text: an instance that is not UTF-8 is given as a
    // program that reads it lossily would give it.
    let pems = feed_all("certificate PEM", pem.as_bytes(), ITERATIONS, |t| {
        Generation::from_pem(&String::from_utf8_lossy(t)).is_ok()
    });
    let ders = feed_all("certificate DER", &der, ITERATIONS, |t| {
        Generation::from_der(t).is_ok()
    });
    no_panics([pems, ders].concat());
}

#[test]
fn a_corrupted_certificate_or_key_pem_never_panics() {
    let m = self_signed();
    let cert = pem::encode("CERTIFICATE", m.cert_chain()[0].as_ref()).unwrap();
    let pkcs8 = m.anchor_pkcs8().unwrap();
    let key = pkcs8.expose(|der| pem::encode("PRIVATE KEY", der)).unwrap();
    let load = |c: &[u8], k: &[u8]| TlsMaterial::load(&CertSource::pem(c, k)).is_ok();
    let certs = feed_all("certificate PEM to load", &cert, ITERATIONS, |t| {
        load(t, &key)
    });
    let keys = feed_all("key PEM to load", &key, ITERATIONS, |t| load(&cert, t));
    no_panics([certs, keys].concat());
}

#[test]
fn a_corrupted_pin_never_panics() {
    let fp = ann::fingerprint_from_pem(field(&baseline(), "curr_cert_pem")).unwrap();
    let pairs = Vec::from_iter(fp.as_bytes().chunks(2).map(String::from_utf8_lossy));
    let pin = format!("SHA256:{}", pairs.join(":").to_uppercase());
    // The pin is text: an instance that is not UTF-8 is read lossily.
    no_panics(feed_all("pin", pin.as_bytes(), ITERATIONS, |t| {
        nettls::pinned_client_config(&String::from_utf8_lossy(t)).is_ok()
    }));
}

#[test]
fn a_corrupted_envelope_never_panics() {
    let key = RecipientKey::from_bytes(SecretBuf::from_vec(vec![0x42; 32]).unwrap()).unwrap();
    let sealed = envelope::seal(&key.public().unwrap(), b"example content").unwrap();
    no_panics(feed_all("envelope", &sealed, ITERATIONS, |t| {
        envelope::open(&key, t).is_ok()
    }));
}

/// Before `unlock` derives a key from the password, it checks that the file
/// holds the 8-byte header and the 32-byte salt, that it starts with the
/// header, and that it is no longer than krypto's largest blob allows. The test
/// touches the first two: replacements, insertions and repeated slices fall in
/// the header, and cuts in the first 40 bytes. An instance that would still
/// pass both is not handed to `unlock`, so no key is derived from a corrupted
/// file.
#[test]
fn a_corrupted_locked_file_never_panics() {
    const HEADER: &[u8] = b"NETTLS\x01\x00";
    const HEADER_AND_SALT: usize = 40;
    let password = SecretString::from_string("example password".into()).unwrap();
    let locked = lockbox::lock(&password, b"example state").unwrap();
    let spans = [HEADER.len(), HEADER_AND_SALT, HEADER.len(), HEADER.len()];
    no_panics(feed("locked file", &locked, ITERATIONS, spans, |t| {
        (t.len() < HEADER_AND_SALT || !t.starts_with(HEADER))
            .then(|| lockbox::unlock(&password, t).is_ok())
    }));
}

/// Copies the files of `from`, and of its `new/`, into a fresh `to`.
fn copy_state(from: &Path, to: &Path) {
    let _ = std::fs::remove_dir_all(to);
    for sub in ["", "new"] {
        std::fs::create_dir_all(to.join(sub)).unwrap();
        for entry in std::fs::read_dir(from.join(sub)).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                std::fs::copy(&path, to.join(sub).join(path.file_name().unwrap())).unwrap();
            }
        }
    }
}

#[test]
fn corrupted_announcer_files_and_archive_never_panic() {
    let root = std::env::temp_dir().join(format!("nettls-corrupted-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let (valid, work, archive) = (root.join("valid"), root.join("work"), root.join("archive"));
    let c0 = self_signed();
    c0.save_pem(&valid).unwrap();
    let start = |dir: &Path| {
        let key = (c0.fingerprint_sha256(), c0.anchor_pkcs8().unwrap());
        let anchor = OwnMaterial {
            previous: None,
            current: key,
        };
        let resolver = Arc::new(RotatingResolver::new(&c0).unwrap());
        let schedule = Schedule::new(vec!["service".to_string()], 0).unwrap();
        let params = SelfSignedParams::new("localhost", ["localhost"]);
        Announcer::new("gateway", dir, params, resolver, anchor, schedule, None)
    };
    // A switch leaves `previous-key.json`; the next prepared rotation leaves
    // `pending-rotation.json` and `new/` beside it.
    let a = start(&valid).unwrap();
    let first = a.prepare(100).unwrap();
    let seed = SecretBuf::from_vec(vec![7; 32]).unwrap();
    let pk = krypto::sign::ed25519_public(&seed).unwrap();
    let receipt = Receipt::new("service", "gateway", first.new_fingerprint(), 100, &seed).unwrap();
    a.acked("service", &receipt, &pk).unwrap();
    a.roll_if_ready(200).unwrap().expect("the switch");
    let second = a.prepare(300).unwrap();
    drop(a);

    let mut panics = Vec::new();
    for file in [PENDING_FILE, "previous-key.json", "cert.pem", "key.pem"] {
        let original = std::fs::read(valid.join(file)).unwrap();
        panics.extend(feed_all(file, &original, ANNOUNCER_ITERATIONS, |t| {
            copy_state(&valid, &work);
            std::fs::write(work.join(file), t).unwrap();
            start(&work).is_ok()
        }));
    }
    std::fs::create_dir_all(&archive).unwrap();
    for k in [first, second, baseline_announcement(&baseline())] {
        ann::archive(&archive, &k).unwrap();
    }
    let records = std::fs::read(archive.join(ann::ARCHIVE_FILE)).unwrap();
    panics.extend(feed_all("archive", &records, ITERATIONS, |t| {
        std::fs::write(archive.join(ann::ARCHIVE_FILE), t).unwrap();
        // Accepted means every record was read back, none skipped.
        matches!(ann::read_archive(&archive), Ok((_, 0)))
    }));
    let _ = std::fs::remove_dir_all(&root);
    no_panics(panics);
}
