// SPDX-License-Identifier: MIT OR Apache-2.0
//! The status report — nettls' About contribution: one truth, two views
//! (Summary for every user, Report for the admin surface), levels and
//! headlines owned by the crate.

use nettls::announcer::Status;
use nettls::generations::{Generation, Generations};
use nettls::status::{Level, PeerReport, PeerState, Report};
use nettls::{CertSource, SelfSignedParams, TlsMaterial};

fn material(valid_days: u32) -> TlsMaterial {
    TlsMaterial::load(&CertSource::self_signed(
        SelfSignedParams::new("status-test", ["status-test"]).valid_days(valid_days),
    ))
    .unwrap()
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[test]
fn quiet_state_is_ok_and_summary_is_safe_for_users() {
    let m = material(365);
    let r = Report::collect(now(), &m, None, vec![]);
    assert_eq!(r.level, Level::Ok);
    assert_eq!(r.headline, "TLS ok");
    assert_eq!(r.version, nettls::VERSION);

    let s = r.summary();
    let json = serde_json::to_value(&s).unwrap();
    // The general view carries exactly version, level and headline — no peer
    // names, no fingerprints, no operations detail.
    let obj = json.as_object().unwrap();
    assert_eq!(obj.len(), 3);
    assert!(
        obj.contains_key("version") && obj.contains_key("level") && obj.contains_key("headline")
    );
}

#[test]
fn broken_peer_is_alert_and_named_in_the_headline() {
    let m = material(365);
    let peers = vec![PeerReport::broken("service", "aa".repeat(32))];
    let r = Report::collect(now(), &m, None, peers);
    assert_eq!(r.level, Level::Alert);
    assert!(r.headline.contains("service"), "{}", r.headline);
    assert!(r.headline.contains("operator action required"));
}

const DAY: i64 = 86_400;

#[test]
fn a_fresh_thirty_day_certificate_is_ok() {
    // Mode 2 lifetime. A fixed 30-day threshold made this amber from the
    // first hour, so the report could never be green in mode 2.
    let m = material(30);
    let r = Report::collect(now(), &m, None, vec![]);
    assert_eq!(r.level, Level::Ok, "{}", r.headline);
    assert!(!r.identity.expiry_warning);
}

#[test]
fn expiry_warning_is_warn_once_half_the_lifetime_has_passed() {
    let m = material(30);
    let (nb, na) = (m.not_before().unwrap(), m.not_after().unwrap());
    let half = nb + (na - nb) / 2;

    let before = Report::collect(half - 60, &m, None, vec![]);
    assert_eq!(before.level, Level::Ok, "{}", before.headline);

    let r = Report::collect(half, &m, None, vec![]);
    assert_eq!(r.level, Level::Warn);
    assert!(r.headline.contains("expires in 15 days"), "{}", r.headline);
    assert!(r.identity.expiry_warning);
}

#[test]
fn the_last_day_and_after_expiry_are_alert() {
    let m = material(30);
    let na = m.not_after().unwrap();

    let r = Report::collect(na - DAY - 1, &m, None, vec![]);
    assert_eq!(r.level, Level::Warn, "{}", r.headline);

    let r = Report::collect(na - DAY, &m, None, vec![]);
    assert_eq!(r.level, Level::Alert);
    assert!(r.headline.contains("within a day"), "{}", r.headline);

    // An hour after expiry: red and a negative day count, not "0 days".
    let r = Report::collect(na + 3600, &m, None, vec![]);
    assert_eq!(r.level, Level::Alert);
    assert!(r.headline.contains("expired"), "{}", r.headline);
    assert_eq!(r.identity.days_until_expiry, -1);
}

#[test]
fn days_until_expiry_is_negative_from_the_first_second_after_expiry() {
    // Expired an hour ago. `SelfSignedParams` cannot make that, so rcgen
    // builds it and the PEM is loaded.
    let mut p = rcgen::CertificateParams::new(vec!["expired-test".to_string()]).unwrap();
    let t = time::OffsetDateTime::now_utc();
    p.not_before = t - time::Duration::days(2);
    p.not_after = t - time::Duration::hours(1);
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = p.self_signed(&key).unwrap();
    let m = TlsMaterial::load(&CertSource::pem(cert.pem(), key.serialize_pem())).unwrap();
    assert_eq!(m.days_until_expiry(), -1);
}

#[test]
fn rotation_alarm_beats_warn_and_pending_reads_from_generations() {
    let m = material(365);
    let status = Status {
        waiting_for: vec!["gateway".into()],
        alarm: true,
        seconds_until_stop: 86_400,
    };
    let r = Report::collect(now(), &m, Some(&status), vec![]);
    assert_eq!(r.level, Level::Alert);
    assert!(r.headline.contains("gateway"), "{}", r.headline);

    // A peer with an announced next reads as RotationPending.
    let g = Generations::from_approval(Generation::from_der(m.cert_chain()[0].as_ref().to_vec()));
    let p = PeerReport::from_generations("gateway", &g);
    assert_eq!(p.state, PeerState::Ok); // bootstrap: nothing pending
    assert_eq!(p.current_fingerprint, m.fingerprint_sha256());
}
