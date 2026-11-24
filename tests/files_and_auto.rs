// SPDX-License-Identifier: MIT OR Apache-2.0
//! PEM to and from disk, and the `CertSource::auto` behaviour.

use std::fs;
use std::path::PathBuf;

use nettls::{CERT_FILE, CertOrigin, CertSource, KEY_FILE, SelfSignedParams, TlsMaterial};

/// A simple temp directory without a dependency. Removed in `Drop`.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let mut p = std::env::temp_dir();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("nettls-test-{name}-{unique}"));
        fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn params() -> SelfSignedParams {
    SelfSignedParams::new("nettls test", ["localhost", "127.0.0.1"])
}

#[test]
fn save_pem_and_load_back_from_file_gives_same_fingerprint() {
    let dir = TempDir::new("save");
    let generated = TlsMaterial::load(&CertSource::self_signed(params())).unwrap();
    generated.save_pem(dir.path()).unwrap();

    let cert_path = dir.path().join(CERT_FILE);
    let key_path = dir.path().join(KEY_FILE);
    assert!(cert_path.is_file() && key_path.is_file());

    let loaded = TlsMaterial::load(&CertSource::files(&cert_path, &key_path)).unwrap();
    assert_eq!(generated.fingerprint_sha256(), loaded.fingerprint_sha256());
    assert_eq!(loaded.origin(), CertOrigin::Files);
    assert_eq!(loaded.sans(), generated.sans());
    // The material must still be usable for an actual ServerConfig.
    loaded.server_config().unwrap();
}

#[cfg(unix)]
#[test]
fn key_file_is_0600_and_cert_file_0644() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new("perm");
    TlsMaterial::load(&CertSource::self_signed(params()))
        .unwrap()
        .save_pem(dir.path())
        .unwrap();

    let key_mode = fs::metadata(dir.path().join(KEY_FILE))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    let cert_mode = fs::metadata(dir.path().join(CERT_FILE))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(key_mode, 0o600, "key.pem must not be readable by others");
    assert_eq!(cert_mode, 0o644);
}

#[test]
fn load_from_pem_in_memory() {
    let dir = TempDir::new("mem");
    let generated = TlsMaterial::load(&CertSource::self_signed(params())).unwrap();
    generated.save_pem(dir.path()).unwrap();

    let cert_pem = fs::read(dir.path().join(CERT_FILE)).unwrap();
    let key_pem = fs::read(dir.path().join(KEY_FILE)).unwrap();
    let loaded = TlsMaterial::load(&CertSource::pem(cert_pem, key_pem)).unwrap();

    assert_eq!(loaded.fingerprint_sha256(), generated.fingerprint_sha256());
    assert_eq!(loaded.origin(), CertOrigin::Pem);
}

#[test]
fn auto_generates_first_time_and_reuses_thereafter() {
    let dir = TempDir::new("auto");

    let first = TlsMaterial::load(&CertSource::auto(dir.path(), params())).unwrap();
    assert_eq!(first.origin(), CertOrigin::Generated);
    assert!(dir.path().join(CERT_FILE).is_file());

    let second = TlsMaterial::load(&CertSource::auto(dir.path(), params())).unwrap();
    assert_eq!(second.origin(), CertOrigin::Reused);
    assert_eq!(
        first.fingerprint_sha256(),
        second.fingerprint_sha256(),
        "auto must reuse the cert — otherwise the operator gets a new browser warning at every restart"
    );
}

#[test]
fn auto_reuses_an_expired_certificate_and_says_so() {
    // Expired an hour ago. `SelfSignedParams` cannot make that, so rcgen
    // builds it, as in `tests/expiry.rs`, and it is stored where `auto` looks.
    let dir = TempDir::new("expired");
    let mut p = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let t = time::OffsetDateTime::now_utc();
    p.not_before = t - time::Duration::days(2);
    p.not_after = t - time::Duration::hours(1);
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = p.self_signed(&key).unwrap();
    let expired = TlsMaterial::load(&CertSource::pem(cert.pem(), key.serialize_pem())).unwrap();
    expired.save_pem(dir.path()).unwrap();

    let m = TlsMaterial::load(&CertSource::auto(dir.path(), params())).unwrap();
    assert_eq!(m.origin(), CertOrigin::ReusedExpired);
    assert!(!m.is_valid_now());
    assert_eq!(m.fingerprint_sha256(), expired.fingerprint_sha256());
}

#[test]
fn auto_reports_a_corrupt_stored_cert_and_leaves_it() {
    let dir = TempDir::new("corrupt");
    TlsMaterial::load(&CertSource::auto(dir.path(), params())).unwrap();
    fs::write(dir.path().join(CERT_FILE), b"this is not PEM\n").unwrap();
    let key_before = fs::read(dir.path().join(KEY_FILE)).unwrap();

    let e = TlsMaterial::load(&CertSource::auto(dir.path(), params())).unwrap_err();
    assert!(matches!(e, nettls::TlsError::Pem(_)), "{e}");
    assert!(
        e.to_string().contains(&dir.path().display().to_string()),
        "the error must say where: {e}"
    );
    assert_eq!(
        fs::read(dir.path().join(CERT_FILE)).unwrap(),
        b"this is not PEM\n"
    );
    assert_eq!(fs::read(dir.path().join(KEY_FILE)).unwrap(), key_before);
}

#[test]
fn auto_reports_a_key_that_does_not_belong_and_leaves_it() {
    let dir = TempDir::new("mismatch");
    TlsMaterial::load(&CertSource::auto(dir.path(), params())).unwrap();
    let other = TempDir::new("mismatch-source");
    TlsMaterial::load(&CertSource::self_signed(params()))
        .unwrap()
        .save_pem(other.path())
        .unwrap();
    fs::copy(other.path().join(KEY_FILE), dir.path().join(KEY_FILE)).unwrap();
    let cert_before = fs::read(dir.path().join(CERT_FILE)).unwrap();
    let key_before = fs::read(dir.path().join(KEY_FILE)).unwrap();

    let e = TlsMaterial::load(&CertSource::auto(dir.path(), params())).unwrap_err();
    assert!(matches!(e, nettls::TlsError::KeyMismatch(_)), "{e}");
    assert_eq!(fs::read(dir.path().join(CERT_FILE)).unwrap(), cert_before);
    assert_eq!(fs::read(dir.path().join(KEY_FILE)).unwrap(), key_before);
}

#[test]
fn auto_reports_an_incomplete_identity() {
    let dir = TempDir::new("incomplete");
    TlsMaterial::load(&CertSource::auto(dir.path(), params())).unwrap();
    fs::remove_file(dir.path().join(KEY_FILE)).unwrap();
    let cert_before = fs::read(dir.path().join(CERT_FILE)).unwrap();

    let e = TlsMaterial::load(&CertSource::auto(dir.path(), params())).unwrap_err();
    assert!(
        matches!(&e, nettls::TlsError::Io { path: Some(p), .. } if p.ends_with(KEY_FILE)),
        "{e}"
    );
    assert_eq!(fs::read(dir.path().join(CERT_FILE)).unwrap(), cert_before);
    assert!(!dir.path().join(KEY_FILE).exists());
}

#[cfg(unix)]
#[test]
fn auto_reports_an_unreadable_stored_file_and_leaves_it() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new("unreadable");
    TlsMaterial::load(&CertSource::auto(dir.path(), params())).unwrap();
    let key = dir.path().join(KEY_FILE);
    fs::set_permissions(&key, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::read(&key).is_ok() {
        // Root reads past mode 000, and then there is nothing to test.
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        eprintln!("skipping: the file is readable despite mode 000");
        return;
    }
    let cert_before = fs::read(dir.path().join(CERT_FILE)).unwrap();

    let e = TlsMaterial::load(&CertSource::auto(dir.path(), params())).unwrap_err();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(e, nettls::TlsError::Io { .. }), "{e}");
    assert_eq!(fs::read(dir.path().join(CERT_FILE)).unwrap(), cert_before);
}

#[test]
fn files_gives_understandable_error_on_mismatched_key() {
    let a = TempDir::new("pair-a");
    let b = TempDir::new("pair-b");
    let cert_owner = TlsMaterial::load(&CertSource::self_signed(params())).unwrap();
    cert_owner.save_pem(a.path()).unwrap();
    TlsMaterial::load(&CertSource::self_signed(params()))
        .unwrap()
        .save_pem(b.path())
        .unwrap();

    let e = TlsMaterial::load(&CertSource::files(
        a.path().join(CERT_FILE),
        b.path().join(KEY_FILE),
    ))
    .unwrap_err();
    let s = e.to_string();
    assert!(
        s.contains("do not belong together"),
        "the error message must say WHAT is wrong: {s}"
    );
    assert!(!s.is_empty());
    // Which certificate, and which two files (0.12.0).
    assert!(s.contains(&cert_owner.fingerprint_sha256()), "{s}");
    assert!(
        s.contains(&a.path().join(CERT_FILE).display().to_string()),
        "{s}"
    );
    assert!(
        s.contains(&b.path().join(KEY_FILE).display().to_string()),
        "{s}"
    );
}

/// The temp files a save of the pair goes through (0.12.0).
const CERT_TMP: &str = "cert.tmp";
const KEY_TMP: &str = "key.tmp";

/// A pair that is not the one stored in a test's directory, saved in its own.
fn another_pair(name: &str) -> (TempDir, TlsMaterial) {
    let dir = TempDir::new(name);
    let m = TlsMaterial::load(&CertSource::self_signed(params())).unwrap();
    m.save_pem(dir.path()).unwrap();
    (dir, m)
}

#[test]
fn a_save_that_fails_before_anything_is_in_place_leaves_the_stored_pair_whole() {
    // 0.12.0. A directory where the temp key goes: the save refuses it before
    // it writes anything.
    let dir = TempDir::new("save-fails");
    let stored = TlsMaterial::load(&CertSource::auto(dir.path(), params())).unwrap();
    fs::create_dir(dir.path().join(KEY_TMP)).unwrap();

    TlsMaterial::load(&CertSource::self_signed(params()))
        .unwrap()
        .save_pem(dir.path())
        .unwrap_err();

    let m = TlsMaterial::load(&CertSource::files(
        dir.path().join(CERT_FILE),
        dir.path().join(KEY_FILE),
    ))
    .unwrap();
    assert_eq!(m.fingerprint_sha256(), stored.fingerprint_sha256());
}

#[test]
fn the_next_load_finishes_a_save_stopped_between_the_renames() {
    // 0.12.0. The new certificate in place, its key in the temp file, and the
    // old key still in place.
    let dir = TempDir::new("finish");
    TlsMaterial::load(&CertSource::auto(dir.path(), params())).unwrap();
    let (new_dir, new) = another_pair("finish-new");
    fs::copy(new_dir.path().join(CERT_FILE), dir.path().join(CERT_FILE)).unwrap();
    fs::copy(new_dir.path().join(KEY_FILE), dir.path().join(KEY_TMP)).unwrap();
    // A temp key left more open than a key may be.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.path().join(KEY_TMP), fs::Permissions::from_mode(0o644)).unwrap();
    }

    let m = TlsMaterial::load(&CertSource::auto(dir.path(), params())).unwrap();
    assert_eq!(m.fingerprint_sha256(), new.fingerprint_sha256());
    assert!(!dir.path().join(KEY_TMP).exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(dir.path().join(KEY_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "a key is put in place for the owner only");
    }
}

#[test]
fn leftover_temp_files_beside_a_whole_pair_are_removed() {
    // 0.12.0. What a save stopped before the first rename leaves.
    let dir = TempDir::new("leftovers");
    let stored = TlsMaterial::load(&CertSource::auto(dir.path(), params())).unwrap();
    let (other, _) = another_pair("leftovers-other");
    fs::copy(other.path().join(CERT_FILE), dir.path().join(CERT_TMP)).unwrap();
    fs::copy(other.path().join(KEY_FILE), dir.path().join(KEY_TMP)).unwrap();

    let m = TlsMaterial::load(&CertSource::auto(dir.path(), params())).unwrap();
    assert_eq!(m.fingerprint_sha256(), stored.fingerprint_sha256());
    assert!(!dir.path().join(CERT_TMP).exists());
    assert!(!dir.path().join(KEY_TMP).exists());
}

#[test]
fn a_temp_key_that_does_not_belong_to_the_certificate_is_removed() {
    // 0.12.0
    let dir = TempDir::new("stray-key");
    let stored = TlsMaterial::load(&CertSource::auto(dir.path(), params())).unwrap();
    let (other, _) = another_pair("stray-key-other");
    fs::copy(other.path().join(KEY_FILE), dir.path().join(KEY_TMP)).unwrap();

    let m = TlsMaterial::load(&CertSource::auto(dir.path(), params())).unwrap();
    assert_eq!(m.fingerprint_sha256(), stored.fingerprint_sha256());
    assert!(!dir.path().join(KEY_TMP).exists());
}

#[test]
fn files_gives_understandable_error_on_missing_file_and_empty_pem() {
    let dir = TempDir::new("missing");
    let e = TlsMaterial::load(&CertSource::files(
        dir.path().join("does-not-exist.pem"),
        dir.path().join("nor-this-one.pem"),
    ))
    .unwrap_err();
    assert!(e.to_string().contains("does-not-exist.pem"), "{e}");

    let e = TlsMaterial::load(&CertSource::pem(b"".to_vec(), b"".to_vec())).unwrap_err();
    assert!(e.to_string().contains("CERTIFICATE"), "{e}");
}

#[test]
fn auto_without_writable_dir_gives_ephemeral_but_works() {
    // /proc is mounted such that create_dir_all fails; should a platform
    // allow it anyway, we skip instead of failing falsely.
    let impossible = std::path::Path::new("/proc/nettls-cannot-write-here");
    if fs::create_dir_all(impossible).is_ok() {
        let _ = fs::remove_dir_all(impossible);
        eprintln!("skipping: the directory could be created after all");
        return;
    }

    let m = TlsMaterial::load(&CertSource::auto(impossible, params())).unwrap();
    assert_eq!(
        m.origin(),
        CertOrigin::Ephemeral,
        "the service must come up with TLS, but the consumer must learn that the fingerprint \
         does not survive a restart"
    );
    m.server_config().unwrap();
}
