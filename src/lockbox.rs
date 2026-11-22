// SPDX-License-Identifier: MIT OR Apache-2.0
//! Lock and unlock local state at rest (SPEC-nettls §6.11).
//!
//! A module comes up **locked**. It cannot read its own peer registry, its
//! generation pairs or its TLS keys until it has been given the password —
//! and the password arrives only once a human has logged in (§8.1).
//!
//! The property this buys, stated precisely:
//!
//! > **A copy of the disk is worthless without at least one user's password**
//! > — because the key has never been on the machine.
//!
//! ## No verification hash
//!
//! We store **no** argon2 hash next to the ciphertext. If the password is
//! wrong, the AEAD authentication fails on its own. A stored hash would also
//! have given an attacker with the disk a **separate oracle** to test
//! candidates against, alongside the ciphertext he had to attack anyway
//! (§8.4).
//!
//! ## Not a new blob format
//!
//! The crypto is `krypto`'s: argon2id as the KDF, and the FAFN blob with the
//! AEAD. Inventing a second format would mean two things to
//! keep correct — and one of them is always the one that never gets reviewed.
//!
//! The salt sits in cleartext in front of the blob. It is no secret: its job
//! is to make precomputed tables useless, and it does that just as well in
//! plain sight.

use krypto::{Alg, SecretBuf, SecretString};

use crate::error::TlsError;

/// Magic + version in front of the salt, so a file we do not understand is
/// rejected as **wrong format** instead of as a wrong password.
///
/// The difference is not cosmetic: "wrong password" sends the operator off to
/// hunt for a password, while "wrong format" sends her to the right place.
const MAGIC: &[u8; 8] = b"NETTLS\x01\x00";
/// The salt length. 16 is the minimum in `krypto`; we use 32.
const SALT_LEN: usize = 32;
/// The `key_id` in the FAFN header. Fixed — we have one key per file, derived
/// from the password, and no key rotation at this layer.
const KEY_ID: [u8; 16] = *b"nettls-local-st1";
/// The longest file [`unlock`] takes: header, salt and the largest blob krypto
/// opens *(0.12.0)*.
const MAX_FILE_LEN: usize = MAGIC.len() + SALT_LEN + crate::KRYPTO_MAX_BLOB_BYTES;

/// Locks content with a password — with the default AEAD,
/// **AEGIS-256** (SPEC-nettls §6.0b: at rest there is no cross-reading —
/// whoever writes, reads — so a Rust-owned store uses the best we have).
///
/// The salt is drawn fresh every time, so two lockings of the same content
/// with the same password yield different ciphertext.
///
/// A password over `krypto::password::MAX_PASSWORD_BYTES`, or a plaintext over
/// `krypto::MAX_DATA_BYTES`, is [`TlsError::Params`] *(0.12.0)*.
pub fn lock(password: &SecretString, plaintext: &[u8]) -> Result<Vec<u8>, TlsError> {
    lock_with(password, plaintext, Alg::Aegis256)
}

/// Like [`lock`], but with an explicit AEAD choice (SPEC-nettls §6.0b: the
/// algorithm menu is krypto's; the choice is the consumer's).
///
/// `Alg::Aes256Gcm` is the documented interop bridge — the one AEAD a reader
/// without AEGIS also has. Unlocking reads the algorithm from the FAFN header,
/// so [`unlock`] opens either; a reader without the algorithm fails hard,
/// never silently (the A1 rule: no fallback below the floor, never to
/// nothing).
///
/// A password or plaintext over krypto's limit is [`TlsError::Params`], as
/// for [`lock`] *(0.12.0)*.
pub fn lock_with(password: &SecretString, plaintext: &[u8], alg: Alg) -> Result<Vec<u8>, TlsError> {
    check_password_len(password)?;
    // `random_bytes` and not `SecretBuf::random`: the salt is stored in
    // cleartext right in front of the blob — it is public by design.
    let salt = krypto::random_bytes(SALT_LEN).map_err(|e| TlsError::Random(e.to_string()))?;

    let blob = seal(password, &salt, plaintext, alg)?;

    let mut out = Vec::with_capacity(MAGIC.len() + SALT_LEN + blob.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&blob);
    Ok(out)
}

/// Unlocks. **A wrong password gives an authentication failure**, not an empty result.
///
/// *(0.12.0)* A password over `krypto::password::MAX_PASSWORD_BYTES` is
/// [`TlsError::Params`], checked first. A file longer than header, salt and
/// krypto's largest blob is [`TlsError::Envelope`], refused before a key is
/// derived from the password; so is a blob that is not a krypto blob, and
/// content krypto refuses as too large once unlocked. Unlocked content that
/// cannot be held in locked memory is [`TlsError::LockedMemory`].
pub fn unlock(password: &SecretString, file: &[u8]) -> Result<SecretBuf, TlsError> {
    check_password_len(password)?;
    if file.len() < MAGIC.len() + SALT_LEN {
        return Err(TlsError::Envelope(
            "the locked file is too short to contain header and salt".into(),
        ));
    }
    if &file[..MAGIC.len()] != MAGIC {
        return Err(TlsError::Envelope(
            "unknown file format — this is not a locked nettls state file. \
             (A wrong FORMAT, not a wrong password: look for the right file, not the right password.)"
                .into(),
        ));
    }
    if file.len() > MAX_FILE_LEN {
        return Err(TlsError::Envelope(format!(
            "the locked file is too long: {} bytes, at most {MAX_FILE_LEN} \
             (header, salt and krypto's largest blob)",
            file.len()
        )));
    }
    let salt = &file[MAGIC.len()..MAGIC.len() + SALT_LEN];
    let blob = &file[MAGIC.len() + SALT_LEN..];

    let key = derive(password, salt)?;
    let dk = krypto::MasterKey::from_bytes(key)
        .and_then(|mk| mk.derive(b"nettls/local-state/v1", salt))
        .map_err(|e| TlsError::Envelope(format!("key derivation failed: {e}")))?;

    krypto::open(&dk, blob).map_err(|e| match e {
        krypto::Error::Hardening(_) => TlsError::not_held("the unlocked content", e),
        krypto::Error::Format(_) => {
            TlsError::Envelope(format!("the locked file was not accepted: {e}"))
        }
        _ => TlsError::ProofInvalid(
            "could not unlock the local state — wrong password, or the file was altered. \
             (We store no verification hash, so this is the AEAD speaking up.)"
                .into(),
        ),
    })
}

fn seal(
    password: &SecretString,
    salt: &[u8],
    plaintext: &[u8],
    alg: Alg,
) -> Result<Vec<u8>, TlsError> {
    let key = derive(password, salt)?;
    let dk = krypto::MasterKey::from_bytes(key)
        .and_then(|mk| mk.derive(b"nettls/local-state/v1", salt))
        .map_err(|e| TlsError::Envelope(format!("key derivation failed: {e}")))?;
    let pt = SecretBuf::from_vec(plaintext.to_vec())
        .map_err(|e| TlsError::not_held("the plaintext", e))?;
    krypto::seal(&dk, &KEY_ID, &pt, alg)
        .map_err(|e| TlsError::Envelope(format!("sealing failed: {e}")))
}

/// The key for `salt` from the password. A password krypto refuses (`Format`,
/// over its length limit) is [`TlsError::Params`] *(0.12.0)*.
fn derive(password: &SecretString, salt: &[u8]) -> Result<SecretBuf, TlsError> {
    krypto::password::derive_key(password, salt, krypto::password::Preset::Interactive).map_err(
        |e| match e {
            krypto::Error::Format(_) => password_not_accepted(e),
            _ => TlsError::Envelope(format!("argon2 derivation failed: {e}")),
        },
    )
}

/// Refuses a password over `krypto::password::MAX_PASSWORD_BYTES` with the
/// answer krypto's own check gives, before the password is used for anything
/// *(0.12.0)*. [`lock_with`], [`unlock`] and `Announcer::new` call it first.
pub(crate) fn check_password_len(password: &SecretString) -> Result<(), TlsError> {
    let max = krypto::password::MAX_PASSWORD_BYTES;
    if password.len() > max {
        return Err(password_not_accepted(krypto::Error::Format(format!(
            "password is {} bytes — max {max}",
            password.len()
        ))));
    }
    Ok(())
}

/// A password krypto refuses, as [`TlsError::Params`] with krypto's text
/// *(0.12.0)*.
fn password_not_accepted(e: krypto::Error) -> TlsError {
    TlsError::Params(format!("the password was not accepted: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pw(s: &str) -> SecretString {
        SecretString::from_string(s.to_string()).expect("valid")
    }

    #[test]
    fn wrong_password_gives_authentication_failure() {
        // O-7: no stored verification hash — the AEAD speaks up.
        let file = lock(&pw("secret"), b"x").unwrap();
        let err = unlock(&pw("secreT"), &file).unwrap_err();
        assert!(format!("{err}").contains("no verification hash"), "{err}");
    }

    #[test]
    fn no_verification_hash_in_the_file() {
        // The requirement itself: the file must contain magic + salt + FAFN
        // blob, and nothing usable as an oracle.
        let file = lock(&pw("secret"), b"x").unwrap();
        assert_eq!(&file[..MAGIC.len()], MAGIC);
        // The FAFN blob starts right after the salt.
        assert_eq!(&file[MAGIC.len() + SALT_LEN..][..4], b"FAFN");
        // No PHC string anywhere.
        assert!(
            !String::from_utf8_lossy(&file).contains("$argon2"),
            "a PHC hash has sneaked into the file"
        );
    }

    #[test]
    fn altered_ciphertext_is_rejected() {
        let mut file = lock(&pw("secret"), b"something important").unwrap();
        let last = file.len() - 1;
        file[last] ^= 0x01;
        assert!(unlock(&pw("secret"), &file).is_err());
    }

    #[test]
    fn altered_salt_is_rejected() {
        let mut file = lock(&pw("secret"), b"something important").unwrap();
        file[MAGIC.len()] ^= 0x01;
        assert!(unlock(&pw("secret"), &file).is_err());
    }

    #[test]
    fn wrong_format_says_it_is_the_format() {
        // "Wrong password" would have sent the operator hunting for a password.
        let err = unlock(
            &pw("x"),
            b"this is quite definitely not a locked state file",
        )
        .unwrap_err();
        assert!(matches!(err, TlsError::Envelope(_)), "{err:?}");
        assert!(format!("{err}").contains("unknown file format"), "{err}");
    }

    #[test]
    fn too_short_file_is_rejected() {
        let err = unlock(&pw("x"), b"short").unwrap_err();
        assert!(matches!(err, TlsError::Envelope(_)), "{err:?}");
    }

    #[test]
    fn same_content_gives_different_ciphertext() {
        // Fresh salt every time.
        let a = lock(&pw("secret"), b"x").unwrap();
        let b = lock(&pw("secret"), b"x").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn empty_content_is_allowed() {
        let file = lock(&pw("secret"), b"").unwrap();
        let out = unlock(&pw("secret"), &file).unwrap();
        out.expose(|b| assert!(b.is_empty()));
    }

    /// Header and salt in front of `blob`: a file `unlock` reads past its
    /// framing checks.
    fn framed(blob: &[u8]) -> Vec<u8> {
        let mut file = MAGIC.to_vec();
        file.extend_from_slice(&[0u8; SALT_LEN]);
        file.extend_from_slice(blob);
        file
    }

    #[test]
    fn a_password_over_krypto_limit_is_params() {
        // 0.12.0: refused before Argon2 runs, and before the file is looked
        // at; the message says so.
        let max = krypto::password::MAX_PASSWORD_BYTES;
        let long = pw(&"p".repeat(max + 1));
        for err in [
            lock(&long, b"x").unwrap_err(),
            unlock(&long, &framed(b"FAFN")).unwrap_err(),
            unlock(&long, b"short").unwrap_err(),
        ] {
            assert!(matches!(err, TlsError::Params(_)), "{err:?}");
            assert!(format!("{err}").contains(&format!("max {max}")), "{err}");
        }
    }

    #[test]
    fn a_plaintext_over_krypto_limit_is_params_not_locked_memory() {
        // 0.12.0: krypto refuses it before any memory is locked.
        let err = lock(&pw("secret"), &vec![0u8; krypto::MAX_DATA_BYTES + 1]).unwrap_err();
        assert!(matches!(err, TlsError::Params(_)), "{err:?}");
        assert!(!format!("{err}").contains("RLIMIT_MEMLOCK"), "{err}");
    }

    #[test]
    fn a_blob_over_krypto_limit_is_refused_by_size() {
        // 0.12.0: not a wrong password, so not `ProofInvalid`.
        let file = framed(&vec![0u8; crate::KRYPTO_MAX_BLOB_BYTES + 1]);
        let err = unlock(&pw("secret"), &file).unwrap_err();
        assert!(matches!(err, TlsError::Envelope(_)), "{err:?}");
        assert!(format!("{err}").contains(&file.len().to_string()), "{err}");
    }

    #[test]
    fn a_blob_krypto_refuses_as_format_is_envelope() {
        // 0.12.0: a blob that is not a krypto blob is a format problem, not a
        // wrong password; the message carries krypto's text.
        let err = unlock(&pw("secret"), &framed(b"not a krypto blob")).unwrap_err();
        assert!(matches!(err, TlsError::Envelope(_)), "{err:?}");
        let text = format!("{err}");
        assert!(text.contains("the locked file was not accepted"), "{text}");
        assert!(text.contains("FAFN"), "{text}");
    }

    /// The locked file the child run of `unlock_under_a_low_memlock_limit`
    /// opens.
    const LOCKED_FILE_ENV: &str = "NETTLS_TEST_LOCKED_FILE";

    /// The system page size, from `getconf`.
    fn page_size() -> usize {
        let out = std::process::Command::new("getconf")
            .arg("PAGESIZE")
            .output()
            .expect("getconf runs");
        String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .expect("getconf PAGESIZE prints a number")
    }

    /// Whether a memlock limit binds this process. It does not with
    /// CAP_IPC_LOCK (bit 14 of `CapEff`), which root outside a container has.
    fn memlock_limit_binds() -> bool {
        let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
            return true;
        };
        let cap_eff = status
            .lines()
            .find_map(|line| line.strip_prefix("CapEff:"))
            .and_then(|value| u64::from_str_radix(value.trim(), 16).ok());
        cap_eff.is_none_or(|caps| caps & (1 << 14) == 0)
    }

    #[test]
    fn unlocked_content_that_cannot_be_held_is_locked_memory() {
        // 0.12.0: krypto locks what it opened; when it cannot, the answer names
        // memory, not the password. The test runs its own binary again with a
        // memlock limit of 8 pages: the password and the keys (3 pages) fit,
        // the content (16 pages) does not. A process with CAP_IPC_LOCK, such as
        // root outside a container, is not bound by the limit, so the test
        // cannot provoke the failure there and is skipped.
        if !memlock_limit_binds() {
            eprintln!("skipped: CAP_IPC_LOCK is set, so no memlock limit binds this process");
            return;
        }
        let page = page_size();
        let file = lock(&pw("secret"), &vec![7u8; 16 * page]).unwrap();
        let path = std::env::temp_dir().join(format!(
            "nettls-locked-memory-{}.locked",
            std::process::id()
        ));
        std::fs::write(&path, &file).unwrap();
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(r#"ulimit -S -l "$1" && exec "$0" "$2" --exact --ignored"#)
            .arg(std::env::current_exe().unwrap())
            .arg((8 * page / 1024).to_string())
            .arg("lockbox::tests::unlock_under_a_low_memlock_limit")
            .env(LOCKED_FILE_ENV, &path)
            .output()
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains("1 passed"),
            "{stdout}{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    #[ignore = "run by unlocked_content_that_cannot_be_held_is_locked_memory, under a low memlock limit"]
    fn unlock_under_a_low_memlock_limit() {
        let path = std::env::var_os(LOCKED_FILE_ENV)
            .expect("started by unlocked_content_that_cannot_be_held_is_locked_memory");
        let file = std::fs::read(path).unwrap();
        let err = unlock(&pw("secret"), &file).unwrap_err();
        assert!(matches!(err, TlsError::LockedMemory(_)), "{err:?}");
        assert!(format!("{err}").contains("the unlocked content"), "{err}");
    }
}
