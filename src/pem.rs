// SPDX-License-Identifier: MIT OR Apache-2.0
//! Minimal PEM encoding (DER → PEM) and safe writing to disk.
//!
//! We *read* PEM with `rustls-pki-types` (its `pem` feature — 0.8.1, wish #3);
//! writing lives here. The base64 body is `krypto::base64` (0.8.1, wish #1's
//! consequence: own variants go away once krypto has the building block).
//!
//! The module also owns the rule that matters when private keys hit disk:
//! **write atomically, and never leave a file more open than it should be.**

use std::fs;
use std::io::Write;
use std::path::Path;

use zeroize::Zeroize;

use crate::error::TlsError;

/// Encodes DER as a PEM block with the given label, 64 chars per line (RFC 7468).
///
/// **Public since 0.8.1 (wish #2):** PEM is TLS domain, so building it lives
/// here — consumers that used to build PEM by hand use this instead. The
/// base64 body is the canonical `krypto::base64`. The intermediate is
/// zeroized: the DER may be a private key. (The returned buffer is the
/// caller's to protect — for a key, `save_pem` holds it in a `SecretBuf`.)
pub fn encode(label: &str, der: &[u8]) -> Vec<u8> {
    let mut b64 = krypto::base64::encode(der).into_bytes();

    let mut out = Vec::with_capacity(b64.len() + b64.len() / 64 + 2 * label.len() + 32);
    out.extend_from_slice(b"-----BEGIN ");
    out.extend_from_slice(label.as_bytes());
    out.extend_from_slice(b"-----\n");
    for line in b64.chunks(64) {
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out.extend_from_slice(b"-----END ");
    out.extend_from_slice(label.as_bytes());
    out.extend_from_slice(b"-----\n");

    b64.zeroize();
    out
}

/// Writes `bytes` to `path` atomically, with `mode`.
///
/// The temp file is created 0600 and only if nothing is there; a leftover or a
/// symlink in its place is removed first. `mode` is set before `rename`, the temp
/// file is removed on error, and the directory is synced afterwards. On non-unix
/// `mode` is ignored.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<(), TlsError> {
    let tmp = path.with_extension("tmp");
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(TlsError::io(&tmp, e)),
    }
    let written = write_new(&tmp, bytes, mode).and_then(|()| {
        fs::rename(&tmp, path).map_err(|e| TlsError::io(path, e))?;
        sync_dir(path)
    });
    if written.is_err() {
        // Best effort: the next write removes it anyway.
        let _ = fs::remove_file(&tmp);
    }
    written
}

/// Creates `tmp` (it must not exist), writes `bytes`, sets `mode` and syncs.
fn write_new(tmp: &Path, bytes: &[u8], mode: u32) -> Result<(), TlsError> {
    let mut open = fs::OpenOptions::new();
    open.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.mode(0o600);
    }
    let mut f = open.open(tmp).map_err(|e| TlsError::io(tmp, e))?;
    f.write_all(bytes).map_err(|e| TlsError::io(tmp, e))?;
    #[cfg(unix)]
    {
        // Explicit: the mode given to `open` is filtered by the umask.
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|e| TlsError::io(tmp, e))?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    f.sync_all().map_err(|e| TlsError::io(tmp, e))
}

/// Syncs the directory `path` lives in, so the `rename` survives a crash.
fn sync_dir(path: &Path) -> Result<(), TlsError> {
    #[cfg(unix)]
    {
        let dir = match path.parent() {
            Some(d) if !d.as_os_str().is_empty() => d,
            _ => Path::new("."),
        };
        fs::File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(|e| TlsError::io(dir, e))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Creates `dir` and any missing parent with mode 0700. An existing directory
/// is left as it is.
pub(crate) fn create_private_dir(dir: &Path) -> Result<(), TlsError> {
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir).map_err(|e| TlsError::io(dir, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    // (The base64 vectors live in krypto::base64 now — the body is its output;
    // the readback test below proves the whole PEM block end-to-end.)

    #[test]
    fn pem_can_be_read_back_by_pki_types() {
        use rustls_pki_types::pem::PemObject;
        // 200 bytes of "DER" → several lines → covers the line wrapping.
        let der: Vec<u8> = (0..200u32).map(|i| (i * 7 % 251) as u8).collect();
        let pem = encode("CERTIFICATE", &der);
        let certs: Vec<_> = rustls_pki_types::CertificateDer::pem_slice_iter(&pem)
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].as_ref(), &der[..]);
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("nettls-pem-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[cfg(unix)]
    fn mode_of(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    #[test]
    fn a_leftover_temp_file_is_replaced_not_reused() {
        use std::os::unix::fs::PermissionsExt;
        let d = scratch("leftover");
        let path = d.join("key.pem");
        // What an interrupted write leaves behind: content, and the umask's mode.
        fs::write(path.with_extension("tmp"), b"half a key").unwrap();
        fs::set_permissions(
            path.with_extension("tmp"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();

        write_atomic(&path, b"the key", 0o600).unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"the key");
        assert_eq!(mode_of(&path), 0o600);
        assert!(!path.with_extension("tmp").exists());
        let _ = fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_where_the_temp_file_goes_is_not_followed() {
        let d = scratch("symlink");
        let path = d.join("key.pem");
        let elsewhere = d.join("elsewhere");
        fs::write(&elsewhere, b"not ours").unwrap();
        std::os::unix::fs::symlink(&elsewhere, path.with_extension("tmp")).unwrap();

        write_atomic(&path, b"the key", 0o600).unwrap();

        assert_eq!(fs::read(&elsewhere).unwrap(), b"not ours");
        assert_eq!(fs::read(&path).unwrap(), b"the key");
        assert!(
            !fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        let _ = fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn the_final_mode_is_the_one_asked_for() {
        let d = scratch("mode");
        write_atomic(&d.join("cert.pem"), b"cert", 0o644).unwrap();
        write_atomic(&d.join("key.pem"), b"key", 0o600).unwrap();
        assert_eq!(mode_of(&d.join("cert.pem")), 0o644);
        assert_eq!(mode_of(&d.join("key.pem")), 0o600);
        let _ = fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn key_directories_are_created_0700_and_existing_ones_are_left_alone() {
        use std::os::unix::fs::PermissionsExt;
        let d = scratch("dirs");
        let nested = d.join("a").join("b");
        create_private_dir(&nested).unwrap();
        assert_eq!(mode_of(&d.join("a")), 0o700);
        assert_eq!(mode_of(&nested), 0o700);

        let existing = d.join("existing");
        fs::create_dir(&existing).unwrap();
        fs::set_permissions(&existing, fs::Permissions::from_mode(0o750)).unwrap();
        create_private_dir(&existing).unwrap();
        assert_eq!(mode_of(&existing), 0o750);
        let _ = fs::remove_dir_all(&d);
    }
}
